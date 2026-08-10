//! The HTTP client. It only ever sends and receives Base64 ciphertext plus public envelope
//! metadata; every encryption and decryption step happens in the caller.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use reqwest::{RequestBuilder, Response, StatusCode};
use std::collections::BTreeMap;

use crate::common::{
    cli::Password,
    consts::{HTTP_TIMEOUT, PROJECT_AUTH_HEADER},
    crypto,
    env::Env,
    wire,
};

/// An unlocked project: the password-derived keys plus the unwrapped DEK, ready to
/// authenticate requests and encrypt or decrypt secrets.
///
/// Both fields wipe themselves when the session is dropped.
pub struct ProjectSession {
    keys: crypto::ProjectKeys,
    pub dek: crypto::SecretKey,
}

pub struct Api {
    http: reqwest::Client,
    base: String,
    /// A credential, so it is wiped when the client is dropped.
    token: Password,
}

impl Api {
    /// Build a client for an already-resolved server and token.
    ///
    /// Both values are validated before they reach here (see `client::runtime`), so this only
    /// normalizes the base URL rather than re-checking for emptiness.
    pub fn new(server: &str, token: &Password, insecure: bool) -> Result<Self> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(HTTP_TIMEOUT)
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            http,
            base: server.trim().trim_end_matches('/').to_owned(),
            token: token.clone(),
        })
    }

    /// Build a URL and percent-encode path segments so special characters in variable names work.
    fn url(&self, segments: &[&str]) -> String {
        let mut url = format!("{}/api/projects", self.base);
        for segment in segments {
            url.push('/');
            url.push_str(&percent_encode(segment));
        }
        url
    }

    /// Send a request and translate non-2xx status codes into readable errors.
    async fn send(&self, request: RequestBuilder) -> Result<Response> {
        let response = request
            .bearer_auth(self.token.as_str())
            .send()
            .await
            .with_context(|| format!("Request to server failed: {}", self.base))?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        if status == StatusCode::UNAUTHORIZED {
            bail!(
                "Authentication failed (401): the token does not match auth_token in the server's config.toml"
            );
        }

        let body = response.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<wire::ApiErrorBody>(&body)
            .map(|parsed| parsed.error)
            .unwrap_or(body);

        if detail.trim().is_empty() {
            bail!("Server returned {status}");
        }
        bail!("Server returned {status}: {detail}");
    }

    /// Create a project: generate a fresh salt and DEK, wrap the DEK under the password-derived
    /// key, and send only public envelope metadata to the server.
    pub async fn create_project(&self, project: &str, password: &str) -> Result<()> {
        let salt = crypto::generate_salt();
        let keys = crypto::derive_project_keys(password, &salt)?;
        let dek = crypto::generate_dek();

        let url = format!("{}/api/projects", self.base);
        self.send(self.http.post(url).json(&wire::CreateProject {
            name: project.to_owned(),
            salt: B64.encode(salt),
            wrapped_dek: crypto::wrap_dek(&keys, &dek, project)?,
            auth_hash: keys.auth_hash_b64(),
        }))
        .await?;
        Ok(())
    }

    /// Fetch the public salt needed to derive the project keys. Bearer-only.
    async fn fetch_kdf(&self, project: &str) -> Result<wire::ProjectKdf> {
        let url = format!("{}/api/project-kdf/{}", self.base, percent_encode(project));
        self.send(self.http.get(url))
            .await?
            .json()
            .await
            .context("Failed to parse project KDF parameters from server")
    }

    /// Fetch the wrapped DEK after proving knowledge of the project password.
    async fn fetch_meta(
        &self,
        project: &str,
        keys: &crypto::ProjectKeys,
    ) -> Result<wire::ProjectMeta> {
        let url = format!("{}/api/project-meta/{}", self.base, percent_encode(project));
        self.send(
            self.http
                .get(url)
                .header(PROJECT_AUTH_HEADER, keys.auth_secret_b64()),
        )
        .await?
        .json()
        .await
        .context("Failed to parse project metadata from server")
    }

    /// Unlock a project: fetch its metadata, derive keys from the password, and unwrap the DEK.
    ///
    /// This exercises every credential at once — the server URL, the bearer token, the project's
    /// existence, and the password — which is why `config init` uses it to verify before writing.
    pub async fn unlock(&self, project: &str, password: &str) -> Result<ProjectSession> {
        let kdf = self.fetch_kdf(project).await?;
        let keys = derive_keys(project, password, &kdf.salt)?;
        let meta = self.fetch_meta(project, &keys).await?;
        let dek = crypto::unwrap_dek(&keys, &meta.wrapped_dek, project)
            .context("Failed to unlock the project; incorrect password")?;
        Ok(ProjectSession { keys, dek })
    }

    /// Re-wrap the project DEK under a new password. The secret ciphertext is never touched.
    pub async fn reset_password(
        &self,
        project: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Unlock with the old password to recover the DEK, then re-wrap that *same* DEK under a
        // fresh salt, so existing ciphertext keeps decrypting.
        let kdf = self.fetch_kdf(project).await?;
        let old_keys = derive_keys(project, old_password, &kdf.salt)?;
        let meta = self.fetch_meta(project, &old_keys).await?;
        let dek = crypto::unwrap_dek(&old_keys, &meta.wrapped_dek, project)
            .context("Failed to unlock the project with the current password")?;

        let new_salt = crypto::generate_salt();
        let new_keys = crypto::derive_project_keys(new_password, &new_salt)?;

        let url = format!(
            "{}/api/project-passwords/{}",
            self.base,
            percent_encode(project)
        );
        self.send(
            self.http
                .post(url)
                .header(PROJECT_AUTH_HEADER, old_keys.auth_secret_b64())
                .json(&wire::ResetProjectPassword {
                    salt: B64.encode(new_salt),
                    wrapped_dek: crypto::wrap_dek(&new_keys, &dek, project)?,
                    auth_hash: new_keys.auth_hash_b64(),
                }),
        )
        .await?;
        Ok(())
    }

    pub async fn set_secret(
        &self,
        project: &str,
        env: Env,
        name: &str,
        blob: &str,
        session: &ProjectSession,
    ) -> Result<()> {
        let url = self.url(&[project, env.as_str(), name]);
        self.send(
            self.http
                .put(url)
                .header(PROJECT_AUTH_HEADER, session.keys.auth_secret_b64())
                .json(&wire::SecretValue {
                    value: blob.to_owned(),
                }),
        )
        .await?;
        Ok(())
    }

    /// Fetch and decrypt one variable.
    pub async fn get_secret(
        &self,
        project: &str,
        env: Env,
        name: &str,
        session: &ProjectSession,
    ) -> Result<crypto::SecretText> {
        let url = self.url(&[project, env.as_str(), name]);
        let payload: wire::SecretValue = self
            .send(
                self.http
                    .get(url)
                    .header(PROJECT_AUTH_HEADER, session.keys.auth_secret_b64()),
            )
            .await?
            .json()
            .await
            .context("Failed to parse server response")?;
        crypto::decrypt_secret(&session.dek, project, env.as_str(), name, &payload.value)
    }

    pub async fn delete_secret(
        &self,
        project: &str,
        env: Env,
        name: &str,
        session: &ProjectSession,
    ) -> Result<()> {
        let url = self.url(&[project, env.as_str(), name]);
        self.send(
            self.http
                .delete(url)
                .header(PROJECT_AUTH_HEADER, session.keys.auth_secret_b64()),
        )
        .await?;
        Ok(())
    }

    /// Fetch and decrypt all variables in an environment.
    ///
    /// Every value is wrapped, so the whole map wipes itself when the caller drops it.
    pub async fn fetch_all(
        &self,
        project: &str,
        env: Env,
        session: &ProjectSession,
    ) -> Result<BTreeMap<String, crypto::SecretText>> {
        let url = self.url(&[project, env.as_str()]);
        let entries: Vec<wire::SecretEntry> = self
            .send(
                self.http
                    .get(url)
                    .header(PROJECT_AUTH_HEADER, session.keys.auth_secret_b64()),
            )
            .await?
            .json()
            .await
            .context("Failed to parse server response")?;

        entries
            .into_iter()
            .map(|entry| {
                let value = crypto::decrypt_secret(
                    &session.dek,
                    project,
                    env.as_str(),
                    &entry.name,
                    &entry.value,
                )
                .with_context(|| format!("Failed to decrypt variable `{}`", entry.name))?;
                Ok((entry.name, value))
            })
            .collect()
    }
}

/// Decode a Base64 salt from the server and derive the per-project keys from a password.
fn derive_keys(project: &str, password: &str, salt_b64: &str) -> Result<crypto::ProjectKeys> {
    let salt = B64
        .decode(salt_b64.trim())
        .with_context(|| format!("Project `{project}` returned an invalid salt"))?;
    crypto::derive_project_keys(password, &salt)
}

/// Percent-encode a single URL path segment according to RFC 3986.
fn percent_encode(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reserved_characters() {
        assert_eq!(percent_encode("DB_URL"), "DB_URL");
        assert_eq!(percent_encode("a/b c"), "a%2Fb%20c");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    /// A trailing slash on the server URL would otherwise produce `//api/...`.
    #[test]
    fn base_url_is_normalized() {
        let token = Password::new("t0ken".to_owned());
        let api = Api::new("  https://example.com/  ", &token, false).unwrap();
        assert_eq!(
            api.url(&["app", "dev", "DB_URL"]),
            "https://example.com/api/projects/app/dev/DB_URL"
        );
    }
}
