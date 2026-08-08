//! Client: all encryption and decryption happen here; the server only sends and receives Base64 ciphertext.

use anyhow::{Context, Result, bail};
use reqwest::{RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, process::Command as ProcessCommand, time::Duration};

use crate::{
    cli::{Cli, Command, Env, SecretsCommand},
    crypto,
    protocol::{CreateProjectRequest, ProjectMetadata},
};

#[derive(Debug, Deserialize)]
struct SecretValue {
    value: String,
}

#[derive(Debug, Deserialize)]
struct SecretEntry {
    name: String,
    value: String,
}

/// Execute a subcommand in client mode.
pub async fn run(cli: Cli) -> Result<()> {
    let command = cli
        .command
        .as_ref()
        .expect("the caller verified that a subcommand exists");
    let api = Api::new(cli.server.as_deref(), cli.token.as_deref(), cli.insecure)?;

    match command {
        Command::Init { project_name } => {
            let password = resolve_new_project_password(&cli.password)?;
            let metadata = crypto::create_project_metadata(project_name, &password)?;
            api.create_project(project_name, &metadata).await?;
            println!("Project `{project_name}` created");
        }

        Command::Secrets { action } => match action {
            SecretsCommand::Set {
                project_name,
                env,
                name,
                value,
            } => {
                let key = unlock_project(&api, project_name, &cli.password).await?;
                let name = resolve_secret_name(name)?;
                let value = resolve_secret_value(value)?;
                let blob = crypto::encrypt_secret(&key, project_name, env.as_str(), &name, &value)?;
                api.set_secret(project_name, *env, &name, &blob).await?;
                println!("Set {name} in {project_name}/{}", env.as_str());
            }

            SecretsCommand::Get {
                project_name,
                env,
                name: Some(name),
            } => {
                let key = unlock_project(&api, project_name, &cli.password).await?;
                let blob = api.get_secret(project_name, *env, name).await?;
                println!(
                    "{}",
                    crypto::decrypt_secret(&key, project_name, env.as_str(), name, &blob)?
                );
            }

            SecretsCommand::Get {
                project_name,
                env,
                name: None,
            } => {
                let key = unlock_project(&api, project_name, &cli.password).await?;
                for (name, value) in api.fetch_all(project_name, *env, &key).await? {
                    println!("{name}={value}");
                }
            }

            SecretsCommand::Delete {
                project_name,
                env,
                name,
            } => {
                let _key = unlock_project(&api, project_name, &cli.password).await?;
                api.delete_secret(project_name, *env, name).await?;
                println!("Deleted {name} from {project_name}/{}", env.as_str());
            }
        },

        Command::Run {
            project_name,
            env,
            argv,
        } => {
            let key = unlock_project(&api, project_name, &cli.password).await?;
            let secrets = api.fetch_all(project_name, *env, &key).await?;
            exec(argv, secrets)?;
        }
    }

    Ok(())
}

async fn unlock_project(
    api: &Api,
    project: &str,
    from_args: &Option<String>,
) -> Result<crypto::ProjectKey> {
    let metadata = api.get_project(project).await?;
    let password = resolve_password(from_args)?;
    crypto::unlock_project(project, &password, &metadata)
}

/// Resolve a secret name from the command line or prompt for it interactively.
fn resolve_secret_name(from_args: &Option<String>) -> Result<String> {
    if let Some(name) = from_args {
        return Ok(name.clone());
    }

    dialoguer::Input::<String>::new()
        .with_prompt("Enter the secret name")
        .interact_text()
        .context("Failed to read secret name (use --name in non-interactive environments)")
}

/// Resolve a secret value from the command line or prompt for it without echoing it.
fn resolve_secret_value(from_args: &Option<String>) -> Result<String> {
    if let Some(value) = from_args {
        return Ok(value.clone());
    }

    dialoguer::Password::new()
        .with_prompt("Enter the secret value")
        .allow_empty_password(true)
        .interact()
        .context("Failed to read secret value (use --value in non-interactive environments)")
}

/// Resolve and confirm the password used to create a new project.
fn resolve_new_project_password(from_args: &Option<String>) -> Result<String> {
    if let Some(password) = from_args {
        if password.is_empty() {
            bail!("Project password cannot be empty");
        }
        return Ok(password.clone());
    }

    dialoguer::Password::new()
        .with_prompt("Enter the new project password")
        .with_confirmation("Confirm the new project password", "Project passwords do not match")
        .interact()
        .context("Failed to read project password (use --password or KEYBEN_PASSWORD in non-interactive environments)")
}

/// Resolve the project password from an argument or environment variable, otherwise prompt securely.
fn resolve_password(from_args: &Option<String>) -> Result<String> {
    if let Some(password) = from_args {
        if password.is_empty() {
            bail!("Project password cannot be empty");
        }
        return Ok(password.clone());
    }

    dialoguer::Password::new()
        .with_prompt("Enter the project password")
        .interact()
        .context("Failed to read project password (use --password or KEYBEN_PASSWORD in non-interactive environments)")
}

/// Inject decrypted environment variables, launch the child process unchanged, and propagate its exit code.
fn exec(argv: &[String], secrets: BTreeMap<String, String>) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .context("A program to execute must be provided after `--`")?;

    let status = ProcessCommand::new(program)
        .args(args)
        .envs(&secrets)
        .status()
        .with_context(|| format!("Failed to execute `{program}`"))?;

    // When a signal terminates the child (status.code() is None), conventionally
    // return 128 + the signal number.
    let code = status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map_or(1, |signo| 128 + signo)
        }
        #[cfg(not(unix))]
        {
            1
        }
    });

    std::process::exit(code);
}

// --------------------------------------------------------------- HTTP client

struct Api {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Api {
    fn new(server: Option<&str>, token: Option<&str>, insecure: bool) -> Result<Self> {
        let base = server
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing server URL; use --server or set KEYBEN_SERVER")?
            .trim_end_matches('/')
            .to_owned();

        let token = token
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing authentication token; use --token or set KEYBEN_TOKEN")?
            .to_owned();

        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self { http, base, token })
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
            .bearer_auth(&self.token)
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
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned))
            .unwrap_or(body);

        if detail.trim().is_empty() {
            bail!("Server returned {status}");
        }
        bail!("Server returned {status}: {detail}");
    }

    async fn create_project(&self, project: &str, metadata: &ProjectMetadata) -> Result<()> {
        let url = format!("{}/api/projects", self.base);
        let request = CreateProjectRequest {
            name: project.to_owned(),
            kdf: metadata.kdf.clone(),
            verifier: metadata.verifier.clone(),
        };
        self.send(self.http.post(url).json(&request)).await?;
        Ok(())
    }

    async fn get_project(&self, project: &str) -> Result<ProjectMetadata> {
        let url = self.url(&[project]);
        self.send(self.http.get(url))
            .await?
            .json()
            .await
            .context("Failed to parse project metadata")
    }

    async fn set_secret(&self, project: &str, env: Env, name: &str, blob: &str) -> Result<()> {
        let url = self.url(&[project, env.as_str(), name]);
        self.send(self.http.put(url).json(&json!({ "value": blob })))
            .await?;
        Ok(())
    }

    async fn get_secret(&self, project: &str, env: Env, name: &str) -> Result<String> {
        let url = self.url(&[project, env.as_str(), name]);
        let payload: SecretValue = self
            .send(self.http.get(url))
            .await?
            .json()
            .await
            .context("Failed to parse server response")?;
        Ok(payload.value)
    }

    async fn delete_secret(&self, project: &str, env: Env, name: &str) -> Result<()> {
        let url = self.url(&[project, env.as_str(), name]);
        self.send(self.http.delete(url)).await?;
        Ok(())
    }

    /// Fetch and decrypt all variables in an environment with a verified project key.
    async fn fetch_all(
        &self,
        project: &str,
        env: Env,
        key: &crypto::ProjectKey,
    ) -> Result<BTreeMap<String, String>> {
        let url = self.url(&[project, env.as_str()]);
        let entries: Vec<SecretEntry> = self
            .send(self.http.get(url))
            .await?
            .json()
            .await
            .context("Failed to parse server response")?;

        entries
            .into_iter()
            .map(|entry| {
                let value =
                    crypto::decrypt_secret(key, project, env.as_str(), &entry.name, &entry.value)
                        .with_context(|| format!("Failed to decrypt variable `{}`", entry.name))?;
                Ok((entry.name, value))
            })
            .collect()
    }
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
    use super::percent_encode;

    #[test]
    fn encodes_reserved_characters() {
        assert_eq!(percent_encode("DB_URL"), "DB_URL");
        assert_eq!(percent_encode("a/b c"), "a%2Fb%20c");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }
}
