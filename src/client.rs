//! Client: all encryption and decryption happen here; the server only sends and receives Base64 ciphertext.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use reqwest::{RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, process::Command as ProcessCommand, time::Duration};

use crate::{
    cli::{Cli, Command, ConfigCommand, Env, PasswordCommand, SecretsCommand},
    config::{self, Config},
    crypto,
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

/// Public per-project metadata the client fetches before deriving keys.
#[derive(Debug, Deserialize)]
struct ProjectMeta {
    salt: String,
    wrapped_dek: String,
}

/// An unlocked project: the password-derived keys plus the unwrapped DEK, ready to
/// authenticate requests and encrypt or decrypt secrets.
struct ProjectSession {
    keys: crypto::ProjectKeys,
    dek: [u8; 32],
}

/// Execute a subcommand in client mode.
pub async fn run(cli: Cli) -> Result<()> {
    let command = cli
        .command
        .as_ref()
        .expect("the caller verified that a subcommand exists");
    if let Command::Config { action } = command {
        return run_config_command(action, &cli).await;
    }

    let project_arg = project_name_arg(command);
    let runtime = resolve_runtime(&cli, project_arg)?;
    let api = Api::new(Some(&runtime.server), Some(&runtime.token), cli.insecure)?;
    let project_name = runtime.project_name.as_str();

    match command {
        Command::Init { .. } => {
            // A password already resolved for `.keyben.toml` was confirmed when that file was
            // written, so reuse it instead of asking for a fresh confirmation here.
            let password = match &runtime.password {
                Some(password) => password.clone(),
                None => resolve_new_password(
                    cli.password.as_ref(),
                    "Enter the new project password",
                    "use --password or KEYBEN_PASSWORD in non-interactive environments",
                )?,
            };
            api.create_project(project_name, &password).await?;
            println!("Project `{project_name}` created");
        }

        Command::Secrets { action } => match action {
            SecretsCommand::Set {
                env, name, value, ..
            } => {
                let password = runtime.project_password(&cli.password)?;
                let name = resolve_secret_name(name)?;
                let value = resolve_secret_value(value)?;
                let session = api.unlock(project_name, &password).await?;
                let blob = crypto::encrypt_secret(
                    &session.dek,
                    project_name,
                    env.as_str(),
                    &name,
                    &value,
                )?;
                api.set_secret(project_name, *env, &name, &blob, &session)
                    .await?;
                println!("Set {name} in {project_name}/{}", env.as_str());
            }

            SecretsCommand::Get {
                env,
                name: Some(name),
                ..
            } => {
                let password = runtime.project_password(&cli.password)?;
                let session = api.unlock(project_name, &password).await?;
                let blob = api.get_secret(project_name, *env, name, &session).await?;
                println!(
                    "{}",
                    crypto::decrypt_secret(&session.dek, project_name, env.as_str(), name, &blob)?
                );
            }

            SecretsCommand::Get {
                env, name: None, ..
            } => {
                let password = runtime.project_password(&cli.password)?;
                let session = api.unlock(project_name, &password).await?;
                for (name, value) in api.fetch_all(project_name, *env, &session).await? {
                    println!("{name}={value}");
                }
            }

            SecretsCommand::Delete { env, name, .. } => {
                let password = runtime.project_password(&cli.password)?;
                let session = api.unlock(project_name, &password).await?;
                api.delete_secret(project_name, *env, name, &session)
                    .await?;
                println!("Deleted {name} from {project_name}/{}", env.as_str());
            }
        },

        Command::Password { action } => match action {
            PasswordCommand::Reset { new_password, .. } => {
                let old_password = runtime.project_password(&cli.password)?;
                reset_project_password(&api, project_name, &old_password, new_password.as_ref())
                    .await?;
                if config::exists()? {
                    println!(
                        "Reset password for project `{project_name}`.\n\
                         Note: .keyben.toml is still encrypted under the old password; \
                         recreate it with `keyben config init` to use the new one."
                    );
                } else {
                    println!("Reset password for project `{project_name}`");
                }
            }
        },

        Command::Run { env, argv, .. } => {
            let password = runtime.project_password(&cli.password)?;
            let session = api.unlock(project_name, &password).await?;
            let secrets = api.fetch_all(project_name, *env, &session).await?;
            exec(argv, secrets)?;
        }
        Command::Config { .. } => {
            unreachable!("config commands are handled before runtime resolution")
        }
    }

    Ok(())
}

struct RuntimeConfig {
    project_name: String,
    server: String,
    token: String,
    /// The password already resolved to decrypt `.keyben.toml`, when that file was read.
    password: Option<String>,
}

impl RuntimeConfig {
    /// One password unlocks both `.keyben.toml` and the project itself, so reuse the value
    /// already resolved for the file rather than prompting a second time.
    fn project_password(&self, from_args: &Option<String>) -> Result<String> {
        match &self.password {
            Some(password) => Ok(password.clone()),
            None => resolve_password(from_args),
        }
    }
}

fn project_name_arg(command: &Command) -> Option<&str> {
    match command {
        Command::Init { project_name } | Command::Run { project_name, .. } => {
            project_name.as_deref()
        }
        Command::Secrets { action } => match action {
            SecretsCommand::Set { project_name, .. }
            | SecretsCommand::Get { project_name, .. }
            | SecretsCommand::Delete { project_name, .. } => project_name.as_deref(),
        },
        Command::Password { action } => match action {
            PasswordCommand::Reset { project_name, .. } => project_name.as_deref(),
        },
        Command::Config { .. } => None,
    }
}

fn resolve_runtime(cli: &Cli, project_arg: Option<&str>) -> Result<RuntimeConfig> {
    let needs_file = cli.server.is_none() || cli.token.is_none() || project_arg.is_none();
    let (file_config, password) = if needs_file && config::exists()? {
        // The project password doubles as the `.keyben.toml` password.
        let password = resolve_password(&cli.password)?;
        (Some(config::read(&password)?), Some(password))
    } else {
        (None, None)
    };

    let project_name = project_arg
        .map(str::to_owned)
        .or_else(|| file_config.as_ref().map(|c| c.project_name.clone()))
        .unwrap_or_default();
    let server = cli
        .server
        .clone()
        .or_else(|| file_config.as_ref().map(|c| c.server.clone()));
    let token = cli
        .token
        .clone()
        .or_else(|| file_config.as_ref().map(|c| c.token.clone()));
    let server = server
        .filter(|s| !s.trim().is_empty())
        .context("Missing server URL; use --server, KEYBEN_SERVER, or create .keyben.toml")?;
    let token = token.filter(|s| !s.trim().is_empty()).context(
        "Missing authentication token; use --token, KEYBEN_TOKEN, or create .keyben.toml",
    )?;
    // Canonicalize once here: the name keys the server row and is bound as associated data,
    // so an untrimmed copy would look up a row that does not exist.
    let project_name = project_name.trim();
    if project_name.is_empty() {
        bail!("Missing project name; use --projectName or create .keyben.toml");
    }
    config::validate_values(project_name, &server, &token)?;
    Ok(RuntimeConfig {
        project_name: project_name.to_owned(),
        server,
        token,
        password,
    })
}

async fn run_config_command(action: &ConfigCommand, cli: &Cli) -> Result<()> {
    match action {
        ConfigCommand::Init { project_name } => {
            let project_name = project_name
                .clone()
                .or_else(|| prompt_text("Enter the project name"))
                .context("Missing project name; use --projectName")?;
            let server = cli
                .server
                .clone()
                .or_else(|| prompt_text("Enter the server URL"))
                .context("Missing server URL; use --server")?;
            let token = cli
                .token
                .clone()
                .or_else(|| prompt_text("Enter the authentication token"))
                .context("Missing authentication token; use --token")?;
            let project_name = project_name.trim().to_owned();
            config::validate_values(&project_name, &server, &token)?;
            if config::exists()? {
                let file = config::path()?;
                let overwrite = dialoguer::Confirm::new()
                    .with_prompt(format!("{} already exists; overwrite it?", file.display()))
                    .default(false)
                    .interact()
                    .unwrap_or(false);
                if !overwrite {
                    bail!("Cancelled; {} was left unchanged", file.display());
                }
            }
            // The project password also encrypts this file, so there is only one to remember.
            let password = resolve_new_password(
                cli.password.as_ref(),
                "Enter the project password",
                "use --password or KEYBEN_PASSWORD",
            )?;
            let file = config::write(
                &Config {
                    project_name,
                    server,
                    token,
                },
                &password,
            )?;
            println!("Wrote {}", file.display());
        }
    }
    Ok(())
}

fn prompt_text(prompt: &str) -> Option<String> {
    dialoguer::Input::<String>::new()
        .with_prompt(prompt)
        .interact_text()
        .ok()
}

/// Resolve the password from an argument or environment variable, otherwise prompt securely.
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
        .context("Failed to read password (use --password or KEYBEN_PASSWORD in non-interactive environments)")
}

fn resolve_secret_name(from_args: &Option<String>) -> Result<String> {
    let name = match from_args {
        Some(name) => name.clone(),
        None => dialoguer::Input::<String>::new()
            .with_prompt("Enter the secret name")
            .interact_text()
            .context("Failed to read secret name (use --name in non-interactive environments)")?,
    };
    if name.trim().is_empty() {
        bail!("Secret name cannot be empty");
    }
    Ok(name)
}

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

fn resolve_new_password(from_args: Option<&String>, prompt: &str, usage: &str) -> Result<String> {
    if let Some(password) = from_args {
        if password.is_empty() {
            bail!("Project password cannot be empty");
        }
        return Ok(password.clone());
    }

    dialoguer::Password::new()
        .with_prompt(prompt)
        .with_confirmation(
            "Confirm the new project password",
            "Project passwords do not match",
        )
        .interact()
        .with_context(|| format!("Failed to read project password ({usage})"))
}

/// Decode a Base64 salt from the server and derive the per-project keys from a password.
fn derive_keys(project: &str, password: &str, salt_b64: &str) -> Result<crypto::ProjectKeys> {
    let salt = B64
        .decode(salt_b64.trim())
        .with_context(|| format!("Project `{project}` returned an invalid salt"))?;
    crypto::derive_project_keys(password, &salt)
}

async fn reset_project_password(
    api: &Api,
    project: &str,
    old_password: &str,
    new_password_args: Option<&String>,
) -> Result<()> {
    let new_password = resolve_new_password(
        new_password_args,
        "Enter the new project password",
        "use --new-password or KEYBEN_NEW_PASSWORD in non-interactive environments",
    )?;
    if old_password == new_password {
        bail!("New project password must differ from the current password");
    }

    // Unlock the project with the old password to recover the DEK, then re-wrap the *same*
    // DEK under a fresh salt and new password. Secret ciphertext is never touched.
    let meta = api.fetch_meta(project).await?;
    let old_keys = derive_keys(project, old_password, &meta.salt)?;
    let dek = crypto::unwrap_dek(&old_keys, &meta.wrapped_dek, project)
        .context("Failed to unlock the project with the current password")?;

    let new_salt = crypto::generate_salt();
    let new_keys = crypto::derive_project_keys(&new_password, &new_salt)?;
    let new_wrapped_dek = crypto::wrap_dek(&new_keys, &dek, project)?;

    api.reset_project_password(
        project,
        &old_keys,
        &B64.encode(new_salt),
        &new_wrapped_dek,
        &new_keys.auth_hash_b64(),
    )
    .await
}

/// keyben's own credentials, which automation supplies through the environment. A child that
/// dumps its environment would otherwise expose the project password and the server token.
const CREDENTIAL_ENV_VARS: [&str; 4] = [
    "KEYBEN_TOKEN",
    "KEYBEN_PASSWORD",
    "KEYBEN_NEW_PASSWORD",
    "KEYBEN_CONFIG_PASSWORD",
];

/// Build the child process: inherit the caller's environment, add the decrypted secrets, and
/// drop keyben's own credentials so they cannot leak into the child.
fn build_child_command(
    program: &str,
    args: &[String],
    secrets: &BTreeMap<String, String>,
) -> ProcessCommand {
    let mut command = ProcessCommand::new(program);
    command.args(args).envs(secrets);
    // Strip inherited credentials, but never a variable the project itself defines under one
    // of these names: an explicit secret wins over the ambient value.
    for name in CREDENTIAL_ENV_VARS {
        if !secrets.contains_key(name) {
            command.env_remove(name);
        }
    }
    command
}

/// Inject decrypted environment variables, launch the child process unchanged, and propagate its exit code.
fn exec(argv: &[String], secrets: BTreeMap<String, String>) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .context("A program to execute must be provided after `--`")?;

    let status = build_child_command(program, args, &secrets)
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

    /// Create a project: generate a fresh salt and DEK, wrap the DEK under the password-derived
    /// key, and send only public envelope metadata to the server.
    async fn create_project(&self, project: &str, password: &str) -> Result<()> {
        let salt = crypto::generate_salt();
        let keys = crypto::derive_project_keys(password, &salt)?;
        let dek = crypto::generate_dek();
        let wrapped_dek = crypto::wrap_dek(&keys, &dek, project)?;

        let url = format!("{}/api/projects", self.base);
        self.send(self.http.post(url).json(&json!({
            "name": project,
            "salt": B64.encode(salt),
            "wrapped_dek": wrapped_dek,
            "auth_hash": keys.auth_hash_b64(),
        })))
        .await?;
        Ok(())
    }

    /// Fetch the public metadata (salt + wrapped DEK) needed to derive keys. Bearer-only.
    async fn fetch_meta(&self, project: &str) -> Result<ProjectMeta> {
        let url = format!("{}/api/project-meta/{}", self.base, percent_encode(project));
        self.send(self.http.get(url))
            .await?
            .json()
            .await
            .context("Failed to parse project metadata from server")
    }

    /// Unlock a project: fetch its metadata, derive keys from the password, and unwrap the DEK.
    async fn unlock(&self, project: &str, password: &str) -> Result<ProjectSession> {
        let meta = self.fetch_meta(project).await?;
        let keys = derive_keys(project, password, &meta.salt)?;
        let dek = crypto::unwrap_dek(&keys, &meta.wrapped_dek, project)
            .context("Failed to unlock the project; incorrect password")?;
        Ok(ProjectSession { keys, dek })
    }

    async fn reset_project_password(
        &self,
        project: &str,
        old_keys: &crypto::ProjectKeys,
        new_salt: &str,
        new_wrapped_dek: &str,
        new_auth_hash: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/api/project-passwords/{}",
            self.base,
            percent_encode(project)
        );
        self.send(
            self.http
                .post(url)
                .header(PROJECT_AUTH_HEADER, old_keys.auth_secret_b64())
                .json(&json!({
                    "salt": new_salt,
                    "wrapped_dek": new_wrapped_dek,
                    "auth_hash": new_auth_hash,
                })),
        )
        .await?;
        Ok(())
    }

    async fn set_secret(
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
                .json(&json!({ "value": blob })),
        )
        .await?;
        Ok(())
    }

    async fn get_secret(
        &self,
        project: &str,
        env: Env,
        name: &str,
        session: &ProjectSession,
    ) -> Result<String> {
        let url = self.url(&[project, env.as_str(), name]);
        let payload: SecretValue = self
            .send(
                self.http
                    .get(url)
                    .header(PROJECT_AUTH_HEADER, session.keys.auth_secret_b64()),
            )
            .await?
            .json()
            .await
            .context("Failed to parse server response")?;
        Ok(payload.value)
    }

    async fn delete_secret(
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
    async fn fetch_all(
        &self,
        project: &str,
        env: Env,
        session: &ProjectSession,
    ) -> Result<BTreeMap<String, String>> {
        let entries = self.fetch_encrypted(project, env, session).await?;

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

    async fn fetch_encrypted(
        &self,
        project: &str,
        env: Env,
        session: &ProjectSession,
    ) -> Result<Vec<SecretEntry>> {
        let url = self.url(&[project, env.as_str()]);
        self.send(
            self.http
                .get(url)
                .header(PROJECT_AUTH_HEADER, session.keys.auth_secret_b64()),
        )
        .await?
        .json()
        .await
        .context("Failed to parse server response")
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

const PROJECT_AUTH_HEADER: &str = "x-keyben-project-auth";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reserved_characters() {
        assert_eq!(percent_encode("DB_URL"), "DB_URL");
        assert_eq!(percent_encode("a/b c"), "a%2Fb%20c");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    /// Look up how a name is configured on the child: `Some` is an explicit value, `None` means
    /// the child will not inherit it, and absent means it inherits the caller's value.
    fn child_env<'a>(command: &'a ProcessCommand, name: &str) -> Option<Option<&'a str>> {
        command
            .get_envs()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.map(|v| v.to_str().unwrap()))
    }

    /// Automation supplies these through the environment, so a child that dumps its environment
    /// would otherwise expose the project password and the server token.
    #[test]
    fn child_process_does_not_inherit_keyben_credentials() {
        let secrets = BTreeMap::from([("DB_URL".to_owned(), "postgres://x".to_owned())]);
        let command = build_child_command("sh", &[], &secrets);

        for name in CREDENTIAL_ENV_VARS {
            assert_eq!(
                child_env(&command, name),
                Some(None),
                "{name} must be cleared rather than inherited"
            );
        }
        assert_eq!(
            child_env(&command, "DB_URL"),
            Some(Some("postgres://x")),
            "decrypted secrets must still reach the child"
        );
        // Everything else is inherited untouched.
        assert_eq!(child_env(&command, "PATH"), None);
    }

    /// A project may legitimately store a secret under one of those names; it must not be
    /// stripped along with the ambient value.
    #[test]
    fn an_explicit_secret_overrides_the_inherited_credential() {
        let secrets = BTreeMap::from([("KEYBEN_TOKEN".to_owned(), "from-project".to_owned())]);
        let args = ["-c".to_owned(), "printf '%s' \"$KEYBEN_TOKEN\"".to_owned()];

        assert_eq!(
            child_env(&build_child_command("sh", &args, &secrets), "KEYBEN_TOKEN"),
            Some(Some("from-project"))
        );
        // And confirm the child really observes it.
        let output = build_child_command("sh", &args, &secrets).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout), "from-project");
    }
}
