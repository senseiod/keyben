//! Client: all encryption and decryption happen here; the server only sends and receives Base64 ciphertext.

use anyhow::{Context, Result, bail};
use reqwest::{RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize)]
struct PasswordResetSecret {
    env: String,
    name: String,
    old_value: String,
    new_value: String,
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

    match command {
        Command::Init { project_name } => {
            let project_name = project_name.as_deref().unwrap_or(&runtime.project_name);
            let password = resolve_new_password(
                cli.password.as_ref(),
                "Enter the new project password",
                "use --password or KEYBEN_PASSWORD in non-interactive environments",
            )?;
            api.create_project(project_name, &password).await?;
            println!("Project `{project_name}` created");
        }

        Command::Secrets { action } => match action {
            SecretsCommand::Set {
                project_name,
                env,
                name,
                value,
            } => {
                let password = resolve_password(&cli.password)?;
                let name = resolve_secret_name(name)?;
                let value = resolve_secret_value(value)?;
                let blob = crypto::encrypt(&password, &value)?;
                let project_name = project_name.as_deref().unwrap_or(&runtime.project_name);
                api.set_secret(project_name, *env, &name, &blob, &password)
                    .await?;
                println!("Set {name} in {project_name}/{}", env.as_str());
            }

            SecretsCommand::Get {
                project_name,
                env,
                name: Some(name),
            } => {
                let password = resolve_password(&cli.password)?;
                let project_name = project_name.as_deref().unwrap_or(&runtime.project_name);
                let blob = api.get_secret(project_name, *env, name, &password).await?;
                println!("{}", crypto::decrypt(&password, &blob)?);
            }

            SecretsCommand::Get {
                project_name,
                env,
                name: None,
            } => {
                let password = resolve_password(&cli.password)?;
                let project_name = project_name.as_deref().unwrap_or(&runtime.project_name);
                for (name, value) in api.fetch_all(project_name, *env, &password).await? {
                    println!("{name}={value}");
                }
            }

            SecretsCommand::Delete {
                project_name,
                env,
                name,
            } => {
                let password = resolve_password(&cli.password)?;
                let project_name = project_name.as_deref().unwrap_or(&runtime.project_name);
                api.delete_secret(project_name, *env, name, &password)
                    .await?;
                println!("Deleted {name} from {project_name}/{}", env.as_str());
            }
        },

        Command::Password { action } => match action {
            PasswordCommand::Reset {
                project_name,
                new_password,
            } => {
                let project_name = project_name.as_deref().unwrap_or(&runtime.project_name);
                reset_project_password(&api, project_name, &cli.password, new_password.as_ref())
                    .await?;
                println!("Reset password for project `{project_name}`");
            }
        },

        Command::Run {
            project_name,
            env,
            argv,
        } => {
            let password = resolve_password(&cli.password)?;
            let project_name = project_name.as_deref().unwrap_or(&runtime.project_name);
            let secrets = api.fetch_all(project_name, *env, &password).await?;
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
    let file_config = if needs_file && config::exists()? {
        let password = resolve_config_password(&cli.config_password)?;
        Some(config::read(&password)?)
    } else {
        None
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
    let project_name = if project_name.trim().is_empty() {
        bail!("Missing project name; use --projectName or create .keyben.toml")
    } else {
        project_name
    };
    config::validate_values(&project_name, &server, &token)?;
    Ok(RuntimeConfig {
        project_name,
        server,
        token,
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
            config::validate_values(&project_name, &server, &token)?;
            let password = resolve_new_password(
                cli.config_password.as_ref(),
                "Enter the configuration password",
                "use --config-password or KEYBEN_CONFIG_PASSWORD",
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

fn resolve_config_password(from_args: &Option<String>) -> Result<String> {
    if let Some(value) = from_args {
        if value.is_empty() {
            bail!("Configuration password cannot be empty");
        }
        return Ok(value.clone());
    }
    dialoguer::Password::new().with_prompt("Enter the configuration password").interact()
        .context("Failed to read configuration password (use --config-password or KEYBEN_CONFIG_PASSWORD)")
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

async fn reset_project_password(
    api: &Api,
    project: &str,
    old_password_args: &Option<String>,
    new_password_args: Option<&String>,
) -> Result<()> {
    let old_password = resolve_password(old_password_args)?;
    let new_password = resolve_new_password(
        new_password_args,
        "Enter the new project password",
        "use --new-password or KEYBEN_NEW_PASSWORD in non-interactive environments",
    )?;
    if old_password == new_password {
        bail!("New project password must differ from the current password");
    }

    let mut secrets = Vec::new();
    for env in [Env::Dev, Env::Prod] {
        for entry in api.fetch_encrypted(project, env, &old_password).await? {
            let plaintext = crypto::decrypt(&old_password, &entry.value).with_context(|| {
                format!(
                    "Failed to decrypt variable `{}` in {}/{}",
                    entry.name,
                    project,
                    env.as_str()
                )
            })?;
            secrets.push(PasswordResetSecret {
                env: env.as_str().to_owned(),
                name: entry.name,
                old_value: entry.value,
                new_value: crypto::encrypt(&new_password, &plaintext)?,
            });
        }
    }

    api.reset_project_password(project, &old_password, &new_password, &secrets)
        .await
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

    async fn create_project(&self, project: &str, password: &str) -> Result<()> {
        let url = format!("{}/api/projects", self.base);
        self.send(self.http.post(url).json(&json!({
            "name": project,
            "password_hash": crypto::project_password_hash(project, password)
        })))
        .await?;
        Ok(())
    }

    async fn reset_project_password(
        &self,
        project: &str,
        old_password: &str,
        new_password: &str,
        secrets: &[PasswordResetSecret],
    ) -> Result<()> {
        let url = format!(
            "{}/api/project-passwords/{}",
            self.base,
            percent_encode(project)
        );
        self.send(
            self.http
                .post(url)
                .header(
                    PROJECT_PASSWORD_HEADER,
                    crypto::project_password_hash(project, old_password),
                )
                .json(&json!({
                    "password_hash": crypto::project_password_hash(project, new_password),
                    "secrets": secrets,
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
        password: &str,
    ) -> Result<()> {
        let url = self.url(&[project, env.as_str(), name]);
        self.send(
            self.http
                .put(url)
                .header(
                    PROJECT_PASSWORD_HEADER,
                    crypto::project_password_hash(project, password),
                )
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
        password: &str,
    ) -> Result<String> {
        let url = self.url(&[project, env.as_str(), name]);
        let payload: SecretValue = self
            .send(self.http.get(url).header(
                PROJECT_PASSWORD_HEADER,
                crypto::project_password_hash(project, password),
            ))
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
        password: &str,
    ) -> Result<()> {
        let url = self.url(&[project, env.as_str(), name]);
        self.send(self.http.delete(url).header(
            PROJECT_PASSWORD_HEADER,
            crypto::project_password_hash(project, password),
        ))
        .await?;
        Ok(())
    }

    /// Fetch and decrypt all variables in an environment.
    async fn fetch_all(
        &self,
        project: &str,
        env: Env,
        password: &str,
    ) -> Result<BTreeMap<String, String>> {
        let entries = self.fetch_encrypted(project, env, password).await?;

        entries
            .into_iter()
            .map(|entry| {
                let value = crypto::decrypt(password, &entry.value)
                    .with_context(|| format!("Failed to decrypt variable `{}`", entry.name))?;
                Ok((entry.name, value))
            })
            .collect()
    }

    async fn fetch_encrypted(
        &self,
        project: &str,
        env: Env,
        password: &str,
    ) -> Result<Vec<SecretEntry>> {
        let url = self.url(&[project, env.as_str()]);
        self.send(self.http.get(url).header(
            PROJECT_PASSWORD_HEADER,
            crypto::project_password_hash(project, password),
        ))
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

const PROJECT_PASSWORD_HEADER: &str = "x-keyben-project-password";

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
