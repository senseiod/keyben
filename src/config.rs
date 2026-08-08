//! Project-local client configuration stored in `.keyben.toml`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::crypto;

pub const FILE_NAME: &str = ".keyben.toml";

#[derive(Debug, Serialize, Deserialize)]
struct StoredConfig {
    version: u32,
    project_name: String,
    encrypted_server: String,
    encrypted_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub project_name: String,
    pub server: String,
    pub token: String,
}

pub fn path() -> Result<PathBuf> {
    Ok(std::env::current_dir()?.join(FILE_NAME))
}

pub fn exists() -> Result<bool> {
    Ok(path()?.is_file())
}

pub fn write(config: &Config, password: &str) -> Result<PathBuf> {
    if password.is_empty() {
        bail!("Configuration password cannot be empty");
    }
    let stored = StoredConfig {
        version: 1,
        project_name: config.project_name.clone(),
        encrypted_server: crypto::encrypt(password, &config.server)?,
        encrypted_token: crypto::encrypt(password, &config.token)?,
    };
    let text = toml::to_string_pretty(&stored).context("Failed to serialize .keyben.toml")?;
    let file = path()?;
    std::fs::write(&file, text).with_context(|| format!("Failed to write {}", file.display()))?;
    Ok(file)
}

pub fn read(password: &str) -> Result<Config> {
    let file = path()?;
    let text = std::fs::read_to_string(&file)
        .with_context(|| format!("Failed to read {}", file.display()))?;
    let stored: StoredConfig =
        toml::from_str(&text).with_context(|| format!("Invalid {}", file.display()))?;
    if stored.version != 1 {
        bail!("Unsupported .keyben.toml version: {}", stored.version);
    }
    let server = crypto::decrypt(password, &stored.encrypted_server).context(
        "Failed to decrypt server URL; incorrect configuration password or corrupted file",
    )?;
    let token = crypto::decrypt(password, &stored.encrypted_token)
        .context("Failed to decrypt token; incorrect configuration password or corrupted file")?;
    validate(&stored.project_name, &server, &token)?;
    Ok(Config {
        project_name: stored.project_name,
        server,
        token,
    })
}

fn validate(project_name: &str, server: &str, token: &str) -> Result<()> {
    if project_name.trim().is_empty() {
        bail!("Project name cannot be empty");
    }
    if server.trim().is_empty() {
        bail!("Server URL cannot be empty");
    }
    if token.trim().is_empty() {
        bail!("Authentication token cannot be empty");
    }
    Ok(())
}

pub fn validate_values(project_name: &str, server: &str, token: &str) -> Result<()> {
    validate(project_name, server, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_config_roundtrip() {
        let value = Config {
            project_name: "app".into(),
            server: "https://example.com".into(),
            token: "secret".into(),
        };
        let stored = StoredConfig {
            version: 1,
            project_name: value.project_name.clone(),
            encrypted_server: crypto::encrypt("pw", &value.server).unwrap(),
            encrypted_token: crypto::encrypt("pw", &value.token).unwrap(),
        };
        let text = toml::to_string(&stored).unwrap();
        let parsed: StoredConfig = toml::from_str(&text).unwrap();
        assert_eq!(
            crypto::decrypt("pw", &parsed.encrypted_server).unwrap(),
            value.server
        );
        assert_eq!(
            crypto::decrypt("pw", &parsed.encrypted_token).unwrap(),
            value.token
        );
    }
}
