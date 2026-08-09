//! Project-local client configuration stored in `.keyben.toml`.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::crypto;

pub const FILE_NAME: &str = ".keyben.toml";

/// Current on-disk format version. v2 derives the file key with Argon2id + a per-file salt.
const VERSION: u32 = 2;

/// Associated-data roles binding each encrypted field to its purpose.
const SERVER_ROLE: &str = "cfg-server-v2";
const TOKEN_ROLE: &str = "cfg-token-v2";

#[derive(Debug, Serialize, Deserialize)]
struct StoredConfig {
    version: u32,
    project_name: String,
    /// Base64 Argon2id salt for the configuration password.
    salt: String,
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
    let salt = crypto::generate_salt();
    let key = crypto::argon2id_key(password, &salt)?;
    let stored = StoredConfig {
        version: VERSION,
        project_name: config.project_name.clone(),
        salt: B64.encode(salt),
        encrypted_server: crypto::config_encrypt(&key, SERVER_ROLE, &config.server)?,
        encrypted_token: crypto::config_encrypt(&key, TOKEN_ROLE, &config.token)?,
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
    if stored.version != VERSION {
        bail!(
            "Unsupported .keyben.toml version: {} (expected {VERSION}); recreate it with `keyben config init`",
            stored.version
        );
    }
    let salt = B64
        .decode(stored.salt.trim())
        .context("Invalid salt in .keyben.toml")?;
    let key = crypto::argon2id_key(password, &salt)?;
    let server = crypto::config_decrypt(&key, SERVER_ROLE, &stored.encrypted_server).context(
        "Failed to decrypt server URL; incorrect configuration password or corrupted file",
    )?;
    let token = crypto::config_decrypt(&key, TOKEN_ROLE, &stored.encrypted_token)
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
        let salt = crypto::generate_salt();
        let key = crypto::argon2id_key("pw", &salt).unwrap();
        let stored = StoredConfig {
            version: VERSION,
            project_name: value.project_name.clone(),
            salt: B64.encode(salt),
            encrypted_server: crypto::config_encrypt(&key, SERVER_ROLE, &value.server).unwrap(),
            encrypted_token: crypto::config_encrypt(&key, TOKEN_ROLE, &value.token).unwrap(),
        };
        let text = toml::to_string(&stored).unwrap();
        let parsed: StoredConfig = toml::from_str(&text).unwrap();
        let parsed_salt = B64.decode(&parsed.salt).unwrap();
        let parsed_key = crypto::argon2id_key("pw", &parsed_salt).unwrap();
        assert_eq!(
            crypto::config_decrypt(&parsed_key, SERVER_ROLE, &parsed.encrypted_server).unwrap(),
            value.server
        );
        assert_eq!(
            crypto::config_decrypt(&parsed_key, TOKEN_ROLE, &parsed.encrypted_token).unwrap(),
            value.token
        );
    }
}
