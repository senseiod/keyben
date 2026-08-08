//! Server configuration file (`config.toml`) parsing.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Listening address, such as "0.0.0.0:8000".
    pub listen: String,

    /// SQLite database file path.
    pub data: PathBuf,

    /// HTTP API authentication token (`Authorization: Bearer <token>`).
    pub auth_token: String,

    /// TLS certificate (PEM); provide it with a private key to enable TLS.
    #[serde(default)]
    pub cert: Option<PathBuf>,

    /// TLS private key (PEM).
    #[serde(default)]
    pub key: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&text)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.server.auth_token.trim().is_empty() {
            bail!(
                "server.auth_token in config.toml must not be empty; otherwise anyone can read and write data"
            );
        }

        match (&self.server.cert, &self.server.key) {
            (Some(_), None) => {
                bail!("server.cert is set but server.key is missing; TLS cannot be enabled")
            }
            (None, Some(_)) => {
                bail!("server.key is set but server.cert is missing; TLS cannot be enabled")
            }
            _ => {}
        }

        Ok(())
    }

    /// Return the TLS file pair when both a certificate and private key are configured.
    pub fn tls_pair(&self) -> Option<(&Path, &Path)> {
        match (&self.server.cert, &self.server.key) {
            (Some(cert), Some(key)) => Some((cert.as_path(), key.as_path())),
            _ => None,
        }
    }
}
