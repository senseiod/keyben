//! 服务端配置文件（config.toml）解析。

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// 监听地址，例如 "0.0.0.0:8000"
    pub listen: String,

    /// SQLite 数据库文件路径
    pub data: PathBuf,

    /// HTTP API 鉴权凭证（Authorization: Bearer <token>）
    pub auth_token: String,

    /// TLS 证书（PEM）；与 key 同时提供才启用 TLS
    #[serde(default)]
    pub cert: Option<PathBuf>,

    /// TLS 私钥（PEM）
    #[serde(default)]
    pub key: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;

        let config: Config = toml::from_str(&text)
            .with_context(|| format!("解析配置文件失败: {}", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.server.auth_token.trim().is_empty() {
            bail!("config.toml 中的 server.auth_token 不能为空，否则任何人都能读写数据");
        }

        match (&self.server.cert, &self.server.key) {
            (Some(_), None) => bail!("提供了 server.cert 但缺少 server.key，无法启用 TLS"),
            (None, Some(_)) => bail!("提供了 server.key 但缺少 server.cert，无法启用 TLS"),
            _ => {}
        }

        Ok(())
    }

    /// 同时配置了证书与私钥时返回 TLS 文件对。
    pub fn tls_pair(&self) -> Option<(&Path, &Path)> {
        match (&self.server.cert, &self.server.key) {
            (Some(cert), Some(key)) => Some((cert.as_path(), key.as_path())),
            _ => None,
        }
    }
}
