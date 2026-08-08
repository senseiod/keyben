//! keyben —— 端到端加密的环境变量管理工具（单二进制：客户端 + 服务端）。
//!
//! - `keyben -c <config.toml>`：以服务端运行，只做存储与 Bearer Token 鉴权。
//! - `keyben init | secrets | run`：以客户端运行，负责基于密码的加解密。
//!
//! 服务端永远接触不到密码与明文，数据库里躺着的只是 ChaCha20-Poly1305 密文。

mod cli;
mod client;
mod crypto;
mod server;

use anyhow::{Result, bail};
use clap::{CommandFactory, Parser};
use cli::Cli;

#[tokio::main]
async fn main() {
    if let Err(err) = dispatch().await {
        eprintln!("错误: {err:#}");
        std::process::exit(1);
    }
}

async fn dispatch() -> Result<()> {
    let cli = Cli::parse();

    // 进程内同时链接了多个 rustls 后端时需显式指定，否则首次建连会 panic。
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match (&cli.config, &cli.command) {
        (Some(config), None) => {
            init_tracing();
            server::run(config).await
        }
        (Some(_), Some(_)) => {
            bail!("-c/--config 用于以服务端模式运行，不能与客户端子命令同时使用")
        }
        (None, Some(_)) => client::run(cli).await,
        (None, None) => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

/// 仅服务端需要日志；默认 info 级别，可用 RUST_LOG 覆盖。
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("keyben=info,tower_http=info"));

    fmt().with_env_filter(filter).init();
}
