//! keyben — an end-to-end encrypted environment variable manager (one binary for client and server).
//!
//! - `keyben -c <config.toml>`: run as the server for storage and Bearer Token authentication.
//! - `keyben init | secrets | run`: run as the client for password-based encryption and decryption.
//!
//! The server never sees passwords or plaintext; the database contains only ChaCha20-Poly1305 ciphertext.

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
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}

async fn dispatch() -> Result<()> {
    let cli = Cli::parse();

    // When multiple rustls backends are linked into the process, explicitly select one
    // to avoid a panic on the first connection.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match (&cli.config, &cli.command) {
        (Some(config), None) => {
            init_tracing();
            server::run(config).await
        }
        (Some(_), Some(_)) => {
            bail!("-c/--config runs the server and cannot be used with a client subcommand")
        }
        (None, Some(_)) => client::run(cli).await,
        (None, None) => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

/// Only the server needs logging; the default level is info and can be overridden with RUST_LOG.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("keyben=info,tower_http=info"));

    fmt().with_env_filter(filter).init();
}
