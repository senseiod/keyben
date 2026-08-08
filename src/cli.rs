//! Command-line interface definitions.
//!
//! The binary has two operating modes:
//! - provide `-c/--config` to run as the server (`keyben-server`);
//! - provide a subcommand (`init` / `secrets` / `run`) to run as the client.

use clap::{ArgAction, Parser, Subcommand, ValueEnum, builder::BoolishValueParser};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "keyben",
    version,
    about = "End-to-end encrypted environment variable manager (one binary for client and server)",
    long_about = "keyben — an end-to-end encrypted environment variable manager.\n\n\
                  Server mode: keyben -c /etc/keyben/config.toml\n\
                  Client mode: keyben init | keyben secrets ... | keyben run ...\n\n\
                  All key derivation and encryption happen on the client (Argon2id + ChaCha20-Poly1305); the server stores only KDF metadata and Base64 ciphertext.",
    after_help = "Examples:\n  \
        keyben -c config.toml\n  \
        keyben --server http://127.0.0.1:8000 init --projectName myapp\n  \
        keyben secrets set --projectName myapp --env dev --name DB_URL --value 'postgres://...'\n  \
        keyben secrets get --projectName myapp --env dev\n  \
        keyben run --projectName myapp --env prod -- ./server --port 8080"
)]
pub struct Cli {
    /// Server configuration file path; providing this option runs the server.
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Server URL, for example http://127.0.0.1:8000.
    #[arg(long, global = true, env = "KEYBEN_SERVER", value_name = "URL")]
    pub server: Option<String>,

    /// HTTP API authentication token.
    #[arg(
        long,
        global = true,
        env = "KEYBEN_TOKEN",
        value_name = "TOKEN",
        hide_env_values = true
    )]
    pub token: Option<String>,

    /// Project password; prompts securely when omitted.
    #[arg(
        long,
        global = true,
        env = "KEYBEN_PASSWORD",
        value_name = "PASSWORD",
        hide_env_values = true
    )]
    pub password: Option<String>,

    /// Skip TLS certificate verification (for private networks with self-signed certificates only).
    #[arg(
        long,
        global = true,
        env = "KEYBEN_INSECURE",
        num_args = 0..=1,
        default_value = "false",
        default_missing_value = "true",
        value_parser = BoolishValueParser::new(),
        action = ArgAction::Set,
    )]
    pub insecure: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a password-protected project on the server.
    Init {
        /// Project name.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,
    },

    /// Manage a project's environment variables.
    Secrets {
        #[command(subcommand)]
        action: SecretsCommand,
    },

    /// Inject decrypted environment variables and launch a child process.
    Run {
        /// Project name.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,

        /// Environment.
        #[arg(long, value_enum)]
        env: Env,

        /// Program and arguments after `--`.
        #[arg(
            last = true,
            required = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        argv: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// Encrypt and write an environment variable.
    Set {
        /// Project name.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,

        /// Environment.
        #[arg(long, value_enum)]
        env: Env,

        /// Variable name; prompts interactively when omitted.
        #[arg(long, value_name = "KEY")]
        name: Option<String>,

        /// Variable plaintext value; prompts securely when omitted.
        #[arg(long, value_name = "VALUE")]
        value: Option<String>,
    },

    /// Read and decrypt an environment variable; without --name, print all variables in the environment.
    Get {
        /// Project name.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,

        /// Environment.
        #[arg(long, value_enum)]
        env: Env,

        /// Variable name; when omitted, print all variables one per line as KEY=VALUE.
        #[arg(long, value_name = "KEY")]
        name: Option<String>,
    },

    /// Delete an environment variable.
    Delete {
        /// Project name.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,

        /// Environment.
        #[arg(long, value_enum)]
        env: Env,

        /// Variable name.
        #[arg(long, value_name = "KEY")]
        name: String,
    },
}

/// Environment identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Env {
    Dev,
    Prod,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Dev => "dev",
            Env::Prod => "prod",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_allows_interactive_name_and_value() {
        let cli = Cli::try_parse_from([
            "keyben",
            "--server",
            "http://b-server.tailcab45.ts.net:4000",
            "secrets",
            "set",
            "--env",
            "dev",
            "--projectName",
            "frontierkings",
            "--token",
            "1234567",
        ])
        .unwrap();

        let Some(Command::Secrets {
            action: SecretsCommand::Set { name, value, .. },
        }) = cli.command
        else {
            panic!("expected secrets set command");
        };

        assert!(name.is_none());
        assert!(value.is_none());
    }

    #[test]
    fn set_accepts_non_interactive_name_and_value() {
        let cli = Cli::try_parse_from([
            "keyben",
            "secrets",
            "set",
            "--env",
            "prod",
            "--projectName",
            "myapp",
            "--name",
            "API_TOKEN",
            "--value",
            "secret",
        ])
        .unwrap();

        let Some(Command::Secrets {
            action: SecretsCommand::Set { name, value, .. },
        }) = cli.command
        else {
            panic!("expected secrets set command");
        };

        assert_eq!(name.as_deref(), Some("API_TOKEN"));
        assert_eq!(value.as_deref(), Some("secret"));
    }

    #[test]
    fn global_project_password_is_accepted_after_get_options() {
        let cli = Cli::try_parse_from([
            "keyben",
            "--server",
            "http://b-server.tailcab45.ts.net:4000",
            "secrets",
            "get",
            "--env",
            "dev",
            "--projectName",
            "frontierkings",
            "--token",
            "123456",
            "--password",
            "123",
        ])
        .unwrap();

        assert_eq!(cli.password.as_deref(), Some("123"));
    }
}
