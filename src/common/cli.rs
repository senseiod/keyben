//! Command-line interface definitions.
//!
//! The binary has two operating modes:
//! - provide `-c/--config` to run as the server (`keyben-server`);
//! - provide a subcommand (`init` / `secrets` / `password` / `export` / `run`) to run as the client.
//!
//! Every value the client needs is optional here. A missing one is not an error: the client
//! prompts for it (see `client::prompt`), so any command can be started bare. The single
//! exception is the program after `--` in `keyben run`, which clap still requires — there is
//! no sensible way to prompt for a command line plus its argument boundaries.

use clap::{ArgAction, Parser, Subcommand, ValueEnum, builder::BoolishValueParser};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::common::env::Env;

/// A password parsed from the command line or the environment, wiped from memory on drop.
pub type Password = Zeroizing<String>;

/// Parse a password argument straight into its wiping wrapper, so clap never stores a bare
/// `String` copy that outlives the process without being cleared.
fn wiped_on_drop(value: &str) -> Result<Password, std::convert::Infallible> {
    Ok(Zeroizing::new(value.to_owned()))
}

#[derive(Debug, Parser)]
#[command(
    name = "keyben",
    version,
    about = "End-to-end encrypted environment variable manager (one binary for client and server)",
    long_about = "keyben — an end-to-end encrypted environment variable manager.\n\n\
                  Server mode: keyben -c /etc/keyben/config.toml\n\
                  Client mode: keyben init | keyben secrets ... | keyben password ... | keyben export ... | keyben run ...\n\n\
                  All encryption and decryption happen on the client (XChaCha20-Poly1305); the server stores only Base64 ciphertext.",
    after_help = "Examples:\n  \
        keyben -c config.toml\n  \
        keyben --server http://127.0.0.1:8000 init --projectName myapp\n  \
        keyben secrets set --projectName myapp --env dev --name DB_URL --value 'postgres://...'\n  \
        keyben secrets get --projectName myapp --env dev\n  \
        keyben export --projectName myapp --env prod --format json --output-file secrets.json\n  \
        keyben password reset --projectName myapp\n  \
        keyben run --projectName myapp --env prod -- ./server --port 8080"
)]
pub struct Cli {
    /// Server configuration file path; providing this option runs the server.
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Server URL, for example http://127.0.0.1:8000. Prompts when omitted.
    #[arg(long, global = true, env = "KEYBEN_SERVER", value_name = "URL")]
    pub server: Option<String>,

    /// HTTP API authentication token. Prompts when omitted.
    #[arg(
        long,
        global = true,
        env = "KEYBEN_TOKEN",
        value_name = "TOKEN",
        hide_env_values = true,
        value_parser = wiped_on_drop
    )]
    pub token: Option<Password>,

    /// Project password; also decrypts its entry in the user config file. Prompts when omitted.
    #[arg(
        long,
        global = true,
        env = "KEYBEN_PASSWORD",
        value_name = "PASSWORD",
        hide_env_values = true,
        value_parser = wiped_on_drop
    )]
    pub password: Option<Password>,

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
    /// Create a project on the server.
    Init {
        /// Project name; prompts interactively when omitted.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: Option<String>,
    },

    /// Manage the per-user, multi-project client configuration.
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },

    /// Manage a project's environment variables.
    Secrets {
        #[command(subcommand)]
        action: SecretsCommand,
    },

    /// Manage a project's encryption password.
    Password {
        #[command(subcommand)]
        action: PasswordCommand,
    },

    /// Export a decrypted environment in dotenv, JSON, or YAML form.
    Export {
        /// Project name; prompts interactively when omitted.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: Option<String>,

        /// Environment; prompts interactively when omitted.
        #[arg(long, value_enum)]
        env: Option<Env>,

        /// Output format. The default matches Infisical's dotenv export.
        #[arg(long, value_enum, default_value = "dotenv")]
        format: ExportFormat,

        /// Write to this file instead of standard output.
        #[arg(long = "output-file", value_name = "FILE")]
        output_file: Option<PathBuf>,
    },

    /// Inject decrypted environment variables and launch a child process.
    Run {
        /// Project name; prompts interactively when omitted.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: Option<String>,

        /// Environment; prompts interactively when omitted.
        #[arg(long, value_enum)]
        env: Option<Env>,

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
        /// Project name; prompts interactively when omitted.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: Option<String>,

        /// Environment; prompts interactively when omitted.
        #[arg(long, value_enum)]
        env: Option<Env>,

        /// Variable name; prompts interactively when omitted.
        #[arg(long, value_name = "KEY")]
        name: Option<String>,

        /// Variable plaintext value; prompts securely when omitted.
        #[arg(long, value_name = "VALUE")]
        value: Option<String>,
    },

    /// Read and decrypt an environment variable; without --name, print all variables in the environment.
    Get {
        /// Project name; prompts interactively when omitted.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: Option<String>,

        /// Environment; prompts interactively when omitted.
        #[arg(long, value_enum)]
        env: Option<Env>,

        /// Variable name; when omitted, print all variables one per line as KEY=VALUE.
        #[arg(long, value_name = "KEY")]
        name: Option<String>,
    },

    /// Delete an environment variable.
    Delete {
        /// Project name; prompts interactively when omitted.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: Option<String>,

        /// Environment; prompts interactively when omitted.
        #[arg(long, value_enum)]
        env: Option<Env>,

        /// Variable name; prompts interactively when omitted.
        #[arg(long, value_name = "KEY")]
        name: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Add or replace a project in the user config file.
    Init {
        /// Project name; prompts interactively when omitted.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PasswordCommand {
    /// Re-wrap the project data key under a new password; secrets are left untouched.
    Reset {
        /// Project name; prompts interactively when omitted.
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: Option<String>,

        /// New project password; prompts securely when omitted.
        #[arg(
            long = "new-password",
            env = "KEYBEN_NEW_PASSWORD",
            value_name = "PASSWORD",
            hide_env_values = true,
            value_parser = wiped_on_drop
        )]
        new_password: Option<Password>,
    },
}

/// Formats supported by `keyben export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ExportFormat {
    /// KEY="value", suitable for dotenv files.
    Dotenv,
    /// export KEY="value", suitable for dotenv files that accept the export prefix.
    DotenvExport,
    /// POSIX-shell-quoted assignments, safe for eval/source.
    DotenvEval,
    /// A JSON object mapping variable names to values.
    Json,
    /// A YAML mapping of variable names to values.
    Yaml,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clap reads `KEYBEN_*` as fallback values for these global flags. Run this assertion in a
    /// child test process so setting environment variables cannot race the parallel test suite.
    #[test]
    fn command_line_credentials_override_environment() {
        const MARKER: &str = "KEYBEN_TEST_CLI_PRIORITY";
        if std::env::var_os(MARKER).is_some() {
            let cli = Cli::try_parse_from([
                "keyben",
                "--server",
                "https://cli.example",
                "--token",
                "cli-token",
                "--password",
                "cli-password",
                "secrets",
                "get",
            ])
            .unwrap();
            assert_eq!(cli.server.as_deref(), Some("https://cli.example"));
            assert_eq!(cli.token.as_deref().map(String::as_str), Some("cli-token"));
            assert_eq!(
                cli.password.as_deref().map(String::as_str),
                Some("cli-password")
            );
            return;
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "common::cli::tests::command_line_credentials_override_environment",
                "--exact",
            ])
            .env(MARKER, "1")
            .env("KEYBEN_SERVER", "https://env.example")
            .env("KEYBEN_TOKEN", "env-token")
            .env("KEYBEN_PASSWORD", "env-password")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn accepts_global_password_after_nested_subcommand_arguments() {
        let cli = Cli::try_parse_from([
            "keyben",
            "--server",
            "http://127.0.0.1:4000",
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

        assert_eq!(cli.password.as_deref().map(String::as_str), Some("123"));
    }

    #[test]
    fn parses_password_reset_arguments() {
        let cli = Cli::try_parse_from([
            "keyben",
            "password",
            "reset",
            "--projectName",
            "frontierkings",
            "--new-password",
            "new-password",
            "--password",
            "old-password",
        ])
        .unwrap();

        let Command::Password {
            action:
                PasswordCommand::Reset {
                    project_name,
                    new_password,
                },
        } = cli.command.unwrap()
        else {
            panic!("expected password reset command");
        };
        assert_eq!(project_name.as_deref(), Some("frontierkings"));
        assert_eq!(
            new_password.as_deref().map(String::as_str),
            Some("new-password")
        );
        assert_eq!(
            cli.password.as_deref().map(String::as_str),
            Some("old-password")
        );
    }

    #[test]
    fn secrets_set_allows_omitting_name_and_value() {
        let cli = Cli::try_parse_from([
            "keyben",
            "secrets",
            "set",
            "--projectName",
            "frontierkings",
            "--env",
            "dev",
        ])
        .unwrap();

        let Command::Secrets {
            action: SecretsCommand::Set { name, value, .. },
        } = cli.command.unwrap()
        else {
            panic!("expected secrets set command");
        };
        assert_eq!(name, None);
        assert_eq!(value, None);
    }

    #[test]
    fn parses_export_format_and_output_file() {
        let cli = Cli::try_parse_from([
            "keyben",
            "export",
            "--projectName",
            "frontierkings",
            "--env",
            "prod",
            "--format",
            "dotenv-eval",
            "--output-file",
            ".env",
        ])
        .unwrap();

        let Command::Export {
            project_name,
            env,
            format,
            output_file,
        } = cli.command.unwrap()
        else {
            panic!("expected export command");
        };
        assert_eq!(project_name.as_deref(), Some("frontierkings"));
        assert_eq!(env, Some(Env::Prod));
        assert_eq!(format, ExportFormat::DotenvEval);
        assert_eq!(output_file, Some(PathBuf::from(".env")));
    }

    #[test]
    fn export_defaults_to_dotenv_and_stdout() {
        let cli = Cli::try_parse_from(["keyben", "export"]).unwrap();
        let Command::Export {
            format,
            output_file,
            ..
        } = cli.command.unwrap()
        else {
            panic!("expected export command");
        };
        assert_eq!(format, ExportFormat::Dotenv);
        assert_eq!(output_file, None);
    }

    /// Every client-supplied value is optional, so a bare subcommand parses and the client is
    /// free to prompt for what is missing.
    #[test]
    fn every_subcommand_parses_with_no_arguments() {
        for argv in [
            vec!["keyben", "init"],
            vec!["keyben", "config", "init"],
            vec!["keyben", "secrets", "set"],
            vec!["keyben", "secrets", "get"],
            vec!["keyben", "secrets", "delete"],
            vec!["keyben", "password", "reset"],
            vec!["keyben", "export"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "{argv:?} should parse and prompt for the rest"
            );
        }
    }

    /// `run` is the exception: the program after `--` cannot be prompted for, so clap keeps it
    /// required and reports the usage error itself.
    #[test]
    fn run_still_requires_a_command_after_the_separator() {
        assert!(Cli::try_parse_from(["keyben", "run"]).is_err());
        assert!(Cli::try_parse_from(["keyben", "run", "--", "sh", "-c", "true"]).is_ok());
    }

    #[test]
    fn parses_config_init_with_optional_values() {
        let cli = Cli::try_parse_from([
            "keyben",
            "config",
            "init",
            "--projectName",
            "frontierkings",
            "--server",
            "http://example.com",
            "--token",
            "123456",
        ])
        .unwrap();

        assert_eq!(cli.server.as_deref(), Some("http://example.com"));
        assert_eq!(cli.token.as_deref().map(String::as_str), Some("123456"));
        let Command::Config {
            action: ConfigCommand::Init { project_name },
        } = cli.command.unwrap()
        else {
            panic!("expected config init command");
        };
        assert_eq!(project_name.as_deref(), Some("frontierkings"));
    }
}
