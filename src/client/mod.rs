//! Client: all encryption and decryption happen here; the server only sends and receives Base64
//! ciphertext.
//!
//! Passwords, derived keys, and decrypted values are held in [`Zeroizing`] wrappers so they are
//! wiped from memory on drop instead of lingering in a core dump or swap file.
//!
//! Anything the user did not pass on the command line is prompted for rather than rejected, so
//! every subcommand can be started bare. See [`prompt`] for the individual prompts.

use anyhow::{Context, Result};
use std::{collections::BTreeMap, ffi::OsString, process::Command as ProcessCommand};

use crate::common::{
    cli::{Cli, Command, ConfigCommand, PasswordCommand, SecretsCommand},
    consts::CREDENTIAL_ENV_PREFIX,
    crypto,
};
use api::Api;
use config::Config;

mod api;
mod config;
mod prompt;
mod runtime;

/// Execute a subcommand in client mode.
pub async fn run(cli: Cli) -> Result<()> {
    let command = cli
        .command
        .as_ref()
        .expect("the caller verified that a subcommand exists");
    // `config init` writes the file that supplies the runtime values, so it cannot depend on them.
    if let Command::Config { action } = command {
        return run_config_command(action, &cli).await;
    }

    let runtime = runtime::resolve(&cli, project_name_arg(command))?;
    let api = Api::new(&runtime.server, &runtime.token, cli.insecure)?;
    let project = runtime.project_name.as_str();

    match command {
        Command::Init { .. } => {
            // A password already resolved for `~/.keyben.toml` was confirmed when that table was
            // written, so reuse it instead of asking for a fresh confirmation here.
            let password = match runtime.resolved_password() {
                Some(password) => password.clone(),
                None => prompt::new_password(
                    cli.password.as_ref(),
                    "Enter the new project password",
                    "use --password or KEYBEN_PASSWORD in non-interactive environments",
                )?,
            };
            api.create_project(project, &password).await?;
            println!("Project `{project}` created");
        }

        Command::Secrets { action } => match action {
            SecretsCommand::Set {
                env, name, value, ..
            } => {
                let env = prompt::env(*env)?;
                let name = prompt::secret_name(name.as_deref())?;
                let value = prompt::secret_value(value.as_deref())?;
                let password = runtime.project_password(cli.password.as_ref())?;
                let session = api.unlock(project, &password).await?;
                let blob =
                    crypto::encrypt_secret(&session.dek, project, env.as_str(), &name, &value)?;
                api.set_secret(project, env, &name, &blob, &session).await?;
                println!("Set {name} in {project}/{}", env.as_str());
            }

            SecretsCommand::Get { env, name, .. } => {
                let env = prompt::env(*env)?;
                let password = runtime.project_password(cli.password.as_ref())?;
                let session = api.unlock(project, &password).await?;
                // An omitted --name lists the whole environment; it is not prompted for, since
                // listing is a documented mode of this command rather than a missing value.
                match name {
                    Some(name) => {
                        let value = api.get_secret(project, env, name, &session).await?;
                        println!("{}", value.as_str());
                    }
                    None => {
                        for (name, value) in api.fetch_all(project, env, &session).await? {
                            println!("{name}={}", value.as_str());
                        }
                    }
                }
            }

            SecretsCommand::Delete { env, name, .. } => {
                let env = prompt::env(*env)?;
                let name = prompt::secret_name(name.as_deref())?;
                let password = runtime.project_password(cli.password.as_ref())?;
                let session = api.unlock(project, &password).await?;
                api.delete_secret(project, env, &name, &session).await?;
                println!("Deleted {name} from {project}/{}", env.as_str());
            }
        },

        Command::Password { action } => match action {
            PasswordCommand::Reset { new_password, .. } => {
                let old_password = runtime.project_password(cli.password.as_ref())?;
                let new_password = prompt::new_password(
                    new_password.as_ref(),
                    "Enter the new project password",
                    "use --new-password or KEYBEN_NEW_PASSWORD in non-interactive environments",
                )?;
                if old_password == new_password {
                    anyhow::bail!("New project password must differ from the current password");
                }
                api.reset_password(project, &old_password, &new_password)
                    .await?;

                if config::contains(project)? {
                    let file = config::path()?;
                    println!(
                        "Reset password for project `{project}`.\n\
                         Note: its entry in {} is still encrypted under the old \
                         password; recreate it with `keyben config init --projectName {project}` \
                         to use the new one.",
                        file.display()
                    );
                } else {
                    println!("Reset password for project `{project}`");
                }
            }
        },

        Command::Run { env, argv, .. } => {
            let env = prompt::env(*env)?;
            let password = runtime.project_password(cli.password.as_ref())?;
            let session = api.unlock(project, &password).await?;
            let secrets = api.fetch_all(project, env, &session).await?;
            exec(argv, secrets)?;
        }

        Command::Config { .. } => {
            unreachable!("config commands are handled before runtime resolution")
        }
    }

    Ok(())
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

/// Add or replace one project in `~/.keyben.toml`.
///
/// Every value is verified against the server before anything is written: a file that looks fine
/// but holds a wrong token or password would only fail on the *next* command, far from the
/// mistake that caused it.
async fn run_config_command(action: &ConfigCommand, cli: &Cli) -> Result<()> {
    match action {
        ConfigCommand::Init { project_name } => {
            let project_name = prompt::project_name(project_name.as_deref())?;
            let server = prompt::server(cli.server.as_deref())?;
            let token = prompt::token(cli.token.as_ref())?;
            config::validate(&project_name, &server, &token)?;

            // Ask before the network round trip, so a declined overwrite costs nothing.
            if config::contains(&project_name)? {
                let file = config::path()?;
                if !prompt::confirm(format!(
                    "{} already contains project `{project_name}`; replace that entry?",
                    file.display()
                )) {
                    anyhow::bail!(
                        "Cancelled; project `{project_name}` in {} was left unchanged",
                        file.display()
                    );
                }
            }

            // The project password also encrypts this project's table, so there is only one to
            // remember.
            let password = prompt::new_password(
                cli.password.as_ref(),
                "Enter the project password",
                "use --password or KEYBEN_PASSWORD",
            )?;

            // One call checks everything: an unreachable server, a rejected token (401), a
            // missing project (404), and a password that cannot unwrap the DEK.
            Api::new(&server, &token, cli.insecure)?
                .unlock(&project_name, &password)
                .await
                .with_context(|| {
                    format!(
                        "Verification against {server} failed; {} was not written",
                        config::path()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|_| "the user configuration file".to_owned())
                    )
                })?;

            let file = config::write(
                &Config {
                    project_name,
                    server,
                    token,
                },
                &password,
            )?;
            println!("Wrote {} (verified against the server)", file.display());
        }
    }
    Ok(())
}

/// Build the child process: inherit the caller's environment, add the decrypted secrets, and
/// drop keyben's own credentials so they cannot leak into the child.
fn build_child_command(
    program: &str,
    args: &[String],
    secrets: &BTreeMap<String, crypto::SecretText>,
) -> ProcessCommand {
    build_child_command_with_ambient(
        program,
        args,
        secrets,
        std::env::vars_os().map(|(name, _)| name),
    )
}

/// The body of [`build_child_command`], with the caller's environment passed in.
///
/// Taking the ambient names as an argument keeps the stripping rule testable: mutating the real
/// process environment from a test would race every other thread in the suite, since `set_var`
/// is only sound while nothing else reads the environment concurrently.
fn build_child_command_with_ambient(
    program: &str,
    args: &[String],
    secrets: &BTreeMap<String, crypto::SecretText>,
    ambient: impl Iterator<Item = OsString>,
) -> ProcessCommand {
    let mut command = ProcessCommand::new(program);
    command
        .args(args)
        .envs(secrets.iter().map(|(name, value)| (name, value.as_str())));

    // Strip every KEYBEN-prefixed variable rather than a fixed list, so a credential added
    // later cannot silently start leaking into children. A variable the project itself defines
    // under such a name is kept: an explicit secret wins over the ambient value.
    for name in ambient {
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(CREDENTIAL_ENV_PREFIX) && !secrets.contains_key(name) {
            command.env_remove(name);
        }
    }
    command
}

/// Inject decrypted environment variables, launch the child process unchanged, and propagate its
/// exit code.
fn exec(argv: &[String], secrets: BTreeMap<String, crypto::SecretText>) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .context("A program to execute must be provided after `--`")?;

    let status = build_child_command(program, args, &secrets)
        .status()
        .with_context(|| format!("Failed to execute `{program}`"))?;

    // `process::exit` below runs no destructors, so wipe the decrypted values by hand first.
    // The child already holds its own copy in its environment.
    drop(secrets);

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

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn build(secrets: &BTreeMap<String, crypto::SecretText>, ambient: &[&str]) -> ProcessCommand {
        build_child_command_with_ambient(
            "sh",
            &[],
            secrets,
            ambient.iter().map(|name| OsString::from(*name)),
        )
    }

    /// Look up how a name is configured on the child: `Some` is an explicit value, `None` means
    /// the child will not inherit it, and absent means it inherits the caller's value.
    fn child_env<'a>(command: &'a ProcessCommand, name: &str) -> Option<Option<&'a str>> {
        command
            .get_envs()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.map(|v| v.to_str().unwrap()))
    }

    /// Automation supplies keyben's credentials through the environment, so a child that dumps
    /// its environment would otherwise expose the project password and the server token.
    ///
    /// The rule is the `KEYBEN` prefix rather than a fixed list, so a variable this code has
    /// never heard of is stripped too.
    #[test]
    fn child_does_not_inherit_any_keyben_prefixed_variable() {
        let stripped = [
            "KEYBEN_TOKEN",
            "KEYBEN_PASSWORD",
            "KEYBEN_NEW_PASSWORD",
            "KEYBEN_CONFIG_PASSWORD",
            // Not in any hard-coded list: the prefix rule alone must catch it.
            "KEYBEN_FUTURE_CREDENTIAL",
            "KEYBENWITHOUTUNDERSCORE",
        ];
        let secrets = BTreeMap::from([(
            "DB_URL".to_owned(),
            Zeroizing::new("postgres://x".to_owned()),
        )]);

        let mut ambient = stripped.to_vec();
        ambient.extend(["NOT_KEYBEN_VAR", "PATH"]);
        let command = build(&secrets, &ambient);

        for name in stripped {
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
        // A variable that merely mentions KEYBEN elsewhere is untouched, as is everything else.
        assert_eq!(child_env(&command, "NOT_KEYBEN_VAR"), None);
        assert_eq!(child_env(&command, "PATH"), None);
    }

    /// A project may legitimately store a secret under one of those names; it must not be
    /// stripped along with the ambient value.
    #[test]
    fn an_explicit_secret_overrides_the_inherited_credential() {
        let secrets = BTreeMap::from([(
            "KEYBEN_TOKEN".to_owned(),
            Zeroizing::new("from-project".to_owned()),
        )]);

        assert_eq!(
            child_env(&build(&secrets, &["KEYBEN_TOKEN"]), "KEYBEN_TOKEN"),
            Some(Some("from-project"))
        );

        // And confirm a real child observes the explicit value. The ambient list is empty here
        // because this process has no KEYBEN_TOKEN of its own to strip.
        let output = build_child_command(
            "sh",
            &["-c".to_owned(), "printf '%s' \"$KEYBEN_TOKEN\"".to_owned()],
            &secrets,
        )
        .output()
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout), "from-project");
    }
}
