//! Resolving the values every client command needs: which project, which server, which token.
//!
//! The project name is resolved first, then three credential sources are consulted in order —
//! command-line flags, the environment (clap reads `KEYBEN_*` into the same fields), then that
//! project's table in `~/.keyben.toml`. Anything still missing is prompted for rather than
//! treated as a usage error, so a bare `keyben secrets get` works.

use anyhow::Result;

use super::{config, prompt};
use crate::common::cli::{Cli, Password};

pub struct RuntimeConfig {
    pub project_name: String,
    pub server: String,
    /// A credential, so it is wiped when the runtime configuration is dropped.
    pub token: Password,
    /// The password already resolved to decrypt this project's global config table, when read.
    password: Option<Password>,
}

impl RuntimeConfig {
    /// One password unlocks both the config table and the project itself, so reuse the value
    /// already resolved for the file rather than prompting a second time.
    pub fn project_password(&self, from_args: Option<&Password>) -> Result<Password> {
        match &self.password {
            Some(password) => Ok(password.clone()),
            None => prompt::password(from_args),
        }
    }

    /// The password resolved while reading `~/.keyben.toml`, if there was one.
    ///
    /// `keyben init` uses this to avoid asking for a confirmation of a password the user already
    /// confirmed when the file was written.
    pub fn resolved_password(&self) -> Option<&Password> {
        self.password.as_ref()
    }
}

pub fn resolve(cli: &Cli, project_arg: Option<&str>) -> Result<RuntimeConfig> {
    // The global file contains multiple tables, so the project must be known before looking up
    // its encrypted server and token.
    let project_name = prompt::project_name(project_arg)?;

    // Reading a table costs a password prompt and an Argon2 derivation, so only do it when a
    // credential is actually missing and this project has a saved entry.
    let needs_file = cli.server.is_none() || cli.token.is_none();
    let (file_config, password) = if needs_file && config::contains(&project_name)? {
        let password = prompt::password(cli.password.as_ref())?;
        (
            Some(config::read(&project_name, &password)?),
            Some(password),
        )
    } else {
        (None, None)
    };

    let server = prompt::server(
        cli.server
            .as_deref()
            .or(file_config.as_ref().map(|c| c.server.as_str())),
    )?;
    let token = prompt::token(
        cli.token
            .as_ref()
            .or(file_config.as_ref().map(|c| &c.token)),
    )?;

    config::validate(&project_name, &server, &token)?;
    Ok(RuntimeConfig {
        project_name,
        server,
        token,
        password,
    })
}
