//! Per-user, multi-project client configuration stored in `~/.keyben.toml`.
//!
//! Each top-level TOML table is keyed by its project name and has its own Argon2id salt. The
//! server URL and Bearer token are encrypted under `project_password || machine_uid`, so selecting
//! a project plus entering its password supplies all credentials needed by later commands while
//! keeping a copied config file bound to the device that created it.
//!
//! The decrypted token is kept in a wrapper that wipes it on drop, since it is a credential.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use crate::common::{consts::CONFIG_FILE_NAME, crypto};

/// Associated-data roles binding each encrypted field to both its purpose and project table.
const SERVER_ROLE: &str = "cfg-server-v4";
const TOKEN_ROLE: &str = "cfg-token-v4";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredProject {
    /// Base64 Argon2id salt used only for encrypting this project's local configuration.
    salt: String,
    encrypted_server: String,
    encrypted_token: String,
}

type StoredConfig = BTreeMap<String, StoredProject>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub project_name: String,
    pub server: String,
    /// A credential, so it is wiped from memory when this value is dropped.
    pub token: Zeroizing<String>,
}

/// Resolve the per-user configuration path on Linux, macOS, and Windows.
pub fn path() -> Result<PathBuf> {
    Ok(home_dir()?.join(CONFIG_FILE_NAME))
}

#[cfg(not(windows))]
fn home_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .context("Cannot locate the user home directory: HOME is not set")?;
    Ok(PathBuf::from(home))
}

#[cfg(windows)]
fn home_dir() -> Result<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .filter(|home| !home.is_empty())
        .context("Cannot locate the user home directory: USERPROFILE is not set")?;
    Ok(PathBuf::from(home))
}

/// Return whether the global configuration already contains a particular project table.
pub fn contains(project_name: &str) -> Result<bool> {
    let file = path()?;
    Ok(read_stored_if_present(&file)?.is_some_and(|stored| stored.contains_key(project_name)))
}

/// Insert or replace one project while preserving every other table in `~/.keyben.toml`.
pub fn write(config: &Config, password: &str) -> Result<PathBuf> {
    if password.is_empty() {
        bail!("Project password cannot be empty");
    }
    let file = path()?;
    let encryption_password = device_bound_password(password)?;
    write_to(&file, config, &encryption_password)?;
    Ok(file)
}

fn write_to(file: &Path, config: &Config, encryption_password: &str) -> Result<()> {
    validate(&config.project_name, &config.server, &config.token)?;

    let mut stored = read_stored_if_present(file)?.unwrap_or_default();
    let salt = crypto::generate_salt();
    let key = crypto::argon2id_key(encryption_password, &salt)?;
    stored.insert(
        config.project_name.clone(),
        StoredProject {
            salt: B64.encode(salt),
            encrypted_server: crypto::config_encrypt(
                &key,
                &field_role(SERVER_ROLE, &config.project_name),
                &config.server,
            )?,
            encrypted_token: crypto::config_encrypt(
                &key,
                &field_role(TOKEN_ROLE, &config.project_name),
                &config.token,
            )?,
        },
    );

    let text =
        toml::to_string_pretty(&stored).context("Failed to serialize the user configuration")?;
    std::fs::write(file, text).with_context(|| format!("Failed to write {}", file.display()))
}

/// Decrypt the selected project table with that project's password.
pub fn read(project_name: &str, password: &str) -> Result<Config> {
    let file = path()?;
    let encryption_password = device_bound_password(password)?;
    read_from(&file, project_name, &encryption_password)
}

fn read_from(file: &Path, project_name: &str, encryption_password: &str) -> Result<Config> {
    let stored = read_stored(file)?;
    let project = stored.get(project_name).with_context(|| {
        format!(
            "Project `{project_name}` is not configured in {}; run `keyben config init --projectName {project_name}` first",
            file.display()
        )
    })?;
    let salt = B64.decode(project.salt.trim()).with_context(|| {
        format!(
            "Invalid salt for project `{project_name}` in {}",
            file.display()
        )
    })?;
    let key = crypto::argon2id_key(encryption_password, &salt)?;
    let server = crypto::config_decrypt(
        &key,
        &field_role(SERVER_ROLE, project_name),
        &project.encrypted_server,
    )
    .map_err(|_| anyhow!("Project password is incorrect"))?;
    let token = crypto::config_decrypt(
        &key,
        &field_role(TOKEN_ROLE, project_name),
        &project.encrypted_token,
    )
    .map_err(|_| anyhow!("Project password is incorrect"))?;
    validate(project_name, &server, &token)?;
    Ok(Config {
        project_name: project_name.to_owned(),
        server: server.to_string(),
        token,
    })
}

fn field_role(role: &str, project_name: &str) -> String {
    format!("{role}:{project_name}")
}

/// Bind the local encryption password to the current device without storing the machine ID.
fn device_bound_password(password: &str) -> Result<Zeroizing<String>> {
    let machine_uid = Zeroizing::new(
        machine_uid::get()
            .map_err(|err| anyhow!("Failed to read the device unique identifier: {err}"))?,
    );
    Ok(device_bound_password_with_uid(password, &machine_uid))
}

fn device_bound_password_with_uid(password: &str, machine_uid: &str) -> Zeroizing<String> {
    let mut bound = Zeroizing::new(String::with_capacity(password.len() + machine_uid.len()));
    bound.push_str(password);
    bound.push_str(machine_uid);
    bound
}

fn read_stored_if_present(file: &Path) -> Result<Option<StoredConfig>> {
    if !file.is_file() {
        return Ok(None);
    }
    read_stored(file).map(Some)
}

fn read_stored(file: &Path) -> Result<StoredConfig> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read {}", file.display()))?;
    toml::from_str(&text).with_context(|| format!("Invalid {}", file.display()))
}

/// Reject values that could never reach the server or would encrypt into nonsense.
pub fn validate(project_name: &str, server: &str, token: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path() -> PathBuf {
        std::env::temp_dir().join(format!("keyben-config-{}.toml", rand::random::<u64>()))
    }

    fn config(project: &str, server: &str, token: &str) -> Config {
        Config {
            project_name: project.to_owned(),
            server: server.to_owned(),
            token: Zeroizing::new(token.to_owned()),
        }
    }

    fn bound(password: &str, machine_uid: &str) -> Zeroizing<String> {
        device_bound_password_with_uid(password, machine_uid)
    }

    #[test]
    fn multiple_projects_roundtrip_independently() {
        let file = test_path();
        write_to(
            &file,
            &config("app-one", "https://one.example", "token-one"),
            &bound("pw-one", "device-a"),
        )
        .unwrap();
        write_to(
            &file,
            &config("app-two", "https://two.example", "token-two"),
            &bound("pw-two", "device-a"),
        )
        .unwrap();

        assert_eq!(
            read_from(&file, "app-one", &bound("pw-one", "device-a")).unwrap(),
            config("app-one", "https://one.example", "token-one")
        );
        assert_eq!(
            read_from(&file, "app-two", &bound("pw-two", "device-a")).unwrap(),
            config("app-two", "https://two.example", "token-two")
        );
        let error = read_from(&file, "app-one", &bound("pw-two", "device-a")).unwrap_err();
        assert_eq!(error.to_string(), "Project password is incorrect");
        let error = read_from(&file, "app-one", &bound("pw-one", "device-b")).unwrap_err();
        assert_eq!(error.to_string(), "Project password is incorrect");

        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("[app-one]"));
        assert!(text.contains("[app-two]"));
        assert!(!text.contains("https://one.example"));
        assert!(!text.contains("token-two"));

        std::fs::remove_file(file).unwrap();
    }

    #[test]
    fn replacing_one_project_preserves_the_others() {
        let file = test_path();
        write_to(
            &file,
            &config("one", "https://old.example", "old"),
            &bound("old-pw", "device-a"),
        )
        .unwrap();
        write_to(
            &file,
            &config("two", "https://two.example", "two"),
            &bound("two-pw", "device-a"),
        )
        .unwrap();
        write_to(
            &file,
            &config("one", "https://new.example", "new"),
            &bound("new-pw", "device-a"),
        )
        .unwrap();

        assert_eq!(
            read_from(&file, "one", &bound("new-pw", "device-a")).unwrap(),
            config("one", "https://new.example", "new")
        );
        assert_eq!(
            read_from(&file, "two", &bound("two-pw", "device-a")).unwrap(),
            config("two", "https://two.example", "two")
        );
        assert!(read_from(&file, "one", &bound("old-pw", "device-a")).is_err());

        std::fs::remove_file(file).unwrap();
    }

    #[test]
    fn validate_rejects_blank_fields() {
        assert!(validate("app", "https://example.com", "token").is_ok());
        assert!(validate("  ", "https://example.com", "token").is_err());
        assert!(validate("app", "", "token").is_err());
        assert!(validate("app", "https://example.com", " ").is_err());
    }

    #[test]
    fn device_bound_password_is_plain_concatenation() {
        assert_eq!(
            device_bound_password_with_uid("project-password", "machine-id").as_str(),
            "project-passwordmachine-id"
        );
    }
}
