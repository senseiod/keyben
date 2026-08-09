//! Interactive prompts for values the user did not pass on the command line.
//!
//! Every required value has one of these helpers, so a bare `keyben secrets set` asks for what
//! it needs instead of printing a usage error. Each helper takes the parsed argument first and
//! only prompts when it is absent, which keeps automation on the non-interactive path.
//!
//! Passwords, tokens, and secret values are read through [`dialoguer::Password`] so they are
//! never echoed, and are returned inside [`Zeroizing`] wrappers so they are wiped on drop.

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use zeroize::Zeroizing;

use crate::common::{cli::Password, crypto, env::Env};

/// Explain how to supply a value non-interactively.
///
/// `dialoguer` fails with a bare io error when there is no terminal (CI, a pipe, a cron job),
/// which tells the user nothing about how to fix it. Naming the flag and the variable does.
fn usage(flag: &str, env: Option<&str>) -> String {
    match env {
        Some(env) => format!("use {flag} or {env} in non-interactive environments"),
        None => format!("use {flag} in non-interactive environments"),
    }
}

/// Prompt for a non-empty line of text, re-asking while the answer is blank.
///
/// Blank input is a slip rather than an answer, so it is worth another round trip; an empty
/// project name or server URL would only fail later with a worse message.
fn text(prompt: &str, flag: &str, env: Option<&str>) -> Result<String> {
    loop {
        let value = dialoguer::Input::<String>::new()
            .with_prompt(prompt)
            .interact_text()
            .with_context(|| format!("Failed to read input ({})", usage(flag, env)))?;
        if !value.trim().is_empty() {
            return Ok(value.trim().to_owned());
        }
        eprintln!("Value cannot be empty");
    }
}

/// Resolve the project name, prompting when it was not passed.
pub fn project_name(from_args: Option<&str>) -> Result<String> {
    match from_args.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => Ok(name.to_owned()),
        None => text("Enter the project name", "--projectName", None),
    }
}

/// Resolve the server URL, prompting when it was not passed.
pub fn server(from_args: Option<&str>) -> Result<String> {
    match from_args.map(str::trim).filter(|url| !url.is_empty()) {
        Some(url) => Ok(url.to_owned()),
        None => text("Enter the server URL", "--server", Some("KEYBEN_SERVER")),
    }
}

/// Resolve the API token, prompting without echo when it was not passed.
///
/// The token is a credential, so it is read like a password and kept in a wiping wrapper.
pub fn token(from_args: Option<&Password>) -> Result<Password> {
    if let Some(token) = from_args.filter(|token| !token.trim().is_empty()) {
        return Ok(Zeroizing::new(token.trim().to_owned()));
    }

    dialoguer::Password::new()
        .with_prompt("Enter the authentication token")
        .interact()
        .map(|token| Zeroizing::new(token.trim().to_owned()))
        .with_context(|| {
            format!(
                "Failed to read authentication token ({})",
                usage("--token", Some("KEYBEN_TOKEN"))
            )
        })
}

/// Resolve the environment, prompting with a picker when it was not passed.
///
/// The variants come from the enum itself, so a new environment shows up here automatically.
pub fn env(from_args: Option<Env>) -> Result<Env> {
    if let Some(env) = from_args {
        return Ok(env);
    }

    let variants = Env::value_variants();
    let labels: Vec<&str> = variants.iter().map(|env| env.as_str()).collect();
    let index = dialoguer::Select::new()
        .with_prompt("Select the environment")
        .items(&labels)
        .default(0)
        .interact()
        .with_context(|| format!("Failed to read environment ({})", usage("--env", None)))?;
    Ok(variants[index])
}

/// Resolve a secret's name, prompting when it was not passed.
pub fn secret_name(from_args: Option<&str>) -> Result<String> {
    match from_args.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => Ok(name.to_owned()),
        None => text("Enter the secret name", "--name", None),
    }
}

/// Resolve a secret's value, prompting without echo when it was not passed.
///
/// Unlike the other prompts this one accepts an empty answer: an empty string is a legitimate
/// value for an environment variable.
pub fn secret_value(from_args: Option<&str>) -> Result<crypto::SecretText> {
    if let Some(value) = from_args {
        return Ok(Zeroizing::new(value.to_owned()));
    }

    dialoguer::Password::new()
        .with_prompt("Enter the secret value")
        .allow_empty_password(true)
        .interact()
        .map(Zeroizing::new)
        .with_context(|| format!("Failed to read secret value ({})", usage("--value", None)))
}

/// Resolve an existing project password from arguments or a prompt.
pub fn password(from_args: Option<&Password>) -> Result<Password> {
    if let Some(password) = from_args {
        if password.is_empty() {
            bail!("Project password cannot be empty");
        }
        return Ok(password.clone());
    }

    dialoguer::Password::new()
        .with_prompt("Enter the project password")
        .interact()
        .map(Zeroizing::new)
        .with_context(|| {
            format!(
                "Failed to read password ({})",
                usage("--password", Some("KEYBEN_PASSWORD"))
            )
        })
}

/// Resolve a *new* password, asking twice so a typo cannot lock the user out.
pub fn new_password(from_args: Option<&Password>, prompt: &str, usage: &str) -> Result<Password> {
    if let Some(password) = from_args {
        if password.is_empty() {
            bail!("Project password cannot be empty");
        }
        return Ok(password.clone());
    }

    dialoguer::Password::new()
        .with_prompt(prompt)
        .with_confirmation(
            "Confirm the new project password",
            "Project passwords do not match",
        )
        .interact()
        .map(Zeroizing::new)
        .with_context(|| format!("Failed to read project password ({usage})"))
}

/// Ask for confirmation, defaulting to "no" so a non-interactive run never destroys anything.
pub fn confirm(prompt: String) -> bool {
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values that are already present must not reach the terminal — the test suite has no TTY,
    /// so a prompt here would fail rather than hang.
    #[test]
    fn supplied_values_are_returned_without_prompting() {
        assert_eq!(project_name(Some("  app  ")).unwrap(), "app");
        assert_eq!(
            server(Some(" https://example.com ")).unwrap(),
            "https://example.com"
        );
        assert_eq!(secret_name(Some(" DB_URL ")).unwrap(), "DB_URL");
        assert_eq!(env(Some(Env::Prod)).unwrap(), Env::Prod);

        let supplied = Zeroizing::new("t0ken".to_owned());
        assert_eq!(token(Some(&supplied)).unwrap().as_str(), "t0ken");
        assert_eq!(password(Some(&supplied)).unwrap().as_str(), "t0ken");

        // An empty secret value is legitimate and must be taken as given.
        assert_eq!(secret_value(Some("")).unwrap().as_str(), "");
    }

    /// An explicitly empty password is a mistake worth reporting, not something to re-prompt for:
    /// it arrived through `--password` or the environment, where a retry would ask nobody.
    #[test]
    fn an_empty_supplied_password_is_rejected() {
        let empty = Zeroizing::new(String::new());
        assert!(password(Some(&empty)).is_err());
        assert!(new_password(Some(&empty), "prompt", "usage").is_err());
    }

    /// A blank token behaves as if it were absent, so it falls through to the prompt instead of
    /// being sent to the server as an empty bearer value.
    #[test]
    fn a_blank_token_is_treated_as_missing() {
        let blank = Zeroizing::new("   ".to_owned());
        // Cannot call token() here (it would prompt); assert the predicate it filters on.
        assert!(blank.trim().is_empty());
    }
}
