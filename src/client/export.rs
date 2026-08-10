//! Rendering and writing decrypted environments for `keyben export`.
//!
//! The rendered buffer is kept in [`Zeroizing`] so the complete plaintext export is wiped when
//! it leaves scope, just like the individual decrypted values returned by the API.

use anyhow::{Context, Result, bail};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};
use zeroize::Zeroizing;

use crate::common::{cli::ExportFormat, crypto::SecretText};

/// Render one decrypted environment in the requested format.
pub fn render(
    secrets: &BTreeMap<String, SecretText>,
    format: ExportFormat,
) -> Result<Zeroizing<String>> {
    match format {
        ExportFormat::Dotenv | ExportFormat::DotenvExport | ExportFormat::DotenvEval => {
            render_dotenv(secrets, format)
        }
        ExportFormat::Json => render_json(secrets),
        ExportFormat::Yaml => render_yaml(secrets),
    }
}

/// Write a rendered export either to stdout or directly to a file.
pub fn write(output: &str, output_file: Option<&Path>) -> Result<()> {
    match output_file {
        Some(path) => write_file(output, path),
        None => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(output.as_bytes())
                .context("Failed to write exported secrets to stdout")?;
            stdout
                .flush()
                .context("Failed to flush exported secrets to stdout")
        }
    }
}

fn write_file(output: &str, path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("Failed to open export file {}", path.display()))?;

    // `mode` only applies to a newly created file. Tighten an existing file before putting any
    // new plaintext into it as well.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to secure export file {}", path.display()))?;
    }

    file.set_len(0)
        .with_context(|| format!("Failed to truncate export file {}", path.display()))?;
    file.write_all(output.as_bytes())
        .with_context(|| format!("Failed to write exported secrets to {}", path.display()))
}

fn render_dotenv(
    secrets: &BTreeMap<String, SecretText>,
    format: ExportFormat,
) -> Result<Zeroizing<String>> {
    let mut output = Zeroizing::new(String::new());
    for (name, value) in secrets {
        if !is_shell_identifier(name) {
            bail!(
                "Secret name `{name}` is not a valid environment variable name; use --format json or --format yaml"
            );
        }

        match format {
            ExportFormat::Dotenv => {}
            ExportFormat::DotenvExport => output.push_str("export "),
            ExportFormat::DotenvEval => {}
            ExportFormat::Json | ExportFormat::Yaml => unreachable!(),
        }
        output.push_str(name);
        output.push('=');
        match format {
            ExportFormat::Dotenv | ExportFormat::DotenvExport => {
                push_dotenv_quoted(&mut output, value);
            }
            ExportFormat::DotenvEval => push_shell_quoted(&mut output, value),
            ExportFormat::Json | ExportFormat::Yaml => unreachable!(),
        }
        output.push('\n');
    }
    Ok(output)
}

fn render_json(secrets: &BTreeMap<String, SecretText>) -> Result<Zeroizing<String>> {
    let plain: BTreeMap<&str, &str> = secrets
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut output = Zeroizing::new(
        serde_json::to_string_pretty(&plain).context("Failed to serialize secrets as JSON")?,
    );
    output.push('\n');
    Ok(output)
}

/// JSON string literals are valid YAML 1.2 scalars, so quoting both sides gives a portable YAML
/// mapping without another serializer dependency or ambiguous implicit types such as `yes`.
fn render_yaml(secrets: &BTreeMap<String, SecretText>) -> Result<Zeroizing<String>> {
    if secrets.is_empty() {
        return Ok(Zeroizing::new("{}\n".to_owned()));
    }

    let mut output = Zeroizing::new(String::new());
    for (name, value) in secrets {
        push_json_quoted(&mut output, name);
        output.push_str(": ");
        push_json_quoted(&mut output, value);
        output.push('\n');
    }
    Ok(output)
}

fn is_shell_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn push_dotenv_quoted(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            _ => output.push(character),
        }
    }
    output.push('"');
}

/// Quote a value for a POSIX shell. A literal single quote closes the string, emits an escaped
/// quote, and opens it again: `'one'\''two'`.
fn push_shell_quoted(output: &mut String, value: &str) {
    output.push('\'');
    for (index, part) in value.split('\'').enumerate() {
        if index > 0 {
            output.push_str("'\\''");
        }
        output.push_str(part);
    }
    output.push('\'');
}

/// Append a JSON string literal. JSON double-quoted strings are also unambiguous YAML 1.2
/// scalars, and writing directly avoids leaving a temporary plaintext copy behind.
fn push_json_quoted(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                let byte = character as u8;
                output.push_str("\\u00");
                output.push(HEX[(byte >> 4) as usize] as char);
                output.push(HEX[(byte & 0x0f) as usize] as char);
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(entries: &[(&str, &str)]) -> BTreeMap<String, SecretText> {
        entries
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Zeroizing::new((*value).to_owned())))
            .collect()
    }

    #[test]
    fn dotenv_quotes_special_characters_and_is_sorted() {
        let values = secrets(&[("Z_LAST", "line 1\nline 2"), ("A_FIRST", "a\\b\"c")]);
        assert_eq!(
            render(&values, ExportFormat::Dotenv).unwrap().as_str(),
            "A_FIRST=\"a\\\\b\\\"c\"\nZ_LAST=\"line 1\\nline 2\"\n"
        );
    }

    #[test]
    fn dotenv_eval_uses_posix_shell_quoting() {
        let values = secrets(&[("MESSAGE", "it's $HOME\nand safe")]);
        assert_eq!(
            render(&values, ExportFormat::DotenvEval).unwrap().as_str(),
            "MESSAGE='it'\\''s $HOME\nand safe'\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dotenv_eval_round_trips_through_a_posix_shell() {
        let original = "'leading' $HOME\ntrailing\\";
        let rendered = render(
            &secrets(&[("MESSAGE", original), ("EMPTY", "")]),
            ExportFormat::DotenvEval,
        )
        .unwrap();
        let script = format!(
            "{}printf '%s' \"$MESSAGE\"; printf '\\n'; printf '%s' \"$EMPTY\"",
            rendered.as_str()
        );
        let output = std::process::Command::new("sh")
            .args(["-c", &script])
            .output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{original}\n")
        );
    }

    #[test]
    fn dotenv_rejects_names_that_a_shell_cannot_assign() {
        let values = secrets(&[("API-KEY", "secret")]);
        let error = render(&values, ExportFormat::Dotenv).unwrap_err();
        assert!(error.to_string().contains("--format json"));
    }

    #[test]
    fn json_is_a_pretty_object_with_literal_values() {
        let values = secrets(&[("ENABLED", "true"), ("PORT", "8080")]);
        let output = render(&values, ExportFormat::Json).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(decoded["ENABLED"], "true");
        assert_eq!(decoded["PORT"], "8080");
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn yaml_quotes_keys_and_values_to_avoid_implicit_types() {
        let values = secrets(&[("BOOL", "yes"), ("MULTILINE", "one\ntwo")]);
        assert_eq!(
            render(&values, ExportFormat::Yaml).unwrap().as_str(),
            "\"BOOL\": \"yes\"\n\"MULTILINE\": \"one\\ntwo\"\n"
        );
        assert_eq!(
            render(&BTreeMap::new(), ExportFormat::Yaml)
                .unwrap()
                .as_str(),
            "{}\n"
        );
    }

    #[test]
    fn output_file_is_replaced_without_trailing_old_bytes() {
        let path = std::env::temp_dir().join(format!(
            "keyben-export-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, "a much longer previous export").unwrap();

        write("A=\"1\"\n", Some(&path)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=\"1\"\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        std::fs::remove_file(path).unwrap();
    }
}
