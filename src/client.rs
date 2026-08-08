//! 客户端：所有加解密都在这里完成，服务端只收发 Base64 密文。

use anyhow::{Context, Result, bail};
use reqwest::{RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, process::Command as ProcessCommand, time::Duration};

use crate::{
    cli::{Cli, Command, Env, SecretsCommand},
    crypto,
};

#[derive(Debug, Deserialize)]
struct SecretValue {
    value: String,
}

#[derive(Debug, Deserialize)]
struct SecretEntry {
    name: String,
    value: String,
}

/// 以客户端模式执行子命令。
pub async fn run(cli: Cli) -> Result<()> {
    let command = cli.command.as_ref().expect("调用方已确认存在子命令");
    let api = Api::new(cli.server.as_deref(), cli.token.as_deref(), cli.insecure)?;

    match command {
        Command::Init { project_name } => {
            api.create_project(project_name).await?;
            println!("项目 `{project_name}` 已创建");
        }

        Command::Secrets { action } => match action {
            SecretsCommand::Set {
                project_name,
                env,
                name,
                value,
            } => {
                let password = resolve_password(&cli.password)?;
                let blob = crypto::encrypt(&password, value)?;
                api.set_secret(project_name, *env, name, &blob).await?;
                println!("已写入 {project_name}/{} 的 {name}", env.as_str());
            }

            SecretsCommand::Get {
                project_name,
                env,
                name: Some(name),
            } => {
                let password = resolve_password(&cli.password)?;
                let blob = api.get_secret(project_name, *env, name).await?;
                println!("{}", crypto::decrypt(&password, &blob)?);
            }

            SecretsCommand::Get {
                project_name,
                env,
                name: None,
            } => {
                let password = resolve_password(&cli.password)?;
                for (name, value) in api.fetch_all(project_name, *env, &password).await? {
                    println!("{name}={value}");
                }
            }

            SecretsCommand::Delete {
                project_name,
                env,
                name,
            } => {
                api.delete_secret(project_name, *env, name).await?;
                println!("已删除 {project_name}/{} 的 {name}", env.as_str());
            }
        },

        Command::Run {
            project_name,
            env,
            argv,
        } => {
            let password = resolve_password(&cli.password)?;
            let secrets = api.fetch_all(project_name, *env, &password).await?;
            exec(argv, secrets)?;
        }
    }

    Ok(())
}

/// 取密码：优先命令行/环境变量，否则交互式隐藏输入。
fn resolve_password(from_args: &Option<String>) -> Result<String> {
    if let Some(password) = from_args {
        return Ok(password.clone());
    }

    dialoguer::Password::new()
        .with_prompt("请输入加解密密码")
        .interact()
        .context("读取密码失败（非交互式环境请使用 --password 或 KEYBEN_PASSWORD）")
}

/// 注入解密后的环境变量并原封不动拉起子进程，透传其退出码。
fn exec(argv: &[String], secrets: BTreeMap<String, String>) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .context("`--` 之后必须给出要执行的程序")?;

    let status = ProcessCommand::new(program)
        .args(args)
        .envs(&secrets)
        .status()
        .with_context(|| format!("无法执行 `{program}`"))?;

    // 子进程被信号终止时（status.code() 为 None）按惯例返回 128 + signo。
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

// --------------------------------------------------------------- HTTP 客户端

struct Api {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Api {
    fn new(server: Option<&str>, token: Option<&str>, insecure: bool) -> Result<Self> {
        let base = server
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("缺少服务端地址，请使用 --server 或设置 KEYBEN_SERVER")?
            .trim_end_matches('/')
            .to_owned();

        let token = token
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("缺少鉴权 Token，请使用 --token 或设置 KEYBEN_TOKEN")?
            .to_owned();

        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(30))
            .build()
            .context("构建 HTTP 客户端失败")?;

        Ok(Self { http, base, token })
    }

    /// 拼接 URL，路径片段做百分号编码，避免变量名含特殊字符时出错。
    fn url(&self, segments: &[&str]) -> String {
        let mut url = format!("{}/api/projects", self.base);
        for segment in segments {
            url.push('/');
            url.push_str(&percent_encode(segment));
        }
        url
    }

    /// 发请求并把非 2xx 状态码翻译成可读错误。
    async fn send(&self, request: RequestBuilder) -> Result<Response> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("请求服务端失败: {}", self.base))?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        if status == StatusCode::UNAUTHORIZED {
            bail!("鉴权失败 (401)：Token 与服务端 config.toml 中的 auth_token 不一致");
        }

        let body = response.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned))
            .unwrap_or(body);

        if detail.trim().is_empty() {
            bail!("服务端返回 {status}");
        }
        bail!("服务端返回 {status}: {detail}");
    }

    async fn create_project(&self, project: &str) -> Result<()> {
        let url = format!("{}/api/projects", self.base);
        self.send(self.http.post(url).json(&json!({ "name": project })))
            .await?;
        Ok(())
    }

    async fn set_secret(&self, project: &str, env: Env, name: &str, blob: &str) -> Result<()> {
        let url = self.url(&[project, env.as_str(), name]);
        self.send(self.http.put(url).json(&json!({ "value": blob })))
            .await?;
        Ok(())
    }

    async fn get_secret(&self, project: &str, env: Env, name: &str) -> Result<String> {
        let url = self.url(&[project, env.as_str(), name]);
        let payload: SecretValue = self
            .send(self.http.get(url))
            .await?
            .json()
            .await
            .context("解析服务端响应失败")?;
        Ok(payload.value)
    }

    async fn delete_secret(&self, project: &str, env: Env, name: &str) -> Result<()> {
        let url = self.url(&[project, env.as_str(), name]);
        self.send(self.http.delete(url)).await?;
        Ok(())
    }

    /// 拉取并解密某环境下的全部变量。
    async fn fetch_all(
        &self,
        project: &str,
        env: Env,
        password: &str,
    ) -> Result<BTreeMap<String, String>> {
        let url = self.url(&[project, env.as_str()]);
        let entries: Vec<SecretEntry> = self
            .send(self.http.get(url))
            .await?
            .json()
            .await
            .context("解析服务端响应失败")?;

        entries
            .into_iter()
            .map(|entry| {
                let value = crypto::decrypt(password, &entry.value)
                    .with_context(|| format!("解密变量 `{}` 失败", entry.name))?;
                Ok((entry.name, value))
            })
            .collect()
    }
}

/// 按 RFC 3986 对单个 URL 路径片段做百分号编码。
fn percent_encode(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::percent_encode;

    #[test]
    fn encodes_reserved_characters() {
        assert_eq!(percent_encode("DB_URL"), "DB_URL");
        assert_eq!(percent_encode("a/b c"), "a%2Fb%20c");
        assert_eq!(percent_encode("中"), "%E4%B8%AD");
    }
}
