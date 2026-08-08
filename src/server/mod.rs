//! 服务端：Axum + SQLite。只做存储与 Token 鉴权，不感知密码与明文。

mod config;
mod db;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, path::Path, time::Duration};
use tower_http::{
    trace::TraceLayer,
    validate_request::{ValidateRequest, ValidateRequestHeaderLayer},
};

use config::Config;
use db::Db;

/// 以服务端模式运行。
pub async fn run(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;

    let addr: SocketAddr = config
        .server
        .listen
        .parse()
        .with_context(|| format!("无法解析监听地址: {}", config.server.listen))?;

    let db = Db::open(&config.server.data).await?;
    let app = router(db, &config.server.auth_token);

    let handle = Handle::new();
    tokio::spawn(shutdown_signal(handle.clone()));

    match config.tls_pair() {
        Some((cert, key)) => {
            let tls = RustlsConfig::from_pem_file(cert, key)
                .await
                .with_context(|| {
                    format!(
                        "加载 TLS 证书失败: cert={}, key={}",
                        cert.display(),
                        key.display()
                    )
                })?;

            tracing::info!(
                "keyben-server 已启动: https://{addr} (数据库: {})",
                config.server.data.display()
            );
            axum_server::bind_rustls(addr, tls)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
        None => {
            tracing::info!(
                "keyben-server 已启动: http://{addr} (数据库: {})",
                config.server.data.display()
            );
            tracing::warn!(
                "未配置 cert/key，正在以明文 HTTP 运行；请确保仅暴露于 Tailscale 等可信内网"
            );
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    }
    .context("服务端运行出错")
}

/// 所有接口（包括 `/healthz`）都经过 Bearer Token 校验。
fn router(db: Db, auth_token: &str) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/projects", post(create_project))
        .route("/api/projects/{project}/{env}", get(list_secrets))
        .route(
            "/api/projects/{project}/{env}/{name}",
            get(get_secret).put(set_secret).delete(delete_secret),
        )
        // 所有 HTTP 接口（包括 healthz）都使用同一个 Token 保护。
        .layer(ValidateRequestHeaderLayer::custom(BearerAuth::new(
            auth_token,
        )))
        .layer(TraceLayer::new_for_http())
        .with_state(db)
}

async fn shutdown_signal(handle: Handle<SocketAddr>) {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("收到中断信号，正在关闭…");
        handle.graceful_shutdown(Some(Duration::from_secs(5)));
    }
}

// --------------------------------------------------------------------- 鉴权

/// 校验 `Authorization: Bearer <token>`，与 config.toml 中的 auth_token 逐字节比对。
#[derive(Clone)]
struct BearerAuth {
    expected: String,
}

impl BearerAuth {
    fn new(token: &str) -> Self {
        Self {
            expected: format!("Bearer {token}"),
        }
    }
}

impl<B> ValidateRequest<B> for BearerAuth {
    type ResponseBody = axum::body::Body;

    fn validate(&mut self, request: &mut Request<B>) -> Result<(), Response> {
        let provided = request
            .headers()
            .get(header::AUTHORIZATION)
            .map(|value| value.as_bytes())
            .unwrap_or_default();

        if constant_time_eq(provided, self.expected.as_bytes()) {
            Ok(())
        } else {
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                message: "缺少或错误的 Authorization: Bearer <token>".to_owned(),
            }
            .into_response())
        }
    }
}

/// 定长比较，避免按字节提前返回而泄露 Token 前缀信息。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u64;
    for index in 0..a.len().max(b.len()) {
        diff |= u64::from(
            a.get(index).copied().unwrap_or_default() ^ b.get(index).copied().unwrap_or_default(),
        );
    }
    diff == 0
}

// ---------------------------------------------------------------- 请求/响应体

#[derive(Debug, Deserialize)]
struct CreateProject {
    name: String,
}

/// value 始终是客户端加密后的 Base64 密文。
#[derive(Debug, Deserialize, Serialize)]
struct SecretValue {
    value: String,
}

#[derive(Debug, Serialize)]
struct SecretEntry {
    name: String,
    value: String,
}

// ------------------------------------------------------------------- 处理函数

async fn create_project(
    State(db): State<Db>,
    Json(body): Json<CreateProject>,
) -> Result<StatusCode, ApiError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("项目名不能为空"));
    }

    db.create_project(name).await?;
    Ok(StatusCode::CREATED)
}

async fn set_secret(
    State(db): State<Db>,
    AxumPath((project, env, name)): AxumPath<(String, String, String)>,
    Json(body): Json<SecretValue>,
) -> Result<StatusCode, ApiError> {
    validate_project_and_env(&project, &env, Some(&name))?;
    if !db.project_exists(&project).await? {
        return Err(ApiError::not_found(format!(
            "项目 `{project}` 不存在，请先执行 keyben init --projectName {project}"
        )));
    }

    db.set_secret(&project, &env, &name, &body.value).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_secret(
    State(db): State<Db>,
    AxumPath((project, env, name)): AxumPath<(String, String, String)>,
) -> Result<Json<SecretValue>, ApiError> {
    validate_project_and_env(&project, &env, Some(&name))?;
    match db.get_secret(&project, &env, &name).await? {
        Some(value) => Ok(Json(SecretValue { value })),
        None => Err(ApiError::not_found(format!(
            "变量 `{name}` 在 {project}/{env} 中不存在"
        ))),
    }
}

async fn list_secrets(
    State(db): State<Db>,
    AxumPath((project, env)): AxumPath<(String, String)>,
) -> Result<Json<Vec<SecretEntry>>, ApiError> {
    validate_project_and_env(&project, &env, None)?;
    if !db.project_exists(&project).await? {
        return Err(ApiError::not_found(format!("项目 `{project}` 不存在")));
    }

    let secrets = db
        .list_secrets(&project, &env)
        .await?
        .into_iter()
        .map(|(name, value)| SecretEntry { name, value })
        .collect();

    Ok(Json(secrets))
}

async fn delete_secret(
    State(db): State<Db>,
    AxumPath((project, env, name)): AxumPath<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    validate_project_and_env(&project, &env, Some(&name))?;
    if db.delete_secret(&project, &env, &name).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!(
            "变量 `{name}` 在 {project}/{env} 中不存在"
        )))
    }
}

fn validate_project_and_env(project: &str, env: &str, name: Option<&str>) -> Result<(), ApiError> {
    if project.trim().is_empty() {
        return Err(ApiError::bad_request("项目名不能为空"));
    }
    if !matches!(env, "dev" | "prod") {
        return Err(ApiError::bad_request("环境必须是 dev 或 prod"));
    }
    if let Some(name) = name
        && name.trim().is_empty()
    {
        return Err(ApiError::bad_request("变量名不能为空"));
    }
    Ok(())
}

// --------------------------------------------------------------------- 错误

/// 统一的 JSON 错误响应：`{"error": "..."}`。
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!("数据库错误: {err}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "数据库错误".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}
