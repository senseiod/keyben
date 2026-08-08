//! Server: Axum + SQLite. It only handles storage and token authentication, never passwords or plaintext.

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

mod config;
mod db;

/// Run in server mode.
pub async fn run(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;

    let addr: SocketAddr = config
        .server
        .listen
        .parse()
        .with_context(|| format!("Failed to parse listen address: {}", config.server.listen))?;

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
                        "Failed to load TLS certificate: cert={}, key={}",
                        cert.display(),
                        key.display()
                    )
                })?;

            tracing::info!(
                "keyben-server started: https://{addr} (database: {})",
                config.server.data.display()
            );
            axum_server::bind_rustls(addr, tls)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
        None => {
            tracing::info!(
                "keyben-server started: http://{addr} (database: {})",
                config.server.data.display()
            );
            tracing::warn!(
                "No cert/key configured; running over plaintext HTTP. Only expose this server on a trusted private network such as Tailscale"
            );
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    }
    .context("Server failed")
}

/// Protect every endpoint, including `/healthz`, with Bearer Token authentication.
fn router(db: Db, auth_token: &str) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/projects", post(create_project))
        .route("/api/projects/{project}/{env}", get(list_secrets))
        .route(
            "/api/projects/{project}/{env}/{name}",
            get(get_secret).put(set_secret).delete(delete_secret),
        )
        // Protect every HTTP endpoint, including healthz, with the same token.
        .layer(ValidateRequestHeaderLayer::custom(BearerAuth::new(
            auth_token,
        )))
        .layer(TraceLayer::new_for_http())
        .with_state(db)
}

async fn shutdown_signal(handle: Handle<SocketAddr>) {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("Interrupt received; shutting down...");
        handle.graceful_shutdown(Some(Duration::from_secs(5)));
    }
}

// --------------------------------------------------------------------- Authentication

/// Validate `Authorization: Bearer <token>` against auth_token in config.toml byte by byte.
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
                message: "Missing or invalid Authorization: Bearer <token>".to_owned(),
            }
            .into_response())
        }
    }
}

/// Compare in constant time to avoid leaking token prefix information through early returns.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u64;
    for index in 0..a.len().max(b.len()) {
        diff |= u64::from(
            a.get(index).copied().unwrap_or_default() ^ b.get(index).copied().unwrap_or_default(),
        );
    }
    diff == 0
}

// ---------------------------------------------------------------- Request/response bodies

#[derive(Debug, Deserialize)]
struct CreateProject {
    name: String,
}

/// The value is always Base64 ciphertext encrypted by the client.
#[derive(Debug, Deserialize, Serialize)]
struct SecretValue {
    value: String,
}

#[derive(Debug, Serialize)]
struct SecretEntry {
    name: String,
    value: String,
}

// ------------------------------------------------------------------- Handlers

async fn create_project(
    State(db): State<Db>,
    Json(body): Json<CreateProject>,
) -> Result<StatusCode, ApiError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("Project name cannot be empty"));
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
            "Project `{project}` does not exist; run keyben init --projectName {project} first"
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
            "Secret `{name}` does not exist in {project}/{env}"
        ))),
    }
}

async fn list_secrets(
    State(db): State<Db>,
    AxumPath((project, env)): AxumPath<(String, String)>,
) -> Result<Json<Vec<SecretEntry>>, ApiError> {
    validate_project_and_env(&project, &env, None)?;
    if !db.project_exists(&project).await? {
        return Err(ApiError::not_found(format!(
            "Project `{project}` does not exist"
        )));
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
            "Secret `{name}` does not exist in {project}/{env}"
        )))
    }
}

fn validate_project_and_env(project: &str, env: &str, name: Option<&str>) -> Result<(), ApiError> {
    if project.trim().is_empty() {
        return Err(ApiError::bad_request("Project name cannot be empty"));
    }
    if !matches!(env, "dev" | "prod") {
        return Err(ApiError::bad_request("Environment must be 'dev' or 'prod'"));
    }
    if let Some(name) = name
        && name.trim().is_empty()
    {
        return Err(ApiError::bad_request("Secret name cannot be empty"));
    }
    Ok(())
}

// --------------------------------------------------------------------- Errors

/// Consistent JSON error response: `{"error": "..."}`.
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
        tracing::error!("Database error: {err}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Database error".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}
