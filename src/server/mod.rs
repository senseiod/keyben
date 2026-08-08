//! Server: Axum + SQLite. It only handles storage and token authentication, never passwords or plaintext.

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, path::Path, time::Duration};
use tower_http::{
    trace::TraceLayer,
    validate_request::{ValidateRequest, ValidateRequestHeaderLayer},
};

use config::Config;
use db::{Db, PasswordResetResult, PasswordResetSecret};

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
        .route(
            "/api/project-passwords/{project}",
            post(reset_project_password),
        )
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
    password_hash: String,
}

#[derive(Debug, Deserialize)]
struct ResetProjectPassword {
    password_hash: String,
    secrets: Vec<ResetProjectSecret>,
}

#[derive(Debug, Deserialize)]
struct ResetProjectSecret {
    env: String,
    name: String,
    old_value: String,
    new_value: String,
}

const PROJECT_PASSWORD_HEADER: &str = "x-keyben-project-password";

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
    validate_password_hash(&body.password_hash)?;

    if db.create_project(name, body.password_hash.trim()).await? {
        Ok(StatusCode::CREATED)
    } else {
        Err(ApiError::conflict(format!(
            "Project `{name}` already has a password"
        )))
    }
}

async fn reset_project_password(
    State(db): State<Db>,
    AxumPath(project): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<ResetProjectPassword>,
) -> Result<StatusCode, ApiError> {
    if project.trim().is_empty() {
        return Err(ApiError::bad_request("Project name cannot be empty"));
    }
    validate_password_hash(&body.password_hash)?;

    let old_password_hash = authorize_project(&db, &project, &headers).await?;
    if constant_time_eq(
        old_password_hash.as_bytes(),
        body.password_hash.trim().as_bytes(),
    ) {
        return Err(ApiError::bad_request(
            "New project password must differ from the current password",
        ));
    }

    let secrets = body
        .secrets
        .into_iter()
        .map(|secret| {
            validate_project_and_env(&project, &secret.env, Some(&secret.name))?;
            Ok(PasswordResetSecret {
                env: secret.env,
                name: secret.name,
                old_value: secret.old_value,
                new_value: secret.new_value,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    match db
        .reset_password(
            &project,
            &old_password_hash,
            body.password_hash.trim(),
            &secrets,
        )
        .await?
    {
        PasswordResetResult::Updated => Ok(StatusCode::NO_CONTENT),
        PasswordResetResult::PasswordMismatch => {
            Err(ApiError::forbidden("Project password is incorrect"))
        }
        PasswordResetResult::SecretsChanged => Err(ApiError::conflict(
            "Project secrets changed while resetting the password; please try again",
        )),
    }
}

fn validate_password_hash(password_hash: &str) -> Result<(), ApiError> {
    if password_hash.trim().is_empty() {
        return Err(ApiError::bad_request(
            "Project password hash cannot be empty",
        ));
    }
    let decoded = B64
        .decode(password_hash.trim())
        .map_err(|_| ApiError::bad_request("Project password hash must be valid Base64"))?;
    if decoded.len() != 32 {
        return Err(ApiError::bad_request(
            "Project password hash must decode to 32 bytes",
        ));
    }
    Ok(())
}

async fn set_secret(
    State(db): State<Db>,
    AxumPath((project, env, name)): AxumPath<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<SecretValue>,
) -> Result<StatusCode, ApiError> {
    validate_project_and_env(&project, &env, Some(&name))?;
    let password_hash = authorize_project(&db, &project, &headers).await?;

    if db
        .set_secret_if_password_matches(&project, &env, &name, &body.value, &password_hash)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::conflict(
            "Project password changed while writing the secret; please try again",
        ))
    }
}

async fn get_secret(
    State(db): State<Db>,
    AxumPath((project, env, name)): AxumPath<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Json<SecretValue>, ApiError> {
    validate_project_and_env(&project, &env, Some(&name))?;
    let _password_hash = authorize_project(&db, &project, &headers).await?;
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
    headers: HeaderMap,
) -> Result<Json<Vec<SecretEntry>>, ApiError> {
    validate_project_and_env(&project, &env, None)?;
    let _password_hash = authorize_project(&db, &project, &headers).await?;

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
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_project_and_env(&project, &env, Some(&name))?;
    let password_hash = authorize_project(&db, &project, &headers).await?;
    if db
        .delete_secret_if_password_matches(&project, &env, &name, &password_hash)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        authorize_project(&db, &project, &headers).await?;
        Err(ApiError::not_found(format!(
            "Secret `{name}` does not exist in {project}/{env}"
        )))
    }
}

async fn authorize_project(
    db: &Db,
    project: &str,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    let expected = db
        .project_password_hash(project)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Project `{project}` does not exist")))?;
    let provided = headers
        .get(PROJECT_PASSWORD_HEADER)
        .map(|value| value.as_bytes())
        .unwrap_or_default();
    if constant_time_eq(provided, expected.as_bytes()) {
        Ok(expected)
    } else {
        Err(ApiError::forbidden("Project password is incorrect"))
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
#[derive(Debug)]
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

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn project_password_is_checked_before_secret_access() {
        let path =
            std::env::temp_dir().join(format!("keyben-server-test-{}.db", rand::random::<u64>()));
        let db = Db::open(&path).await.unwrap();
        db.create_project("app", "correct-hash").await.unwrap();
        db.set_secret("app", "dev", "TOKEN", "ciphertext")
            .await
            .unwrap();

        let mut wrong_headers = HeaderMap::new();
        wrong_headers.insert(PROJECT_PASSWORD_HEADER, "wrong-hash".parse().unwrap());
        let error = get_secret(
            State(db.clone()),
            AxumPath(("app".to_owned(), "dev".to_owned(), "TOKEN".to_owned())),
            wrong_headers,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);

        let mut correct_headers = HeaderMap::new();
        correct_headers.insert(PROJECT_PASSWORD_HEADER, "correct-hash".parse().unwrap());
        let Json(secret) = get_secret(
            State(db.clone()),
            AxumPath(("app".to_owned(), "dev".to_owned(), "TOKEN".to_owned())),
            correct_headers,
        )
        .await
        .unwrap();
        assert_eq!(secret.value, "ciphertext");

        drop(db);
        std::fs::remove_file(path).unwrap();
    }
}
