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
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::Path, time::Duration};
use tower_http::{
    trace::TraceLayer,
    validate_request::{ValidateRequest, ValidateRequestHeaderLayer},
};

use config::Config;
use db::{Db, PasswordResetResult, ProjectMeta};

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
        .route("/api/projects/{project}/meta", get(get_project_meta))
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
    salt: String,
    wrapped_dek: String,
    auth_hash: String,
}

#[derive(Debug, Deserialize)]
struct ResetProjectPassword {
    salt: String,
    wrapped_dek: String,
    auth_hash: String,
}

const PROJECT_AUTH_HEADER: &str = "x-keyben-project-auth";

/// Decoded byte length of the public Argon2 salt.
const SALT_BYTES: usize = 16;
/// Decoded byte length of the stored auth hash (SHA-256 output).
const AUTH_HASH_BYTES: usize = 32;
/// Minimum decoded length of a wrapped DEK: 24-byte nonce + 32-byte key + 16-byte tag.
const MIN_WRAPPED_DEK_BYTES: usize = 24 + 32 + 16;

/// The value is always Base64 ciphertext encrypted by the client.
#[derive(Debug, Deserialize, Serialize)]
struct SecretValue {
    value: String,
}

/// Public per-project metadata returned to any token-holder so the client can derive keys.
#[derive(Debug, Serialize)]
struct ProjectMetaResponse {
    salt: String,
    wrapped_dek: String,
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
    validate_envelope_fields(&body.salt, &body.wrapped_dek, &body.auth_hash)?;

    if db
        .create_project(
            name,
            body.salt.trim(),
            body.wrapped_dek.trim(),
            body.auth_hash.trim(),
        )
        .await?
    {
        Ok(StatusCode::CREATED)
    } else {
        Err(ApiError::conflict(format!(
            "Project `{name}` already exists"
        )))
    }
}

async fn get_project_meta(
    State(db): State<Db>,
    AxumPath(project): AxumPath<String>,
) -> Result<Json<ProjectMetaResponse>, ApiError> {
    if project.trim().is_empty() {
        return Err(ApiError::bad_request("Project name cannot be empty"));
    }
    match db.project_meta(&project).await? {
        Some(ProjectMeta { salt, wrapped_dek }) => {
            Ok(Json(ProjectMetaResponse { salt, wrapped_dek }))
        }
        None => Err(ApiError::not_found(format!(
            "Project `{project}` does not exist"
        ))),
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
    validate_envelope_fields(&body.salt, &body.wrapped_dek, &body.auth_hash)?;

    let old_auth_hash = authorize_project(&db, &project, &headers).await?;

    match db
        .reset_password(
            &project,
            &old_auth_hash,
            body.salt.trim(),
            body.wrapped_dek.trim(),
            body.auth_hash.trim(),
        )
        .await?
    {
        PasswordResetResult::Updated => Ok(StatusCode::NO_CONTENT),
        PasswordResetResult::PasswordMismatch => {
            Err(ApiError::forbidden("Project password is incorrect"))
        }
    }
}

/// Validate the public envelope metadata a client submits when creating or re-keying a project.
fn validate_envelope_fields(
    salt: &str,
    wrapped_dek: &str,
    auth_hash: &str,
) -> Result<(), ApiError> {
    decode_exact(salt, SALT_BYTES, "project salt")?;
    decode_exact(auth_hash, AUTH_HASH_BYTES, "auth hash")?;
    let dek = B64
        .decode(wrapped_dek.trim())
        .map_err(|_| ApiError::bad_request("Wrapped DEK must be valid Base64"))?;
    if dek.len() < MIN_WRAPPED_DEK_BYTES {
        return Err(ApiError::bad_request(
            "Wrapped DEK is too short to be valid",
        ));
    }
    Ok(())
}

fn decode_exact(value: &str, expected: usize, label: &str) -> Result<Vec<u8>, ApiError> {
    let decoded = B64
        .decode(value.trim())
        .map_err(|_| ApiError::bad_request(format!("{label} must be valid Base64")))?;
    if decoded.len() != expected {
        return Err(ApiError::bad_request(format!(
            "{label} must decode to {expected} bytes"
        )));
    }
    Ok(decoded)
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

/// Authenticate a project request. The client sends `base64(auth_secret)` in the project
/// header; the server hashes it and compares against the stored `auth_hash` in constant time.
/// Returns the stored `auth_hash` so callers can gate their database writes on it.
async fn authorize_project(
    db: &Db,
    project: &str,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    let expected = db
        .project_auth_hash(project)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Project `{project}` does not exist")))?;
    let provided = headers
        .get(PROJECT_AUTH_HEADER)
        .map(|value| value.as_bytes())
        .unwrap_or_default();
    let provided_hash = B64
        .decode(provided)
        .map(|secret| B64.encode(Sha256::digest(secret)))
        .unwrap_or_default();
    if constant_time_eq(provided_hash.as_bytes(), expected.as_bytes()) {
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
    use crate::crypto;

    /// Build the project auth header a client would send from its derived keys.
    fn auth_headers(keys: &crypto::ProjectKeys) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(PROJECT_AUTH_HEADER, keys.auth_secret_b64().parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn project_password_is_checked_before_secret_access() {
        let path =
            std::env::temp_dir().join(format!("keyben-server-test-{}.db", rand::random::<u64>()));
        let db = Db::open(&path).await.unwrap();

        // The client sends base64(auth_secret); the server stores base64(SHA256(auth_secret)).
        let auth_secret = [7u8; 32];
        let auth_secret_b64 = B64.encode(auth_secret);
        let auth_hash = B64.encode(Sha256::digest(auth_secret));
        db.create_project("app", "c2FsdA==", "d3JhcHBlZC1kZWs=", &auth_hash)
            .await
            .unwrap();
        db.set_secret("app", "dev", "TOKEN", "ciphertext")
            .await
            .unwrap();

        let mut wrong_headers = HeaderMap::new();
        wrong_headers.insert(PROJECT_AUTH_HEADER, B64.encode([1u8; 32]).parse().unwrap());
        let error = get_secret(
            State(db.clone()),
            AxumPath(("app".to_owned(), "dev".to_owned(), "TOKEN".to_owned())),
            wrong_headers,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);

        let mut correct_headers = HeaderMap::new();
        correct_headers.insert(PROJECT_AUTH_HEADER, auth_secret_b64.parse().unwrap());
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

    /// Drive the handlers the way a client does: init, write, rotate the password, read back.
    #[tokio::test]
    async fn envelope_flow_survives_password_reset_and_resists_relocation() {
        let path = std::env::temp_dir().join(format!("keyben-e2e-{}.db", rand::random::<u64>()));
        let db = Db::open(&path).await.unwrap();
        let dev_db_url = || AxumPath(("app".to_owned(), "dev".to_owned(), "DB_URL".to_owned()));

        // Client init: fresh salt and DEK, with the DEK wrapped under the password-derived key.
        let salt = crypto::generate_salt();
        let keys = crypto::derive_project_keys("pw1", &salt).unwrap();
        let dek = crypto::generate_dek();
        let create = || CreateProject {
            name: "app".to_owned(),
            salt: B64.encode(salt),
            wrapped_dek: crypto::wrap_dek(&keys, &dek, "app").unwrap(),
            auth_hash: keys.auth_hash_b64(),
        };
        assert_eq!(
            create_project(State(db.clone()), Json(create()))
                .await
                .unwrap(),
            StatusCode::CREATED
        );
        // A second create for a taken name is always a conflict, never an idempotent success.
        assert_eq!(
            create_project(State(db.clone()), Json(create()))
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );

        // Metadata is readable with only the bearer token, so a client can derive its keys.
        let Json(meta) = get_project_meta(State(db.clone()), AxumPath("app".to_owned()))
            .await
            .unwrap();
        assert_eq!(meta.salt, B64.encode(salt));
        assert_eq!(
            crypto::unwrap_dek(&keys, &meta.wrapped_dek, "app").unwrap(),
            dek
        );

        let blob = crypto::encrypt_secret(&dek, "app", "dev", "DB_URL", "postgres://x").unwrap();
        set_secret(
            State(db.clone()),
            dev_db_url(),
            auth_headers(&keys),
            Json(SecretValue {
                value: blob.clone(),
            }),
        )
        .await
        .unwrap();

        // Rotate the password: same DEK, new salt and new wrapper.
        let new_salt = crypto::generate_salt();
        let new_keys = crypto::derive_project_keys("pw2", &new_salt).unwrap();
        reset_project_password(
            State(db.clone()),
            AxumPath("app".to_owned()),
            auth_headers(&keys),
            Json(ResetProjectPassword {
                salt: B64.encode(new_salt),
                wrapped_dek: crypto::wrap_dek(&new_keys, &dek, "app").unwrap(),
                auth_hash: new_keys.auth_hash_b64(),
            }),
        )
        .await
        .unwrap();

        // The new password unwraps the same DEK, so untouched ciphertext still decrypts.
        let Json(meta) = get_project_meta(State(db.clone()), AxumPath("app".to_owned()))
            .await
            .unwrap();
        assert_eq!(
            crypto::unwrap_dek(&new_keys, &meta.wrapped_dek, "app").unwrap(),
            dek
        );
        let Json(secret) = get_secret(State(db.clone()), dev_db_url(), auth_headers(&new_keys))
            .await
            .unwrap();
        assert_eq!(
            crypto::decrypt_secret(&dek, "app", "dev", "DB_URL", &secret.value).unwrap(),
            "postgres://x"
        );

        // The old password no longer authenticates.
        assert_eq!(
            get_secret(State(db.clone()), dev_db_url(), auth_headers(&keys))
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        // Relocating ciphertext to another name fails: the AAD binds (project, env, name).
        let other = || AxumPath(("app".to_owned(), "dev".to_owned(), "OTHER".to_owned()));
        set_secret(
            State(db.clone()),
            other(),
            auth_headers(&new_keys),
            Json(SecretValue { value: blob }),
        )
        .await
        .unwrap();
        let Json(moved) = get_secret(State(db.clone()), other(), auth_headers(&new_keys))
            .await
            .unwrap();
        assert!(crypto::decrypt_secret(&dek, "app", "dev", "OTHER", &moved.value).is_err());

        drop(db);
        std::fs::remove_file(path).unwrap();
    }
}
