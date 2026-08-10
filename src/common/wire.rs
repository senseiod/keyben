//! The JSON bodies exchanged between the client and the server.
//!
//! Both halves used to declare their own copy of each body; sharing one definition means a
//! renamed field cannot compile on one side and silently mismatch on the other.
//!
//! Every value here is public envelope metadata or Base64 ciphertext the client produced.
//! No plaintext and no key material ever appears in these structures.

use serde::{Deserialize, Serialize};

/// Body of `POST /api/projects`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateProject {
    pub name: String,
    pub salt: String,
    pub wrapped_dek: String,
    pub auth_hash: String,
}

/// Body of `POST /api/project-passwords/{project}`: the re-wrapped envelope under a new password.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResetProjectPassword {
    pub salt: String,
    pub wrapped_dek: String,
    pub auth_hash: String,
}

/// Public KDF parameters fetched before the client can prove knowledge of the project password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectKdf {
    pub salt: String,
}

/// Password-protected project metadata returned only after project authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub wrapped_dek: String,
}

/// A single secret. The value is always Base64 ciphertext encrypted by the client.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretValue {
    pub value: String,
}

/// One entry of an environment listing.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub value: String,
}

/// The server's error body. The client reads it to surface the server's own wording.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub error: String,
}
