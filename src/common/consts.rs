//! Constants shared by the client and the server.
//!
//! Each value here was previously duplicated on both sides; a single definition keeps the two
//! halves from drifting apart.

use std::time::Duration;

/// Header carrying `base64(auth_secret)`, which proves knowledge of the project password.
///
/// The client sends it and the server hashes it, so the two must name it identically.
pub const PROJECT_AUTH_HEADER: &str = "x-keyben-project-auth";

/// Name of the per-user, multi-project client configuration file in the home directory.
pub const CONFIG_FILE_NAME: &str = ".keyben.toml";

/// Prefix of every environment variable keyben itself reads.
///
/// A child process launched by `keyben run` has all of these stripped, so adding a new
/// `KEYBEN_*` variable never silently leaks into children.
pub const CREDENTIAL_ENV_PREFIX: &str = "KEYBEN";

/// Timeout applied to every HTTP request the client makes.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
