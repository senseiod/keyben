//! SQLite storage layer. The server performs only basic storage operations and treats values as opaque Base64 ciphertext.

use anyhow::{Context, Result};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::path::Path;

// The stored row and the metadata response are the same two public fields, so the wire type
// doubles as the row type rather than being copied field by field into it.
use crate::common::wire::ProjectMeta;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordResetResult {
    Updated,
    PasswordMismatch,
}

/// Schema containing only the `projects` and `secrets` tables.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS projects (
    name         TEXT NOT NULL PRIMARY KEY,
    salt         TEXT NOT NULL,
    wrapped_dek  TEXT NOT NULL,
    auth_hash    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
    project_name TEXT NOT NULL,
    env          TEXT NOT NULL,
    name         TEXT NOT NULL,
    value        TEXT NOT NULL,
    PRIMARY KEY (project_name, env, name)
);
"#;

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Open or create the database file and initialize its schema.
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create data directory: {}", parent.display())
            })?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .with_context(|| format!("Failed to open database: {}", path.display()))?;

        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .context("Failed to initialize database table structure")?;

        Ok(Self { pool })
    }

    /// Create a project. Returns `false` if a project with this name already exists.
    pub async fn create_project(
        &self,
        name: &str,
        salt: &str,
        wrapped_dek: &str,
        auth_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO projects (name, salt, wrapped_dek, auth_hash) VALUES (?, ?, ?, ?)
             ON CONFLICT(name) DO NOTHING",
        )
        .bind(name)
        .bind(salt)
        .bind(wrapped_dek)
        .bind(auth_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Fetch the public metadata (salt + wrapped DEK) a client needs to derive keys.
    pub async fn project_meta(&self, name: &str) -> Result<Option<ProjectMeta>, sqlx::Error> {
        let row = sqlx::query("SELECT salt, wrapped_dek FROM projects WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| ProjectMeta {
            salt: row.get("salt"),
            wrapped_dek: row.get("wrapped_dek"),
        }))
    }

    pub async fn project_auth_hash(&self, name: &str) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT auth_hash FROM projects WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
    }

    /// Replace a project's salt, wrapped DEK, and auth hash in one statement, gated on the
    /// current auth hash. The secret ciphertext is untouched because the DEK is unchanged.
    pub async fn reset_password(
        &self,
        project: &str,
        old_auth_hash: &str,
        new_salt: &str,
        new_wrapped_dek: &str,
        new_auth_hash: &str,
    ) -> Result<PasswordResetResult, sqlx::Error> {
        let updated = sqlx::query(
            "UPDATE projects SET salt = ?, wrapped_dek = ?, auth_hash = ?
             WHERE name = ? AND auth_hash = ?",
        )
        .bind(new_salt)
        .bind(new_wrapped_dek)
        .bind(new_auth_hash)
        .bind(project)
        .bind(old_auth_hash)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if updated == 0 {
            Ok(PasswordResetResult::PasswordMismatch)
        } else {
            Ok(PasswordResetResult::Updated)
        }
    }

    /// Write or overwrite a variable whose value is Base64 ciphertext from the client.
    #[cfg(test)]
    pub async fn set_secret(
        &self,
        project: &str,
        env: &str,
        name: &str,
        value: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO secrets (project_name, env, name, value) VALUES (?, ?, ?, ?)
             ON CONFLICT (project_name, env, name) DO UPDATE SET value = excluded.value",
        )
        .bind(project)
        .bind(env)
        .bind(name)
        .bind(value)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    pub async fn set_secret_if_password_matches(
        &self,
        project: &str,
        env: &str,
        name: &str,
        value: &str,
        auth_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO secrets (project_name, env, name, value)
             SELECT ?, ?, ?, ?
             WHERE EXISTS (
                 SELECT 1 FROM projects WHERE name = ? AND auth_hash = ?
             )
             ON CONFLICT (project_name, env, name) DO UPDATE SET value = excluded.value",
        )
        .bind(project)
        .bind(env)
        .bind(name)
        .bind(value)
        .bind(project)
        .bind(auth_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_secret(
        &self,
        project: &str,
        env: &str,
        name: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT value FROM secrets WHERE project_name = ? AND env = ? AND name = ?",
        )
        .bind(project)
        .bind(env)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
    }

    /// List all variables in a project and environment, sorted by variable name.
    pub async fn list_secrets(
        &self,
        project: &str,
        env: &str,
    ) -> Result<Vec<(String, String)>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT name, value FROM secrets WHERE project_name = ? AND env = ? ORDER BY name",
        )
        .bind(project)
        .bind(env)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| Ok((row.try_get("name")?, row.try_get("value")?)))
            .collect()
    }

    pub async fn delete_secret_if_password_matches(
        &self,
        project: &str,
        env: &str,
        name: &str,
        auth_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM secrets
             WHERE project_name = ? AND env = ? AND name = ?
               AND EXISTS (
                   SELECT 1 FROM projects WHERE projects.name = ? AND auth_hash = ?
               )",
        )
        .bind(project)
        .bind(env)
        .bind(name)
        .bind(project)
        .bind(auth_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("keyben-test-{}.db", rand::random::<u64>()))
    }

    #[tokio::test]
    async fn create_project_is_exclusive_once_a_name_is_taken() {
        let path = test_db_path();
        let db = Db::open(&path).await.unwrap();

        assert!(
            db.create_project("app", "salt-1", "dek-1", "auth-1")
                .await
                .unwrap()
        );
        // A second create for the same name is rejected, even with identical values.
        assert!(
            !db.create_project("app", "salt-1", "dek-1", "auth-1")
                .await
                .unwrap()
        );
        assert!(
            !db.create_project("app", "salt-2", "dek-2", "auth-2")
                .await
                .unwrap()
        );
        assert_eq!(
            db.project_meta("app").await.unwrap(),
            Some(ProjectMeta {
                salt: "salt-1".to_owned(),
                wrapped_dek: "dek-1".to_owned(),
            })
        );
        assert_eq!(
            db.project_auth_hash("app").await.unwrap().as_deref(),
            Some("auth-1")
        );

        db.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn password_reset_rewraps_dek_without_touching_secrets() {
        let path = test_db_path();
        let db = Db::open(&path).await.unwrap();
        db.create_project("app", "old-salt", "old-dek", "old-auth")
            .await
            .unwrap();
        db.set_secret("app", "prod", "B", "cipher-B").await.unwrap();
        db.set_secret("app", "dev", "A", "cipher-A").await.unwrap();

        assert_eq!(
            db.reset_password("app", "old-auth", "new-salt", "new-dek", "new-auth")
                .await
                .unwrap(),
            PasswordResetResult::Updated
        );
        assert_eq!(
            db.project_meta("app").await.unwrap(),
            Some(ProjectMeta {
                salt: "new-salt".to_owned(),
                wrapped_dek: "new-dek".to_owned(),
            })
        );
        assert_eq!(
            db.project_auth_hash("app").await.unwrap().as_deref(),
            Some("new-auth")
        );
        // Secret ciphertext is unchanged because the DEK itself did not change.
        assert_eq!(
            db.list_secrets("app", "dev").await.unwrap(),
            vec![("A".to_owned(), "cipher-A".to_owned())]
        );
        assert_eq!(
            db.list_secrets("app", "prod").await.unwrap(),
            vec![("B".to_owned(), "cipher-B".to_owned())]
        );

        db.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn password_reset_with_wrong_auth_hash_changes_nothing() {
        let path = test_db_path();
        let db = Db::open(&path).await.unwrap();
        db.create_project("app", "old-salt", "old-dek", "old-auth")
            .await
            .unwrap();
        db.set_secret("app", "dev", "A", "cipher-A").await.unwrap();

        assert_eq!(
            db.reset_password("app", "wrong-auth", "new-salt", "new-dek", "new-auth")
                .await
                .unwrap(),
            PasswordResetResult::PasswordMismatch
        );
        assert_eq!(
            db.project_meta("app").await.unwrap(),
            Some(ProjectMeta {
                salt: "old-salt".to_owned(),
                wrapped_dek: "old-dek".to_owned(),
            })
        );
        assert_eq!(
            db.project_auth_hash("app").await.unwrap().as_deref(),
            Some("old-auth")
        );

        db.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }
}
