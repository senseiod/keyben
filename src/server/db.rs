//! SQLite storage layer. The server performs only basic storage operations and treats values as opaque Base64 ciphertext.

use anyhow::{Context, Result};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordResetSecret {
    pub env: String,
    pub name: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordResetResult {
    Updated,
    PasswordMismatch,
    SecretsChanged,
}

/// Schema containing only the `projects` and `secrets` tables.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS projects (
    name TEXT NOT NULL PRIMARY KEY,
    password_hash TEXT NOT NULL
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

    /// Create a project; using the same password hash again is idempotent.
    pub async fn create_project(
        &self,
        name: &str,
        password_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO projects (name, password_hash) VALUES (?, ?)
             ON CONFLICT(name) DO UPDATE SET password_hash = excluded.password_hash
             WHERE projects.password_hash = excluded.password_hash",
        )
        .bind(name)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn project_password_hash(&self, name: &str) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT password_hash FROM projects WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn reset_password(
        &self,
        project: &str,
        old_password_hash: &str,
        new_password_hash: &str,
        secrets: &[PasswordResetSecret],
    ) -> Result<PasswordResetResult, sqlx::Error> {
        let mut expected_secrets = secrets.to_vec();
        expected_secrets
            .sort_by(|left, right| (&left.env, &left.name).cmp(&(&right.env, &right.name)));

        let mut transaction = self.pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE projects SET password_hash = ?
             WHERE name = ? AND password_hash = ?",
        )
        .bind(new_password_hash)
        .bind(project)
        .bind(old_password_hash)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if updated == 0 {
            transaction.rollback().await?;
            return Ok(PasswordResetResult::PasswordMismatch);
        }

        let current_secrets: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT env, name, value FROM secrets
             WHERE project_name = ? ORDER BY env, name",
        )
        .bind(project)
        .fetch_all(&mut *transaction)
        .await?;

        let snapshot_matches = current_secrets.len() == expected_secrets.len()
            && current_secrets.iter().zip(&expected_secrets).all(
                |((env, name, value), expected)| {
                    env == &expected.env && name == &expected.name && value == &expected.old_value
                },
            );
        if !snapshot_matches {
            transaction.rollback().await?;
            return Ok(PasswordResetResult::SecretsChanged);
        }

        for secret in &expected_secrets {
            sqlx::query(
                "UPDATE secrets SET value = ?
                 WHERE project_name = ? AND env = ? AND name = ?",
            )
            .bind(&secret.new_value)
            .bind(project)
            .bind(&secret.env)
            .bind(&secret.name)
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        Ok(PasswordResetResult::Updated)
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
        password_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO secrets (project_name, env, name, value)
             SELECT ?, ?, ?, ?
             WHERE EXISTS (
                 SELECT 1 FROM projects WHERE name = ? AND password_hash = ?
             )
             ON CONFLICT (project_name, env, name) DO UPDATE SET value = excluded.value",
        )
        .bind(project)
        .bind(env)
        .bind(name)
        .bind(value)
        .bind(project)
        .bind(password_hash)
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
        password_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM secrets
             WHERE project_name = ? AND env = ? AND name = ?
               AND EXISTS (
                   SELECT 1 FROM projects WHERE projects.name = ? AND password_hash = ?
               )",
        )
        .bind(project)
        .bind(env)
        .bind(name)
        .bind(project)
        .bind(password_hash)
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
    async fn project_password_is_idempotent_but_cannot_be_changed() {
        let path = test_db_path();
        let db = Db::open(&path).await.unwrap();

        assert!(db.create_project("app", "hash-one").await.unwrap());
        assert!(db.create_project("app", "hash-one").await.unwrap());
        assert!(!db.create_project("app", "hash-two").await.unwrap());
        assert_eq!(
            db.project_password_hash("app").await.unwrap().as_deref(),
            Some("hash-one")
        );

        db.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn password_reset_replaces_all_ciphertexts_atomically() {
        let path = test_db_path();
        let db = Db::open(&path).await.unwrap();
        db.create_project("app", "old-hash").await.unwrap();
        db.set_secret("app", "prod", "B", "old-prod").await.unwrap();
        db.set_secret("app", "dev", "A", "old-dev").await.unwrap();

        let secrets = vec![
            PasswordResetSecret {
                env: "prod".to_owned(),
                name: "B".to_owned(),
                old_value: "old-prod".to_owned(),
                new_value: "new-prod".to_owned(),
            },
            PasswordResetSecret {
                env: "dev".to_owned(),
                name: "A".to_owned(),
                old_value: "old-dev".to_owned(),
                new_value: "new-dev".to_owned(),
            },
        ];
        assert_eq!(
            db.reset_password("app", "old-hash", "new-hash", &secrets)
                .await
                .unwrap(),
            PasswordResetResult::Updated
        );
        assert_eq!(
            db.project_password_hash("app").await.unwrap().as_deref(),
            Some("new-hash")
        );
        assert_eq!(
            db.list_secrets("app", "dev").await.unwrap(),
            vec![("A".to_owned(), "new-dev".to_owned())]
        );
        assert_eq!(
            db.list_secrets("app", "prod").await.unwrap(),
            vec![("B".to_owned(), "new-prod".to_owned())]
        );

        db.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn password_reset_snapshot_mismatch_does_not_change_anything() {
        let path = test_db_path();
        let db = Db::open(&path).await.unwrap();
        db.create_project("app", "old-hash").await.unwrap();
        db.set_secret("app", "dev", "A", "current").await.unwrap();

        let secrets = vec![PasswordResetSecret {
            env: "dev".to_owned(),
            name: "A".to_owned(),
            old_value: "stale".to_owned(),
            new_value: "new-value".to_owned(),
        }];
        assert_eq!(
            db.reset_password("app", "old-hash", "new-hash", &secrets)
                .await
                .unwrap(),
            PasswordResetResult::SecretsChanged
        );
        assert_eq!(
            db.project_password_hash("app").await.unwrap().as_deref(),
            Some("old-hash")
        );
        assert_eq!(
            db.get_secret("app", "dev", "A").await.unwrap().as_deref(),
            Some("current")
        );

        db.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }
}
