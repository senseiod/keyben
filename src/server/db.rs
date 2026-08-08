//! SQLite storage layer. The server performs only basic storage operations and treats values as opaque Base64 ciphertext.

use anyhow::{Context, Result};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::path::Path;

/// Schema containing only the `projects` and `secrets` tables.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS projects (
    name TEXT NOT NULL PRIMARY KEY
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

    /// Create a project; this operation is idempotent if it already exists.
    pub async fn create_project(&self, name: &str) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT OR IGNORE INTO projects (name) VALUES (?)")
            .bind(name)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    pub async fn project_exists(&self, name: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query("SELECT 1 FROM projects WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Write or overwrite a variable whose value is Base64 ciphertext from the client.
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

    /// Delete a variable and report whether a row was deleted.
    pub async fn delete_secret(
        &self,
        project: &str,
        env: &str,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM secrets WHERE project_name = ? AND env = ? AND name = ?")
                .bind(project)
                .bind(env)
                .bind(name)
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected() > 0)
    }
}
