//! SQLite storage layer. The server performs only basic storage operations and treats values as opaque Base64 ciphertext.

use anyhow::{Context, Result, bail};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::path::Path;

use crate::protocol::{KdfConfig, ProjectMetadata};

const SCHEMA_VERSION: i64 = 2;

/// Schema containing only the `projects` and `secrets` tables.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS projects (
    name                 TEXT NOT NULL PRIMARY KEY,
    kdf_algorithm        TEXT NOT NULL,
    kdf_version          INTEGER NOT NULL,
    kdf_memory_cost      INTEGER NOT NULL,
    kdf_time_cost        INTEGER NOT NULL,
    kdf_parallelism      INTEGER NOT NULL,
    kdf_salt             TEXT NOT NULL,
    password_verifier    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
    project_name TEXT NOT NULL,
    env          TEXT NOT NULL,
    name         TEXT NOT NULL,
    value        TEXT NOT NULL,
    PRIMARY KEY (project_name, env, name),
    FOREIGN KEY (project_name) REFERENCES projects(name) ON DELETE CASCADE
);

PRAGMA user_version = 2;
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

        let schema_version: i64 = sqlx::query_scalar::<_, i64>("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .context("Failed to read database schema version")?;
        let has_project_table: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'projects')",
        )
        .fetch_one(&pool)
        .await
        .context("Failed to inspect database schema")?;

        if schema_version == 0 && has_project_table != 0 {
            bail!(
                "Legacy database schema detected; this version requires a new database file because project password metadata is not backward compatible"
            );
        }
        if schema_version != 0 && schema_version != SCHEMA_VERSION {
            bail!(
                "Unsupported database schema version {schema_version}; expected {SCHEMA_VERSION}"
            );
        }

        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .context("Failed to initialize database table structure")?;

        Ok(Self { pool })
    }

    /// Create a project and report whether a row was inserted.
    pub async fn create_project(
        &self,
        name: &str,
        metadata: &ProjectMetadata,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT OR IGNORE INTO projects (
                name, kdf_algorithm, kdf_version, kdf_memory_cost,
                kdf_time_cost, kdf_parallelism, kdf_salt, password_verifier
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(name)
        .bind(&metadata.kdf.algorithm)
        .bind(i64::from(metadata.kdf.version))
        .bind(i64::from(metadata.kdf.memory_cost))
        .bind(i64::from(metadata.kdf.time_cost))
        .bind(i64::from(metadata.kdf.parallelism))
        .bind(&metadata.kdf.salt)
        .bind(&metadata.verifier)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn project_exists(&self, name: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query("SELECT 1 FROM projects WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn get_project(&self, name: &str) -> Result<Option<ProjectMetadata>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT kdf_algorithm, kdf_version, kdf_memory_cost, kdf_time_cost,
                    kdf_parallelism, kdf_salt, password_verifier
             FROM projects WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            Ok(ProjectMetadata {
                kdf: KdfConfig {
                    algorithm: row.try_get("kdf_algorithm")?,
                    version: sqlite_u32(row.try_get("kdf_version")?, "kdf_version")?,
                    memory_cost: sqlite_u32(row.try_get("kdf_memory_cost")?, "kdf_memory_cost")?,
                    time_cost: sqlite_u32(row.try_get("kdf_time_cost")?, "kdf_time_cost")?,
                    parallelism: sqlite_u32(row.try_get("kdf_parallelism")?, "kdf_parallelism")?,
                    salt: row.try_get("kdf_salt")?,
                },
                verifier: row.try_get("password_verifier")?,
            })
        })
        .transpose()
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

fn sqlite_u32(value: i64, column: &'static str) -> Result<u32, sqlx::Error> {
    u32::try_from(value).map_err(|err| sqlx::Error::ColumnDecode {
        index: column.to_owned(),
        source: Box::new(err),
    })
}
