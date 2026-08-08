//! SQLite 存储层。服务端只做极简存取，不理解 value 的内容（Base64 密文）。

use anyhow::{Context, Result};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::path::Path;

/// 建表语句：只有 projects 与 secrets 两张表。
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
    /// 打开（必要时创建）数据库文件并建表。
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建数据目录失败: {}", parent.display()))?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .with_context(|| format!("打开数据库失败: {}", path.display()))?;

        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .context("初始化数据库表结构失败")?;

        Ok(Self { pool })
    }

    /// 创建项目；已存在时保持幂等。
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

    /// 写入或覆盖一个变量（value 为客户端加密后的 Base64 密文）。
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

    /// 列出某项目某环境下的全部变量，按变量名排序。
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

    /// 删除一个变量，返回是否真的删掉了一行。
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
