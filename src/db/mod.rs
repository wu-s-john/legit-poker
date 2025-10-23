use std::env;
use std::time::Duration;

use anyhow::{Context, Result};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};

pub mod entity;

const DEFAULT_POSTGRES_URL: &str = "postgresql://postgres:postgres@127.0.0.1:54322/postgres";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve the Postgres URL from the environment, falling back to the local
/// development database used in tests and demos.
pub fn postgres_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_POSTGRES_URL.to_owned())
}

/// Resolve the Postgres URL for tests. Prefers `TEST_DATABASE_URL` but falls
/// back to `DATABASE_URL` and finally a local default.
pub fn postgres_test_url() -> String {
    env::var("TEST_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .unwrap_or_else(|_| DEFAULT_POSTGRES_URL.to_owned())
}

fn build_postgres_options(database_url: &str) -> ConnectOptions {
    let mut opts = ConnectOptions::new(database_url.to_owned());
    opts.max_connections(5)
        .min_connections(1)
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .sqlx_logging(true);
    opts
}

/// Create a Postgres connection using the shared options for the project.
pub async fn connect_to_postgres_db(database_url: &str) -> Result<DatabaseConnection> {
    let opts = build_postgres_options(database_url);
    Database::connect(opts)
        .await
        .with_context(|| format!("failed to connect to database at {database_url}"))
}

/// Convenience helper that connects to the Postgres URL resolved from
/// `DATABASE_URL` or the configured default.
pub async fn connect_default_postgres_db() -> Result<DatabaseConnection> {
    let url = postgres_url();
    connect_to_postgres_db(&url).await
}

/// Create a single-connection in-memory SQLite database, tuned for tests.
pub async fn sqlite_memory_one_conn() -> Result<DatabaseConnection> {
    let mut opts = ConnectOptions::new("sqlite::memory:".to_owned());
    opts.max_connections(1)
        .min_connections(1)
        .sqlx_logging(false);

    let db = Database::connect(opts)
        .await
        .context("failed to connect to in-memory sqlite database")?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA foreign_keys=ON;",
    ))
    .await
    .context("failed to enable sqlite foreign_keys pragma")?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA journal_mode=MEMORY;",
    ))
    .await
    .context("failed to set sqlite journal_mode pragma")?;

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA synchronous=OFF;",
    ))
    .await
    .context("failed to set sqlite synchronous pragma")?;

    Ok(db)
}

pub async fn connect() -> Result<DatabaseConnection> {
    connect_default_postgres_db().await
}
