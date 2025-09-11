use anyhow::Result;
use sea_orm::{Database, DatabaseConnection};

pub mod entity;

const DEFAULT_DB_URL: &str = "postgres://postgres:postgres@127.0.0.1:54322/postgres";

pub async fn connect() -> Result<DatabaseConnection> {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DB_URL.to_string());
    let conn = Database::connect(url).await?;
    Ok(conn)
}
