use anyhow::Result;
use sea_orm::EntityTrait;
use tracing::info;
use tracing_subscriber::EnvFilter;

use legit_poker::db::{self, entity::test};

#[tokio::main]
async fn main() -> Result<()> {
    // Logging with default if RUST_LOG is unset
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("db=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    dotenv::dotenv().ok();

    let conn = db::connect().await?;

    // Delete all rows from the test table using SeaORM DSL (no raw SQL)
    let res = test::Entity::delete_many().exec(&conn).await?;
    info!(
        target = "db",
        affected = res.rows_affected,
        "cleared public.test table"
    );

    Ok(())
}
