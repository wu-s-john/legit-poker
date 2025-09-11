use anyhow::Result;
use sea_orm::EntityTrait;
use tracing::info;
use tracing_subscriber::EnvFilter;

use zk_poker::db::{self, entity::test};

#[tokio::main]
async fn main() -> Result<()> {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    dotenv::dotenv().ok();

    let conn = db::connect().await?;

    // Delete all rows from the test table using SeaORM DSL (no raw SQL)
    let res = test::Entity::delete_many().exec(&conn).await?;
    info!(target = "db", affected = res.rows_affected, "cleared public.test table");

    Ok(())
}

