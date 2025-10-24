use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use sea_orm::{ActiveModelTrait, ActiveValue::NotSet, ActiveValue::Set, DatabaseConnection};
use tokio::net::TcpListener;
use tracing::info;
use url::Url;

use crate::curve_absorb::CurveAbsorb;
use crate::db::connect_to_postgres_db;
use crate::db::entity::shufflers;
use crate::game::coordinator::{
    GameCoordinator, GameCoordinatorConfig, ShufflerSecret, ShufflerSecretConfig,
    SupabaseRealtimeClientConfig,
};
use crate::ledger::serialization::serialize_curve_bytes;
use crate::ledger::state::LedgerState;
use crate::ledger::store::{EventStore, SeaOrmEventStore, SeaOrmSnapshotStore, SnapshotStore};
use crate::ledger::verifier::{LedgerVerifier, Verifier};
use crate::ledger::{LobbyService, LobbyServiceFactory};

use super::routes::LegitPokerServer;

const LOG_TARGET: &str = "server::bootstrap";

/// Bootstrap coordinator shufflers into the database using SeaORM.
///
/// Takes shuffler secrets without IDs, inserts them into the database,
/// and returns configs with database-assigned IDs paired with their secrets.
async fn bootstrap_coordinator_shufflers<C>(
    secrets: Vec<ShufflerSecret<C>>,
    db: &DatabaseConnection,
) -> Result<Vec<ShufflerSecretConfig<C>>>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField>,
    C::ScalarField: PrimeField,
    C::BaseField: PrimeField,
{
    let mut configs = Vec::with_capacity(secrets.len());

    for (idx, secret) in secrets.into_iter().enumerate() {
        // 1. Compute public key from secret
        let public_key = C::generator() * secret.secret.clone();
        let public_key_bytes = serialize_curve_bytes(&public_key)
            .context("failed to serialize shuffler public key")?;

        // 2. Insert into database using SeaORM, get ID back
        let shuffler_active = shufflers::ActiveModel {
            id: NotSet,
            display_name: Set("coordinator-shuffler-temp".to_string()),
            public_key: Set(public_key_bytes),
            created_at: NotSet,
        };

        let inserted = shuffler_active
            .insert(db)
            .await
            .with_context(|| format!("failed to insert shuffler {}", idx))?;

        let db_id = inserted.id;

        // 3. Update display name with actual DB ID using SeaORM
        let mut update_model: shufflers::ActiveModel = inserted.into();
        update_model.display_name = Set(format!("coordinator-shuffler-{}", db_id));

        update_model
            .update(db)
            .await
            .with_context(|| format!("failed to update shuffler {} display name", db_id))?;

        tracing::info!(
            target: LOG_TARGET,
            shuffler_id = db_id,
            "Inserted coordinator shuffler"
        );

        // 4. Create config with database ID
        configs.push(ShufflerSecretConfig {
            id: db_id,
            secret: secret.secret,
        });
    }

    Ok(configs)
}

pub struct ServerConfig<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    pub bind: SocketAddr,
    pub database_url: String,
    pub supabase_realtime: Url,
    pub supabase_anon_key: String,
    pub shufflers: Vec<ShufflerSecret<C>>,
    pub rng_seed: Option<[u8; 32]>,
}

pub async fn run_server<C>(config: ServerConfig<C>) -> Result<()>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    let db = connect_to_postgres_db(&config.database_url).await?;
    let event_store: Arc<dyn EventStore<C>> = Arc::new(SeaOrmEventStore::<C>::new(db.clone()));
    let snapshot_store: Arc<dyn SnapshotStore<C>> =
        Arc::new(SeaOrmSnapshotStore::<C>::new(db.clone()));
    let state = Arc::new(LedgerState::<C>::new());

    let verifier: Arc<dyn Verifier<C> + Send + Sync> =
        Arc::new(LedgerVerifier::new(Arc::clone(&state)));

    let supabase_cfg = SupabaseRealtimeClientConfig::new(
        config.supabase_realtime.clone(),
        &config.supabase_anon_key,
    );

    // Bootstrap shufflers into database and get back configs with IDs
    let shufflers_with_db_ids = bootstrap_coordinator_shufflers(config.shufflers, &db)
        .await
        .context("failed to bootstrap coordinator shufflers")?;

    tracing::info!(
        target: LOG_TARGET,
        count = shufflers_with_db_ids.len(),
        "Bootstrapped coordinator shufflers"
    );

    let coordinator_config = GameCoordinatorConfig::<C> {
        verifier,
        event_store: Arc::clone(&event_store),
        snapshot_store,
        state,
        supabase: supabase_cfg,
        shufflers: shufflers_with_db_ids,
        submit_channel_capacity: 256,
        rng_seed: config.rng_seed,
    };

    let coordinator = GameCoordinator::spawn(coordinator_config)
        .await
        .context("failed to spawn game coordinator")?;
    let coordinator = Arc::new(coordinator);

    let lobby: Arc<dyn LobbyService<C>> =
        Arc::new(LobbyServiceFactory::<C>::from_sea_orm(db.clone()));

    let server = LegitPokerServer::new(Arc::clone(&coordinator), Arc::clone(&lobby));
    let router = server.into_router();
    let make_service = router.into_make_service();

    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("failed to bind {}", config.bind))?;
    let local_addr = listener.local_addr()?;
    info!(
        target = LOG_TARGET,
        %local_addr,
        realtime = %config.supabase_realtime,
        "legit poker server listening"
    );

    axum::serve(listener, make_service)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server exited with error")
}

async fn shutdown_signal() {
    use tracing::warn;

    if let Err(err) = tokio::signal::ctrl_c().await {
        warn!(
            target = LOG_TARGET,
            error = %err,
            "failed to install ctrl-c handler"
        );
    }
    info!(target = LOG_TARGET, "shutdown signal received");
}
