use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use tokio::net::TcpListener;
use tracing::info;
use url::Url;

use crate::curve_absorb::CurveAbsorb;
use crate::game::coordinator::{
    GameCoordinator, GameCoordinatorConfig, ShufflerSecretConfig, SupabaseRealtimeClientConfig,
};
use crate::ledger::state::LedgerState;
use crate::ledger::store::{EventStore, SeaOrmEventStore, SeaOrmSnapshotStore, SnapshotStore};
use crate::ledger::verifier::{LedgerVerifier, Verifier};

use super::routes::LegitPokerServer;

const LOG_TARGET: &str = "server::bootstrap";

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
    pub shufflers: Vec<ShufflerSecretConfig<C>>,
    pub rng_seed: Option<[u8; 32]>,
}

pub async fn run_server<C>(config: ServerConfig<C>) -> Result<()>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    let db = connect_database(&config.database_url).await?;
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

    let coordinator_config = GameCoordinatorConfig::<C> {
        verifier,
        event_store: Arc::clone(&event_store),
        snapshot_store,
        state,
        supabase: supabase_cfg,
        shufflers: config.shufflers,
        submit_channel_capacity: 256,
        rng_seed: config.rng_seed,
    };

    let coordinator = GameCoordinator::spawn(coordinator_config)
        .await
        .context("failed to spawn game coordinator")?;
    let coordinator = Arc::new(coordinator);

    let server = LegitPokerServer::new(Arc::clone(&coordinator), Arc::clone(&event_store));
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

async fn connect_database(database_url: &str) -> Result<sea_orm::DatabaseConnection> {
    use sea_orm::{ConnectOptions, Database};

    let mut opts = ConnectOptions::new(database_url.to_owned());
    opts.max_connections(5)
        .min_connections(1)
        .sqlx_logging(true);
    Database::connect(opts)
        .await
        .with_context(|| format!("failed to connect to database at {}", database_url))
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
