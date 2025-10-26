use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ark_crypto_primitives::signature::{schnorr::SecretKey as SchnorrSecretKey, SignatureScheme};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use dashmap::DashMap;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::Deserialize;
use tokio::{
    signal,
    sync::{broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    curve_absorb::CurveAbsorb,
    game::coordinator::realtime::{SupabaseRealtimeClient, SupabaseRealtimeClientConfig},
    ledger::{
        messages::{
            AnyMessageEnvelope, EnvelopedMessage, FinalizedAnyMessageEnvelope, GameShuffleMessage,
        },
        snapshot::{AnyTableSnapshot, Shared},
        store::{EventStore, SnapshotStore},
        types::{GameId, HandId, ShufflerId},
        verifier::Verifier,
        worker::{LedgerWorker, StagingLedgerUpdate, WorkerError},
        CommenceGameOutcome, LedgerOperator, LedgerState,
    },
    shuffler::{HandSubscription, ShufflerRunConfig, ShufflerScheme, ShufflerService},
    shuffling::make_global_public_keys,
    tokio_tools::spawn_named_task,
};

/// Shuffler secret configuration without database ID (for initial parsing)
#[derive(Clone)]
pub struct ShufflerSecret<C: CurveGroup> {
    pub secret: C::ScalarField,
}

/// Bootstrapped shuffler configuration with database-assigned ID
#[derive(Clone)]
pub struct ShufflerSecretConfig<C: CurveGroup> {
    pub id: ShufflerId,
    pub secret: C::ScalarField,
}

impl<C: CurveGroup> From<(ShufflerId, ShufflerSecret<C>)> for ShufflerSecretConfig<C> {
    fn from((id, secret): (ShufflerId, ShufflerSecret<C>)) -> Self {
        Self {
            id,
            secret: secret.secret,
        }
    }
}

#[derive(Clone)]
pub struct ShufflerDescriptor<C: CurveGroup> {
    pub shuffler_id: ShufflerId,
    pub turn_index: usize,
    pub public_key: crate::ledger::CanonicalKey<C>,
    pub aggregated_public_key: C,
}

#[derive(Clone)]
pub struct GameCoordinatorConfig<C: CurveGroup>
where
    C::ScalarField: PrimeField + UniformRand + CanonicalSerialize,
{
    pub verifier: Arc<dyn Verifier<C> + Send + Sync>,
    pub event_store: Arc<dyn EventStore<C>>,
    pub snapshot_store: Arc<dyn SnapshotStore<C>>,
    pub state: Arc<LedgerState<C>>,
    pub supabase: SupabaseRealtimeClientConfig,
    pub shufflers: Vec<ShufflerSecretConfig<C>>,
    pub submit_channel_capacity: usize,
    pub rng_seed: Option<[u8; 32]>,
}

impl<C> GameCoordinatorConfig<C>
where
    C: CurveGroup,
    C::ScalarField: PrimeField + UniformRand + CanonicalSerialize,
{
    pub fn require_shufflers(&self) -> Result<()> {
        if self.shufflers.is_empty() {
            return Err(anyhow!(
                "GameCoordinatorConfig requires at least one shuffler secret"
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct EnvSecretRecord {
    secret: String,
}

pub fn load_shuffler_secrets_from_env<C>(var: &str) -> Result<Vec<ShufflerSecret<C>>>
where
    C: CurveGroup,
    C::ScalarField: PrimeField + CanonicalSerialize,
{
    let raw = std::env::var(var).with_context(|| format!("environment variable {var} not set"))?;
    let records: Vec<EnvSecretRecord> =
        serde_json::from_str(&raw).context("failed to parse shuffler secret JSON array")?;

    if records.is_empty() {
        return Err(anyhow!(
            "environment variable {var} must contain at least one shuffler secret"
        ));
    }

    records
        .into_iter()
        .map(|record| {
            let trimmed = record.secret.trim();
            let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
            let bytes =
                hex::decode(without_prefix).context("invalid hex encoding for shuffler secret")?;
            if bytes.is_empty() {
                return Err(anyhow!("shuffler secret cannot be empty"));
            }
            let scalar = C::ScalarField::from_le_bytes_mod_order(&bytes);
            Ok(ShufflerSecret { secret: scalar })
        })
        .collect()
}

const LOG_TARGET: &str = "legit_poker::game::coordinator";

pub struct GameCoordinator<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    operator: Arc<LedgerOperator<C>>,
    state: Arc<LedgerState<C>>,
    event_store: Arc<dyn EventStore<C>>,
    snapshot_store: Arc<dyn SnapshotStore<C>>,
    updates_tx: broadcast::Sender<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    _event_broadcast: broadcast::Sender<FinalizedAnyMessageEnvelope<C>>,
    _snapshot_broadcast: broadcast::Sender<Shared<AnyTableSnapshot<C>>>,
    _staging_broadcast: broadcast::Sender<StagingLedgerUpdate<C>>,
    realtime_stop: CancellationToken,
    realtime_handle: Option<JoinHandle<anyhow::Result<()>>>,
    worker_handle: Option<JoinHandle<Result<(), WorkerError>>>,
    shufflers: Arc<HashMap<ShufflerId, Arc<ShufflerService<C, ShufflerScheme<C>>>>>,
    shuffler_order: Arc<HashMap<ShufflerId, usize>>,
    active_hands: Arc<DashMap<(GameId, HandId), Vec<HandSubscription<C>>>>,
}

impl<C> GameCoordinator<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    pub async fn spawn(config: GameCoordinatorConfig<C>) -> Result<Self> {
        config.require_shufflers()?;

        let mut rng = match config.rng_seed {
            Some(seed) => StdRng::from_seed(seed),
            None => StdRng::from_entropy(),
        };

        let generator = C::generator();
        let mut public_keys = Vec::with_capacity(config.shufflers.len());
        for shuffler in &config.shufflers {
            public_keys.push(generator * shuffler.secret.clone());
        }
        let aggregated_public_key = make_global_public_keys(public_keys.clone());

        let schnorr_params = ShufflerScheme::<C>::setup(&mut rng)
            .map_err(|err| anyhow!("failed to setup shuffler Schnorr parameters: {err}"))?;

        let (submit_tx, submit_rx): (mpsc::Sender<AnyMessageEnvelope<C>>, _) =
            mpsc::channel(config.submit_channel_capacity);
        let (events_tx, _) = broadcast::channel(1024);
        let (snapshots_tx, _) = broadcast::channel(1024);
        let (staging_tx, _) = broadcast::channel(1024);
        let operator = Arc::new(LedgerOperator::new(
            Arc::clone(&config.verifier),
            submit_tx.clone(),
            Arc::clone(&config.event_store),
            Arc::clone(&config.state),
            events_tx.clone(),
            snapshots_tx.clone(),
            staging_tx.clone(),
        ));

        let realtime_stop = CancellationToken::new();
        let (client, _rx0) =
            SupabaseRealtimeClient::new(config.supabase.clone(), realtime_stop.clone());
        let updates_tx = client.broadcaster();
        let realtime_handle = Some(spawn_named_task(
            "coordinator-realtime-client",
            async move {
                client
                    .run()
                    .await
                    .map_err(|err| anyhow!("supabase realtime client exited with error: {err}"))
            },
        ));

        let mut shufflers = HashMap::with_capacity(config.shufflers.len());
        let mut shuffler_order = HashMap::with_capacity(config.shufflers.len());
        for (index, (shuffler, public_key)) in config
            .shufflers
            .iter()
            .zip(public_keys.into_iter())
            .enumerate()
        {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let run_cfg = ShufflerRunConfig::new(seed);
            let signing_secret = SchnorrSecretKey::<C>(shuffler.secret.clone());
            let events_rx = operator.event_updates();
            let snapshots_rx = operator.snapshot_updates();
            let instance = Arc::new(ShufflerService::<C, ShufflerScheme<C>>::new(
                shuffler.id,
                public_key,
                aggregated_public_key.clone(),
                signing_secret.clone(),
                schnorr_params.clone(),
                submit_tx.clone(),
                run_cfg,
                events_rx,
                snapshots_rx,
            ));
            shufflers.insert(shuffler.id, instance);
            shuffler_order.insert(shuffler.id, index);
        }

        let shufflers = Arc::new(shufflers);
        let shuffler_order = Arc::new(shuffler_order);
        let active_hands = Arc::new(DashMap::new());

        let worker = LedgerWorker::new(
            submit_rx,
            Arc::clone(&config.event_store),
            Arc::clone(&config.snapshot_store),
            Arc::clone(&config.state),
            events_tx.clone(),
            snapshots_tx.clone(),
            staging_tx.clone(),
        );
        let worker_handle = Some(operator.start(worker).await?);

        Ok(Self {
            operator,
            state: Arc::clone(&config.state),
            event_store: Arc::clone(&config.event_store),
            snapshot_store: Arc::clone(&config.snapshot_store),
            updates_tx,
            _event_broadcast: events_tx,
            _snapshot_broadcast: snapshots_tx,
            _staging_broadcast: staging_tx,
            realtime_stop,
            realtime_handle,
            worker_handle,
            shufflers,
            shuffler_order,
            active_hands,
        })
    }

    pub fn state(&self) -> Arc<LedgerState<C>> {
        Arc::clone(&self.state)
    }

    pub fn operator(&self) -> Arc<LedgerOperator<C>> {
        Arc::clone(&self.operator)
    }

    pub fn event_store(&self) -> Arc<dyn EventStore<C>> {
        Arc::clone(&self.event_store)
    }

    pub fn snapshot_store(&self) -> Arc<dyn SnapshotStore<C>> {
        Arc::clone(&self.snapshot_store)
    }

    pub fn shuffler_descriptors(&self) -> Vec<ShufflerDescriptor<C>>
    where
        C: Clone,
    {
        let mut descriptors = self
            .shufflers
            .iter()
            .filter_map(|(shuffler_id, shuffler)| {
                self.shuffler_order.get(shuffler_id).map(|turn_index| {
                    let public_key = shuffler.public_key();
                    let aggregated_public_key = shuffler.aggregated_public_key();
                    ShufflerDescriptor {
                        shuffler_id: *shuffler_id,
                        turn_index: *turn_index,
                        public_key: crate::ledger::CanonicalKey::new(public_key),
                        aggregated_public_key,
                    }
                })
            })
            .collect::<Vec<_>>();
        descriptors.sort_by_key(|descriptor| descriptor.turn_index);
        descriptors
    }

    pub async fn attach_hand(&self, outcome: CommenceGameOutcome<C>) -> Result<()> {
        let hand_id = outcome.hand.state.id;
        let game_id = outcome.hand.game_id;
        let snapshot = outcome.initial_snapshot;
        let expected_order = snapshot.shuffling.expected_order.clone();

        let mut subscriptions = Vec::with_capacity(expected_order.len());
        for (turn_index, shuffler_key) in expected_order.iter().enumerate() {
            let identity = snapshot
                .shufflers
                .get(shuffler_key)
                .ok_or_else(|| anyhow!("expected shuffler key not found in snapshot"))?;
            let shuffler = self
                .shufflers
                .get(&identity.shuffler_id)
                .ok_or_else(|| {
                    anyhow!(
                        "no shuffler configured for shuffler id  {:?}",
                        identity.shuffler_id
                    )
                })?
                .clone();
            let subscription = shuffler
                .subscribe_per_hand(game_id, hand_id, turn_index, &snapshot)
                .await?;
            subscriptions.push(subscription);
        }

        if let Some(first_shuffler_key) = expected_order.first() {
            let identity = snapshot
                .shufflers
                .get(first_shuffler_key)
                .ok_or_else(|| anyhow!("expected shuffler key not found in snapshot"))?;
            let first = self
                .shufflers
                .get(&identity.shuffler_id)
                .ok_or_else(|| {
                    anyhow!(
                        "no shuffler configured for shuffler id  {:?}",
                        identity.shuffler_id
                    )
                })?
                .clone();
            first
                .kick_start_hand(game_id, hand_id)
                .await
                .with_context(|| {
                    format!(
                        "failed to kick start hand {} for shuffler {}",
                        hand_id, identity.shuffler_id
                    )
                })?;
        }

        if let Some(previous) = self.active_hands.insert((game_id, hand_id), subscriptions) {
            for sub in previous {
                sub.cancel();
            }
        }
        Ok(())
    }

    pub fn release_hand(&self, game_id: GameId, hand_id: HandId) {
        if let Some((_, subs)) = self.active_hands.remove(&(game_id, hand_id)) {
            for sub in subs {
                sub.cancel();
            }
        }
    }

    /// Waits for a Ctrl+C signal and then gracefully shuts down the coordinator.
    pub async fn shutdown_on_ctrl_c(self) -> Result<()> {
        let ctrl_c_result = signal::ctrl_c().await;
        match &ctrl_c_result {
            Ok(()) => info!(
                target = LOG_TARGET,
                "Ctrl+C received; initiating coordinator shutdown"
            ),
            Err(err) => warn!(
                target = LOG_TARGET,
                error = ?err,
                "failed to listen for Ctrl+C; shutting down coordinator anyway"
            ),
        }

        let shutdown_result = self.shutdown().await;
        match shutdown_result {
            Ok(()) => ctrl_c_result.map_err(|err| anyhow!("failed to listen for ctrl+c: {err}")),
            Err(err) => Err(err),
        }
    }

    pub async fn shutdown(mut self) -> Result<()> {
        info!(
            target = LOG_TARGET,
            active_shuffles = self.active_hands.len(),
            "initiating coordinator shutdown"
        );
        self.realtime_stop.cancel();
        let keys: Vec<_> = self.active_hands.iter().map(|entry| *entry.key()).collect();
        for key in keys {
            let (game_id, hand_id) = key;
            if let Some((_, subs)) = self.active_hands.remove(&key) {
                info!(
                    target = LOG_TARGET,
                    game_id, hand_id, "cancelling hand subscriptions"
                );
                for sub in subs {
                    sub.cancel();
                }
            }
        }

        for shuffler in self.shufflers.values() {
            info!(
                target = LOG_TARGET,
                shuffler_id = shuffler.shuffler_id(),
                "cancelling shuffler tasks"
            );
            shuffler.cancel_all();
        }
        if let Some(handle) = self.realtime_handle.take() {
            info!(target = LOG_TARGET, "waiting for realtime task to finish");
            match handle.await {
                Ok(result) => {
                    result?;
                    info!(target = LOG_TARGET, "realtime task joined successfully");
                }
                Err(err) => return Err(anyhow!("failed to join realtime task: {err}")),
            }
        }

        if let Some(handle) = self.worker_handle.take() {
            info!(target = LOG_TARGET, "waiting for ledger worker to finish");
            match handle.await {
                Ok(Ok(())) => {
                    info!(target = LOG_TARGET, "ledger worker joined successfully");
                }
                Ok(Err(err)) => {
                    return Err(anyhow!("ledger worker exited with error: {err}"));
                }
                Err(err) => return Err(anyhow!("failed to join ledger worker: {err}")),
            }
        }

        info!(target = LOG_TARGET, "coordinator shutdown complete");
        Ok(())
    }
}

impl<C> Drop for GameCoordinator<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    fn drop(&mut self) {
        self.realtime_stop.cancel();
        if let Some(handle) = self.realtime_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.worker_handle.take() {
            handle.abort();
        }
    }
}
