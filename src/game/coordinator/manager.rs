use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ark_crypto_primitives::signature::{schnorr::SecretKey as SchnorrSecretKey, SignatureScheme};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use async_trait::async_trait;
use dashmap::DashMap;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::Deserialize;
use tokio::{
    signal,
    sync::{broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const DEAL_CHANNEL_CAPACITY: usize = 2048;

use crate::{
    curve_absorb::CurveAbsorb,
    game::coordinator::realtime::{SupabaseRealtimeClient, SupabaseRealtimeClientConfig},
    ledger::{
        messages::{AnyMessageEnvelope, EnvelopedMessage, GameShuffleMessage},
        shuffler_signals::{
            DealShufflerRequest, DealingPhaseStarted, ShufflerDealSignalDispatcher,
            ShufflerSignalRouter,
        },
        store::{EventStore, SnapshotStore},
        types::{GameId, HandId, ShufflerId},
        verifier::Verifier,
        worker::{LedgerWorker, WorkerError},
        CommenceGameOutcome, LedgerOperator, LedgerState,
    },
    shuffler::{HandSubscription, Shuffler, ShufflerRunConfig, ShufflerScheme},
    shuffling::make_global_public_keys,
};

#[derive(Clone)]
pub struct ShufflerSecretConfig<C: CurveGroup> {
    pub id: ShufflerId,
    pub secret: C::ScalarField,
}

struct CoordinatorDealRouter<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    deal_channels: Arc<DashMap<(GameId, HandId), broadcast::Sender<DealShufflerRequest<C>>>>,
    active_hands: Arc<DashMap<(GameId, HandId), Vec<HandSubscription<C, ShufflerScheme<C>>>>>,
}

impl<C> CoordinatorDealRouter<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    fn new(
        deal_channels: Arc<DashMap<(GameId, HandId), broadcast::Sender<DealShufflerRequest<C>>>>,
        active_hands: Arc<DashMap<(GameId, HandId), Vec<HandSubscription<C, ShufflerScheme<C>>>>>,
    ) -> Self {
        Self {
            deal_channels,
            active_hands,
        }
    }
}

#[async_trait]
impl<C> ShufflerSignalRouter<C> for CoordinatorDealRouter<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    async fn broadcast_dealing_started(
        &self,
        shufflers: &[ShufflerId],
        signal: &DealingPhaseStarted<C>,
    ) -> Result<()> {
        let key = (signal.game_id, signal.hand_id);
        self.deal_channels.remove(&key);
        let (sender, _) = broadcast::channel(DEAL_CHANNEL_CAPACITY);
        let sender_for_subs = sender.clone();
        self.deal_channels.insert(key, sender);

        if let Some(subs_ref) = self.active_hands.get(&key) {
            let subscriptions = subs_ref.value();
            for &shuffler_id in shufflers {
                match subscriptions
                    .iter()
                    .find(|subscription| subscription.shuffler_id() == shuffler_id)
                {
                    Some(subscription) => {
                        if let Err(err) = subscription
                            .handle_dealing_phase_started(signal, sender_for_subs.subscribe())
                        {
                            warn!(
                                target = LOG_TARGET,
                                game_id = signal.game_id,
                                hand_id = signal.hand_id,
                                shuffler_id,
                                error = %err,
                                "failed to register dealing listener"
                            );
                        }
                    }
                    None => {
                        warn!(
                            target = LOG_TARGET,
                            game_id = signal.game_id,
                            hand_id = signal.hand_id,
                            shuffler_id,
                            "no shuffler subscription registered for dealing"
                        );
                    }
                }
            }
        } else {
            warn!(
                target = LOG_TARGET,
                game_id = signal.game_id,
                hand_id = signal.hand_id,
                "no hand subscriptions available for dealing start"
            );
        }

        Ok(())
    }

    async fn broadcast_deal_request(
        &self,
        _shufflers: &[ShufflerId],
        request: &DealShufflerRequest<C>,
    ) -> Result<()> {
        let key = match request {
            DealShufflerRequest::Player(req) => (req.game_id, req.hand_id),
            DealShufflerRequest::Board(req) => (req.game_id, req.hand_id),
        };

        match self.deal_channels.get(&key) {
            Some(sender) => {
                if let Err(err) = sender.value().send(request.clone()) {
                    warn!(
                        target = LOG_TARGET,
                        game_id = key.0,
                        hand_id = key.1,
                        error = %err,
                        "failed to broadcast deal request"
                    );
                }
                debug!(
                    target = LOG_TARGET,
                    game_id = key.0,
                    hand_id = key.1,
                    request_kind = match request {
                        DealShufflerRequest::Player(_) => "player",
                        DealShufflerRequest::Board(_) => "board",
                    },
                    "deal request broadcast"
                );
            }
            None => {
                warn!(
                    target = LOG_TARGET,
                    game_id = key.0,
                    hand_id = key.1,
                    "no deal channel registered for hand"
                );
            }
        }

        Ok(())
    }
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
    id: ShufflerId,
    secret: String,
}

pub fn load_shuffler_secrets_from_env<C>(var: &str) -> Result<Vec<ShufflerSecretConfig<C>>>
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
            Ok(ShufflerSecretConfig {
                id: record.id,
                secret: scalar,
            })
        })
        .collect()
}

const LOG_TARGET: &str = "game::coordinator";

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
    updates_tx: broadcast::Sender<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    realtime_stop: CancellationToken,
    realtime_handle: Option<JoinHandle<anyhow::Result<()>>>,
    worker_handle: Option<JoinHandle<Result<(), WorkerError>>>,
    shufflers: Arc<HashMap<ShufflerId, Arc<Shuffler<C, ShufflerScheme<C>>>>>,
    active_hands: Arc<DashMap<(GameId, HandId), Vec<HandSubscription<C, ShufflerScheme<C>>>>>,
    deal_channels: Arc<DashMap<(GameId, HandId), broadcast::Sender<DealShufflerRequest<C>>>>,
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
        let operator = Arc::new(LedgerOperator::new(
            Arc::clone(&config.verifier),
            submit_tx.clone(),
            Arc::clone(&config.event_store),
            Arc::clone(&config.state),
        ));

        let realtime_stop = CancellationToken::new();
        let (client, _rx0) =
            SupabaseRealtimeClient::new(config.supabase.clone(), realtime_stop.clone());
        let updates_tx = client.broadcaster();
        let realtime_handle = Some(tokio::spawn(async move {
            client
                .run()
                .await
                .map_err(|err| anyhow!("supabase realtime client exited with error: {err}"))
        }));

        let mut shufflers = HashMap::with_capacity(config.shufflers.len());
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
            let instance = Arc::new(Shuffler::<C, ShufflerScheme<C>>::new(
                index,
                shuffler.id,
                public_key,
                aggregated_public_key.clone(),
                shuffler.secret.clone(),
                schnorr_params.clone(),
                signing_secret,
                submit_tx.clone(),
                run_cfg,
            ));
            shufflers.insert(shuffler.id, instance);
        }

        let shufflers = Arc::new(shufflers);
        let deal_channels = Arc::new(DashMap::new());
        let active_hands = Arc::new(DashMap::new());
        let router: Arc<dyn ShufflerSignalRouter<C>> = Arc::new(CoordinatorDealRouter::new(
            Arc::clone(&deal_channels),
            Arc::clone(&active_hands),
        ));
        let dispatcher = Arc::new(ShufflerDealSignalDispatcher::new(
            Arc::clone(&router),
            config.state.hasher(),
        ));

        let worker = LedgerWorker::new(
            submit_rx,
            Arc::clone(&config.event_store),
            Arc::clone(&config.snapshot_store),
            Arc::clone(&config.state),
            Some(dispatcher),
        );
        let worker_handle = Some(operator.start(worker).await?);

        Ok(Self {
            operator,
            state: Arc::clone(&config.state),
            event_store: Arc::clone(&config.event_store),
            updates_tx,
            realtime_stop,
            realtime_handle,
            worker_handle,
            shufflers,
            active_hands,
            deal_channels,
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

    pub async fn attach_hand(&self, outcome: CommenceGameOutcome<C>) -> Result<()> {
        let hand_id = outcome.hand.state.id;
        let game_id = outcome.hand.game_id;
        let snapshot = outcome.initial_snapshot;
        let expected_order = snapshot.shuffling.expected_order.clone();

        let mut subscriptions = Vec::with_capacity(expected_order.len());
        for (turn_index, shuffler_id) in expected_order.iter().enumerate() {
            let shuffler = self
                .shufflers
                .get(shuffler_id)
                .ok_or_else(|| anyhow!("no shuffler configured for id {}", shuffler_id))?
                .clone();
            let updates = self.updates_tx.subscribe();
            let subscription = shuffler
                .subscribe_per_hand(game_id, hand_id, turn_index, &snapshot, updates)
                .await?;
            subscriptions.push(subscription);
        }

        if let Some(first_shuffler_id) = expected_order.first() {
            let first = self
                .shufflers
                .get(first_shuffler_id)
                .ok_or_else(|| anyhow!("no shuffler configured for id {}", first_shuffler_id))?
                .clone();
            first
                .kick_start_hand(game_id, hand_id)
                .await
                .with_context(|| {
                    format!(
                        "failed to kick start hand {} for shuffler {}",
                        hand_id, first_shuffler_id
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
        self.deal_channels.remove(&(game_id, hand_id));
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
        self.realtime_stop.cancel();
        let keys: Vec<_> = self.active_hands.iter().map(|entry| *entry.key()).collect();
        for key in keys {
            if let Some((_, subs)) = self.active_hands.remove(&key) {
                for sub in subs {
                    sub.cancel();
                }
            }
        }

        for shuffler in self.shufflers.values() {
            shuffler.cancel_all();
        }
        self.deal_channels.clear();

        if let Some(handle) = self.realtime_handle.take() {
            match handle.await {
                Ok(result) => result?,
                Err(err) => return Err(anyhow!("failed to join realtime task: {err}")),
            }
        }

        if let Some(handle) = self.worker_handle.take() {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(anyhow!("ledger worker exited with error: {err}"));
                }
                Err(err) => return Err(anyhow!("failed to join ledger worker: {err}")),
            }
        }

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
