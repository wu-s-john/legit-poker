use std::sync::Arc;

use anyhow::{anyhow, Result};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::curve_absorb::CurveAbsorb;

use crate::ledger::actor::{AnyActor, ShufflerActor};
use crate::ledger::messages::{
    AnyGameMessage, AnyMessageEnvelope, EnvelopedMessage, FinalizedAnyMessageEnvelope,
    GameShuffleMessage, MetadataEnvelope, SignatureEncoder,
};
use crate::ledger::snapshot::{AnyTableSnapshot, Shared, TableAtShuffling};
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::CanonicalKey;

use super::api::{ShufflerApi, ShufflerEngine, ShufflerSigningSecret};
use super::dealing::{deal_loop, DealShufflerRequest};
use super::hand_runtime::{HandRuntime, HandSubscription, ShufflingHandState};
use super::{spawn_named_task, DEAL_CHANNEL_CAPACITY, LOG_TARGET};
use crate::signing::WithSignature;

#[derive(Clone, Debug)]
pub struct ShufflerRunConfig {
    pub rng_seed: [u8; 32],
    pub message_history_cap: usize,
}

impl ShufflerRunConfig {
    pub fn new(rng_seed: [u8; 32]) -> Self {
        Self {
            rng_seed,
            message_history_cap: 64,
        }
    }

    pub fn with_message_history_cap(mut self, cap: usize) -> Self {
        self.message_history_cap = cap;
        self
    }
}

pub struct ShufflerService<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::SecretKey: ShufflerSigningSecret<C>,
{
    shuffler_id: ShufflerId,
    public_key: C,
    aggregated_public_key: C,
    engine: Arc<ShufflerEngine<C, S>>,
    submit: mpsc::Sender<AnyMessageEnvelope<C>>,
    states: Arc<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
    rng: Mutex<StdRng>,
    config: ShufflerRunConfig,
    events_rx: Mutex<broadcast::Receiver<FinalizedAnyMessageEnvelope<C>>>,
    snapshots_rx: Mutex<broadcast::Receiver<Shared<AnyTableSnapshot<C>>>>,
}

impl<C, S> ShufflerService<C, S>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    C::ScalarField: PrimeField + Absorb,
    S: SignatureScheme<PublicKey = C::Affine> + Send + Sync + 'static,
    S::SecretKey: ShufflerSigningSecret<C> + Send + Sync + 'static,
    S::Signature: SignatureEncoder + Send + Sync + 'static,
    S::Parameters: Send + Sync + 'static,
    S::SecretKey: Send + Sync + 'static,
{
    pub fn new(
        shuffler_id: ShufflerId,
        public_key: C,
        aggregated_public_key: C,
        secret_key: S::SecretKey,
        params: S::Parameters,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        config: ShufflerRunConfig,
        events_rx: broadcast::Receiver<FinalizedAnyMessageEnvelope<C>>,
        snapshots_rx: broadcast::Receiver<Shared<AnyTableSnapshot<C>>>,
    ) -> Self {
        let rng = StdRng::from_seed(config.rng_seed);
        let engine = Arc::new(ShufflerEngine::new(
            Arc::new(secret_key),
            public_key.clone(),
            Arc::new(params),
        ));
        Self {
            shuffler_id,
            public_key,
            aggregated_public_key,
            engine,
            submit,
            states: Arc::new(DashMap::new()),
            rng: Mutex::new(rng),
            config,
            events_rx: Mutex::new(events_rx),
            snapshots_rx: Mutex::new(snapshots_rx),
        }
    }

    pub fn shuffler_id(&self) -> ShufflerId {
        self.shuffler_id
    }

    pub fn public_key(&self) -> C
    where
        C: Clone,
    {
        self.public_key.clone()
    }

    pub fn aggregated_public_key(&self) -> C
    where
        C: Clone,
    {
        self.aggregated_public_key.clone()
    }

    pub fn cancel_all(&self) {
        let mut keys = Vec::new();
        for entry in self.states.iter() {
            entry.value().cancel_all();
            keys.push(*entry.key());
        }
        for key in keys {
            self.states.remove(&key);
        }
    }

    pub async fn subscribe_per_hand(
        &self,
        game_id: GameId,
        hand_id: HandId,
        turn_index: usize,
        snapshot: &TableAtShuffling<C>,
    ) -> Result<HandSubscription<C>>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync,
        C::BaseField: PrimeField + Send + Sync,
        S::Signature: SignatureEncoder + Send + Sync + 'static,
        S::Parameters: Send + Sync + 'static,
        S::SecretKey: Send + Sync + 'static,
    {
        let key = (game_id, hand_id);
        if self.states.contains_key(&key) {
            return Err(anyhow!(
                "hand {} for game {} already registered on shuffler {}",
                hand_id,
                game_id,
                self.shuffler_id
            ));
        }

        let mut global_rng = self.rng.lock();
        let mut hand_seed = [0u8; 32];
        global_rng.fill_bytes(&mut hand_seed);
        drop(global_rng);

        let expected_order = snapshot.shuffling.expected_order.clone();
        if expected_order.is_empty() {
            return Err(anyhow!(
                "hand {} for game {} has empty shuffler order",
                hand_id,
                game_id
            ));
        }
        if turn_index >= expected_order.len() {
            return Err(anyhow!(
                "turn index {} out of range ({} shufflers) for hand {}",
                turn_index,
                expected_order.len(),
                hand_id
            ));
        }

        let initial_deck = snapshot.shuffling.initial_deck.clone();
        let latest_deck = snapshot.shuffling.initial_deck.clone();
        let next_nonce = u64::from(snapshot.sequence);

        let state = ShufflingHandState {
            expected_order,
            buffered: Vec::new(),
            next_nonce,
            turn_index,
            initial_deck,
            latest_deck,
            acted: false,
            aggregated_public_key: self.aggregated_public_key.clone(),
            rng: StdRng::from_seed(hand_seed),
        };

        let registry = Arc::downgrade(&self.states);
        let shuffler_key = CanonicalKey::new(self.public_key.clone());
        let runtime = Arc::new(HandRuntime::new(
            game_id,
            hand_id,
            self.shuffler_id,
            turn_index,
            shuffler_key.clone(),
            state,
            registry.clone(),
        ));

        if self.states.insert(key, Arc::clone(&runtime)).is_some() {
            return Err(anyhow!(
                "hand {} for game {} already registered on shuffler {}",
                hand_id,
                game_id,
                self.shuffler_id
            ));
        }

        info!(
            target = LOG_TARGET,
            game_id,
            hand_id,
            shuffler_id = self.shuffler_id,
            turn_index,
            "registered hand subscription"
        );

        let engine = Arc::clone(&self.engine);
        let submit = self.submit.clone();
        let public_key = self.public_key.clone();
        let actor = ShufflerActor {
            shuffler_id: self.shuffler_id,
            shuffler_key: shuffler_key.clone(),
        };
        let events_rx = {
            let guard = self.events_rx.lock();
            guard.resubscribe()
        };
        let snapshots_rx = {
            let guard = self.snapshots_rx.lock();
            guard.resubscribe()
        };

        let history_cap = self.config.message_history_cap;
        let shuffle_handle = Self::spawn_shuffle_loop_per_hand(
            turn_index,
            engine.clone(),
            submit.clone(),
            Arc::clone(&runtime),
            events_rx,
            history_cap,
            public_key.clone(),
            &actor,
        );

        runtime.set_shuffle_handle(shuffle_handle);

        let (deal_tx, deal_rx) = broadcast::channel(DEAL_CHANNEL_CAPACITY);
        let dealing_producer = Self::spawn_dealing_request_producer(
            Arc::clone(&runtime),
            snapshots_rx,
            deal_tx.clone(),
        );
        let dealing_worker = Self::spawn_dealing_request_worker(
            turn_index,
            Arc::clone(&runtime),
            deal_rx,
            submit.clone(),
            Arc::clone(&engine),
            &actor,
        );

        runtime.set_dealing_handles(dealing_producer, dealing_worker);

        Ok(HandSubscription::new(runtime))
    }

    pub async fn kick_start_hand(&self, game_id: GameId, hand_id: HandId) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        let key = (game_id, hand_id);
        let runtime_arc = {
            let entry = self
                .states
                .get(&key)
                .ok_or_else(|| anyhow!("hand {} for game {} not registered", hand_id, game_id))?;
            let runtime = Arc::clone(entry.value());
            drop(entry);
            runtime
        };

        {
            let state = runtime_arc.shuffling.lock();
            if state.turn_index != 0 {
                return Err(anyhow!(
                    "shuffler {} cannot kick start hand {} turn index {}",
                    self.shuffler_id,
                    hand_id,
                    state.turn_index
                ));
            }
        }

        let shuffler_key = CanonicalKey::new(self.public_key.clone());
        let actor = ShufflerActor {
            shuffler_id: self.shuffler_id,
            shuffler_key,
        };
        let public_key = self.public_key.clone();
        Self::emit_shuffle(
            &self.engine,
            &self.submit,
            &runtime_arc,
            &public_key,
            &actor,
        )
        .await
    }

    fn spawn_shuffle_loop_per_hand(
        shuffler_index: usize,
        engine: Arc<ShufflerEngine<C, S>>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: Arc<HandRuntime<C>>,
        shuffle_updates: broadcast::Receiver<FinalizedAnyMessageEnvelope<C>>,
        history_cap: usize,
        public_key: C,
        actor: &ShufflerActor<C>,
    ) -> JoinHandle<()>
    where
        C: Send + Sync + 'static,
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync + 'static,
        C::BaseField: PrimeField + Send + Sync + 'static,
        C: CurveAbsorb<C::BaseField>,
        C::Affine: Absorb,
        S: SignatureScheme<PublicKey = C::Affine> + Send + Sync + 'static,
        S::Signature: SignatureEncoder + Send + Sync + 'static,
    {
        let actor_clone = actor.clone();
        let game_id = runtime.game_id;
        let hand_id = runtime.hand_id;
        let task_name = format!("shuffler-{shuffler_index}-game-{game_id}-hand-{hand_id}-shuffle");
        spawn_named_task(task_name, async move {
            if let Err(err) = Self::shuffle_loop_per_hand(
                engine,
                submit,
                Arc::clone(&runtime),
                shuffle_updates,
                history_cap,
                public_key,
                &actor_clone,
                shuffler_index,
            )
            .await
            {
                warn!(
                    target = LOG_TARGET,
                    game_id,
                    hand_id,
                    shuffler_index,
                    error = %err,
                    "shuffle loop exited with error"
                );
            } else {
                debug!(
                    target = LOG_TARGET,
                    game_id, hand_id, shuffler_index, "shuffle loop finished"
                );
            }
        })
    }

    async fn shuffle_loop_per_hand(
        engine: Arc<ShufflerEngine<C, S>>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: Arc<HandRuntime<C>>,
        mut updates: broadcast::Receiver<FinalizedAnyMessageEnvelope<C>>,
        history_cap: usize,
        public_key: C,
        actor: &ShufflerActor<C>,
        shuffler_index: usize,
    ) -> Result<()>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureEncoder,
    {
        loop {
            tokio::select! {
                _ = runtime.cancel.cancelled() => {
                    debug!(
                        target = LOG_TARGET,
                        game_id = runtime.game_id,
                        hand_id = runtime.hand_id,
                        shuffler_index,
                        "cancellation token triggered; stopping shuffle loop"
                    );
                    break;
                }
                msg = updates.recv() => {
                    match msg {
                        Ok(finalized) => {
                            if finalized.envelope.game_id != runtime.game_id
                                || finalized.envelope.hand_id != runtime.hand_id
                            {
                                continue;
                            }

                            if let Some(envelope) = Self::as_shuffle_envelope(&finalized) {
                                let should_emit = Self::record_incoming(&runtime, &envelope, history_cap);
                                if should_emit {
                                    if let Err(err) = Self::emit_shuffle(
                                        &engine,
                                        &submit,
                                        &runtime,
                                        &public_key,
                                        actor,
                                    )
                                    .await
                                    {
                                        error!(
                                            target = LOG_TARGET,
                                            game_id = runtime.game_id,
                                            hand_id = runtime.hand_id,
                                            shuffler_index,
                                            error = %err,
                                            "failed to emit shuffle message"
                                        );
                                        break;
                                    }
                                }

                                let is_complete = {
                                    let state = runtime.shuffling.lock();
                                    state.is_complete()
                                };
                                if is_complete {
                                    info!(
                                        target = LOG_TARGET,
                                        game_id = runtime.game_id,
                                        hand_id = runtime.hand_id,
                                        shuffler_index,
                                        "shuffling complete; exiting shuffle loop"
                                    );
                                    break;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                target = LOG_TARGET,
                                game_id = runtime.game_id,
                                hand_id = runtime.hand_id,
                                shuffler_index,
                                skipped,
                                "lagged on realtime updates"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!(
                                target = LOG_TARGET,
                                game_id = runtime.game_id,
                                hand_id = runtime.hand_id,
                                shuffler_index,
                                "realtime channel closed"
                            );
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn record_incoming(
        runtime: &HandRuntime<C>,
        envelope: &EnvelopedMessage<C, GameShuffleMessage<C>>,
        history_cap: usize,
    ) -> bool {
        let mut state = runtime.shuffling.lock();
        if envelope.hand_id != runtime.hand_id || envelope.game_id != runtime.game_id {
            return false;
        }
        if state.is_complete() {
            return false;
        }

        let position = state.buffered.len();
        if let Some(expected) = state.expected_order.get(position) {
            if *expected != envelope.actor.shuffler_key {
                warn!(
                    target = LOG_TARGET,
                    game_id = runtime.game_id,
                    hand_id = runtime.hand_id,
                    expected = ?expected,
                    actual = ?envelope.actor.shuffler_key,
                    "incoming shuffle actor mismatch"
                );
            }
        }

        state.latest_deck = envelope.message.value.deck_out.clone();
        state.buffered.push(envelope.clone());
        if state.buffered.len() > history_cap {
            let drop_count = state.buffered.len() - history_cap;
            state.buffered.drain(0..drop_count);
        }
        state.next_nonce = state.next_nonce.max(envelope.nonce.saturating_add(1));

        !state.acted && state.buffered.len() == state.turn_index
    }

    fn as_shuffle_envelope(
        finalized: &FinalizedAnyMessageEnvelope<C>,
    ) -> Option<EnvelopedMessage<C, GameShuffleMessage<C>>> {
        let actor = match &finalized.envelope.actor {
            AnyActor::Shuffler {
                shuffler_id,
                shuffler_key,
            } => ShufflerActor {
                shuffler_id: *shuffler_id,
                shuffler_key: shuffler_key.clone(),
            },
            _ => return None,
        };

        match &finalized.envelope.message.value {
            AnyGameMessage::Shuffle(message) => Some(EnvelopedMessage {
                hand_id: finalized.envelope.hand_id,
                game_id: finalized.envelope.game_id,
                actor,
                nonce: finalized.envelope.nonce,
                public_key: finalized.envelope.public_key.clone(),
                message: WithSignature {
                    value: message.clone(),
                    signature: finalized.envelope.message.signature.clone(),
                    transcript: finalized.envelope.message.transcript.clone(),
                },
            }),
            _ => None,
        }
    }

    async fn emit_shuffle(
        engine: &Arc<ShufflerEngine<C, S>>,
        submit: &mpsc::Sender<AnyMessageEnvelope<C>>,
        runtime: &Arc<HandRuntime<C>>,
        public_key: &C,
        actor: &ShufflerActor<C>,
    ) -> Result<()> {
        let (any_envelope, deck_out_state, nonce_for_update) = {
            let mut state = runtime.shuffling.lock();
            if state.is_complete() || state.acted {
                return Ok(());
            }

            let position = state.buffered.len();
            if let Some(expected) = state.expected_order.get(position) {
                if *expected != actor.shuffler_key {
                    warn!(
                        target = LOG_TARGET,
                        game_id = runtime.game_id,
                        hand_id = runtime.hand_id,
                        expected = ?expected,
                        actual = ?actor.shuffler_key,
                        "attempted to emit shuffle out of turn"
                    );
                    return Ok(());
                }
            }

            let deck_in = state.latest_deck.clone();
            let turn_index = u16::try_from(state.turn_index)
                .map_err(|_| anyhow!("turn index overflow for shuffle message"))?;
            let ctx = MetadataEnvelope {
                hand_id: runtime.hand_id,
                game_id: runtime.game_id,
                actor: actor.clone(),
                nonce: state.next_nonce,
                public_key: public_key.clone(),
            };
            let aggregated = state.aggregated_public_key.clone();

            let (typed, any) =
                engine.shuffle_and_sign(&aggregated, &ctx, &deck_in, turn_index, &mut state.rng)?;
            let deck_out_state = typed.message.value.deck_out.clone();
            let nonce = state.next_nonce;

            (any, deck_out_state, nonce)
        };

        submit
            .send(any_envelope)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;

        {
            let mut state = runtime.shuffling.lock();
            state.next_nonce = nonce_for_update.saturating_add(1);
            state.latest_deck = deck_out_state;
            state.acted = true;
        }

        info!(
            target = LOG_TARGET,
            game_id = runtime.game_id,
            hand_id = runtime.hand_id,
            shuffler_id = actor.shuffler_id,
            "emitted shuffle message"
        );

        Ok(())
    }

    fn spawn_dealing_request_worker(
        shuffler_index: usize,
        runtime: Arc<HandRuntime<C>>,
        updates: broadcast::Receiver<DealShufflerRequest<C>>,
        submit: mpsc::Sender<AnyMessageEnvelope<C>>,
        shuffler: Arc<ShufflerEngine<C, S>>,
        actor: &ShufflerActor<C>,
    ) -> JoinHandle<()>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField:
            CanonicalSerialize + PrimeField + UniformRand + Send + Sync + 'static + Absorb,
        C::BaseField: PrimeField + Send + Sync + 'static,
        C::Affine: Absorb,
        S: SignatureScheme<PublicKey = C::Affine> + Send + Sync + 'static,
        S::Signature: SignatureEncoder + Send + Sync + 'static,
    {
        let actor_clone = actor.clone();
        let game_id = runtime.game_id;
        let hand_id = runtime.hand_id;
        let task_name =
            format!("dealing-worker-shuffler-{shuffler_index}-game-{game_id}-hand-{hand_id}");
        spawn_named_task(task_name, async move {
            let result = deal_loop::<C, S, _>(
                runtime.clone(),
                updates,
                submit,
                shuffler,
                &actor_clone,
                shuffler_index,
            )
            .await;

            if let Err(err) = result {
                warn!(
                    target = LOG_TARGET,
                    game_id,
                    hand_id,
                    shuffler_index,
                    error = %err,
                    "dealing request worker exited with error"
                );
            } else {
                debug!(
                    target = LOG_TARGET,
                    game_id, hand_id, shuffler_index, "dealing request worker finished"
                );
            }
        })
    }

    fn spawn_dealing_request_producer(
        runtime: Arc<HandRuntime<C>>,
        mut snapshots: broadcast::Receiver<Shared<AnyTableSnapshot<C>>>,
        deal_tx: broadcast::Sender<DealShufflerRequest<C>>,
    ) -> JoinHandle<()>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync + Absorb,
        C::BaseField: PrimeField + Send + Sync,
        C::Affine: Absorb,
    {
        let game_id = runtime.game_id;
        let hand_id = runtime.hand_id;
        let shuffler_id = runtime.shuffler_id;
        let shuffler_index = runtime.shuffler_index;
        let task_name =
            format!("dealing-producer-shuffler-{shuffler_id}-game-{game_id}-hand-{hand_id}");
        spawn_named_task(task_name, async move {
            loop {
                tokio::select! {
                    _ = runtime.cancel.cancelled() => break,
                    msg = snapshots.recv() => {
                        match msg {
                            Ok(shared) => {
                                match shared.as_ref() {
                                    AnyTableSnapshot::Dealing(table) => {
                                        if table.game_id != game_id
                                            || table.hand_id != Some(hand_id)
                                        {
                                            continue;
                                        }
                                        let mut state = runtime.dealing.lock();
                                        match state.process_snapshot_and_make_responses(
                                            table,
                                            shuffler_id,
                                            &runtime.shuffler_key,
                                        ) {
                                            Ok(requests) => {
                                                for request in requests {
                                                    if let Err(err) = deal_tx.send({
                                                        debug!(
                                                            target = LOG_TARGET,
                                                            game_id,
                                                            hand_id,
                                                            shuffler_id,
                                                            shuffler_index,
                                                            request = ?request,
                                                            "broadcasting dealing request"
                                                        );
                                                        request
                                                    }) {
                                                        warn!(
                                                            target = LOG_TARGET,
                                                            game_id,
                                                            hand_id,
                                                            error = %err,
                                                            "failed to broadcast dealing request"
                                                        );
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                warn!(
                                                    target = LOG_TARGET,
                                                    game_id,
                                                    hand_id,
                                                    error = %err,
                                                    "failed to process dealing snapshot"
                                                );
                                            }
                                        }
                                    }
                                    AnyTableSnapshot::Preflop(table) => {
                                        if table.game_id != game_id
                                            || table.hand_id != Some(hand_id)
                                        {
                                            continue;
                                        }
                                        runtime.dealing.lock().reset();
                                    }
                                    AnyTableSnapshot::Flop(table) => {
                                        if table.game_id != game_id
                                            || table.hand_id != Some(hand_id)
                                        {
                                            continue;
                                        }
                                        runtime.dealing.lock().reset();
                                    }
                                    AnyTableSnapshot::Turn(table) => {
                                        if table.game_id != game_id
                                            || table.hand_id != Some(hand_id)
                                        {
                                            continue;
                                        }
                                        runtime.dealing.lock().reset();
                                    }
                                    AnyTableSnapshot::River(table) => {
                                        if table.game_id != game_id
                                            || table.hand_id != Some(hand_id)
                                        {
                                            continue;
                                        }
                                        runtime.dealing.lock().reset();
                                    }
                                    AnyTableSnapshot::Showdown(table) => {
                                        if table.game_id != game_id
                                            || table.hand_id != Some(hand_id)
                                        {
                                            continue;
                                        }
                                        runtime.dealing.lock().reset();
                                    }
                                    AnyTableSnapshot::Complete(table) => {
                                        if table.game_id != game_id
                                            || table.hand_id != Some(hand_id)
                                        {
                                            continue;
                                        }
                                        runtime.dealing.lock().reset();
                                    }
                                    _ => {}
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(
                                    target = LOG_TARGET,
                                    game_id,
                                    hand_id,
                                    skipped,
                                    "lagged on dealing snapshots"
                                );
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
pub(crate) fn submit_sender_for_tests<C, S>(
    service: &ShufflerService<C, S>,
) -> mpsc::Sender<AnyMessageEnvelope<C>>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::SecretKey: ShufflerSigningSecret<C>,
{
    service.submit.clone()
}

#[cfg(test)]
pub(crate) fn engine_for_tests<C, S>(service: &ShufflerService<C, S>) -> Arc<ShufflerEngine<C, S>>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::SecretKey: ShufflerSigningSecret<C>,
{
    Arc::clone(&service.engine)
}

#[cfg(test)]
pub(crate) fn spawn_dealing_request_worker_for_tests<C, S>(
    shuffler_index: usize,
    runtime: Arc<HandRuntime<C>>,
    updates: broadcast::Receiver<DealShufflerRequest<C>>,
    submit: mpsc::Sender<AnyMessageEnvelope<C>>,
    shuffler: Arc<ShufflerEngine<C, S>>,
    actor: &ShufflerActor<C>,
) -> JoinHandle<()>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::Config: CurveConfig<ScalarField = C::ScalarField>,
    C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Send + Sync + 'static + Absorb,
    C::BaseField: PrimeField + Send + Sync + 'static,
    C::Affine: Absorb,
    S: SignatureScheme<PublicKey = C::Affine> + Send + Sync + 'static,
    S::SecretKey: ShufflerSigningSecret<C> + Send + Sync + 'static,
    S::Signature: SignatureEncoder + Send + Sync + 'static,
{
    ShufflerService::<C, S>::spawn_dealing_request_worker(
        shuffler_index,
        runtime,
        updates,
        submit,
        shuffler,
        actor,
    )
}
