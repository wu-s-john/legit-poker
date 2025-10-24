use std::sync::{Arc, Weak};

use ark_ec::CurveGroup;
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::rngs::StdRng;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ledger::messages::{EnvelopedMessage, GameShuffleMessage};
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::CanonicalKey;
use crate::shuffling::{ElGamalCiphertext, DECK_SIZE};

use super::dealing::DealingHandState;

#[derive(Debug)]
pub struct ShufflingHandState<C: CurveGroup> {
    pub expected_order: Vec<CanonicalKey<C>>,
    pub buffered: Vec<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    pub next_nonce: u64,
    pub turn_index: usize,
    pub initial_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub latest_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub acted: bool,
    pub aggregated_public_key: C,
    pub rng: StdRng,
}

impl<C: CurveGroup> ShufflingHandState<C> {
    pub fn is_complete(&self) -> bool {
        self.buffered.len() >= self.expected_order.len()
    }
}

#[derive(Debug, Default)]
struct ShufflerTasks {
    shuffle: Option<JoinHandle<()>>,
    dealing_producer: Option<JoinHandle<()>>,
    dealing_worker: Option<JoinHandle<()>>,
}

#[derive(Debug)]
pub struct HandRuntime<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub shuffler_id: ShufflerId,
    pub shuffler_index: usize,
    pub shuffler_key: CanonicalKey<C>,
    pub cancel: CancellationToken,
    pub shuffling: Mutex<ShufflingHandState<C>>,
    pub dealing: Mutex<DealingHandState<C>>,
    tasks: Mutex<ShufflerTasks>,
    registry: Weak<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
}

impl<C: CurveGroup> HandRuntime<C> {
    pub fn new(
        game_id: GameId,
        hand_id: HandId,
        shuffler_id: ShufflerId,
        shuffler_index: usize,
        shuffler_key: CanonicalKey<C>,
        shuffling_state: ShufflingHandState<C>,
        registry: Weak<DashMap<(GameId, HandId), Arc<HandRuntime<C>>>>,
    ) -> Self {
        let cancel = CancellationToken::new();
        Self {
            game_id,
            hand_id,
            shuffler_id,
            shuffler_index,
            shuffler_key,
            cancel,
            shuffling: Mutex::new(shuffling_state),
            dealing: Mutex::new(DealingHandState::new()),
            tasks: Mutex::new(ShufflerTasks::default()),
            registry,
        }
    }

    pub fn set_shuffle_handle(&self, handle: JoinHandle<()>) {
        let mut tasks = self.tasks.lock();
        if let Some(existing) = tasks.shuffle.replace(handle) {
            existing.abort();
        }
    }

    pub fn set_dealing_handles(&self, producer: JoinHandle<()>, worker: JoinHandle<()>) {
        let mut tasks = self.tasks.lock();
        if let Some(existing) = tasks.dealing_producer.replace(producer) {
            existing.abort();
        }
        if let Some(existing) = tasks.dealing_worker.replace(worker) {
            existing.abort();
        }
    }

    pub fn cancel_all(&self) {
        self.cancel.cancel();
        let mut tasks = self.tasks.lock();
        if let Some(handle) = tasks.shuffle.take() {
            handle.abort();
        }
        if let Some(handle) = tasks.dealing_producer.take() {
            handle.abort();
        }
        if let Some(handle) = tasks.dealing_worker.take() {
            handle.abort();
        }
    }

    pub fn remove_from_registry(&self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.remove(&(self.game_id, self.hand_id));
        }
    }
}

pub struct HandSubscription<C>
where
    C: CurveGroup,
{
    runtime: Arc<HandRuntime<C>>,
}

impl<C> HandSubscription<C>
where
    C: CurveGroup,
{
    pub fn new(runtime: Arc<HandRuntime<C>>) -> Self {
        Self { runtime }
    }

    pub fn cancel(&self) {
        self.runtime.cancel_all();
    }
}

impl<C> Drop for HandSubscription<C>
where
    C: CurveGroup,
{
    fn drop(&mut self) {
        self.runtime.cancel_all();
        self.runtime.remove_from_registry();
    }
}
