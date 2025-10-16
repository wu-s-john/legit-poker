use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use ark_crypto_primitives::{signature::SignatureScheme, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::broadcast;

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::messages::{EnvelopedMessage, GameShuffleMessage, SignatureEncoder};
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::{CommenceGameOutcome, LedgerOperator};
use crate::shuffler::{HandSubscription, Shuffler, ShufflerScheme};

/// Coordinates shuffler runtimes with the ledger operator and realtime feed.
pub struct GameCoordinator<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Absorb + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
    ShufflerScheme<C>: SignatureScheme<PublicKey = C>,
    <ShufflerScheme<C> as SignatureScheme>::Signature: SignatureEncoder,
    <ShufflerScheme<C> as SignatureScheme>::SecretKey: Send + Sync + 'static,
{
    operator: Arc<LedgerOperator<C>>,
    realtime: Mutex<broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>>,
    shufflers: HashMap<ShufflerId, Arc<Shuffler<C, ShufflerScheme<C>>>>,
    active_hands: DashMap<(GameId, HandId), Vec<HandSubscription<C>>>,
}

impl<C> GameCoordinator<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Absorb + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
    ShufflerScheme<C>: SignatureScheme<PublicKey = C>,
    <ShufflerScheme<C> as SignatureScheme>::Signature: SignatureEncoder,
    <ShufflerScheme<C> as SignatureScheme>::SecretKey: Send + Sync + 'static,
{
    pub fn new(
        operator: Arc<LedgerOperator<C>>,
        realtime: broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>,
        shufflers: impl IntoIterator<Item = Arc<Shuffler<C, ShufflerScheme<C>>>>,
    ) -> Self {
        let mut map = HashMap::new();
        for shuffler in shufflers {
            map.insert(shuffler.shuffler_id(), Arc::clone(&shuffler));
        }

        Self {
            operator,
            realtime: Mutex::new(realtime),
            shufflers: map,
            active_hands: DashMap::new(),
        }
    }

    pub fn operator(&self) -> Arc<LedgerOperator<C>> {
        Arc::clone(&self.operator)
    }

    /// Attach all configured shufflers to a newly commenced hand.
    pub async fn attach_hand(&self, outcome: CommenceGameOutcome<C>) -> Result<()> {
        let hand_id = outcome.hand.state.id;
        let game_id = outcome.hand.game_id;
        let expected_order = outcome.initial_snapshot.shuffling.expected_order.clone();

        let mut subscriptions = Vec::with_capacity(expected_order.len());
        let snapshot = outcome.initial_snapshot;

        for (turn_index, shuffler_id) in expected_order.iter().enumerate() {
            let shuffler = self
                .shufflers
                .get(shuffler_id)
                .ok_or_else(|| anyhow!("no shuffler configured for id {}", shuffler_id))?
                .clone();

            let updates = {
                let guard = self.realtime.lock();
                guard.resubscribe()
            };

            let subscription = shuffler
                .subscribe_per_hand(game_id, hand_id, turn_index, &snapshot, updates)
                .await?;

            subscriptions.push(subscription);
        }

        self.active_hands.insert((game_id, hand_id), subscriptions);
        Ok(())
    }

    /// Release shuffler subscriptions for a completed hand.
    pub fn release_hand(&self, game_id: GameId, hand_id: HandId) {
        if let Some((_, subscriptions)) = self.active_hands.remove(&(game_id, hand_id)) {
            drop(subscriptions);
        }
    }
}
