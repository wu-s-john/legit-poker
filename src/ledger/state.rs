use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Context};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::actor::{AnyActor, PlayerActor, ShufflerActor};
use crate::ledger::hash::{default_poseidon_hasher, LedgerHasher};
use crate::ledger::messages::{
    AnyGameMessage, AnyMessageEnvelope, EnvelopedMessage, FlopStreet,
    GameBlindingDecryptionMessage, GamePartialUnblindingShareMessage, GamePlayerMessage,
    GameShowdownMessage, GameShuffleMessage, PreflopStreet, RiverStreet, TurnStreet,
};
use crate::ledger::snapshot::AnyTableSnapshot;
use crate::ledger::transition::apply_transition;
use crate::ledger::types::{HandId, StateHash};
use crate::signing::WithSignature;
type SharedHasher = Arc<dyn LedgerHasher + Send + Sync>;

#[derive(Default)]
struct HandLedger<C: CurveGroup> {
    tip: Option<StateHash>,
    snapshots: HashMap<StateHash, AnyTableSnapshot<C>>,
}

pub struct LedgerState<C>
where
    C: CurveGroup,
{
    inner: RwLock<HashMap<HandId, HandLedger<C>>>,
    hasher: SharedHasher,
}

impl<C> LedgerState<C>
where
    C: CurveGroup,
{
    pub fn with_hasher(hasher: SharedHasher) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            hasher,
        }
    }

    pub fn hasher(&self) -> SharedHasher {
        Arc::clone(&self.hasher)
    }

    pub fn hands(&self) -> Vec<HandId> {
        let guard = self.inner.read().expect("ledger state poisoned");
        guard.keys().copied().collect()
    }

    pub fn tip_hash(&self, hand_id: HandId) -> Option<StateHash> {
        let guard = self.inner.read().expect("ledger state poisoned");
        guard.get(&hand_id).and_then(|ledger| ledger.tip)
    }

    pub fn tip_snapshot(&self, hand_id: HandId) -> Option<(StateHash, AnyTableSnapshot<C>)> {
        let guard = self.inner.read().expect("ledger state poisoned");
        let ledger = guard.get(&hand_id)?;
        let tip_hash = ledger.tip?;
        let snapshot = ledger.snapshots.get(&tip_hash)?.clone();
        Some((tip_hash, snapshot))
    }

    pub fn snapshot(&self, hand_id: HandId, hash: StateHash) -> Option<AnyTableSnapshot<C>> {
        let guard = self.inner.read().expect("ledger state poisoned");
        guard
            .get(&hand_id)
            .and_then(|ledger| ledger.snapshots.get(&hash).cloned())
    }

    pub fn upsert_snapshot(&self, hand_id: HandId, snapshot: AnyTableSnapshot<C>, make_tip: bool) {
        let hash = snapshot.state_hash();
        let mut guard = self.inner.write().expect("ledger state poisoned");
        let ledger = guard.entry(hand_id).or_insert_with(HandLedger::default);
        ledger.snapshots.insert(hash, snapshot);
        if make_tip || ledger.tip.is_none() {
            ledger.tip = Some(hash);
        }
    }

    pub fn set_tip(&self, hand_id: HandId, tip: Option<StateHash>) {
        let mut guard = self.inner.write().expect("ledger state poisoned");
        let ledger = guard.entry(hand_id).or_insert_with(HandLedger::default);
        ledger.tip = tip;
    }

    pub fn remove_hand(&self, hand_id: HandId) {
        let mut guard = self.inner.write().expect("ledger state poisoned");
        guard.remove(&hand_id);
    }

    pub fn apply_event(&self, event: &AnyMessageEnvelope<C>) -> anyhow::Result<ApplyOutcome<C>>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        let hand_id = event.hand_id;
        let (_, current_snapshot) = self
            .tip_snapshot(hand_id)
            .with_context(|| format!("no snapshot tip for hand {}", hand_id))?;
        let hasher = self.hasher();

        let outcome = self.apply_message(current_snapshot.clone(), event, &hasher)?;

        if matches!(outcome.status, ApplyStatus::Success) {
            self.upsert_snapshot(hand_id, outcome.snapshot.clone(), true);
        }

        Ok(outcome)
    }

    pub fn replay<I>(&self, events: I) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = AnyMessageEnvelope<C>>,
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        for event in events {
            let outcome = self.apply_event(&event)?;
            if !matches!(outcome.status, ApplyStatus::Success) {
                return Err(anyhow!(
                    "replay failed to apply event: hand_id={}, nonce={}",
                    event.hand_id,
                    event.nonce
                ));
            }
        }
        Ok(())
    }
}

fn remap_signature<C, M>(
    original: &WithSignature<crate::ledger::SignatureBytes, AnyGameMessage<C>>,
    value: M,
) -> WithSignature<crate::ledger::SignatureBytes, M>
where
    C: CurveGroup,
    M: crate::signing::Signable,
{
    WithSignature {
        value,
        signature: original.signature.clone(),
        transcript: original.transcript.clone(),
    }
}

impl<C> LedgerState<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
{
    pub fn new() -> Self {
        Self::with_hasher(default_poseidon_hasher::<C::BaseField>())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::ledger::hash::LedgerHasher;
    use crate::ledger::snapshot::{
        build_default_card_plan, AnyTableSnapshot, PlayerStackInfo, PlayerStacks, RevealsSnapshot,
        ShufflerIdentity, ShufflerRoster, ShufflingSnapshot, ShufflingStep, TableAtShuffling,
        TableSnapshot,
    };
    use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
    use ark_bn254::G1Projective as Curve;
    use ark_ff::Zero;

    fn sample_cipher<C: CurveGroup>() -> ElGamalCiphertext<C> {
        ElGamalCiphertext::new(C::zero(), C::zero())
    }

    fn sample_shuffle_proof<C: CurveGroup>() -> ShuffleProof<C> {
        ShuffleProof::new(
            vec![sample_cipher(); DECK_SIZE],
            vec![(sample_cipher(), C::BaseField::zero()); DECK_SIZE],
            vec![C::ScalarField::zero(); DECK_SIZE],
        )
        .unwrap()
    }

    fn sample_table_snapshot<C: CurveGroup>(hasher: &dyn LedgerHasher) -> TableAtShuffling<C> {
        use crate::engine::nl::types::{HandConfig, PlayerStatus, TableStakes};
        use std::sync::Arc;

        let shuffling = ShufflingSnapshot {
            initial_deck: std::array::from_fn(|_| sample_cipher()),
            steps: vec![ShufflingStep {
                shuffler_public_key: C::zero(),
                proof: sample_shuffle_proof(),
            }],
            final_deck: std::array::from_fn(|_| sample_cipher()),
            expected_order: vec![0],
        };

        let mut stacks = PlayerStacks::new();
        stacks.insert(
            0,
            PlayerStackInfo {
                seat: 0,
                player_id: Some(0),
                starting_stack: 100,
                committed_blind: 0,
                status: PlayerStatus::Active,
            },
        );

        let _reveals: RevealsSnapshot<C> = RevealsSnapshot {
            board: Vec::new(),
            revealed_holes: BTreeMap::new(),
        };

        let hand_cfg = HandConfig {
            stakes: TableStakes {
                small_blind: 0,
                big_blind: 0,
                ante: 0,
            },
            button: 0,
            small_blind_seat: 0,
            big_blind_seat: 0,
            check_raise_allowed: true,
        };

        let mut seating_map = BTreeMap::new();
        seating_map.insert(0, Some(0));
        let _plan = build_default_card_plan(&hand_cfg, &seating_map);

        let mut shufflers = ShufflerRoster::new();
        shufflers.insert(
            0,
            ShufflerIdentity {
                public_key: C::zero(),
                aggregated_public_key: C::zero(),
            },
        );

        let mut snapshot = TableSnapshot {
            game_id: 0,
            hand_id: Some(0),
            sequence: 0,
            cfg: Some(Arc::new(hand_cfg)),
            shufflers: Arc::new(shufflers),
            players: Arc::new(BTreeMap::new()),
            seating: Arc::new(seating_map),
            stacks: Arc::new(stacks),
            previous_hash: None,
            state_hash: StateHash::default(),
            shuffling,
            dealing: (),
            betting: (),
            reveals: (),
        };

        snapshot.initialize_hash(hasher);
        snapshot
    }

    #[test]
    fn tip_updates_when_inserting() {
        let state = LedgerState::<Curve>::new();
        let hasher = state.hasher();
        let snapshot = sample_table_snapshot::<Curve>(&*hasher);
        let any = AnyTableSnapshot::Shuffling(snapshot.clone());
        state.upsert_snapshot(42, any, true);

        let (tip_hash, tip_snapshot) = state.tip_snapshot(42).expect("tip exists");
        assert_eq!(tip_hash, tip_snapshot.state_hash());
        assert_eq!(tip_hash, snapshot.state_hash);
    }

    #[test]
    fn snapshot_lookup_by_hash() {
        let state = LedgerState::<Curve>::new();
        let hasher = state.hasher();
        let snapshot = sample_table_snapshot::<Curve>(&*hasher);
        let hash = snapshot.state_hash;
        state.upsert_snapshot(7, AnyTableSnapshot::Shuffling(snapshot), true);

        let found = state.snapshot(7, hash).expect("snapshot stored");
        assert_eq!(found.state_hash(), hash);
    }

    #[test]
    fn set_tip_switches_head() {
        let state = LedgerState::<Curve>::new();
        let hasher = state.hasher();

        let first = sample_table_snapshot::<Curve>(&*hasher);
        let first_hash = first.state_hash;
        state.upsert_snapshot(1, AnyTableSnapshot::Shuffling(first), true);

        let mut second = sample_table_snapshot::<Curve>(&*hasher);
        // simulate new hash by tweaking seed
        second.state_hash = hasher.hash(b"second");
        state.upsert_snapshot(1, AnyTableSnapshot::Shuffling(second.clone()), false);
        state.set_tip(1, Some(second.state_hash));

        let (tip_hash, _) = state.tip_snapshot(1).expect("tip should exist");
        assert_eq!(tip_hash, second.state_hash);

        // ensure original snapshot still accessible
        assert!(state.snapshot(1, first_hash).is_some());
    }
}

#[derive(Debug, Clone)]
pub struct ApplyOutcome<C: CurveGroup> {
    pub status: ApplyStatus,
    pub snapshot: AnyTableSnapshot<C>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyStatus {
    Success,
    Failed,
}

impl<C> LedgerState<C>
where
    C: CurveGroup,
{
    fn apply_message(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        match &event.message.value {
            AnyGameMessage::Shuffle(message) => {
                self.apply_shuffle(snapshot, event, message.clone(), hasher)
            }
            AnyGameMessage::Blinding(message) => {
                self.apply_blinding(snapshot, event, message.clone(), hasher)
            }
            AnyGameMessage::PartialUnblinding(message) => {
                self.apply_partial_unblinding(snapshot, event, message.clone(), hasher)
            }
            AnyGameMessage::PlayerPreflop(message) => {
                self.apply_player_preflop(snapshot, event, message.clone(), hasher)
            }
            AnyGameMessage::PlayerFlop(message) => {
                self.apply_player_flop(snapshot, event, message.clone(), hasher)
            }
            AnyGameMessage::PlayerTurn(message) => {
                self.apply_player_turn(snapshot, event, message.clone(), hasher)
            }
            AnyGameMessage::PlayerRiver(message) => {
                self.apply_player_river(snapshot, event, message.clone(), hasher)
            }
            AnyGameMessage::Showdown(message) => {
                self.apply_showdown(snapshot, event, message.clone(), hasher)
            }
        }
    }

    fn apply_shuffle(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GameShuffleMessage<C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Shuffling(table) => table,
            other => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: other,
                })
            }
        };

        let actor = match event.actor {
            AnyActor::Shuffler { shuffler_id } => ShufflerActor { shuffler_id },
            _ => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: AnyTableSnapshot::Shuffling(table),
                })
            }
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        let applied = apply_transition(table, &envelope, hasher)?;

        Ok(ApplyOutcome {
            status: ApplyStatus::Success,
            snapshot: applied,
        })
    }

    fn apply_blinding(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GameBlindingDecryptionMessage<C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        let table = match snapshot {
            AnyTableSnapshot::Dealing(table) => table,
            other => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: other,
                })
            }
        };

        let actor = match event.actor {
            AnyActor::Shuffler { shuffler_id } => ShufflerActor { shuffler_id },
            _ => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: AnyTableSnapshot::Dealing(table),
                })
            }
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        let applied = apply_transition(table, &envelope, hasher)?;

        Ok(ApplyOutcome {
            status: ApplyStatus::Success,
            snapshot: applied,
        })
    }

    fn apply_partial_unblinding(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePartialUnblindingShareMessage<C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Dealing(table) => table,
            other => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: other,
                })
            }
        };

        let actor = match event.actor {
            AnyActor::Shuffler { shuffler_id } => ShufflerActor { shuffler_id },
            _ => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: AnyTableSnapshot::Dealing(table),
                })
            }
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        let applied = apply_transition(table, &envelope, hasher)?;

        Ok(ApplyOutcome {
            status: ApplyStatus::Success,
            snapshot: applied,
        })
    }

    fn apply_player_preflop(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePlayerMessage<PreflopStreet, C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Preflop(table) => table,
            other => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: other,
                })
            }
        };
        let actor = match event.actor {
            AnyActor::Player { seat_id, player_id } => PlayerActor { seat_id, player_id },
            _ => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: AnyTableSnapshot::Preflop(table),
                })
            }
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        let applied = apply_transition(table, &envelope, hasher)?;

        Ok(ApplyOutcome {
            status: ApplyStatus::Success,
            snapshot: applied,
        })
    }

    fn apply_player_flop(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePlayerMessage<FlopStreet, C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Flop(table) => table,
            other => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: other,
                })
            }
        };
        let actor = match event.actor {
            AnyActor::Player { seat_id, player_id } => PlayerActor { seat_id, player_id },
            _ => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: AnyTableSnapshot::Flop(table),
                })
            }
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        let applied = apply_transition(table, &envelope, hasher)?;

        Ok(ApplyOutcome {
            status: ApplyStatus::Success,
            snapshot: applied,
        })
    }

    fn apply_player_turn(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePlayerMessage<TurnStreet, C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Turn(table) => table,
            other => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: other,
                })
            }
        };
        let actor = match event.actor {
            AnyActor::Player { seat_id, player_id } => PlayerActor { seat_id, player_id },
            _ => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: AnyTableSnapshot::Turn(table),
                })
            }
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        let applied = apply_transition(table, &envelope, hasher)?;

        Ok(ApplyOutcome {
            status: ApplyStatus::Success,
            snapshot: applied,
        })
    }

    fn apply_player_river(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePlayerMessage<RiverStreet, C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>> {
        let table = match snapshot {
            AnyTableSnapshot::River(table) => table,
            other => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: other,
                })
            }
        };
        let actor = match event.actor {
            AnyActor::Player { seat_id, player_id } => PlayerActor { seat_id, player_id },
            _ => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: AnyTableSnapshot::River(table),
                })
            }
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        let applied = apply_transition(table, &envelope, hasher)?;

        Ok(ApplyOutcome {
            status: ApplyStatus::Success,
            snapshot: applied,
        })
    }

    fn apply_showdown(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GameShowdownMessage<C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<ApplyOutcome<C>>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
    {
        let table = match snapshot {
            AnyTableSnapshot::Showdown(table) => table,
            other => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: other,
                })
            }
        };

        let actor = match event.actor {
            AnyActor::Player { seat_id, player_id } => PlayerActor { seat_id, player_id },
            _ => {
                return Ok(ApplyOutcome {
                    status: ApplyStatus::Failed,
                    snapshot: AnyTableSnapshot::Showdown(table),
                })
            }
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        let applied = apply_transition(table, &envelope, hasher)?;

        Ok(ApplyOutcome {
            status: ApplyStatus::Success,
            snapshot: applied,
        })
    }
}
