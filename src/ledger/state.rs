use std::collections::{hash_map::Entry, HashMap};
use std::sync::{Arc, RwLock};

use anyhow::{bail, Context};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::actor::{AnyActor, PlayerActor, ShufflerActor};
use crate::ledger::hash::{default_poseidon_hasher, LedgerHasher};
use crate::ledger::messages::{
    AnyGameMessage, AnyMessageEnvelope, EnvelopedMessage, FinalizedAnyMessageEnvelope, FlopStreet,
    GameBlindingDecryptionMessage, GamePartialUnblindingShareMessage, GamePlayerMessage,
    GameShowdownMessage, GameShuffleMessage, PreflopStreet, RiverStreet, TurnStreet,
};
use crate::ledger::snapshot::{clone_snapshot_for_failure, AnyTableSnapshot, SnapshotStatus};
use crate::ledger::transition::apply_transition;
use crate::ledger::types::{HandId, StateHash};
use crate::signing::{DomainSeparated, WithSignature};
type SharedHasher = Arc<dyn LedgerHasher + Send + Sync>;

struct HandLedger<C: CurveGroup> {
    tip_hash: StateHash,
    tip_snapshot: AnyTableSnapshot<C>,
    snapshots: HashMap<StateHash, AnyTableSnapshot<C>>,
    message_snapshots: HashMap<StateHash, (FinalizedAnyMessageEnvelope<C>, AnyTableSnapshot<C>)>,
    message_order: Vec<StateHash>,
}

impl<C: CurveGroup> HandLedger<C> {
    fn new(snapshot: AnyTableSnapshot<C>) -> Self {
        let hash = snapshot.state_hash();
        let mut snapshots = HashMap::new();
        snapshots.insert(hash, snapshot.clone());
        Self {
            tip_hash: hash,
            tip_snapshot: snapshot,
            snapshots,
            message_snapshots: HashMap::new(),
            message_order: Vec::new(),
        }
    }

    fn insert(&mut self, snapshot: AnyTableSnapshot<C>, make_tip: bool) {
        let hash = snapshot.state_hash();
        self.snapshots.insert(hash, snapshot.clone());
        if make_tip || hash == self.tip_hash {
            self.tip_hash = hash;
            self.tip_snapshot = snapshot;
        }
    }

    fn insert_message_snapshot(
        &mut self,
        message: FinalizedAnyMessageEnvelope<C>,
        snapshot: AnyTableSnapshot<C>,
    ) {
        let hash = snapshot.state_hash();
        self.message_snapshots.insert(hash, (message, snapshot));
        self.message_order.push(hash);
    }
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
        guard.get(&hand_id).map(|ledger| ledger.tip_hash)
    }

    pub fn tip_snapshot(&self, hand_id: HandId) -> Option<(StateHash, AnyTableSnapshot<C>)> {
        let guard = self.inner.read().expect("ledger state poisoned");
        guard
            .get(&hand_id)
            .map(|ledger| (ledger.tip_hash, ledger.tip_snapshot.clone()))
    }

    pub fn snapshot(&self, hand_id: HandId, hash: StateHash) -> Option<AnyTableSnapshot<C>> {
        let guard = self.inner.read().expect("ledger state poisoned");
        guard
            .get(&hand_id)
            .and_then(|ledger| ledger.snapshots.get(&hash).cloned())
    }

    pub fn upsert_snapshot(&self, hand_id: HandId, snapshot: AnyTableSnapshot<C>, make_tip: bool) {
        let mut guard = self.inner.write().expect("ledger state poisoned");
        match guard.entry(hand_id) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().insert(snapshot, make_tip);
            }
            Entry::Vacant(entry) => {
                entry.insert(HandLedger::new(snapshot));
            }
        }
    }

    pub fn insert_message_snapshot(
        &self,
        hand_id: HandId,
        message: FinalizedAnyMessageEnvelope<C>,
        snapshot: AnyTableSnapshot<C>,
    ) {
        let mut guard = self.inner.write().expect("ledger state poisoned");
        if let Some(ledger) = guard.get_mut(&hand_id) {
            ledger.insert_message_snapshot(message, snapshot);
        }
    }

    pub fn messages_up_to_sequence(
        &self,
        hand_id: HandId,
        max_sequence: u32,
    ) -> Vec<FinalizedAnyMessageEnvelope<C>> {
        let guard = self.inner.read().expect("ledger state poisoned");
        let Some(ledger) = guard.get(&hand_id) else {
            return Vec::new();
        };

        ledger
            .message_order
            .iter()
            .filter_map(|hash| {
                ledger.message_snapshots.get(hash).and_then(|(msg, snapshot)| {
                    if snapshot.sequence() <= max_sequence {
                        Some(msg.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    pub fn set_tip(&self, hand_id: HandId, tip: Option<StateHash>) {
        let mut guard = self.inner.write().expect("ledger state poisoned");
        match guard.entry(hand_id) {
            Entry::Occupied(mut entry) => match tip {
                Some(hash) => {
                    let snapshot = entry
                        .get()
                        .snapshots
                        .get(&hash)
                        .cloned()
                        .expect("tip snapshot must exist");
                    let ledger = entry.get_mut();
                    ledger.tip_hash = hash;
                    ledger.tip_snapshot = snapshot;
                }
                None => {
                    entry.remove();
                }
            },
            Entry::Vacant(_) => {
                if let Some(hash) = tip {
                    panic!(
                        "attempted to set tip for unknown hand {} to {:?}",
                        hand_id, hash
                    );
                }
            }
        }
    }

    pub fn remove_hand(&self, hand_id: HandId) {
        let mut guard = self.inner.write().expect("ledger state poisoned");
        guard.remove(&hand_id);
    }

    pub fn preview_event(
        &self,
        event: &AnyMessageEnvelope<C>,
    ) -> anyhow::Result<AnyTableSnapshot<C>>
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

        self.apply_message(current_snapshot, event, &hasher)
    }

    pub fn apply_event(&self, event: &AnyMessageEnvelope<C>) -> anyhow::Result<AnyTableSnapshot<C>>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        let hand_id = event.hand_id;
        let snapshot = self.preview_event(event)?;
        self.upsert_snapshot(hand_id, snapshot.clone(), true);

        Ok(snapshot)
    }

    pub fn replay<I>(&self, events: I) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = FinalizedAnyMessageEnvelope<C>>,
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        for finalized in events {
            match finalized.snapshot_status {
                SnapshotStatus::Success => {
                    self.apply_event(&finalized.envelope)?;
                }
                SnapshotStatus::Failure(reason) => {
                    let hand_id = finalized.envelope.hand_id;
                    let (_, current_snapshot) = self
                        .tip_snapshot(hand_id)
                        .with_context(|| format!("no snapshot tip for hand {}", hand_id))?;
                    let hasher = self.hasher();
                    let failure_snapshot =
                        clone_snapshot_for_failure(&current_snapshot, hasher.as_ref(), reason);
                    let failure_sequence = failure_snapshot.sequence();
                    let failure_phase = failure_snapshot.event_phase();
                    self.upsert_snapshot(hand_id, failure_snapshot, true);
                    debug_assert_eq!(
                        failure_sequence, finalized.snapshot_sequence_id,
                        "replayed failure snapshot sequence should match persisted sequence"
                    );
                    debug_assert_eq!(
                        failure_phase, finalized.applied_phase,
                        "replayed failure phase should match persisted phase"
                    );
                }
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
    M: CanonicalSerialize + DomainSeparated,
{
    WithSignature {
        value,
        signature: original.signature.clone(),
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
    use crate::ledger::actor::AnyActor;
    use crate::ledger::hash::LedgerHasher;
    use crate::ledger::messages::{
        AnyGameMessage, AnyMessageEnvelope, FinalizedAnyMessageEnvelope, GameShuffleMessage,
    };
    use crate::ledger::snapshot::{
        build_default_card_plan, AnyTableSnapshot, PlayerIdentity, PlayerRoster, PlayerStackInfo,
        PlayerStacks, RevealsSnapshot, SeatingMap, ShufflerIdentity, ShufflerRoster,
        ShufflingSnapshot, ShufflingStep, TableAtShuffling, TableSnapshot,
    };
    use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
    use crate::signing::WithSignature;
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

        let shuffler_public = C::zero();
        let shuffler_key = crate::ledger::CanonicalKey::new(shuffler_public.clone());

        let shuffling = ShufflingSnapshot {
            initial_deck: std::array::from_fn(|_| sample_cipher()),
            steps: vec![ShufflingStep {
                shuffler_public_key: C::zero(),
                proof: sample_shuffle_proof(),
            }],
            final_deck: std::array::from_fn(|_| sample_cipher()),
            expected_order: vec![shuffler_key.clone()],
        };

        let player_public = C::zero();
        let player_key = crate::ledger::CanonicalKey::new(player_public.clone());

        let mut stacks: PlayerStacks<C> = BTreeMap::new();
        stacks.insert(
            0,
            PlayerStackInfo {
                seat: 0,
                player_key: Some(player_key.clone()),
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

        let mut seating_map: SeatingMap<C> = BTreeMap::new();
        seating_map.insert(0, Some(player_key.clone()));
        let _plan = build_default_card_plan(&hand_cfg, &seating_map);

        let mut shufflers = ShufflerRoster::new();
        shufflers.insert(
            shuffler_key.clone(),
            ShufflerIdentity {
                public_key: shuffler_public.clone(),
                shuffler_key: shuffler_key.clone(),
                shuffler_id: 0,
                aggregated_public_key: shuffler_public,
            },
        );

        let mut players = PlayerRoster::new();
        players.insert(
            player_key.clone(),
            PlayerIdentity {
                public_key: player_public,
                player_key: player_key.clone(),
                player_id: 0,
                nonce: 0,
                seat: 0,
            },
        );

        let mut snapshot = TableSnapshot {
            game_id: 0,
            hand_id: Some(0),
            sequence: 0,
            cfg: Arc::new(hand_cfg),
            shufflers: Arc::new(shufflers),
            players: Arc::new(players),
            seating: Arc::new(seating_map),
            stacks: Arc::new(stacks),
            previous_hash: None,
            state_hash: StateHash::default(),
            status: SnapshotStatus::Success,
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

    #[test]
    fn replay_skips_failed_events() {
        let state = LedgerState::<Curve>::new();
        let hasher = state.hasher();
        let hand_id = 24;
        let initial_snapshot =
            AnyTableSnapshot::Shuffling(sample_table_snapshot::<Curve>(&*hasher));
        let initial_sequence = initial_snapshot.sequence();
        let initial_hash = initial_snapshot.state_hash();
        let applied_phase = initial_snapshot.event_phase();
        state.upsert_snapshot(hand_id, initial_snapshot, true);

        let shuffle_message = GameShuffleMessage::new(
            std::array::from_fn(|_| sample_cipher::<Curve>()),
            std::array::from_fn(|_| sample_cipher::<Curve>()),
            sample_shuffle_proof::<Curve>(),
            0,
        );

        let envelope = AnyMessageEnvelope {
            hand_id,
            game_id: 11,
            actor: AnyActor::None,
            nonce: 1,
            public_key: Curve::zero(),
            message: WithSignature {
                value: AnyGameMessage::Shuffle(shuffle_message),
                signature: Vec::new(),
            },
        };

        let failure_reason = "boom".to_string();
        let finalized = FinalizedAnyMessageEnvelope::new(
            envelope,
            SnapshotStatus::Failure(failure_reason.clone()),
            applied_phase,
            initial_sequence + 1,
        );

        state
            .replay(vec![finalized])
            .expect("replay should tolerate failed events");

        let (_, tip) = state
            .tip_snapshot(hand_id)
            .expect("tip remains available after replay");
        assert!(matches!(
            tip.status(),
            SnapshotStatus::Failure(reason) if reason == &failure_reason
        ));
        assert_eq!(tip.sequence(), initial_sequence + 1);
        assert_eq!(tip.previous_hash(), Some(initial_hash));
    }
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
    ) -> anyhow::Result<AnyTableSnapshot<C>>
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
    ) -> anyhow::Result<AnyTableSnapshot<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Shuffling(table) => table,
            _ => bail!("shuffle message can only be applied during shuffling phase"),
        };

        let actor = match &event.actor {
            AnyActor::Shuffler {
                shuffler_id,
                shuffler_key,
            } => ShufflerActor {
                shuffler_id: *shuffler_id,
                shuffler_key: shuffler_key.clone(),
            },
            _ => bail!("shuffle message must originate from a shuffler"),
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        apply_transition(table, &envelope, hasher)
    }

    fn apply_blinding(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GameBlindingDecryptionMessage<C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<AnyTableSnapshot<C>>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        let table = match snapshot {
            AnyTableSnapshot::Dealing(table) => table,
            _ => bail!("blinding decryption message can only be applied during dealing phase"),
        };

        let actor = match &event.actor {
            AnyActor::Shuffler {
                shuffler_id,
                shuffler_key,
            } => ShufflerActor {
                shuffler_id: *shuffler_id,
                shuffler_key: shuffler_key.clone(),
            },
            _ => bail!("blinding decryption message must originate from a shuffler"),
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        apply_transition(table, &envelope, hasher)
    }

    fn apply_partial_unblinding(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePartialUnblindingShareMessage<C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<AnyTableSnapshot<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Dealing(table) => table,
            _ => bail!("partial unblinding message can only be applied during dealing phase"),
        };

        let actor = match &event.actor {
            AnyActor::Shuffler {
                shuffler_id,
                shuffler_key,
            } => ShufflerActor {
                shuffler_id: *shuffler_id,
                shuffler_key: shuffler_key.clone(),
            },
            _ => bail!("partial unblinding message must originate from a shuffler"),
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        apply_transition(table, &envelope, hasher)
    }

    fn apply_player_preflop(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePlayerMessage<PreflopStreet, C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<AnyTableSnapshot<C>>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        let table = match snapshot {
            AnyTableSnapshot::Preflop(table) => table,
            _ => bail!("preflop action can only be applied during preflop phase"),
        };
        let actor = match &event.actor {
            AnyActor::Player {
                seat_id,
                player_id,
                player_key,
            } => PlayerActor {
                seat_id: *seat_id,
                player_id: *player_id,
                player_key: player_key.clone(),
            },
            _ => bail!("preflop action must originate from a player"),
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        apply_transition(table, &envelope, hasher)
    }

    fn apply_player_flop(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePlayerMessage<FlopStreet, C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<AnyTableSnapshot<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Flop(table) => table,
            _ => bail!("flop action can only be applied during flop phase"),
        };
        let actor = match &event.actor {
            AnyActor::Player {
                seat_id,
                player_id,
                player_key,
            } => PlayerActor {
                seat_id: *seat_id,
                player_id: *player_id,
                player_key: player_key.clone(),
            },
            _ => bail!("flop action must originate from a player"),
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        apply_transition(table, &envelope, hasher)
    }

    fn apply_player_turn(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePlayerMessage<TurnStreet, C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<AnyTableSnapshot<C>> {
        let table = match snapshot {
            AnyTableSnapshot::Turn(table) => table,
            _ => bail!("turn action can only be applied during turn phase"),
        };
        let actor = match &event.actor {
            AnyActor::Player {
                seat_id,
                player_id,
                player_key,
            } => PlayerActor {
                seat_id: *seat_id,
                player_id: *player_id,
                player_key: player_key.clone(),
            },
            _ => bail!("turn action must originate from a player"),
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        apply_transition(table, &envelope, hasher)
    }

    fn apply_player_river(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GamePlayerMessage<RiverStreet, C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<AnyTableSnapshot<C>> {
        let table = match snapshot {
            AnyTableSnapshot::River(table) => table,
            _ => bail!("river action can only be applied during river phase"),
        };
        let actor = match &event.actor {
            AnyActor::Player {
                seat_id,
                player_id,
                player_key,
            } => PlayerActor {
                seat_id: *seat_id,
                player_id: *player_id,
                player_key: player_key.clone(),
            },
            _ => bail!("river action must originate from a player"),
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        apply_transition(table, &envelope, hasher)
    }

    fn apply_showdown(
        &self,
        snapshot: AnyTableSnapshot<C>,
        event: &AnyMessageEnvelope<C>,
        message: GameShowdownMessage<C>,
        hasher: &SharedHasher,
    ) -> anyhow::Result<AnyTableSnapshot<C>>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
    {
        let table = match snapshot {
            AnyTableSnapshot::Showdown(table) => table,
            _ => bail!("showdown message can only be applied during showdown phase"),
        };

        let actor = match &event.actor {
            AnyActor::Player {
                seat_id,
                player_id,
                player_key,
            } => PlayerActor {
                seat_id: *seat_id,
                player_id: *player_id,
                player_key: player_key.clone(),
            },
            _ => bail!("showdown message must originate from a player"),
        };

        let envelope = EnvelopedMessage {
            hand_id: event.hand_id,
            game_id: event.game_id,
            actor,
            nonce: event.nonce,
            public_key: event.public_key.clone(),
            message: remap_signature(&event.message, message),
        };

        apply_transition(table, &envelope, hasher)
    }
}
