use std::collections::HashMap;
use std::sync::RwLock;

use ark_ec::CurveGroup;

use crate::ledger::snapshot::AnyTableSnapshot;
use crate::ledger::types::HandId;

// ---- Ledger state --------------------------------------------------------------------------

pub struct LedgerState<C>
where
    C: CurveGroup,
{
    inner: RwLock<HashMap<HandId, AnyTableSnapshot<C>>>,
}

impl<C> LedgerState<C>
where
    C: CurveGroup,
{
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn snapshot(&self, hand_id: HandId) -> Option<AnyTableSnapshot<C>> {
        let guard = self.inner.read().expect("ledger state poisoned");
        guard.get(&hand_id).cloned()
    }

    pub fn apply_event(
        &self,
        event: &super::messages::AnyMessageEnvelope<C>,
    ) -> anyhow::Result<()> {
        let _ = event;
        todo!("ledger state apply_event not implemented")
    }

    pub fn replay<I>(&self, events: I) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = super::messages::AnyMessageEnvelope<C>>,
    {
        for event in events {
            self.apply_event(&event)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use crate::ledger::snapshot::{
        build_default_card_plan, AnyTableSnapshot, PlayerStackInfo, PlayerStacks, RevealsSnapshot,
        ShufflingSnapshot, ShufflingStep, TableAtShuffling, TableSnapshot,
    };
    use crate::ledger::StateHash;
    use crate::shuffler::Shuffler;
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

    fn sample_table_snapshot<C: CurveGroup>() -> TableAtShuffling<C> {
        use crate::engine::nl::types::{HandConfig, PlayerStatus, TableStakes};

        let shuffling = ShufflingSnapshot {
            initial_deck: std::array::from_fn(|_| sample_cipher()),
            steps: vec![ShufflingStep {
                shuffler_public_key: C::zero(),
                proof: sample_shuffle_proof(),
            }],
            final_deck: std::array::from_fn(|_| sample_cipher()),
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

        let mut snapshot = TableSnapshot {
            game_id: 0,
            hand_id: Some(0),
            cfg: Some(Arc::new(hand_cfg)),
            shufflers: Arc::new(vec![Shuffler {
                index: 0,
                secret_key: C::ScalarField::zero(),
                public_key: C::zero(),
                aggregated_public_key: C::zero(),
            }]),
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

        snapshot.initialize_hash();
        snapshot
    }

    #[test]
    fn replay_with_no_events_keeps_state_empty() {
        let state = LedgerState::<Curve>::new();
        assert!(state.replay(Vec::new()).is_ok());
        assert!(state.snapshot(0).is_none());
    }

    #[test]
    fn snapshots_are_copied_on_read() {
        let state = LedgerState::<Curve>::new();
        let mut guard = state.inner.write().unwrap();
        guard.insert(0, AnyTableSnapshot::Shuffling(sample_table_snapshot()));
        drop(guard);

        let snapshot = state.snapshot(0).unwrap();
        match snapshot {
            AnyTableSnapshot::Shuffling(table) => {
                assert_eq!(table.game_id, 0);
                assert!(table.previous_hash.is_none());
                assert_ne!(table.state_hash, StateHash::default());
            }
            _ => panic!("unexpected snapshot variant"),
        }
    }

    #[test]
    fn any_table_snapshot_variants_exist() {
        let shuffling = AnyTableSnapshot::Shuffling(sample_table_snapshot::<Curve>());
        matches!(shuffling, AnyTableSnapshot::Shuffling(_));
    }
}
