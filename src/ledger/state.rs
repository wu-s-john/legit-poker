use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

use ark_ec::CurveGroup;

use super::messages::{FlopStreet, TurnStreet};
use super::messages::{GamePlayerMessage, PreflopStreet, RiverStreet};
use super::types::{GameId, HandId, ShufflerId};
use crate::engine::nl::state::BettingState;
use crate::engine::nl::types::{HandConfig, PlayerId, SeatId};
use crate::shuffler::Shuffler;
use crate::shuffling::community_decryption::CommunityDecryptionShare;
use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
use crate::shuffling::player_decryption::{
    PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
};

// Shared alias used throughout snapshots
pub type Shared<T> = Arc<T>;

// ---- Player identity / seating --------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PlayerIdentity<C: CurveGroup> {
    pub public_key: C,
    pub nonce: u64,
    pub seat: SeatId,
}

pub type PlayerRoster<C> = BTreeMap<PlayerId, PlayerIdentity<C>>;
pub type SeatingMap = BTreeMap<SeatId, Option<PlayerId>>;

// ---- Shuffling -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ShufflingStep<C: CurveGroup> {
    pub shuffler_public_key: C,
    pub proof: ShuffleProof<C>,
}

#[derive(Clone, Debug)]
pub struct ShufflingSnapshot<C: CurveGroup> {
    pub initial_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub steps: Vec<ShufflingStep<C>>,
    pub final_deck: [ElGamalCiphertext<C>; DECK_SIZE],
}

// ---- Dealing -------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DealtCard<C: CurveGroup> {
    pub cipher: ElGamalCiphertext<C>,
    pub source_index: Option<u8>,
}

pub type CardRef = u16;
pub type HoleIndex = u8;

#[derive(Clone, Debug)]
pub struct DealingSnapshot<C: CurveGroup> {
    pub assignments: BTreeMap<CardRef, DealtCard<C>>,
    pub player_ciphertexts: BTreeMap<(SeatId, HoleIndex), PlayerAccessibleCiphertext<C>>,
    pub player_blinding_contribs:
        BTreeMap<(ShufflerId, SeatId, HoleIndex), PlayerTargetedBlindingContribution<C>>,
    pub community_decryption_shares: BTreeMap<(ShufflerId, CardRef), CommunityDecryptionShare<C>>,
}

// ---- Betting --------------------------------------------------------------------------------

type BettingStateNL = BettingState;

#[derive(Clone, Debug)]
pub enum PlayerActionMsgVariant<C: CurveGroup> {
    Preflop(GamePlayerMessage<PreflopStreet, C>),
    Flop(GamePlayerMessage<FlopStreet, C>),
    Turn(GamePlayerMessage<TurnStreet, C>),
    River(GamePlayerMessage<RiverStreet, C>),
}

#[derive(Clone, Debug)]
pub struct BettingSnapshot<C: CurveGroup> {
    pub state: BettingStateNL,
    pub last_events: Vec<PlayerActionMsgVariant<C>>,
}

// ---- Reveals -------------------------------------------------------------------------------

pub type CardIndex = u8;

#[derive(Clone, Debug)]
pub struct RevealedHand<C: CurveGroup> {
    pub hole: [CardIndex; 2],
    pub hole_ciphertexts: [PlayerAccessibleCiphertext<C>; 2],
}

#[derive(Clone, Debug)]
pub struct RevealsSnapshot<C: CurveGroup> {
    pub board: Vec<CardIndex>,
    pub revealed_holes: BTreeMap<SeatId, RevealedHand<C>>,
}

// ---- Hand phases ---------------------------------------------------------------------------

pub trait HandPhase<C: CurveGroup> {
    type ShufflingS;
    type DealingS;
    type BettingS;
    type RevealsS;
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseShuffling;

impl<C: CurveGroup> HandPhase<C> for PhaseShuffling {
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = ();
    type BettingS = ();
    type RevealsS = ();
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseDealing;

impl<C: CurveGroup> HandPhase<C> for PhaseDealing {
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = DealingSnapshot<C>;
    type BettingS = ();
    type RevealsS = ();
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseBetting<R>(pub PhantomData<R>);

impl<R, C> HandPhase<C> for PhaseBetting<R>
where
    C: CurveGroup,
{
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = DealingSnapshot<C>;
    type BettingS = BettingSnapshot<C>;
    type RevealsS = RevealsSnapshot<C>;
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseShowdown;

impl<C: CurveGroup> HandPhase<C> for PhaseShowdown {
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = DealingSnapshot<C>;
    type BettingS = BettingSnapshot<C>;
    type RevealsS = RevealsSnapshot<C>;
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseComplete;

impl<C: CurveGroup> HandPhase<C> for PhaseComplete {
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = DealingSnapshot<C>;
    type BettingS = BettingSnapshot<C>;
    type RevealsS = RevealsSnapshot<C>;
}

// ---- Table snapshot ------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TableSnapshot<P, C>
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    pub game_id: GameId,
    pub hand_id: Option<HandId>,
    pub cfg: Option<Shared<HandConfig>>,
    pub shufflers: Shared<Vec<Shuffler<C>>>,
    pub players: Shared<PlayerRoster<C>>,
    pub seating: Shared<SeatingMap>,
    pub shuffling: P::ShufflingS,
    pub dealing: P::DealingS,
    pub betting: P::BettingS,
    pub reveals: P::RevealsS,
}

pub type TableAtShuffling<C> = TableSnapshot<PhaseShuffling, C>;
pub type TableAtDealing<C> = TableSnapshot<PhaseDealing, C>;
pub type TableAtPreflop<C> = TableSnapshot<PhaseBetting<PreflopStreet>, C>;
pub type TableAtFlop<C> = TableSnapshot<PhaseBetting<FlopStreet>, C>;
pub type TableAtTurn<C> = TableSnapshot<PhaseBetting<TurnStreet>, C>;
pub type TableAtRiver<C> = TableSnapshot<PhaseBetting<RiverStreet>, C>;
pub type TableAtShowdown<C> = TableSnapshot<PhaseShowdown, C>;
pub type TableAtComplete<C> = TableSnapshot<PhaseComplete, C>;

#[derive(Clone, Debug)]
pub enum AnyTableSnapshot<C: CurveGroup> {
    Shuffling(TableAtShuffling<C>),
    Dealing(TableAtDealing<C>),
    Preflop(TableAtPreflop<C>),
    Flop(TableAtFlop<C>),
    Turn(TableAtTurn<C>),
    River(TableAtRiver<C>),
    Showdown(TableAtShowdown<C>),
    Complete(TableAtComplete<C>),
}

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

    pub fn apply_event(&self, event: &super::messages::VerifiedEnvelope<C>) -> anyhow::Result<()> {
        let _ = event;
        todo!("ledger state apply_event not implemented")
    }

    pub fn replay<I>(&self, events: I) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = super::messages::VerifiedEnvelope<C>>,
    {
        for event in events {
            self.apply_event(&event)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        use crate::engine::nl::state::{BettingState, Pot, Pots};
        use crate::engine::nl::types::{
            ActionLog, HandConfig, PlayerState, PlayerStatus, Street as EngineStreet, TableStakes,
        };

        let shuffling = ShufflingSnapshot {
            initial_deck: std::array::from_fn(|_| sample_cipher()),
            steps: vec![ShufflingStep {
                shuffler_public_key: C::zero(),
                proof: sample_shuffle_proof(),
            }],
            final_deck: std::array::from_fn(|_| sample_cipher()),
        };

        let dealing = DealingSnapshot {
            assignments: BTreeMap::new(),
            player_ciphertexts: BTreeMap::new(),
            player_blinding_contribs: BTreeMap::new(),
            community_decryption_shares: BTreeMap::new(),
        };

        let betting = BettingSnapshot {
            state: BettingState {
                street: EngineStreet::Preflop,
                button: 0,
                first_to_act: 0,
                to_act: 0,
                current_bet_to_match: 0,
                last_full_raise_amount: 0,
                last_aggressor: None,
                voluntary_bet_opened: false,
                players: vec![PlayerState {
                    seat: 0,
                    player_id: Some(0),
                    stack: 0,
                    committed_this_round: 0,
                    committed_total: 0,
                    status: PlayerStatus::Active,
                    has_acted_this_round: false,
                }],
                pots: Pots {
                    main: Pot {
                        amount: 0,
                        eligible: vec![],
                    },
                    sides: vec![],
                },
                cfg: HandConfig {
                    stakes: TableStakes {
                        small_blind: 0,
                        big_blind: 0,
                        ante: 0,
                    },
                    button: 0,
                    small_blind_seat: 0,
                    big_blind_seat: 0,
                    check_raise_allowed: true,
                },
                pending_to_match: vec![],
                betting_locked_all_in: false,
                action_log: ActionLog::default(),
            },
            last_events: Vec::new(),
        };

        let reveals = RevealsSnapshot {
            board: Vec::new(),
            revealed_holes: BTreeMap::new(),
        };

        TableSnapshot {
            game_id: 0,
            hand_id: Some(0),
            cfg: Some(Arc::new(HandConfig {
                stakes: TableStakes {
                    small_blind: 0,
                    big_blind: 0,
                    ante: 0,
                },
                button: 0,
                small_blind_seat: 0,
                big_blind_seat: 0,
                check_raise_allowed: true,
            })),
            shufflers: Arc::new(vec![Shuffler {
                index: 0,
                secret_key: C::ScalarField::zero(),
                public_key: C::zero(),
                aggregated_public_key: C::zero(),
            }]),
            players: Arc::new(BTreeMap::new()),
            seating: Arc::new(BTreeMap::new()),
            shuffling,
            dealing,
            betting,
            reveals,
        }
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
