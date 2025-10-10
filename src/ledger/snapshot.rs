use std::collections::BTreeMap;
use std::sync::Arc;

use ark_ec::CurveGroup;

use crate::engine::nl::engine::{BettingEngineNL, EngineNL};
use crate::engine::nl::state::BettingState;
use crate::engine::nl::types::{
    HandConfig, PlayerId, PlayerState, PlayerStatus, Pot, Pots, SeatId,
};
use crate::ledger::hash::{chain_hash, initial_snapshot_hash, message_hash, LedgerHasher};
use crate::ledger::messages::{
    EnvelopedMessage, FlopStreet, GameMessage, GamePlayerMessage, PreflopStreet, RiverStreet,
    TurnStreet,
};
use crate::ledger::types::{GameId, HandId, ShufflerId, StateHash};
use crate::showdown::HandCategory;
use crate::shuffling::community_decryption::CommunityDecryptionShare;
use crate::shuffling::data_structures::{
    append_curve_point, ElGamalCiphertext, ShuffleProof, DECK_SIZE,
};
use crate::shuffling::player_decryption::{
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
};
use crate::signing::Signable;
use crate::signing::TranscriptBuilder;

pub mod phases;

pub use phases::{
    HandPhase, PhaseBetting, PhaseComplete, PhaseDealing, PhaseShowdown, PhaseShuffling,
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

impl<C: CurveGroup> PlayerIdentity<C> {
    pub fn append_to_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(self.seat);
        builder.append_u64(self.nonce);
        append_curve_point(builder, &self.public_key);
    }
}

#[derive(Clone, Debug)]
pub struct ShufflerIdentity<C: CurveGroup> {
    pub public_key: C,
    pub aggregated_public_key: C,
}

pub type PlayerRoster<C> = BTreeMap<PlayerId, PlayerIdentity<C>>;
pub type ShufflerRoster<C> = BTreeMap<ShufflerId, ShufflerIdentity<C>>;
pub type SeatingMap = BTreeMap<SeatId, Option<PlayerId>>;
pub type PlayerStacks = BTreeMap<SeatId, PlayerStackInfo>;

impl<C: CurveGroup> Signable for PlayerIdentity<C> {
    fn domain_kind(&self) -> &'static str {
        "ledger/player_identity_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        self.append_to_transcript(builder);
    }
}

impl<C: CurveGroup> Signable for ShufflerIdentity<C> {
    fn domain_kind(&self) -> &'static str {
        "ledger/shuffler_identity_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        append_curve_point(builder, &self.public_key);
        append_curve_point(builder, &self.aggregated_public_key);
    }
}

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

#[derive(Clone, Debug)]
pub struct PlayerStackInfo {
    pub seat: SeatId,
    pub player_id: Option<PlayerId>,
    pub starting_stack: u64,
    pub committed_blind: u64,
    pub status: PlayerStatus,
}

impl PlayerStackInfo {
    pub fn append_to_transcript(&self, builder: &mut TranscriptBuilder) {
        match self.player_id {
            Some(player_id) => {
                builder.append_u8(1);
                builder.append_u64(player_id);
            }
            None => builder.append_u8(0),
        }
        builder.append_u64(self.starting_stack);
        builder.append_u64(self.committed_blind);
        builder.append_u8(self.status.as_byte());
    }
}

impl Signable for PlayerStackInfo {
    fn domain_kind(&self) -> &'static str {
        "ledger/player_stack_info_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        self.append_to_transcript(builder);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardDestination {
    Hole { seat: SeatId, hole_index: u8 },
    Board { board_index: u8 },
    Burn,
    Unused,
}

pub type CardPlan = BTreeMap<u8, CardDestination>;

pub fn build_default_card_plan(cfg: &HandConfig, seating: &SeatingMap) -> CardPlan {
    let mut plan = CardPlan::new();

    let mut active_seats: Vec<SeatId> = seating
        .iter()
        .filter_map(|(&seat, player)| player.map(|_| seat))
        .collect();
    active_seats.sort();

    if !active_seats.is_empty() {
        if let Some(button_pos) = active_seats.iter().position(|&seat| seat == cfg.button) {
            let mut rotated = Vec::with_capacity(active_seats.len());
            for idx in 1..=active_seats.len() {
                let seat = active_seats[(button_pos + idx) % active_seats.len()];
                rotated.push(seat);
            }
            active_seats = rotated;
        }
    }

    let mut next_card: u8 = 1;
    for hole_index in 0..2 {
        for &seat in &active_seats {
            plan.insert(next_card, CardDestination::Hole { seat, hole_index });
            next_card += 1;
        }
    }

    let push_burn = |plan: &mut CardPlan, next: &mut u8| {
        plan.insert(*next, CardDestination::Burn);
        *next += 1;
    };
    let push_board = |plan: &mut CardPlan, next: &mut u8, board_index: u8| {
        plan.insert(*next, CardDestination::Board { board_index });
        *next += 1;
    };

    push_burn(&mut plan, &mut next_card);
    for board_index in 0..3 {
        push_board(&mut plan, &mut next_card, board_index);
    }
    push_burn(&mut plan, &mut next_card);
    push_board(&mut plan, &mut next_card, 3);
    push_burn(&mut plan, &mut next_card);
    push_board(&mut plan, &mut next_card, 4);

    while (next_card as usize) <= DECK_SIZE {
        plan.insert(next_card, CardDestination::Unused);
        next_card += 1;
    }

    plan
}

pub fn build_initial_betting_state(cfg: &HandConfig, stacks: &PlayerStacks) -> BettingStateNL {
    let mut player_states: Vec<PlayerState> = stacks
        .values()
        .map(|info| {
            let committed = info.committed_blind;
            PlayerState {
                seat: info.seat,
                player_id: info.player_id,
                stack: info.starting_stack.saturating_sub(committed),
                committed_this_round: committed,
                committed_total: 0,
                status: info.status,
                has_acted_this_round: false,
            }
        })
        .collect();

    player_states.sort_by_key(|p| p.seat);

    let main_amount: u64 = player_states.iter().map(|p| p.committed_this_round).sum();

    let eligible: Vec<SeatId> = player_states
        .iter()
        .filter(|p| p.status != PlayerStatus::Folded && p.status != PlayerStatus::SittingOut)
        .map(|p| p.seat)
        .collect();

    let pots = Pots {
        main: Pot {
            amount: main_amount,
            eligible,
        },
        sides: Vec::new(),
    };

    EngineNL::new_after_deal(cfg.clone(), player_states, pots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::nl::types::Street;

    #[test]
    #[ignore]
    fn build_initial_betting_state_uses_stack_info() {
        let cfg = HandConfig {
            stakes: crate::engine::nl::types::TableStakes {
                small_blind: 1,
                big_blind: 2,
                ante: 0,
            },
            button: 0,
            small_blind_seat: 1,
            big_blind_seat: 2,
            check_raise_allowed: true,
        };

        let mut stacks = PlayerStacks::new();
        stacks.insert(
            1,
            PlayerStackInfo {
                seat: 1,
                player_id: Some(10),
                starting_stack: 100,
                committed_blind: 1,
                status: PlayerStatus::Active,
            },
        );
        stacks.insert(
            2,
            PlayerStackInfo {
                seat: 2,
                player_id: Some(11),
                starting_stack: 120,
                committed_blind: 2,
                status: PlayerStatus::Active,
            },
        );

        let state = build_initial_betting_state(&cfg, &stacks);

        assert_eq!(state.street, Street::Preflop);
        assert_eq!(state.players.len(), 2);
        let bb = state.players.iter().find(|p| p.seat == 2).unwrap();
        assert_eq!(bb.stack, 118);
        assert_eq!(bb.committed_this_round, 2);
        assert_eq!(state.pots.main.amount, 3);
    }
}

#[derive(Clone, Debug)]
pub struct DealingSnapshot<C: CurveGroup> {
    pub assignments: BTreeMap<u8, DealtCard<C>>,
    pub player_ciphertexts: BTreeMap<(SeatId, u8), PlayerAccessibleCiphertext<C>>,
    pub player_blinding_contribs:
        BTreeMap<(ShufflerId, SeatId, u8), PlayerTargetedBlindingContribution<C>>,
    pub player_unblinding_shares:
        BTreeMap<(SeatId, u8), BTreeMap<usize, PartialUnblindingShare<C>>>,
    pub player_unblinding_combined: BTreeMap<(SeatId, u8), C>,
    pub community_decryption_shares: BTreeMap<(ShufflerId, u8), CommunityDecryptionShare<C>>,
    pub community_cards: BTreeMap<u8, CardIndex>,
    pub card_plan: CardPlan,
}

// ---- Betting --------------------------------------------------------------------------------

type BettingStateNL = BettingState;

#[derive(Clone, Debug)]
pub enum AnyPlayerActionMsg<C: CurveGroup> {
    Preflop(GamePlayerMessage<PreflopStreet, C>),
    Flop(GamePlayerMessage<FlopStreet, C>),
    Turn(GamePlayerMessage<TurnStreet, C>),
    River(GamePlayerMessage<RiverStreet, C>),
}

#[derive(Clone, Debug)]
pub struct BettingSnapshot<C: CurveGroup> {
    pub state: BettingStateNL,
    pub last_events: Vec<AnyPlayerActionMsg<C>>,
}

// ---- Reveals -------------------------------------------------------------------------------

pub type CardIndex = u8;

#[derive(Clone, Debug)]
pub struct RevealedHand<C: CurveGroup> {
    pub hole: [CardIndex; 2],
    pub hole_ciphertexts: [PlayerAccessibleCiphertext<C>; 2],
    pub best_five: [CardIndex; 5],
    pub best_category: HandCategory,
    pub best_tiebreak: [u8; 5],
    pub best_score: u32,
}

#[derive(Clone, Debug)]
pub struct RevealsSnapshot<C: CurveGroup> {
    pub board: Vec<CardIndex>,
    pub revealed_holes: BTreeMap<SeatId, RevealedHand<C>>,
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
    pub shufflers: Shared<ShufflerRoster<C>>,
    pub players: Shared<PlayerRoster<C>>,
    pub seating: Shared<SeatingMap>,
    pub stacks: Shared<PlayerStacks>,
    pub previous_hash: Option<StateHash>,
    pub state_hash: StateHash,
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

impl<P, C> TableSnapshot<P, C>
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    pub fn initialize_hash(&mut self, hasher: &dyn LedgerHasher) {
        self.previous_hash = None;
        self.state_hash = initial_snapshot_hash(self, hasher);
    }

    pub fn advance_state_with_message<M>(
        &mut self,
        envelope: &EnvelopedMessage<C, M>,
        hasher: &dyn LedgerHasher,
    ) where
        M: GameMessage<C> + Signable,
        M::Actor: Signable,
    {
        let message = message_hash(envelope, hasher);
        let chained = chain_hash(self.state_hash, message, hasher);
        self.previous_hash = Some(self.state_hash);
        self.state_hash = chained;
    }
}

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

impl<C: CurveGroup> AnyTableSnapshot<C> {
    pub fn state_hash(&self) -> StateHash {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.state_hash,
            AnyTableSnapshot::Dealing(table) => table.state_hash,
            AnyTableSnapshot::Preflop(table) => table.state_hash,
            AnyTableSnapshot::Flop(table) => table.state_hash,
            AnyTableSnapshot::Turn(table) => table.state_hash,
            AnyTableSnapshot::River(table) => table.state_hash,
            AnyTableSnapshot::Showdown(table) => table.state_hash,
            AnyTableSnapshot::Complete(table) => table.state_hash,
        }
    }

    pub fn previous_hash(&self) -> Option<StateHash> {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.previous_hash,
            AnyTableSnapshot::Dealing(table) => table.previous_hash,
            AnyTableSnapshot::Preflop(table) => table.previous_hash,
            AnyTableSnapshot::Flop(table) => table.previous_hash,
            AnyTableSnapshot::Turn(table) => table.previous_hash,
            AnyTableSnapshot::River(table) => table.previous_hash,
            AnyTableSnapshot::Showdown(table) => table.previous_hash,
            AnyTableSnapshot::Complete(table) => table.previous_hash,
        }
    }
}
