use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::de::Error as DeError;
use serde::ser::Error as SerError;
use serde::{
    de::DeserializeOwned, ser::SerializeMap, Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::Value as JsonValue;

use crate::db::entity::sea_orm_active_enums::{ApplicationStatus, PhaseKind};
use crate::db::entity::{
    hand_configs, hand_player, hand_shufflers, phases as phase_table, players, shufflers,
    table_snapshots,
};
use crate::engine::nl::actions::PlayerBetAction;
use crate::engine::nl::engine::{BettingEngineNL, EngineNL};
use crate::engine::nl::events::NormalizedAction;
use crate::engine::nl::state::BettingState;
use crate::engine::nl::types::{
    ActionLog, ActionLogEntry, HandConfig, PlayerId, PlayerState, PlayerStatus, Pot, Pots, SeatId,
    Street,
};
use crate::ledger::hash::{chain_hash, initial_snapshot_hash, message_hash, LedgerHasher};
use crate::ledger::messages::{
    EnvelopedMessage, FlopStreet, GameMessage, GamePlayerMessage, PreflopStreet, RiverStreet,
    TurnStreet,
};
use crate::ledger::serialization::{
    canonical_deserialize_hex, deserialize_curve_bytes, deserialize_curve_hex, serialize_curve_hex,
};
use crate::ledger::types::{EventPhase, GameId, HandId, ShufflerId, StateHash};
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
use ark_ff::PrimeField;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};

pub mod phases;

pub use phases::{
    HandPhase, PhaseBetting, PhaseComplete, PhaseDealing, PhaseShowdown, PhaseShuffling,
};

// Shared alias used throughout snapshots
pub type Shared<T> = Arc<T>;
pub type SnapshotSeq = u32;

// ---- Player identity / seating --------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct PlayerIdentity<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::curve")]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct ShufflerIdentity<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::curve")]
    pub public_key: C,
    #[serde(with = "crate::crypto_serde::curve")]
    pub aggregated_public_key: C,
}

pub type PlayerRoster<C> = BTreeMap<PlayerId, PlayerIdentity<C>>;
pub type ShufflerRoster<C> = BTreeMap<ShufflerId, ShufflerIdentity<C>>;
pub type SeatingMap = BTreeMap<SeatId, Option<PlayerId>>;
pub type PlayerStacks = BTreeMap<SeatId, PlayerStackInfo>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Success,
    Failure(String),
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct ShufflingStep<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::curve")]
    pub shuffler_public_key: C,
    pub proof: ShuffleProof<C>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct ShufflingSnapshot<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::elgamal_array")]
    pub initial_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub steps: Vec<ShufflingStep<C>>,
    #[serde(with = "crate::crypto_serde::elgamal_array")]
    pub final_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub expected_order: Vec<ShufflerId>,
}

// ---- Dealing -------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct DealtCard<C: CurveGroup> {
    pub cipher: ElGamalCiphertext<C>,
    pub source_index: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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

    let mut next_card: u8 = 0;
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

    while (next_card as usize) < DECK_SIZE {
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

    #[ignore]
    #[test]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct DealingSnapshot<C: CurveGroup> {
    pub assignments: BTreeMap<u8, DealtCard<C>>,
    pub player_ciphertexts: BTreeMap<(SeatId, u8), PlayerAccessibleCiphertext<C>>,
    pub player_blinding_contribs:
        BTreeMap<(ShufflerId, SeatId, u8), PlayerTargetedBlindingContribution<C>>,
    pub player_unblinding_shares:
        BTreeMap<(SeatId, u8), BTreeMap<usize, PartialUnblindingShare<C>>>,
    #[serde(
        serialize_with = "serialize_player_unblinding_combined",
        deserialize_with = "deserialize_player_unblinding_combined"
    )]
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

#[derive(Serialize, Deserialize)]
struct PlayerActionSerde {
    street: String,
    action: PlayerBetAction,
}

impl<C> Serialize for AnyPlayerActionMsg<C>
where
    C: CurveGroup,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let helper = match self {
            AnyPlayerActionMsg::Preflop(msg) => PlayerActionSerde {
                street: "preflop".to_string(),
                action: msg.action.clone(),
            },
            AnyPlayerActionMsg::Flop(msg) => PlayerActionSerde {
                street: "flop".to_string(),
                action: msg.action.clone(),
            },
            AnyPlayerActionMsg::Turn(msg) => PlayerActionSerde {
                street: "turn".to_string(),
                action: msg.action.clone(),
            },
            AnyPlayerActionMsg::River(msg) => PlayerActionSerde {
                street: "river".to_string(),
                action: msg.action.clone(),
            },
        };
        helper.serialize(serializer)
    }
}

impl<'de, C> Deserialize<'de> for AnyPlayerActionMsg<C>
where
    C: CurveGroup,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = PlayerActionSerde::deserialize(deserializer)?;
        let action = helper.action;
        match helper.street.as_str() {
            "preflop" => Ok(AnyPlayerActionMsg::Preflop(GamePlayerMessage::new(action))),
            "flop" => Ok(AnyPlayerActionMsg::Flop(GamePlayerMessage::new(action))),
            "turn" => Ok(AnyPlayerActionMsg::Turn(GamePlayerMessage::new(action))),
            "river" => Ok(AnyPlayerActionMsg::River(GamePlayerMessage::new(action))),
            other => Err(serde::de::Error::custom(format!(
                "unknown betting action street {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct BettingSnapshot<C: CurveGroup> {
    pub state: BettingStateNL,
    pub last_events: Vec<AnyPlayerActionMsg<C>>,
}

// ---- Reveals -------------------------------------------------------------------------------

pub type CardIndex = u8;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct RevealedHand<C: CurveGroup> {
    pub hole: [CardIndex; 2],
    pub hole_ciphertexts: [PlayerAccessibleCiphertext<C>; 2],
    pub best_five: [CardIndex; 5],
    pub best_category: HandCategory,
    pub best_tiebreak: [u8; 5],
    pub best_score: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct RevealsSnapshot<C: CurveGroup> {
    pub board: Vec<CardIndex>,
    pub revealed_holes: BTreeMap<SeatId, RevealedHand<C>>,
}

// ---- Table snapshot ------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P::ShufflingS: Serialize, P::DealingS: Serialize, P::BettingS: Serialize, P::RevealsS: Serialize, C: CanonicalSerialize",
    deserialize = "P::ShufflingS: DeserializeOwned, P::DealingS: DeserializeOwned, P::BettingS: DeserializeOwned, P::RevealsS: DeserializeOwned, C: CanonicalDeserialize"
))]
pub struct TableSnapshot<P, C>
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    pub game_id: GameId,
    pub hand_id: Option<HandId>,
    pub sequence: SnapshotSeq,
    #[serde(with = "crate::crypto_serde::arc")]
    pub cfg: Shared<HandConfig>,
    #[serde(with = "crate::crypto_serde::arc")]
    pub shufflers: Shared<ShufflerRoster<C>>,
    #[serde(with = "crate::crypto_serde::arc")]
    pub players: Shared<PlayerRoster<C>>,
    #[serde(with = "crate::crypto_serde::arc")]
    pub seating: Shared<SeatingMap>,
    #[serde(with = "crate::crypto_serde::arc")]
    pub stacks: Shared<PlayerStacks>,
    pub previous_hash: Option<StateHash>,
    pub state_hash: StateHash,
    pub status: SnapshotStatus,
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
        self.sequence = 0;
        self.previous_hash = None;
        self.state_hash = initial_snapshot_hash(self, hasher);
        self.status = SnapshotStatus::Success;
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
        self.sequence = self.sequence.saturating_add(1);
        self.status = SnapshotStatus::Success;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "phase",
    content = "snapshot",
    rename_all = "snake_case",
    bound(
        serialize = "C: CanonicalSerialize",
        deserialize = "C: CanonicalDeserialize"
    )
)]
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

    pub fn sequence(&self) -> SnapshotSeq {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.sequence,
            AnyTableSnapshot::Dealing(table) => table.sequence,
            AnyTableSnapshot::Preflop(table) => table.sequence,
            AnyTableSnapshot::Flop(table) => table.sequence,
            AnyTableSnapshot::Turn(table) => table.sequence,
            AnyTableSnapshot::River(table) => table.sequence,
            AnyTableSnapshot::Showdown(table) => table.sequence,
            AnyTableSnapshot::Complete(table) => table.sequence,
        }
    }

    pub fn event_phase(&self) -> EventPhase {
        match self {
            AnyTableSnapshot::Shuffling(_) => EventPhase::Shuffling,
            AnyTableSnapshot::Dealing(_) => EventPhase::Dealing,
            AnyTableSnapshot::Preflop(_) => EventPhase::Betting,
            AnyTableSnapshot::Flop(_) => EventPhase::Betting,
            AnyTableSnapshot::Turn(_) => EventPhase::Betting,
            AnyTableSnapshot::River(_) => EventPhase::Betting,
            AnyTableSnapshot::Showdown(_) => EventPhase::Showdown,
            AnyTableSnapshot::Complete(_) => EventPhase::Complete,
        }
    }

    pub fn status(&self) -> &SnapshotStatus {
        match self {
            AnyTableSnapshot::Shuffling(table) => &table.status,
            AnyTableSnapshot::Dealing(table) => &table.status,
            AnyTableSnapshot::Preflop(table) => &table.status,
            AnyTableSnapshot::Flop(table) => &table.status,
            AnyTableSnapshot::Turn(table) => &table.status,
            AnyTableSnapshot::River(table) => &table.status,
            AnyTableSnapshot::Showdown(table) => &table.status,
            AnyTableSnapshot::Complete(table) => &table.status,
        }
    }

    pub fn failure_reason(&self) -> Option<&str> {
        match self.status() {
            SnapshotStatus::Success => None,
            SnapshotStatus::Failure(reason) => Some(reason.as_str()),
        }
    }

    pub fn set_status(&mut self, status: SnapshotStatus) {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.status = status,
            AnyTableSnapshot::Dealing(table) => table.status = status,
            AnyTableSnapshot::Preflop(table) => table.status = status,
            AnyTableSnapshot::Flop(table) => table.status = status,
            AnyTableSnapshot::Turn(table) => table.status = status,
            AnyTableSnapshot::River(table) => table.status = status,
            AnyTableSnapshot::Showdown(table) => table.status = status,
            AnyTableSnapshot::Complete(table) => table.status = status,
        }
    }
}

fn failure_chain_hash(previous: StateHash, reason: &str, hasher: &dyn LedgerHasher) -> StateHash {
    let mut builder = TranscriptBuilder::new("ledger/state/failure");
    builder.append_bytes(reason.as_bytes());
    let failure_message = hasher.hash(&builder.finish());
    chain_hash(previous, failure_message, hasher)
}

fn mark_failure<P, C>(table: &mut TableSnapshot<P, C>, reason: &str, hasher: &dyn LedgerHasher)
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    let previous = table.state_hash;
    table.previous_hash = Some(previous);
    table.sequence = table.sequence.saturating_add(1);
    table.state_hash = failure_chain_hash(previous, reason, hasher);
    table.status = SnapshotStatus::Failure(reason.to_string());
}

// ---------------------------------------------------------------------
// Deserialization helpers for persisted snapshots
// ---------------------------------------------------------------------

fn deserialize_player_status(label: &str) -> Result<PlayerStatus> {
    match label {
        "active" => Ok(PlayerStatus::Active),
        "folded" => Ok(PlayerStatus::Folded),
        "all_in" => Ok(PlayerStatus::AllIn),
        "sitting_out" => Ok(PlayerStatus::SittingOut),
        other => Err(anyhow!("unknown player status {other}")),
    }
}

fn serialize_player_unblinding_combined<C, S>(
    value: &BTreeMap<(SeatId, u8), C>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    C: CurveGroup + CanonicalSerialize,
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(value.len()))?;
    for (key, point) in value {
        let hex = serialize_curve_hex(point).map_err(SerError::custom)?;
        map.serialize_entry(key, &hex)?;
    }
    map.end()
}

fn deserialize_player_unblinding_combined<'de, C, D>(
    deserializer: D,
) -> Result<BTreeMap<(SeatId, u8), C>, D::Error>
where
    C: CurveGroup + CanonicalDeserialize,
    D: Deserializer<'de>,
{
    let raw: BTreeMap<(SeatId, u8), String> = BTreeMap::deserialize(deserializer)?;
    raw.into_iter()
        .map(|(key, hex)| {
            let point = deserialize_curve_hex(&hex).map_err(DeError::custom)?;
            Ok((key, point))
        })
        .collect()
}

fn state_hash_from_vec(bytes: Vec<u8>) -> Result<StateHash> {
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("state hash must be 32 bytes"))?;
    Ok(StateHash::from(array))
}

fn hand_config_from_model(model: &hand_configs::Model) -> Result<HandConfig> {
    Ok(HandConfig {
        stakes: crate::engine::nl::types::TableStakes {
            small_blind: u64::try_from(model.small_blind)
                .map_err(|_| anyhow!("small blind exceeds u64 range"))?,
            big_blind: u64::try_from(model.big_blind)
                .map_err(|_| anyhow!("big blind exceeds u64 range"))?,
            ante: u64::try_from(model.ante).map_err(|_| anyhow!("ante exceeds u64 range"))?,
        },
        button: u8::try_from(model.button_seat)
            .map_err(|_| anyhow!("button seat exceeds u8 range"))?,
        small_blind_seat: u8::try_from(model.small_blind_seat)
            .map_err(|_| anyhow!("small blind seat exceeds u8 range"))?,
        big_blind_seat: u8::try_from(model.big_blind_seat)
            .map_err(|_| anyhow!("big blind seat exceeds u8 range"))?,
        check_raise_allowed: model.check_raise_allowed,
    })
}

pub fn deserialize_player_stacks(value: &JsonValue) -> Result<PlayerStacks> {
    #[derive(Deserialize)]
    struct Entry {
        seat: u8,
        player_id: Option<PlayerId>,
        starting_stack: u64,
        committed_blind: u64,
        status: PlayerStatus,
    }

    let entries: Vec<Entry> =
        serde_json::from_value(value.clone()).context("player stacks payload invalid")?;

    let mut stacks = BTreeMap::new();
    for entry in entries {
        stacks.insert(
            entry.seat,
            PlayerStackInfo {
                seat: entry.seat,
                player_id: entry.player_id,
                starting_stack: entry.starting_stack,
                committed_blind: entry.committed_blind,
                status: entry.status,
            },
        );
    }

    Ok(stacks)
}

async fn load_player_roster<C>(
    conn: &DatabaseConnection,
    game_id: GameId,
    hand_id: HandId,
) -> Result<(PlayerRoster<C>, SeatingMap)>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let rows = hand_player::Entity::find()
        .filter(hand_player::Column::GameId.eq(game_id))
        .filter(hand_player::Column::HandId.eq(hand_id))
        .order_by_asc(hand_player::Column::Seat)
        .find_also_related(players::Entity)
        .all(conn)
        .await?;

    let mut roster = BTreeMap::new();
    let mut seating = BTreeMap::new();

    for (seat_row, player_row) in rows {
        let player = player_row.context("player row missing public key")?;
        let seat = u8::try_from(seat_row.seat)
            .map_err(|_| anyhow!("seat {} exceeds u8 range", seat_row.seat))?;
        let player_id = u64::try_from(seat_row.player_id)
            .map_err(|_| anyhow!("player id {} exceeds u64 range", seat_row.player_id))?;
        let nonce = u64::try_from(seat_row.nonce)
            .map_err(|_| anyhow!("nonce {} exceeds u64 range", seat_row.nonce))?;
        let public_key = deserialize_curve_bytes::<C>(&player.public_key)
            .context("failed to deserialize player public key")?;

        roster.insert(
            player_id,
            PlayerIdentity {
                public_key,
                nonce,
                seat,
            },
        );
        seating.insert(seat, Some(player_id));
    }

    Ok((roster, seating))
}

async fn load_shuffler_roster<C>(
    conn: &DatabaseConnection,
    _game_id: GameId,
    hand_id: HandId,
) -> Result<ShufflerRoster<C>>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let assignments = hand_shufflers::Entity::find()
        .filter(hand_shufflers::Column::HandId.eq(hand_id))
        .order_by_asc(hand_shufflers::Column::Sequence)
        .all(conn)
        .await?;

    if assignments.is_empty() {
        return Ok(BTreeMap::new());
    }

    let shuffler_ids: Vec<i64> = assignments.iter().map(|row| row.shuffler_id).collect();
    let shuffler_models = shufflers::Entity::find()
        .filter(shufflers::Column::Id.is_in(shuffler_ids.clone()))
        .all(conn)
        .await?;

    let mut public_keys: HashMap<i64, C> = HashMap::new();
    for model in shuffler_models {
        let pk = deserialize_curve_bytes::<C>(&model.public_key)
            .context("failed to deserialize shuffler public key")?;
        public_keys.insert(model.id, pk);
    }

    let mut aggregated = C::zero();
    for id in &shuffler_ids {
        let pk = public_keys
            .get(id)
            .context("shuffler assignment missing public key")?;
        aggregated += pk.clone();
    }

    let mut roster = BTreeMap::new();
    for assignment in assignments {
        let pk = public_keys
            .get(&assignment.shuffler_id)
            .context("shuffler assignment missing public key")?
            .clone();
        roster.insert(
            assignment.shuffler_id,
            ShufflerIdentity {
                public_key: pk,
                aggregated_public_key: aggregated.clone(),
            },
        );
    }

    Ok(roster)
}

async fn load_phase_payload<T, F>(
    conn: &DatabaseConnection,
    hash: &Option<Vec<u8>>,
    expected: PhaseKind,
    label: &str,
    parser: F,
) -> Result<Option<T>>
where
    F: FnOnce(&JsonValue) -> Result<T>,
{
    if let Some(bytes) = hash {
        let row = phase_table::Entity::find_by_id(bytes.clone())
            .one(conn)
            .await?
            .with_context(|| format!("{label} phase payload not found"))?;

        anyhow::ensure!(
            row.phase_type == expected,
            "{label} phase type mismatch: expected {:?}, found {:?}",
            expected,
            row.phase_type
        );

        let payload = parser(&row.payload)
            .with_context(|| format!("failed to decode {label} phase payload"))?;
        Ok(Some(payload))
    } else {
        Ok(None)
    }
}

pub async fn rehydrate_snapshot_by_hash<C>(
    conn: &DatabaseConnection,
    game_id: GameId,
    hand_id: HandId,
    state_hash: StateHash,
) -> Result<AnyTableSnapshot<C>>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize + CanonicalDeserialize,
    C::BaseField: PrimeField + CanonicalSerialize + CanonicalDeserialize,
    C::Affine: Absorb,
{
    let snapshot_model = table_snapshots::Entity::find()
        .filter(table_snapshots::Column::GameId.eq(game_id))
        .filter(table_snapshots::Column::HandId.eq(hand_id))
        .filter(table_snapshots::Column::SnapshotHash.eq(state_hash.into_bytes().to_vec()))
        .one(conn)
        .await?
        .with_context(|| format!("snapshot {:?} not found", state_hash))?;

    let snapshot_sequence = u32::try_from(snapshot_model.sequence).map_err(|_| {
        anyhow!(
            "snapshot sequence {} exceeds u32::MAX",
            snapshot_model.sequence
        )
    })?;
    let previous_hash = snapshot_model
        .previous_hash
        .map(state_hash_from_vec)
        .transpose()?;
    let status = match snapshot_model.application_status {
        ApplicationStatus::Success => SnapshotStatus::Success,
        ApplicationStatus::Failure => SnapshotStatus::Failure(
            snapshot_model
                .failure_reason
                .clone()
                .unwrap_or_else(|| "unknown failure".to_string()),
        ),
    };
    let state_hash = state_hash_from_vec(snapshot_model.state_hash)?;
    let player_stacks = deserialize_player_stacks(&snapshot_model.player_stacks)?;

    let hand_config_model = hand_configs::Entity::find_by_id(snapshot_model.hand_config_id)
        .one(conn)
        .await?
        .context("hand config not found")?;
    let hand_config = hand_config_from_model(&hand_config_model)?;

    let (player_roster, seating) = load_player_roster::<C>(conn, game_id, hand_id).await?;
    let shuffler_roster = load_shuffler_roster::<C>(conn, game_id, hand_id).await?;

    let shuffling: ShufflingSnapshot<C> = load_phase_payload(
        conn,
        &snapshot_model.shuffling_hash,
        PhaseKind::Shuffling,
        "shuffling",
        |value| deserialize_shuffling_snapshot::<C>(value),
    )
    .await?
    .context("snapshot missing shuffling payload")?;
    let dealing: Option<DealingSnapshot<C>> = load_phase_payload(
        conn,
        &snapshot_model.dealing_hash,
        PhaseKind::Dealing,
        "dealing",
        |value| deserialize_dealing_snapshot::<C>(value),
    )
    .await?;
    let betting: Option<BettingSnapshot<C>> = load_phase_payload(
        conn,
        &snapshot_model.betting_hash,
        PhaseKind::Betting,
        "betting",
        |value| deserialize_betting_snapshot::<C>(value),
    )
    .await?;
    let reveals: Option<RevealsSnapshot<C>> = load_phase_payload(
        conn,
        &snapshot_model.reveals_hash,
        PhaseKind::Reveals,
        "reveals",
        |value| serde_json::from_value(value.clone()).map_err(Into::into),
    )
    .await?;

    let cfg_arc = Arc::new(hand_config);
    let shufflers_arc = Arc::new(shuffler_roster);
    let players_arc = Arc::new(player_roster);
    let seating_arc = Arc::new(seating);
    let stacks_arc = Arc::new(player_stacks);

    if let Some(reveals_snapshot) = reveals {
        let dealing_snapshot = dealing
            .clone()
            .context("reveals snapshot missing dealing payload")?;
        let betting_snapshot = betting
            .clone()
            .context("reveals snapshot missing betting payload")?;

        let table = TableSnapshot::<PhaseShowdown, C> {
            game_id,
            hand_id: Some(hand_id),
            sequence: snapshot_sequence,
            cfg: Arc::clone(&cfg_arc),
            shufflers: Arc::clone(&shufflers_arc),
            players: Arc::clone(&players_arc),
            seating: Arc::clone(&seating_arc),
            stacks: Arc::clone(&stacks_arc),
            previous_hash,
            state_hash,
            status,
            shuffling: shuffling.clone(),
            dealing: dealing_snapshot,
            betting: betting_snapshot,
            reveals: reveals_snapshot,
        };
        return Ok(AnyTableSnapshot::Showdown(table));
    }

    if let Some(betting_snapshot) = betting {
        let dealing_snapshot = dealing
            .clone()
            .context("betting snapshot missing dealing payload")?;

        let empty_reveals = || RevealsSnapshot::<C> {
            board: Vec::new(),
            revealed_holes: BTreeMap::new(),
        };

        let table = match betting_snapshot.state.street {
            Street::Preflop => {
                AnyTableSnapshot::Preflop(TableSnapshot::<PhaseBetting<PreflopStreet>, C> {
                    game_id,
                    hand_id: Some(hand_id),
                    sequence: snapshot_sequence,
                    cfg: Arc::clone(&cfg_arc),
                    shufflers: Arc::clone(&shufflers_arc),
                    players: Arc::clone(&players_arc),
                    seating: Arc::clone(&seating_arc),
                    stacks: Arc::clone(&stacks_arc),
                    previous_hash,
                    state_hash,
                    status,
                    shuffling: shuffling.clone(),
                    dealing: dealing_snapshot,
                    betting: betting_snapshot,
                    reveals: empty_reveals(),
                })
            }
            Street::Flop => AnyTableSnapshot::Flop(TableSnapshot::<PhaseBetting<FlopStreet>, C> {
                game_id,
                hand_id: Some(hand_id),
                sequence: snapshot_sequence,
                cfg: Arc::clone(&cfg_arc),
                shufflers: Arc::clone(&shufflers_arc),
                players: Arc::clone(&players_arc),
                seating: Arc::clone(&seating_arc),
                stacks: Arc::clone(&stacks_arc),
                previous_hash,
                state_hash,
                status,
                shuffling: shuffling.clone(),
                dealing: dealing_snapshot,
                betting: betting_snapshot,
                reveals: empty_reveals(),
            }),
            Street::Turn => AnyTableSnapshot::Turn(TableSnapshot::<PhaseBetting<TurnStreet>, C> {
                game_id,
                hand_id: Some(hand_id),
                sequence: snapshot_sequence,
                cfg: Arc::clone(&cfg_arc),
                shufflers: Arc::clone(&shufflers_arc),
                players: Arc::clone(&players_arc),
                seating: Arc::clone(&seating_arc),
                stacks: Arc::clone(&stacks_arc),
                previous_hash,
                state_hash,
                status,
                shuffling: shuffling.clone(),
                dealing: dealing_snapshot,
                betting: betting_snapshot,
                reveals: empty_reveals(),
            }),
            Street::River => {
                AnyTableSnapshot::River(TableSnapshot::<PhaseBetting<RiverStreet>, C> {
                    game_id,
                    hand_id: Some(hand_id),
                    sequence: snapshot_sequence,
                    cfg: Arc::clone(&cfg_arc),
                    shufflers: Arc::clone(&shufflers_arc),
                    players: Arc::clone(&players_arc),
                    seating: Arc::clone(&seating_arc),
                    stacks: Arc::clone(&stacks_arc),
                    previous_hash,
                    state_hash,
                    status,
                    shuffling: shuffling.clone(),
                    dealing: dealing_snapshot,
                    betting: betting_snapshot,
                    reveals: empty_reveals(),
                })
            }
        };

        return Ok(table);
    }

    if let Some(dealing_snapshot) = dealing {
        let table = TableSnapshot::<PhaseDealing, C> {
            game_id,
            hand_id: Some(hand_id),
            sequence: snapshot_sequence,
            cfg: Arc::clone(&cfg_arc),
            shufflers: Arc::clone(&shufflers_arc),
            players: Arc::clone(&players_arc),
            seating: Arc::clone(&seating_arc),
            stacks: Arc::clone(&stacks_arc),
            previous_hash,
            state_hash,
            status,
            shuffling: shuffling.clone(),
            dealing: dealing_snapshot,
            betting: (),
            reveals: (),
        };
        return Ok(AnyTableSnapshot::Dealing(table));
    }

    let table = TableSnapshot::<PhaseShuffling, C> {
        game_id,
        hand_id: Some(hand_id),
        sequence: snapshot_sequence,
        cfg: cfg_arc,
        shufflers: shufflers_arc,
        players: players_arc,
        seating: seating_arc,
        stacks: stacks_arc,
        previous_hash,
        state_hash,
        status,
        shuffling,
        dealing: (),
        betting: (),
        reveals: (),
    };

    Ok(AnyTableSnapshot::Shuffling(table))
}
fn deserialize_ciphertext<C>(value: &JsonValue) -> Result<ElGamalCiphertext<C>>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let c1_hex = value
        .get("c1")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("ciphertext missing c1"))?;
    let c2_hex = value
        .get("c2")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("ciphertext missing c2"))?;
    let c1 = deserialize_curve_hex::<C>(c1_hex).context("failed to deserialize ciphertext c1")?;
    let c2 = deserialize_curve_hex::<C>(c2_hex).context("failed to deserialize ciphertext c2")?;
    Ok(ElGamalCiphertext::new(c1, c2))
}

fn deserialize_chaum_pedersen_proof<C>(
    value: &JsonValue,
) -> Result<crate::chaum_pedersen::ChaumPedersenProof<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    let t_g_hex = value
        .get("t_g")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("Chaum-Pedersen proof missing t_g"))?;
    let t_h_hex = value
        .get("t_h")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("Chaum-Pedersen proof missing t_h"))?;
    let z_hex = value
        .get("z")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("Chaum-Pedersen proof missing z"))?;

    Ok(crate::chaum_pedersen::ChaumPedersenProof {
        t_g: deserialize_curve_hex::<C>(t_g_hex)
            .context("failed to deserialize Chaum-Pedersen t_g")?,
        t_h: deserialize_curve_hex::<C>(t_h_hex)
            .context("failed to deserialize Chaum-Pedersen t_h")?,
        z: canonical_deserialize_hex::<C::ScalarField>(z_hex)
            .context("failed to deserialize Chaum-Pedersen z")?,
    })
}

fn deserialize_shuffle_proof<C>(value: &JsonValue) -> Result<ShuffleProof<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::BaseField: CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    let input_deck = value
        .get("input_deck")
        .context("shuffle proof missing input_deck")?
        .as_array()
        .context("input_deck is not an array")?
        .iter()
        .map(deserialize_ciphertext::<C>)
        .collect::<Result<Vec<_>>>()?;

    let sorted_deck_entries = value
        .get("sorted_deck")
        .context("shuffle proof missing sorted_deck")?
        .as_array()
        .context("sorted_deck is not an array")?;
    let mut sorted_deck = Vec::with_capacity(sorted_deck_entries.len());
    for entry in sorted_deck_entries {
        let cipher_value = entry
            .get("ciphertext")
            .context("sorted deck entry missing ciphertext")?;
        let cipher = deserialize_ciphertext::<C>(cipher_value)?;
        let randomizer_hex = entry
            .get("randomizer")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| anyhow!("sorted deck entry missing randomizer"))?;
        let randomizer = canonical_deserialize_hex::<C::BaseField>(randomizer_hex)
            .context("failed to deserialize shuffle proof randomizer")?;
        sorted_deck.push((cipher, randomizer));
    }

    let rerand_values = value
        .get("rerandomization_values")
        .context("shuffle proof missing rerandomization_values")?
        .as_array()
        .context("rerandomization_values is not an array")?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("rerandomization value not a string"))
                .and_then(|hex| {
                    canonical_deserialize_hex::<C::ScalarField>(hex)
                        .context("failed to deserialize rerandomization value")
                })
        })
        .collect::<Result<Vec<_>>>()?;

    ShuffleProof::new(input_deck, sorted_deck, rerand_values)
        .map_err(|err| anyhow!("invalid shuffle proof: {err}"))
}

pub fn deserialize_shuffling_snapshot<C>(value: &JsonValue) -> Result<ShufflingSnapshot<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::BaseField: CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    let initial = value
        .get("initial_deck")
        .context("shuffling payload missing initial_deck")?
        .as_array()
        .context("initial_deck is not an array")?
        .iter()
        .map(deserialize_ciphertext::<C>)
        .collect::<Result<Vec<_>>>()?;
    let initial: [ElGamalCiphertext<C>; DECK_SIZE] = initial
        .try_into()
        .map_err(|_| anyhow!("initial deck length mismatch"))?;

    let steps_value = value
        .get("steps")
        .context("shuffling payload missing steps")?
        .as_array()
        .context("steps is not an array")?;
    let mut steps = Vec::with_capacity(steps_value.len());
    for step in steps_value {
        let pk_hex = step
            .get("shuffler_public_key")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| anyhow!("shuffle step missing public key"))?;
        let public_key = deserialize_curve_hex::<C>(pk_hex)
            .context("failed to deserialize shuffle step public key")?;
        let proof_value = step.get("proof").context("shuffle step missing proof")?;
        let proof = deserialize_shuffle_proof::<C>(proof_value)?;
        steps.push(ShufflingStep {
            shuffler_public_key: public_key,
            proof,
        });
    }

    let final_deck = value
        .get("final_deck")
        .context("shuffling payload missing final_deck")?
        .as_array()
        .context("final_deck is not an array")?
        .iter()
        .map(deserialize_ciphertext::<C>)
        .collect::<Result<Vec<_>>>()?;
    let final_deck: [ElGamalCiphertext<C>; DECK_SIZE] = final_deck
        .try_into()
        .map_err(|_| anyhow!("final deck length mismatch"))?;

    let expected_order = value
        .get("expected_order")
        .context("shuffling payload missing expected_order")?
        .as_array()
        .context("expected_order is not an array")?
        .iter()
        .map(|entry| {
            entry
                .as_i64()
                .ok_or_else(|| anyhow!("expected_order entry not an integer"))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ShufflingSnapshot {
        initial_deck: initial,
        steps,
        final_deck,
        expected_order,
    })
}

fn deserialize_street(label: &str) -> Result<Street> {
    match label {
        "preflop" => Ok(Street::Preflop),
        "flop" => Ok(Street::Flop),
        "turn" => Ok(Street::Turn),
        "river" => Ok(Street::River),
        other => Err(anyhow!("unknown street {other}")),
    }
}

fn deserialize_player_bet_action(value: &JsonValue) -> Result<PlayerBetAction> {
    let ty = value
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("player bet action missing type"))?;
    match ty {
        "fold" => Ok(PlayerBetAction::Fold),
        "check" => Ok(PlayerBetAction::Check),
        "call" => Ok(PlayerBetAction::Call),
        "bet_to" => {
            let to = value
                .get("to")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("bet_to action missing to"))?;
            Ok(PlayerBetAction::BetTo { to })
        }
        "raise_to" => {
            let to = value
                .get("to")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("raise_to action missing to"))?;
            Ok(PlayerBetAction::RaiseTo { to })
        }
        "all_in" => Ok(PlayerBetAction::AllIn),
        other => Err(anyhow!("unknown player bet action {other}")),
    }
}

fn deserialize_normalized_action(value: &JsonValue) -> Result<NormalizedAction> {
    let ty = value
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("normalized action missing type"))?;
    match ty {
        "fold" => Ok(NormalizedAction::Fold),
        "check" => Ok(NormalizedAction::Check),
        "call" => {
            let call_amount = value
                .get("call_amount")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("call action missing call_amount"))?;
            let full_call = value
                .get("full_call")
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| anyhow!("call action missing full_call"))?;
            Ok(NormalizedAction::Call {
                call_amount,
                full_call,
            })
        }
        "bet" => {
            let to = value
                .get("to")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("bet action missing to"))?;
            Ok(NormalizedAction::Bet { to })
        }
        "raise" => {
            let to = value
                .get("to")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("raise action missing to"))?;
            let raise_amount = value
                .get("raise_amount")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("raise action missing raise_amount"))?;
            let full_raise = value
                .get("full_raise")
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| anyhow!("raise action missing full_raise"))?;
            Ok(NormalizedAction::Raise {
                to,
                raise_amount,
                full_raise,
            })
        }
        "all_in_as_call" => {
            let call_amount = value
                .get("call_amount")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("all_in_as_call missing call_amount"))?;
            let full_call = value
                .get("full_call")
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| anyhow!("all_in_as_call missing full_call"))?;
            Ok(NormalizedAction::AllInAsCall {
                call_amount,
                full_call,
            })
        }
        "all_in_as_bet" => {
            let to = value
                .get("to")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("all_in_as_bet missing to"))?;
            Ok(NormalizedAction::AllInAsBet { to })
        }
        "all_in_as_raise" => {
            let to = value
                .get("to")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("all_in_as_raise missing to"))?;
            let raise_amount = value
                .get("raise_amount")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("all_in_as_raise missing raise_amount"))?;
            let full_raise = value
                .get("full_raise")
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| anyhow!("all_in_as_raise missing full_raise"))?;
            Ok(NormalizedAction::AllInAsRaise {
                to,
                raise_amount,
                full_raise,
            })
        }
        other => Err(anyhow!("unknown normalized action {other}")),
    }
}

fn deserialize_player_state(entry: &JsonValue) -> Result<PlayerState> {
    let seat = entry
        .get("seat")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("player state missing seat"))?;
    let player_id = entry.get("player_id").and_then(JsonValue::as_u64);
    let stack = entry
        .get("stack")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("player state missing stack"))?;
    let committed_this_round = entry
        .get("committed_this_round")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("player state missing committed_this_round"))?;
    let committed_total = entry
        .get("committed_total")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("player state missing committed_total"))?;
    let status_label = entry
        .get("status")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("player state missing status"))?;
    let has_acted = entry
        .get("has_acted_this_round")
        .and_then(JsonValue::as_bool)
        .ok_or_else(|| anyhow!("player state missing has_acted_this_round"))?;

    Ok(PlayerState {
        seat: u8::try_from(seat).map_err(|_| anyhow!("seat {seat} exceeds u8 range"))?,
        player_id,
        stack,
        committed_this_round,
        committed_total,
        status: deserialize_player_status(status_label)?,
        has_acted_this_round: has_acted,
    })
}

fn deserialize_pot(entry: &JsonValue) -> Result<Pot> {
    let amount = entry
        .get("amount")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("pot missing amount"))?;
    let eligible = entry
        .get("eligible")
        .context("pot missing eligible array")?
        .as_array()
        .context("eligible is not an array")?
        .iter()
        .map(|seat| {
            seat.as_u64()
                .ok_or_else(|| anyhow!("eligible seat not an integer"))
                .and_then(|value| {
                    u8::try_from(value)
                        .map_err(|_| anyhow!("eligible seat {value} exceeds u8 range"))
                })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Pot { amount, eligible })
}

fn deserialize_pots(value: &JsonValue) -> Result<Pots> {
    let main = value.get("main").context("pots missing main")?;
    let sides_array = value
        .get("sides")
        .context("pots missing sides")?
        .as_array()
        .context("sides is not an array")?;
    let sides = sides_array
        .iter()
        .map(deserialize_pot)
        .collect::<Result<Vec<_>>>()?;

    Ok(Pots {
        main: deserialize_pot(main)?,
        sides,
    })
}

fn deserialize_hand_config(value: &JsonValue) -> Result<HandConfig> {
    let stakes_value = value.get("stakes").context("hand config missing stakes")?;
    let small_blind = stakes_value
        .get("small_blind")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("hand config missing small_blind"))?;
    let big_blind = stakes_value
        .get("big_blind")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("hand config missing big_blind"))?;
    let ante = stakes_value
        .get("ante")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("hand config missing ante"))?;

    let button = value
        .get("button")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("hand config missing button"))?;
    let small_blind_seat = value
        .get("small_blind_seat")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("hand config missing small_blind_seat"))?;
    let big_blind_seat = value
        .get("big_blind_seat")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("hand config missing big_blind_seat"))?;
    let check_raise_allowed = value
        .get("check_raise_allowed")
        .and_then(JsonValue::as_bool)
        .ok_or_else(|| anyhow!("hand config missing check_raise_allowed"))?;

    Ok(HandConfig {
        stakes: crate::engine::nl::types::TableStakes {
            small_blind,
            big_blind,
            ante,
        },
        button: u8::try_from(button).map_err(|_| anyhow!("button {button} exceeds u8 range"))?,
        small_blind_seat: u8::try_from(small_blind_seat)
            .map_err(|_| anyhow!("small_blind_seat {small_blind_seat} exceeds u8 range"))?,
        big_blind_seat: u8::try_from(big_blind_seat)
            .map_err(|_| anyhow!("big_blind_seat {big_blind_seat} exceeds u8 range"))?,
        check_raise_allowed,
    })
}

fn deserialize_action_log_entry(entry: &JsonValue) -> Result<ActionLogEntry> {
    let street_label = entry
        .get("street")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("action log entry missing street"))?;
    let seat = entry
        .get("seat")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("action log entry missing seat"))?;
    let action_value = entry
        .get("action")
        .context("action log entry missing action")?;
    let price_before = entry
        .get("price_to_call_before")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("action log entry missing price_to_call_before"))?;
    let current_after = entry
        .get("current_bet_to_match_after")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("action log entry missing current_bet_to_match_after"))?;

    Ok(ActionLogEntry {
        street: deserialize_street(street_label)?,
        seat: u8::try_from(seat).map_err(|_| anyhow!("seat {seat} exceeds u8 range"))?,
        action: deserialize_normalized_action(action_value)?,
        price_to_call_before: price_before,
        current_bet_to_match_after: current_after,
    })
}

fn deserialize_action_log(value: &JsonValue) -> Result<ActionLog> {
    let entries = value
        .as_array()
        .context("action_log is not an array")?
        .iter()
        .map(deserialize_action_log_entry)
        .collect::<Result<Vec<_>>>()?;
    Ok(ActionLog(entries))
}

pub fn deserialize_betting_snapshot<C>(value: &JsonValue) -> Result<BettingSnapshot<C>>
where
    C: CurveGroup,
{
    let state_value = value
        .get("state")
        .context("betting payload missing state")?;
    let street_label = state_value
        .get("street")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("betting state missing street"))?;
    let button = state_value
        .get("button")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("betting state missing button"))?;
    let first_to_act = state_value
        .get("first_to_act")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("betting state missing first_to_act"))?;
    let to_act = state_value
        .get("to_act")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("betting state missing to_act"))?;
    let current_bet_to_match = state_value
        .get("current_bet_to_match")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("betting state missing current_bet_to_match"))?;
    let last_full_raise_amount = state_value
        .get("last_full_raise_amount")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("betting state missing last_full_raise_amount"))?;
    let last_aggressor = state_value
        .get("last_aggressor")
        .and_then(JsonValue::as_u64);
    let voluntary_bet_opened = state_value
        .get("voluntary_bet_opened")
        .and_then(JsonValue::as_bool)
        .ok_or_else(|| anyhow!("betting state missing voluntary_bet_opened"))?;
    let players_array = state_value
        .get("players")
        .context("betting state missing players")?
        .as_array()
        .context("players is not an array")?;
    let players = players_array
        .iter()
        .map(deserialize_player_state)
        .collect::<Result<Vec<_>>>()?;
    let pots_value = state_value
        .get("pots")
        .context("betting state missing pots")?;
    let cfg_value = state_value
        .get("hand_config")
        .context("betting state missing hand_config")?;
    let pending_to_match = state_value
        .get("pending_to_match")
        .context("betting state missing pending_to_match")?
        .as_array()
        .context("pending_to_match is not an array")?
        .iter()
        .map(|seat| {
            seat.as_u64()
                .ok_or_else(|| anyhow!("pending_to_match entry not an integer"))
                .and_then(|value| {
                    u8::try_from(value)
                        .map_err(|_| anyhow!("pending seat {value} exceeds u8 range"))
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let betting_locked_all_in = state_value
        .get("betting_locked_all_in")
        .and_then(JsonValue::as_bool)
        .ok_or_else(|| anyhow!("betting state missing betting_locked_all_in"))?;
    let action_log_value = state_value
        .get("action_log")
        .context("betting state missing action_log")?;

    let last_events = value
        .get("last_events")
        .context("betting payload missing last_events")?
        .as_array()
        .context("last_events is not an array")?
        .iter()
        .map(|entry| {
            let street_label = entry
                .get("street")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| anyhow!("player action entry missing street"))?;
            let action_value = entry
                .get("action")
                .context("player action entry missing action")?;
            let action = deserialize_player_bet_action(action_value)?;
            Ok(match street_label {
                "preflop" => AnyPlayerActionMsg::Preflop(GamePlayerMessage::new(action)),
                "flop" => AnyPlayerActionMsg::Flop(GamePlayerMessage::new(action)),
                "turn" => AnyPlayerActionMsg::Turn(GamePlayerMessage::new(action)),
                "river" => AnyPlayerActionMsg::River(GamePlayerMessage::new(action)),
                other => return Err(anyhow!("unknown player action street {other}")),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(BettingSnapshot {
        state: BettingState {
            street: deserialize_street(street_label)?,
            button: u8::try_from(button)
                .map_err(|_| anyhow!("button {button} exceeds u8 range"))?,
            first_to_act: u8::try_from(first_to_act)
                .map_err(|_| anyhow!("first_to_act {first_to_act} exceeds u8 range"))?,
            to_act: u8::try_from(to_act)
                .map_err(|_| anyhow!("to_act {to_act} exceeds u8 range"))?,
            current_bet_to_match,
            last_full_raise_amount,
            last_aggressor: last_aggressor
                .map(|value| {
                    u8::try_from(value).map_err(|_| anyhow!("last_aggressor exceeds u8 range"))
                })
                .transpose()?,
            voluntary_bet_opened,
            players,
            pots: deserialize_pots(pots_value)?,
            cfg: deserialize_hand_config(cfg_value)?,
            pending_to_match,
            betting_locked_all_in,
            action_log: deserialize_action_log(action_log_value)?,
        },
        last_events,
    })
}

fn deserialize_player_accessible_ciphertext<C>(
    value: &JsonValue,
) -> Result<PlayerAccessibleCiphertext<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    let blinded_base_hex = value
        .get("blinded_base")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("player ciphertext missing blinded_base"))?;
    let blinded_message_hex = value
        .get("blinded_message_with_player_key")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("player ciphertext missing blinded_message_with_player_key"))?;
    let helper_hex = value
        .get("player_unblinding_helper")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("player ciphertext missing player_unblinding_helper"))?;
    let proofs_value = value
        .get("shuffler_proofs")
        .context("player ciphertext missing shuffler_proofs")?
        .as_array()
        .context("shuffler_proofs is not an array")?;

    let proofs = proofs_value
        .iter()
        .map(deserialize_chaum_pedersen_proof::<C>)
        .collect::<Result<Vec<_>>>()?;

    Ok(PlayerAccessibleCiphertext {
        blinded_base: deserialize_curve_hex::<C>(blinded_base_hex)
            .context("failed to deserialize blinded_base")?,
        blinded_message_with_player_key: deserialize_curve_hex::<C>(blinded_message_hex)
            .context("failed to deserialize blinded_message_with_player_key")?,
        player_unblinding_helper: deserialize_curve_hex::<C>(helper_hex)
            .context("failed to deserialize player_unblinding_helper")?,
        shuffler_proofs: proofs,
    })
}

fn deserialize_blinding_contribution<C>(
    value: &JsonValue,
) -> Result<PlayerTargetedBlindingContribution<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    let base_hex = value
        .get("blinding_base_contribution")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("blinding contribution missing blinding_base_contribution"))?;
    let combined_hex = value
        .get("blinding_combined_contribution")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("blinding contribution missing blinding_combined_contribution"))?;
    let proof_value = value
        .get("proof")
        .context("blinding contribution missing proof")?;

    Ok(PlayerTargetedBlindingContribution {
        blinding_base_contribution: deserialize_curve_hex::<C>(base_hex)
            .context("failed to deserialize blinding_base_contribution")?,
        blinding_combined_contribution: deserialize_curve_hex::<C>(combined_hex)
            .context("failed to deserialize blinding_combined_contribution")?,
        proof: deserialize_chaum_pedersen_proof::<C>(proof_value)?,
    })
}

fn deserialize_partial_unblinding_share<C>(value: &JsonValue) -> Result<PartialUnblindingShare<C>>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let member_index = value
        .get("member_index")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("partial unblinding share missing member_index"))?;
    let share_hex = value
        .get("share")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("partial unblinding share missing share"))?;

    Ok(PartialUnblindingShare {
        share: deserialize_curve_hex::<C>(share_hex)
            .context("failed to deserialize partial unblinding share")?,
        member_index: usize::try_from(member_index)
            .map_err(|_| anyhow!("member_index {member_index} exceeds usize range"))?,
    })
}

fn deserialize_community_share<C>(value: &JsonValue) -> Result<CommunityDecryptionShare<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    let member_index = value
        .get("member_index")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow!("community share missing member_index"))?;
    let share_hex = value
        .get("share")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("community share missing share"))?;
    let proof_value = value
        .get("proof")
        .context("community share missing proof")?;

    Ok(CommunityDecryptionShare {
        member_index: usize::try_from(member_index)
            .map_err(|_| anyhow!("member_index {member_index} exceeds usize range"))?,
        share: deserialize_curve_hex::<C>(share_hex)
            .context("failed to deserialize community share")?,
        proof: deserialize_chaum_pedersen_proof::<C>(proof_value)?,
    })
}

fn deserialize_card_destination(entry: &JsonValue) -> Result<CardDestination> {
    let kind = entry
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("card destination missing type"))?;
    match kind {
        "hole" => {
            let seat = entry
                .get("seat")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("card destination hole missing seat"))?;
            let hole_index = entry
                .get("hole_index")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("card destination hole missing hole_index"))?;
            Ok(CardDestination::Hole {
                seat: u8::try_from(seat).map_err(|_| anyhow!("seat {seat} exceeds u8 range"))?,
                hole_index: u8::try_from(hole_index)
                    .map_err(|_| anyhow!("hole_index {hole_index} exceeds u8 range"))?,
            })
        }
        "board" => {
            let board_index = entry
                .get("board_index")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| anyhow!("card destination board missing board_index"))?;
            Ok(CardDestination::Board {
                board_index: u8::try_from(board_index)
                    .map_err(|_| anyhow!("board_index {board_index} exceeds u8 range"))?,
            })
        }
        "burn" => Ok(CardDestination::Burn),
        "unused" => Ok(CardDestination::Unused),
        other => Err(anyhow!("unknown card destination type {other}")),
    }
}

pub fn deserialize_dealing_snapshot<C>(value: &JsonValue) -> Result<DealingSnapshot<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::BaseField: CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    let assignments_array = value
        .get("assignments")
        .context("dealing payload missing assignments")?
        .as_array()
        .context("assignments is not an array")?;
    let mut assignments = BTreeMap::new();
    for entry in assignments_array {
        let card = entry
            .get("card")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("assignment missing card"))?;
        let cipher_value = entry
            .get("ciphertext")
            .context("assignment missing ciphertext")?;
        let source_index = entry.get("source_index").and_then(JsonValue::as_i64);
        assignments.insert(
            u8::try_from(card).map_err(|_| anyhow!("card {card} exceeds u8 range"))?,
            DealtCard {
                cipher: deserialize_ciphertext::<C>(cipher_value)?,
                source_index: source_index
                    .map(|idx| u8::try_from(idx).map_err(|_| anyhow!("source_index out of range")))
                    .transpose()?,
            },
        );
    }

    let player_ciphertexts_array = value
        .get("player_ciphertexts")
        .context("dealing payload missing player_ciphertexts")?
        .as_array()
        .context("player_ciphertexts is not an array")?;
    let mut player_ciphertexts = BTreeMap::new();
    for entry in player_ciphertexts_array {
        let seat = entry
            .get("seat")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("player ciphertext missing seat"))?;
        let hole_index = entry
            .get("hole_index")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("player ciphertext missing hole_index"))?;
        let cipher_value = entry
            .get("ciphertext")
            .context("player ciphertext missing ciphertext")?;
        player_ciphertexts.insert(
            (
                u8::try_from(seat).map_err(|_| anyhow!("seat {seat} exceeds u8 range"))?,
                u8::try_from(hole_index)
                    .map_err(|_| anyhow!("hole_index {hole_index} exceeds u8 range"))?,
            ),
            deserialize_player_accessible_ciphertext::<C>(cipher_value)?,
        );
    }

    let blinding_array = value
        .get("player_blinding_contributions")
        .context("dealing payload missing player_blinding_contributions")?
        .as_array()
        .context("player_blinding_contributions is not an array")?;
    let mut blinding = BTreeMap::new();
    for entry in blinding_array {
        let shuffler_id = entry
            .get("shuffler_id")
            .and_then(JsonValue::as_i64)
            .ok_or_else(|| anyhow!("blinding contribution missing shuffler_id"))?;
        let seat = entry
            .get("seat")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("blinding contribution missing seat"))?;
        let hole_index = entry
            .get("hole_index")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("blinding contribution missing hole_index"))?;
        let contribution_value = entry
            .get("contribution")
            .context("blinding contribution missing contribution")?;
        blinding.insert(
            (
                shuffler_id,
                u8::try_from(seat).map_err(|_| anyhow!("seat {seat} exceeds u8 range"))?,
                u8::try_from(hole_index)
                    .map_err(|_| anyhow!("hole_index {hole_index} exceeds u8 range"))?,
            ),
            deserialize_blinding_contribution::<C>(contribution_value)?,
        );
    }

    let unblinding_shares_array = value
        .get("player_unblinding_shares")
        .context("dealing payload missing player_unblinding_shares")?
        .as_array()
        .context("player_unblinding_shares is not an array")?;
    let mut unblinding_shares = BTreeMap::new();
    for entry in unblinding_shares_array {
        let seat = entry
            .get("seat")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("unblinding shares entry missing seat"))?;
        let hole_index = entry
            .get("hole_index")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("unblinding shares entry missing hole_index"))?;
        let shares_value = entry
            .get("shares")
            .context("unblinding shares entry missing shares")?
            .as_array()
            .context("shares field is not an array")?;
        let mut shares_map = BTreeMap::new();
        for share in shares_value {
            let parsed = deserialize_partial_unblinding_share::<C>(share)?;
            shares_map.insert(parsed.member_index, parsed);
        }
        unblinding_shares.insert(
            (
                u8::try_from(seat).map_err(|_| anyhow!("seat {seat} exceeds u8 range"))?,
                u8::try_from(hole_index)
                    .map_err(|_| anyhow!("hole_index {hole_index} exceeds u8 range"))?,
            ),
            shares_map,
        );
    }

    let unblinding_combined_array = value
        .get("player_unblinding_combined")
        .context("dealing payload missing player_unblinding_combined")?
        .as_array()
        .context("player_unblinding_combined is not an array")?;
    let mut unblinding_combined = BTreeMap::new();
    for entry in unblinding_combined_array {
        let seat = entry
            .get("seat")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("unblinding combined entry missing seat"))?;
        let hole_index = entry
            .get("hole_index")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("unblinding combined entry missing hole_index"))?;
        let combined_hex = entry
            .get("combined")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| anyhow!("unblinding combined entry missing combined"))?;
        unblinding_combined.insert(
            (
                u8::try_from(seat).map_err(|_| anyhow!("seat {seat} exceeds u8 range"))?,
                u8::try_from(hole_index)
                    .map_err(|_| anyhow!("hole_index {hole_index} exceeds u8 range"))?,
            ),
            deserialize_curve_hex::<C>(combined_hex)
                .context("failed to deserialize combined unblinding point")?,
        );
    }

    let community_shares_array = value
        .get("community_decryption_shares")
        .context("dealing payload missing community_decryption_shares")?
        .as_array()
        .context("community_decryption_shares is not an array")?;
    let mut community_shares = BTreeMap::new();
    for entry in community_shares_array {
        let shuffler_id = entry
            .get("shuffler_id")
            .and_then(JsonValue::as_i64)
            .ok_or_else(|| anyhow!("community share missing shuffler_id"))?;
        let card_index = entry
            .get("card_index")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("community share missing card_index"))?;
        let share_value = entry
            .get("share")
            .context("community share missing share")?;
        community_shares.insert(
            (
                shuffler_id,
                u8::try_from(card_index)
                    .map_err(|_| anyhow!("card_index {card_index} exceeds u8 range"))?,
            ),
            deserialize_community_share::<C>(share_value)?,
        );
    }

    let community_cards_array = value
        .get("community_cards")
        .context("dealing payload missing community_cards")?
        .as_array()
        .context("community_cards is not an array")?;
    let mut community_cards = BTreeMap::new();
    for entry in community_cards_array {
        let card_index = entry
            .get("card_index")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("community card entry missing card_index"))?;
        let value_card = entry
            .get("value")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("community card entry missing value"))?;
        community_cards.insert(
            u8::try_from(card_index)
                .map_err(|_| anyhow!("card_index {card_index} exceeds u8 range"))?,
            u8::try_from(value_card)
                .map_err(|_| anyhow!("card value {value_card} exceeds u8 range"))?,
        );
    }

    let card_plan_array = value
        .get("card_plan")
        .context("dealing payload missing card_plan")?
        .as_array()
        .context("card_plan is not an array")?;
    let mut card_plan = CardPlan::new();
    for entry in card_plan_array {
        let card = entry
            .get("card")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| anyhow!("card plan entry missing card"))?;
        let destination_value = entry
            .get("destination")
            .context("card plan entry missing destination")?;
        card_plan.insert(
            u8::try_from(card).map_err(|_| anyhow!("card {card} exceeds u8 range"))?,
            deserialize_card_destination(destination_value)?,
        );
    }

    Ok(DealingSnapshot {
        assignments,
        player_ciphertexts,
        player_blinding_contribs: blinding,
        player_unblinding_shares: unblinding_shares,
        player_unblinding_combined: unblinding_combined,
        community_decryption_shares: community_shares,
        community_cards,
        card_plan,
    })
}

pub fn clone_snapshot_for_failure<C: CurveGroup>(
    snapshot: &AnyTableSnapshot<C>,
    hasher: &dyn LedgerHasher,
    reason: String,
) -> AnyTableSnapshot<C> {
    let mut failed = snapshot.clone();
    match &mut failed {
        AnyTableSnapshot::Shuffling(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Dealing(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Preflop(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Flop(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Turn(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::River(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Showdown(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Complete(table) => mark_failure(table, &reason, hasher),
    }
    failed
}
