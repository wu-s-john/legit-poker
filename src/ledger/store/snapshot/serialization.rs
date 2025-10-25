use anyhow::{anyhow, Context};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde_json::Value as JsonValue;
use tracing::info;

use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::sea_orm_active_enums::{
    self as db_enums, ApplicationStatus as DbApplicationStatus,
};
use crate::db::entity::{games, hand_configs, hands, phases, table_snapshots};
use crate::engine::nl::events::NormalizedAction;
use crate::engine::nl::state::BettingState;
use crate::engine::nl::types::{
    HandConfig, PlayerState as EnginePlayerState, PlayerStatus as EnginePlayerStatus,
    Pot as EnginePot, Pots as EnginePots, Street,
};
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::{
    AnyPlayerActionMsg, AnyTableSnapshot, BettingSnapshot, CardDestination, PhaseBetting,
    PhaseComplete, RevealsSnapshot, ShufflingSnapshot, SnapshotSeq, SnapshotStatus, TableAtDealing,
    TableAtShowdown, TableAtShuffling, TableSnapshot,
};
use crate::ledger::types::{GameId, HandId, StateHash};
use crate::showdown::HandCategory;
use crate::shuffling::data_structures::DECK_SIZE;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct PreparedPhase {
    kind: db_enums::PhaseKind,
    hash: StateHash,
    payload: JsonValue,
}

pub struct PreparedSnapshot {
    pub(super) game_id: GameId,
    pub(super) hand_id: HandId,
    pub(super) sequence: i32,
    pub(super) state_hash: StateHash,
    pub(super) previous_hash: Option<StateHash>,
    pub(super) hand_config: Arc<HandConfig>,
    pub(super) stacks: JsonValue,
    pub(super) shuffling_hash: Option<StateHash>,
    pub(super) dealing_hash: Option<StateHash>,
    pub(super) betting_hash: Option<StateHash>,
    pub(super) reveals_hash: Option<StateHash>,
    pub(super) phase_kind: db_enums::PhaseKind,
    pub(super) application_status: DbApplicationStatus,
    pub(super) failure_reason: Option<String>,
    phases: Vec<PreparedPhase>,
}

fn map_status(status: &SnapshotStatus) -> (DbApplicationStatus, Option<String>) {
    match status {
        SnapshotStatus::Success => (DbApplicationStatus::Success, None),
        SnapshotStatus::Failure(reason) => (DbApplicationStatus::Failure, Some(reason.clone())),
    }
}

pub(super) fn prepare_snapshot_data<C>(
    snapshot: &AnyTableSnapshot<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<PreparedSnapshot>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    match snapshot {
        AnyTableSnapshot::Shuffling(table) => prepare_from_shuffling(table, hasher),
        AnyTableSnapshot::Dealing(table) => prepare_from_dealing(table, hasher),
        AnyTableSnapshot::Preflop(table) => {
            prepare_from_betting(table, db_enums::PhaseKind::Betting, hasher)
        }
        AnyTableSnapshot::Flop(table) => {
            prepare_from_betting(table, db_enums::PhaseKind::Betting, hasher)
        }
        AnyTableSnapshot::Turn(table) => {
            prepare_from_betting(table, db_enums::PhaseKind::Betting, hasher)
        }
        AnyTableSnapshot::River(table) => {
            prepare_from_betting(table, db_enums::PhaseKind::Betting, hasher)
        }
        AnyTableSnapshot::Showdown(table) => {
            prepare_from_showdown(table, db_enums::PhaseKind::Reveals, hasher)
        }
        AnyTableSnapshot::Complete(table) => {
            prepare_from_complete(table, db_enums::PhaseKind::Reveals, hasher)
        }
    }
}

fn prepare_from_shuffling<C>(
    table: &TableAtShuffling<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<PreparedSnapshot>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let hand_id = table
        .hand_id
        .ok_or_else(|| anyhow!("snapshot missing hand id"))?;
    let sequence = cast_sequence(table.sequence)?;
    let stacks =
        serde_json::to_value(table.stacks.as_ref()).context("failed to serialize player stacks")?;
    let (phase, hash) = build_shuffling_phase(&table.shuffling, hasher)?;
    let (application_status, failure_reason) = map_status(&table.status);

    Ok(PreparedSnapshot {
        game_id: table.game_id,
        hand_id,
        sequence,
        state_hash: table.state_hash,
        previous_hash: table.previous_hash,
        hand_config: Arc::clone(&table.cfg),
        stacks,
        shuffling_hash: Some(hash),
        dealing_hash: None,
        betting_hash: None,
        reveals_hash: None,
        phase_kind: db_enums::PhaseKind::Shuffling,
        application_status,
        failure_reason,
        phases: vec![phase],
    })
}

fn prepare_from_dealing<C>(
    table: &TableAtDealing<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<PreparedSnapshot>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let hand_id = table
        .hand_id
        .ok_or_else(|| anyhow!("snapshot missing hand id"))?;
    let sequence = cast_sequence(table.sequence)?;
    let stacks =
        serde_json::to_value(table.stacks.as_ref()).context("failed to serialize player stacks")?;
    let (shuffle_phase, shuffle_hash) = build_shuffling_phase(&table.shuffling, hasher)?;
    let (deal_phase, deal_hash) = build_dealing_phase(&table.dealing, hasher)?;
    let (application_status, failure_reason) = map_status(&table.status);

    Ok(PreparedSnapshot {
        game_id: table.game_id,
        hand_id,
        sequence,
        state_hash: table.state_hash,
        previous_hash: table.previous_hash,
        hand_config: Arc::clone(&table.cfg),
        stacks,
        shuffling_hash: Some(shuffle_hash),
        dealing_hash: Some(deal_hash),
        betting_hash: None,
        reveals_hash: None,
        phase_kind: db_enums::PhaseKind::Dealing,
        application_status,
        failure_reason,
        phases: vec![shuffle_phase, deal_phase],
    })
}

fn prepare_from_betting<C, R>(
    table: &TableSnapshot<PhaseBetting<R>, C>,
    phase_kind: db_enums::PhaseKind,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<PreparedSnapshot>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let hand_id = table
        .hand_id
        .ok_or_else(|| anyhow!("snapshot missing hand id"))?;
    let sequence = cast_sequence(table.sequence)?;
    let stacks =
        serde_json::to_value(table.stacks.as_ref()).context("failed to serialize player stacks")?;

    let (shuffle_phase, shuffle_hash) = build_shuffling_phase(&table.shuffling, hasher)?;
    let (deal_phase, deal_hash) = build_dealing_phase(&table.dealing, hasher)?;
    let (bet_phase, bet_hash) = build_betting_phase(&table.betting, hasher)?;
    let (reveals_phase, reveals_hash) = build_reveals_phase(&table.reveals, hasher)?;
    let (application_status, failure_reason) = map_status(&table.status);

    Ok(PreparedSnapshot {
        game_id: table.game_id,
        hand_id,
        sequence,
        state_hash: table.state_hash,
        previous_hash: table.previous_hash,
        hand_config: Arc::clone(&table.cfg),
        stacks,
        shuffling_hash: Some(shuffle_hash),
        dealing_hash: Some(deal_hash),
        betting_hash: Some(bet_hash),
        reveals_hash: Some(reveals_hash),
        phase_kind,
        application_status,
        failure_reason,
        phases: vec![shuffle_phase, deal_phase, bet_phase, reveals_phase],
    })
}

fn prepare_from_showdown<C>(
    table: &TableAtShowdown<C>,
    phase_kind: db_enums::PhaseKind,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<PreparedSnapshot>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let hand_id = table
        .hand_id
        .ok_or_else(|| anyhow!("snapshot missing hand id"))?;
    let sequence = cast_sequence(table.sequence)?;
    let stacks =
        serde_json::to_value(table.stacks.as_ref()).context("failed to serialize player stacks")?;

    let (shuffle_phase, shuffle_hash) = build_shuffling_phase(&table.shuffling, hasher)?;
    let (deal_phase, deal_hash) = build_dealing_phase(&table.dealing, hasher)?;
    let (bet_phase, bet_hash) = build_betting_phase(&table.betting, hasher)?;
    let (reveals_phase, reveals_hash) = build_reveals_phase(&table.reveals, hasher)?;
    let (application_status, failure_reason) = map_status(&table.status);

    Ok(PreparedSnapshot {
        game_id: table.game_id,
        hand_id,
        sequence,
        state_hash: table.state_hash,
        previous_hash: table.previous_hash,
        hand_config: Arc::clone(&table.cfg),
        stacks,
        shuffling_hash: Some(shuffle_hash),
        dealing_hash: Some(deal_hash),
        betting_hash: Some(bet_hash),
        reveals_hash: Some(reveals_hash),
        phase_kind,
        application_status,
        failure_reason,
        phases: vec![shuffle_phase, deal_phase, bet_phase, reveals_phase],
    })
}

fn prepare_from_complete<C>(
    table: &TableSnapshot<PhaseComplete, C>,
    phase_kind: db_enums::PhaseKind,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<PreparedSnapshot>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let hand_id = table
        .hand_id
        .ok_or_else(|| anyhow!("snapshot missing hand id"))?;
    let sequence = cast_sequence(table.sequence)?;
    let stacks =
        serde_json::to_value(table.stacks.as_ref()).context("failed to serialize player stacks")?;

    let (shuffle_phase, shuffle_hash) = build_shuffling_phase(&table.shuffling, hasher)?;
    let (deal_phase, deal_hash) = build_dealing_phase(&table.dealing, hasher)?;
    let (bet_phase, bet_hash) = build_betting_phase(&table.betting, hasher)?;
    let (reveals_phase, reveals_hash) = build_reveals_phase(&table.reveals, hasher)?;
    let (application_status, failure_reason) = map_status(&table.status);

    Ok(PreparedSnapshot {
        game_id: table.game_id,
        hand_id,
        sequence,
        state_hash: table.state_hash,
        previous_hash: table.previous_hash,
        hand_config: Arc::clone(&table.cfg),
        stacks,
        shuffling_hash: Some(shuffle_hash),
        dealing_hash: Some(deal_hash),
        betting_hash: Some(bet_hash),
        reveals_hash: Some(reveals_hash),
        phase_kind,
        application_status,
        failure_reason,
        phases: vec![shuffle_phase, deal_phase, bet_phase, reveals_phase],
    })
}

fn build_shuffling_phase<C>(
    shuffling: &ShufflingSnapshot<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<(PreparedPhase, StateHash)>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ledger/phase/shuffling\0");

    (DECK_SIZE as u64).serialize_compressed(&mut bytes)?;
    for cipher in &shuffling.initial_deck {
        cipher.serialize_compressed(&mut bytes)?;
    }

    (shuffling.steps.len() as u64).serialize_compressed(&mut bytes)?;
    for step in &shuffling.steps {
        step.shuffler_public_key.serialize_compressed(&mut bytes)?;
        step.proof.serialize_compressed(&mut bytes)?;
    }

    (DECK_SIZE as u64).serialize_compressed(&mut bytes)?;
    for cipher in &shuffling.final_deck {
        cipher.serialize_compressed(&mut bytes)?;
    }

    (shuffling.expected_order.len() as u64).serialize_compressed(&mut bytes)?;
    for key in &shuffling.expected_order {
        key.serialize_compressed(&mut bytes)?;
    }

    let hash = hasher.hash(&bytes);
    let payload_json =
        serde_json::to_value(shuffling).context("failed to serialize shuffling phase")?;
    Ok((
        PreparedPhase {
            kind: db_enums::PhaseKind::Shuffling,
            hash,
            payload: payload_json,
        },
        hash,
    ))
}

pub fn compute_dealing_hash<C>(
    dealing: &crate::ledger::snapshot::DealingSnapshot<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<StateHash>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ledger/phase/dealing\0");
    serialize_dealing_phase(&mut bytes, dealing)?;
    Ok(hasher.hash(&bytes))
}

fn serialize_dealing_phase<C>(
    bytes: &mut Vec<u8>,
    dealing: &crate::ledger::snapshot::DealingSnapshot<C>,
) -> anyhow::Result<()>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    (dealing.assignments.len() as u64).serialize_compressed(&mut *bytes)?;
    for (&card_index, dealt) in dealing.assignments.iter() {
        card_index.serialize_compressed(&mut *bytes)?;
        dealt.cipher.serialize_compressed(&mut *bytes)?;
        match dealt.source_index {
            Some(idx) => {
                1u8.serialize_compressed(&mut *bytes)?;
                idx.serialize_compressed(&mut *bytes)?;
            }
            None => 0u8.serialize_compressed(&mut *bytes)?,
        }
    }

    (dealing.player_ciphertexts.len() as u64).serialize_compressed(&mut *bytes)?;
    for (&(seat, hole_index), ciphertext) in dealing.player_ciphertexts.iter() {
        seat.serialize_compressed(&mut *bytes)?;
        hole_index.serialize_compressed(&mut *bytes)?;
        ciphertext.serialize_compressed(&mut *bytes)?;
    }

    (dealing.player_blinding_contribs.len() as u64).serialize_compressed(&mut *bytes)?;
    for ((shuffler_key, seat, hole_index), contrib) in dealing.player_blinding_contribs.iter() {
        shuffler_key.serialize_compressed(&mut *bytes)?;
        seat.serialize_compressed(&mut *bytes)?;
        hole_index.serialize_compressed(&mut *bytes)?;
        contrib.serialize_compressed(&mut *bytes)?;
    }

    (dealing.player_unblinding_shares.len() as u64).serialize_compressed(&mut *bytes)?;
    for (&(seat, hole_index), shares) in dealing.player_unblinding_shares.iter() {
        seat.serialize_compressed(&mut *bytes)?;
        hole_index.serialize_compressed(&mut *bytes)?;
        (shares.len() as u64).serialize_compressed(&mut *bytes)?;
        for (member_key, share) in shares {
            member_key.serialize_compressed(&mut *bytes)?;
            share.serialize_compressed(&mut *bytes)?;
        }
    }

    (dealing.player_unblinding_combined.len() as u64).serialize_compressed(&mut *bytes)?;
    for (&(seat, hole_index), combined) in dealing.player_unblinding_combined.iter() {
        seat.serialize_compressed(&mut *bytes)?;
        hole_index.serialize_compressed(&mut *bytes)?;
        combined.serialize_compressed(&mut *bytes)?;
    }

    (dealing.community_decryption_shares.len() as u64).serialize_compressed(&mut *bytes)?;
    for ((shuffler_key, card_index), share) in dealing.community_decryption_shares.iter() {
        shuffler_key.serialize_compressed(&mut *bytes)?;
        card_index.serialize_compressed(&mut *bytes)?;
        share.share.serialize_compressed(&mut *bytes)?;
        share.proof.serialize_compressed(&mut *bytes)?;
        share.member_key.serialize_compressed(&mut *bytes)?;
    }

    (dealing.community_cards.len() as u64).serialize_compressed(&mut *bytes)?;
    for (&card_index, &value) in dealing.community_cards.iter() {
        card_index.serialize_compressed(&mut *bytes)?;
        value.serialize_compressed(&mut *bytes)?;
    }

    (dealing.card_plan.len() as u64).serialize_compressed(&mut *bytes)?;
    for (&card, destination) in dealing.card_plan.iter() {
        card.serialize_compressed(&mut *bytes)?;
        match destination {
            CardDestination::Hole { seat, hole_index } => {
                0u8.serialize_compressed(&mut *bytes)?;
                seat.serialize_compressed(&mut *bytes)?;
                hole_index.serialize_compressed(&mut *bytes)?;
            }
            CardDestination::Board { board_index } => {
                1u8.serialize_compressed(&mut *bytes)?;
                board_index.serialize_compressed(&mut *bytes)?;
            }
            CardDestination::Burn => 2u8.serialize_compressed(&mut *bytes)?,
            CardDestination::Unused => 3u8.serialize_compressed(&mut *bytes)?,
        }
    }

    Ok(())
}

fn build_dealing_phase<C>(
    dealing: &crate::ledger::snapshot::DealingSnapshot<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<(PreparedPhase, StateHash)>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ledger/phase/dealing\0");
    serialize_dealing_phase(&mut bytes, dealing)?;
    let hash = hasher.hash(&bytes);
    let payload_json =
        serde_json::to_value(dealing).context("failed to serialize dealing phase")?;
    Ok((
        PreparedPhase {
            kind: db_enums::PhaseKind::Dealing,
            hash,
            payload: payload_json,
        },
        hash,
    ))
}

fn build_betting_phase<C>(
    betting: &BettingSnapshot<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<(PreparedPhase, StateHash)>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ledger/phase/betting\0");
    serialize_betting_state(&mut bytes, &betting.state)?;
    (betting.last_events.len() as u64).serialize_compressed(&mut bytes)?;
    for event in &betting.last_events {
        serialize_player_action(&mut bytes, event)?;
    }

    let hash = hasher.hash(&bytes);
    let payload_json =
        serde_json::to_value(betting).context("failed to serialize betting phase")?;
    Ok((
        PreparedPhase {
            kind: db_enums::PhaseKind::Betting,
            hash,
            payload: payload_json,
        },
        hash,
    ))
}

fn build_reveals_phase<C>(
    reveals: &RevealsSnapshot<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<(PreparedPhase, StateHash)>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ledger/phase/reveals\0");

    (reveals.board.len() as u64).serialize_compressed(&mut bytes)?;
    for card in &reveals.board {
        card.serialize_compressed(&mut bytes)?;
    }

    (reveals.revealed_holes.len() as u64).serialize_compressed(&mut bytes)?;
    for (&seat, hand) in reveals.revealed_holes.iter() {
        seat.serialize_compressed(&mut bytes)?;
        for value in &hand.hole {
            value.serialize_compressed(&mut bytes)?;
        }
        for cipher in &hand.hole_ciphertexts {
            cipher.serialize_compressed(&mut bytes)?;
        }
        for value in &hand.best_five {
            value.serialize_compressed(&mut bytes)?;
        }
        let label = hand_category_label(hand.best_category);
        bytes.extend_from_slice(&(label.len() as u32).to_be_bytes());
        bytes.extend_from_slice(label.as_bytes());
        for value in &hand.best_tiebreak {
            value.serialize_compressed(&mut bytes)?;
        }
        (hand.best_score as u64).serialize_compressed(&mut bytes)?;
    }

    let hash = hasher.hash(&bytes);
    let payload_json =
        serde_json::to_value(reveals).context("failed to serialize reveals phase")?;
    Ok((
        PreparedPhase {
            kind: db_enums::PhaseKind::Reveals,
            hash,
            payload: payload_json,
        },
        hash,
    ))
}

fn street_label(street: Street) -> &'static str {
    match street {
        Street::Preflop => "preflop",
        Street::Flop => "flop",
        Street::Turn => "turn",
        Street::River => "river",
    }
}

fn hand_category_label(category: HandCategory) -> &'static str {
    match category {
        HandCategory::HighCard => "high_card",
        HandCategory::OnePair => "one_pair",
        HandCategory::TwoPair => "two_pair",
        HandCategory::ThreeOfAKind => "three_of_a_kind",
        HandCategory::Straight => "straight",
        HandCategory::Flush => "flush",
        HandCategory::FullHouse => "full_house",
        HandCategory::FourOfAKind => "four_of_a_kind",
        HandCategory::StraightFlush => "straight_flush",
    }
}

fn serialize_betting_state(bytes: &mut Vec<u8>, state: &BettingState) -> anyhow::Result<()> {
    let label = street_label(state.street);
    bytes.extend_from_slice(&(label.len() as u32).to_be_bytes());
    bytes.extend_from_slice(label.as_bytes());

    state.button.serialize_compressed(&mut *bytes)?;
    state.first_to_act.serialize_compressed(&mut *bytes)?;
    state.to_act.serialize_compressed(&mut *bytes)?;
    state.current_bet_to_match.serialize_compressed(&mut *bytes)?;
    state.last_full_raise_amount.serialize_compressed(&mut *bytes)?;
    match state.last_aggressor {
        Some(seat) => {
            1u8.serialize_compressed(&mut *bytes)?;
            seat.serialize_compressed(&mut *bytes)?;
        }
        None => 0u8.serialize_compressed(&mut *bytes)?,
    }
    (state.voluntary_bet_opened as u8).serialize_compressed(&mut *bytes)?;

    (state.players.len() as u64).serialize_compressed(&mut *bytes)?;
    for player in &state.players {
        serialize_player_state(bytes, player)?;
    }

    serialize_pots(bytes, &state.pots)?;
    // Inline HandConfig serialization
    state.cfg.stakes.small_blind.serialize_compressed(&mut *bytes)?;
    state.cfg.stakes.big_blind.serialize_compressed(&mut *bytes)?;
    state.cfg.stakes.ante.serialize_compressed(&mut *bytes)?;
    state.cfg.button.serialize_compressed(&mut *bytes)?;
    state.cfg.small_blind_seat.serialize_compressed(&mut *bytes)?;
    state.cfg.big_blind_seat.serialize_compressed(&mut *bytes)?;
    (state.cfg.check_raise_allowed as u8).serialize_compressed(&mut *bytes)?;

    (state.pending_to_match.len() as u64).serialize_compressed(&mut *bytes)?;
    for seat in &state.pending_to_match {
        seat.serialize_compressed(&mut *bytes)?;
    }
    (state.betting_locked_all_in as u8).serialize_compressed(&mut *bytes)?;

    (state.action_log.0.len() as u64).serialize_compressed(&mut *bytes)?;
    for entry in &state.action_log.0 {
        let street = street_label(entry.street);
        bytes.extend_from_slice(&(street.len() as u32).to_be_bytes());
        bytes.extend_from_slice(street.as_bytes());
        entry.seat.serialize_compressed(&mut *bytes)?;
        serialize_normalized_action(bytes, &entry.action)?;
        entry.price_to_call_before.serialize_compressed(&mut *bytes)?;
        entry.current_bet_to_match_after.serialize_compressed(&mut *bytes)?;
    }

    Ok(())
}

fn serialize_player_state(bytes: &mut Vec<u8>, state: &EnginePlayerState) -> anyhow::Result<()> {
    state.seat.serialize_compressed(&mut *bytes)?;
    match state.player_id {
        Some(id) => {
            1u8.serialize_compressed(&mut *bytes)?;
            id.serialize_compressed(&mut *bytes)?;
        }
        None => 0u8.serialize_compressed(&mut *bytes)?,
    }
    state.stack.serialize_compressed(&mut *bytes)?;
    state.committed_this_round.serialize_compressed(&mut *bytes)?;
    state.committed_total.serialize_compressed(&mut *bytes)?;
    let status_byte = match state.status {
        EnginePlayerStatus::Active => 0u8,
        EnginePlayerStatus::Folded => 1u8,
        EnginePlayerStatus::AllIn => 2u8,
        EnginePlayerStatus::SittingOut => 3u8,
    };
    status_byte.serialize_compressed(&mut *bytes)?;
    (state.has_acted_this_round as u8).serialize_compressed(&mut *bytes)?;

    Ok(())
}

fn serialize_pots(bytes: &mut Vec<u8>, pots: &EnginePots) -> anyhow::Result<()> {
    serialize_pot(bytes, &pots.main)?;
    (pots.sides.len() as u64).serialize_compressed(&mut *bytes)?;
    for pot in &pots.sides {
        serialize_pot(bytes, pot)?;
    }
    Ok(())
}

fn serialize_pot(bytes: &mut Vec<u8>, pot: &EnginePot) -> anyhow::Result<()> {
    pot.amount.serialize_compressed(&mut *bytes)?;
    (pot.eligible.len() as u64).serialize_compressed(&mut *bytes)?;
    for seat in &pot.eligible {
        seat.serialize_compressed(&mut *bytes)?;
    }
    Ok(())
}

fn serialize_normalized_action(bytes: &mut Vec<u8>, action: &NormalizedAction) -> anyhow::Result<()> {
    match action {
        NormalizedAction::Fold => 0u8.serialize_compressed(&mut *bytes)?,
        NormalizedAction::Check => 1u8.serialize_compressed(&mut *bytes)?,
        NormalizedAction::Call {
            call_amount,
            full_call,
        } => {
            2u8.serialize_compressed(&mut *bytes)?;
            call_amount.serialize_compressed(&mut *bytes)?;
            (*full_call as u8).serialize_compressed(&mut *bytes)?;
        }
        NormalizedAction::Bet { to } => {
            3u8.serialize_compressed(&mut *bytes)?;
            to.serialize_compressed(&mut *bytes)?;
        }
        NormalizedAction::Raise {
            to,
            raise_amount,
            full_raise,
        } => {
            4u8.serialize_compressed(&mut *bytes)?;
            to.serialize_compressed(&mut *bytes)?;
            raise_amount.serialize_compressed(&mut *bytes)?;
            (*full_raise as u8).serialize_compressed(&mut *bytes)?;
        }
        NormalizedAction::AllInAsCall {
            call_amount,
            full_call,
        } => {
            5u8.serialize_compressed(&mut *bytes)?;
            call_amount.serialize_compressed(&mut *bytes)?;
            (*full_call as u8).serialize_compressed(&mut *bytes)?;
        }
        NormalizedAction::AllInAsBet { to } => {
            6u8.serialize_compressed(&mut *bytes)?;
            to.serialize_compressed(&mut *bytes)?;
        }
        NormalizedAction::AllInAsRaise {
            to,
            raise_amount,
            full_raise,
        } => {
            7u8.serialize_compressed(&mut *bytes)?;
            to.serialize_compressed(&mut *bytes)?;
            raise_amount.serialize_compressed(&mut *bytes)?;
            (*full_raise as u8).serialize_compressed(&mut *bytes)?;
        }
    }
    Ok(())
}

fn serialize_player_action<C>(bytes: &mut Vec<u8>, event: &AnyPlayerActionMsg<C>) -> anyhow::Result<()>
where
    C: CurveGroup,
{
    match event {
        AnyPlayerActionMsg::Preflop(msg) => {
            bytes.extend_from_slice(&(7u32).to_be_bytes()); // "preflop".len()
            bytes.extend_from_slice(b"preflop");
            msg.serialize_compressed(&mut *bytes)?;
        }
        AnyPlayerActionMsg::Flop(msg) => {
            bytes.extend_from_slice(&(4u32).to_be_bytes()); // "flop".len()
            bytes.extend_from_slice(b"flop");
            msg.serialize_compressed(&mut *bytes)?;
        }
        AnyPlayerActionMsg::Turn(msg) => {
            bytes.extend_from_slice(&(4u32).to_be_bytes()); // "turn".len()
            bytes.extend_from_slice(b"turn");
            msg.serialize_compressed(&mut *bytes)?;
        }
        AnyPlayerActionMsg::River(msg) => {
            bytes.extend_from_slice(&(5u32).to_be_bytes()); // "river".len()
            bytes.extend_from_slice(b"river");
            msg.serialize_compressed(&mut *bytes)?;
        }
    }
    Ok(())
}

fn cast_sequence(sequence: SnapshotSeq) -> anyhow::Result<i32> {
    i32::try_from(sequence).map_err(|_| anyhow!("snapshot sequence {} exceeds i32::MAX", sequence))
}

pub async fn persist_prepared_snapshot(
    txn: &DatabaseTransaction,
    prepared: &PreparedSnapshot,
) -> anyhow::Result<()> {
    for phase in &prepared.phases {
        insert_phase_if_needed(txn, phase).await?;
    }
    info!(
        target = SNAPSHOT_LOG_TARGET,
        game_id = prepared.game_id,
        hand_id = prepared.hand_id,
        phase_count = prepared.phases.len(),
        "phase entries ensured"
    );

    let hand_config_id =
        ensure_hand_config(txn, prepared.game_id, prepared.hand_config.as_ref()).await?;

    let snapshot_model = table_snapshots::ActiveModel {
        snapshot_hash: Set(prepared.state_hash.as_bytes().to_vec()),
        game_id: Set(prepared.game_id),
        hand_id: Set(prepared.hand_id),
        sequence: Set(prepared.sequence),
        state_hash: Set(prepared.state_hash.as_bytes().to_vec()),
        previous_hash: Set(prepared.previous_hash.map(|hash| hash.as_bytes().to_vec())),
        hand_config_id: Set(hand_config_id),
        player_stacks: Set(prepared.stacks.clone()),
        shuffling_hash: Set(prepared.shuffling_hash.map(|hash| hash.as_bytes().to_vec())),
        dealing_hash: Set(prepared.dealing_hash.map(|hash| hash.as_bytes().to_vec())),
        betting_hash: Set(prepared.betting_hash.map(|hash| hash.as_bytes().to_vec())),
        reveals_hash: Set(prepared.reveals_hash.map(|hash| hash.as_bytes().to_vec())),
        application_status: Set(prepared.application_status.clone()),
        failure_reason: Set(prepared.failure_reason.clone()),
        ..Default::default()
    };

    table_snapshots::Entity::insert(snapshot_model)
        .on_conflict(
            OnConflict::column(table_snapshots::Column::SnapshotHash)
                .do_nothing()
                .to_owned(),
        )
        .exec(txn)
        .await?;
    info!(
        target = SNAPSHOT_LOG_TARGET,
        game_id = prepared.game_id,
        hand_id = prepared.hand_id,
        sequence = prepared.sequence,
        "snapshot row inserted or already present"
    );

    let mut hand_model = hands::ActiveModel {
        id: Set(prepared.hand_id),
        ..Default::default()
    };
    hand_model.hand_config_id = Set(hand_config_id);
    hand_model.current_sequence = Set(prepared.sequence);
    hand_model.current_state_hash = Set(Some(prepared.state_hash.as_bytes().to_vec()));
    hand_model.current_phase = Set(Some(prepared.phase_kind.clone()));
    hand_model.update(txn).await?;
    info!(
        target = SNAPSHOT_LOG_TARGET,
        hand_id = prepared.hand_id,
        sequence = prepared.sequence,
        "hand row updated"
    );

    let mut game_model = games::ActiveModel {
        id: Set(prepared.game_id),
        ..Default::default()
    };
    game_model.default_hand_config_id = Set(Some(hand_config_id));
    game_model.current_hand_id = Set(Some(prepared.hand_id));
    game_model.current_state_hash = Set(Some(prepared.state_hash.as_bytes().to_vec()));
    game_model.current_phase = Set(Some(prepared.phase_kind.clone()));
    game_model.update(txn).await?;
    info!(
        target = SNAPSHOT_LOG_TARGET,
        game_id = prepared.game_id,
        hand_id = prepared.hand_id,
        "game row updated"
    );

    Ok(())
}

async fn ensure_hand_config(
    txn: &DatabaseTransaction,
    game_id: GameId,
    config: &HandConfig,
) -> anyhow::Result<i64> {
    use hand_configs::Column;

    let small_blind = chips_to_i64(config.stakes.small_blind, "small blind")?;
    let big_blind = chips_to_i64(config.stakes.big_blind, "big blind")?;
    let ante = chips_to_i64(config.stakes.ante, "ante")?;
    let button = i16::from(config.button);
    let small_blind_seat = i16::from(config.small_blind_seat);
    let big_blind_seat = i16::from(config.big_blind_seat);

    if let Some(existing) = hand_configs::Entity::find()
        .filter(Column::GameId.eq(game_id))
        .filter(Column::SmallBlind.eq(small_blind))
        .filter(Column::BigBlind.eq(big_blind))
        .filter(Column::Ante.eq(ante))
        .filter(Column::ButtonSeat.eq(button))
        .filter(Column::SmallBlindSeat.eq(small_blind_seat))
        .filter(Column::BigBlindSeat.eq(big_blind_seat))
        .filter(Column::CheckRaiseAllowed.eq(config.check_raise_allowed))
        .order_by_desc(Column::CreatedAt)
        .one(txn)
        .await?
    {
        return Ok(existing.id);
    }

    let active = hand_configs::ActiveModel {
        game_id: Set(game_id),
        small_blind: Set(small_blind),
        big_blind: Set(big_blind),
        ante: Set(ante),
        button_seat: Set(button),
        small_blind_seat: Set(small_blind_seat),
        big_blind_seat: Set(big_blind_seat),
        check_raise_allowed: Set(config.check_raise_allowed),
        ..Default::default()
    };

    let inserted = active.insert(txn).await?;
    Ok(inserted.id)
}

fn chips_to_i64(value: u64, label: &str) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(|_| anyhow!("{label} {value} exceeds i64::MAX"))
}

async fn insert_phase_if_needed(
    txn: &DatabaseTransaction,
    phase: &PreparedPhase,
) -> anyhow::Result<()> {
    let hash_vec = phase.hash.as_bytes().to_vec();
    let existing = phases::Entity::find_by_id(hash_vec.clone())
        .one(txn)
        .await?;
    if existing.is_none() {
        let model = phases::ActiveModel {
            hash: Set(hash_vec),
            phase_type: Set(phase.kind.clone()),
            payload: Set(phase.payload.clone()),
            message_id: Set(None),
            ..Default::default()
        };
        phases::Entity::insert(model)
            .on_conflict(
                OnConflict::column(phases::Column::Hash)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(txn)
            .await?;
        info!(
            target = SNAPSHOT_LOG_TARGET,
            phase_kind = ?phase.kind,
            "phase payload inserted"
        );
    }
    Ok(())
}

pub(super) const SNAPSHOT_LOG_TARGET: &str = "legit_poker::ledger::snapshot_store";
