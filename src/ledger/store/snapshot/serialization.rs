use anyhow::anyhow;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde_json::{json, Value as JsonValue};
use tracing::info;

use crate::chaum_pedersen::ChaumPedersenProof;
use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::sea_orm_active_enums::{
    self as db_enums, ApplicationStatus as DbApplicationStatus,
};
use crate::db::entity::{games, hand_configs, hands, phases, table_snapshots};
use crate::engine::nl::actions::PlayerBetAction;
use crate::engine::nl::events::NormalizedAction;
use crate::engine::nl::state::BettingState;
use crate::engine::nl::types::{
    ActionLogEntry as EngineActionLogEntry, HandConfig, PlayerState as EnginePlayerState,
    PlayerStatus as EnginePlayerStatus, Pot as EnginePot, Pots as EnginePots, Street,
};
use crate::ledger::hash::LedgerHasher;
use crate::ledger::serialization::canonical_serialize_hex_prefixed;
use crate::ledger::snapshot::{
    AnyPlayerActionMsg, AnyTableSnapshot, BettingSnapshot, CardDestination, PhaseBetting,
    PhaseComplete, PlayerStacks, RevealsSnapshot, ShufflingSnapshot, SnapshotSeq, SnapshotStatus,
    TableAtDealing, TableAtShowdown, TableAtShuffling, TableSnapshot,
};
use crate::ledger::types::{GameId, HandId, StateHash};
use crate::showdown::HandCategory;
use crate::shuffling::community_decryption::CommunityDecryptionShare;
use crate::shuffling::data_structures::{
    append_ciphertext, append_curve_point, append_shuffle_proof, ElGamalCiphertext, ShuffleProof,
    DECK_SIZE,
};
use crate::shuffling::player_decryption::{
    PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
};
use crate::signing::{Signable, TranscriptBuilder};
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
    let stacks = serialize_player_stacks(table.stacks.as_ref());
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
    let stacks = serialize_player_stacks(table.stacks.as_ref());
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
    let stacks = serialize_player_stacks(table.stacks.as_ref());

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
    let stacks = serialize_player_stacks(table.stacks.as_ref());

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
    let stacks = serialize_player_stacks(table.stacks.as_ref());

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
    let mut builder = TranscriptBuilder::new("ledger/phase/shuffling");
    builder.append_u64(DECK_SIZE as u64);
    for cipher in &shuffling.initial_deck {
        append_ciphertext(&mut builder, cipher);
    }
    builder.append_u64(shuffling.steps.len() as u64);
    for step in &shuffling.steps {
        append_curve_point(&mut builder, &step.shuffler_public_key);
        append_shuffle_proof(&mut builder, &step.proof);
    }
    builder.append_u64(DECK_SIZE as u64);
    for cipher in &shuffling.final_deck {
        append_ciphertext(&mut builder, cipher);
    }
    builder.append_u64(shuffling.expected_order.len() as u64);
    for &id in &shuffling.expected_order {
        builder.append_i64(id);
    }
    let payload = builder.finish();
    let hash = hasher.hash(&payload);
    let payload_json = shuffling_phase_payload(shuffling)?;
    Ok((
        PreparedPhase {
            kind: db_enums::PhaseKind::Shuffling,
            hash,
            payload: payload_json,
        },
        hash,
    ))
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
    let mut builder = TranscriptBuilder::new("ledger/phase/dealing");

    builder.append_u64(dealing.assignments.len() as u64);
    for (&card_index, dealt) in dealing.assignments.iter() {
        builder.append_u8(card_index);
        append_ciphertext(&mut builder, &dealt.cipher);
        match dealt.source_index {
            Some(idx) => {
                builder.append_u8(1);
                builder.append_u8(idx);
            }
            None => builder.append_u8(0),
        }
    }

    builder.append_u64(dealing.player_ciphertexts.len() as u64);
    for (&(seat, hole_index), ciphertext) in dealing.player_ciphertexts.iter() {
        builder.append_u8(seat);
        builder.append_u8(hole_index);
        ciphertext.write_transcript(&mut builder);
    }

    builder.append_u64(dealing.player_blinding_contribs.len() as u64);
    for (&(shuffler_id, seat, hole_index), contrib) in dealing.player_blinding_contribs.iter() {
        builder.append_i64(shuffler_id);
        builder.append_u8(seat);
        builder.append_u8(hole_index);
        contrib.write_transcript(&mut builder);
    }

    builder.append_u64(dealing.player_unblinding_shares.len() as u64);
    for (&(seat, hole_index), shares) in dealing.player_unblinding_shares.iter() {
        builder.append_u8(seat);
        builder.append_u8(hole_index);
        builder.append_u64(shares.len() as u64);
        for (&member_index, share) in shares {
            builder.append_u64(member_index as u64);
            share.write_transcript(&mut builder);
        }
    }

    builder.append_u64(dealing.player_unblinding_combined.len() as u64);
    for (&(seat, hole_index), combined) in dealing.player_unblinding_combined.iter() {
        builder.append_u8(seat);
        builder.append_u8(hole_index);
        append_curve_point(&mut builder, combined);
    }

    builder.append_u64(dealing.community_decryption_shares.len() as u64);
    for (&(shuffler_id, card_index), share) in dealing.community_decryption_shares.iter() {
        builder.append_i64(shuffler_id);
        builder.append_u8(card_index);
        append_curve_point(&mut builder, &share.share);
        share.proof.write_transcript(&mut builder);
        builder.append_u64(share.member_index as u64);
    }

    builder.append_u64(dealing.community_cards.len() as u64);
    for (&card_index, &value) in dealing.community_cards.iter() {
        builder.append_u8(card_index);
        builder.append_u8(value);
    }

    builder.append_u64(dealing.card_plan.len() as u64);
    for (&card, destination) in dealing.card_plan.iter() {
        builder.append_u8(card);
        match destination {
            CardDestination::Hole { seat, hole_index } => {
                builder.append_u8(0);
                builder.append_u8(*seat);
                builder.append_u8(*hole_index);
            }
            CardDestination::Board { board_index } => {
                builder.append_u8(1);
                builder.append_u8(*board_index);
            }
            CardDestination::Burn => builder.append_u8(2),
            CardDestination::Unused => builder.append_u8(3),
        }
    }

    let payload = builder.finish();
    let hash = hasher.hash(&payload);
    let payload_json = dealing_phase_payload(dealing)?;
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
    let mut builder = TranscriptBuilder::new("ledger/phase/betting");
    append_betting_state(&mut builder, &betting.state);
    builder.append_u64(betting.last_events.len() as u64);
    for event in &betting.last_events {
        append_player_action(&mut builder, event);
    }

    let payload = builder.finish();
    let hash = hasher.hash(&payload);
    let payload_json = betting_phase_payload(betting)?;
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
    let mut builder = TranscriptBuilder::new("ledger/phase/reveals");
    builder.append_u64(reveals.board.len() as u64);
    for card in &reveals.board {
        builder.append_u8(*card);
    }
    builder.append_u64(reveals.revealed_holes.len() as u64);
    for (&seat, hand) in reveals.revealed_holes.iter() {
        builder.append_u8(seat);
        for value in &hand.hole {
            builder.append_u8(*value);
        }
        for cipher in &hand.hole_ciphertexts {
            cipher.write_transcript(&mut builder);
        }
        for value in &hand.best_five {
            builder.append_u8(*value);
        }
        builder.append_bytes(hand_category_label(hand.best_category).as_bytes());
        for value in &hand.best_tiebreak {
            builder.append_u8(*value);
        }
        builder.append_u64(hand.best_score as u64);
    }

    let payload = builder.finish();
    let hash = hasher.hash(&payload);
    let payload_json = reveals_phase_payload(reveals)?;
    Ok((
        PreparedPhase {
            kind: db_enums::PhaseKind::Reveals,
            hash,
            payload: payload_json,
        },
        hash,
    ))
}

fn append_betting_state(builder: &mut TranscriptBuilder, state: &BettingState) {
    builder.append_bytes(street_label(state.street).as_bytes());
    builder.append_u8(state.button);
    builder.append_u8(state.first_to_act);
    builder.append_u8(state.to_act);
    builder.append_u64(state.current_bet_to_match);
    builder.append_u64(state.last_full_raise_amount);
    match state.last_aggressor {
        Some(seat) => {
            builder.append_u8(1);
            builder.append_u8(seat);
        }
        None => builder.append_u8(0),
    }
    builder.append_u8(state.voluntary_bet_opened as u8);

    builder.append_u64(state.players.len() as u64);
    for player in &state.players {
        append_player_state(builder, player);
    }

    append_pots(builder, &state.pots);
    state.cfg.append_to_transcript(builder);

    builder.append_u64(state.pending_to_match.len() as u64);
    for seat in &state.pending_to_match {
        builder.append_u8(*seat);
    }
    builder.append_u8(state.betting_locked_all_in as u8);

    builder.append_u64(state.action_log.0.len() as u64);
    for entry in &state.action_log.0 {
        builder.append_bytes(street_label(entry.street).as_bytes());
        builder.append_u8(entry.seat);
        append_normalized_action(builder, &entry.action);
        builder.append_u64(entry.price_to_call_before);
        builder.append_u64(entry.current_bet_to_match_after);
    }
}

fn append_player_state(builder: &mut TranscriptBuilder, state: &EnginePlayerState) {
    builder.append_u8(state.seat);
    match state.player_id {
        Some(id) => {
            builder.append_u8(1);
            builder.append_u64(id);
        }
        None => builder.append_u8(0),
    }
    builder.append_u64(state.stack);
    builder.append_u64(state.committed_this_round);
    builder.append_u64(state.committed_total);
    builder.append_u8(match state.status {
        EnginePlayerStatus::Active => 0,
        EnginePlayerStatus::Folded => 1,
        EnginePlayerStatus::AllIn => 2,
        EnginePlayerStatus::SittingOut => 3,
    });
    builder.append_u8(state.has_acted_this_round as u8);
}

fn append_pots(builder: &mut TranscriptBuilder, pots: &EnginePots) {
    append_pot(builder, &pots.main);
    builder.append_u64(pots.sides.len() as u64);
    for pot in &pots.sides {
        append_pot(builder, pot);
    }
}

fn append_pot(builder: &mut TranscriptBuilder, pot: &EnginePot) {
    builder.append_u64(pot.amount);
    builder.append_u64(pot.eligible.len() as u64);
    for seat in &pot.eligible {
        builder.append_u8(*seat);
    }
}

fn append_normalized_action(builder: &mut TranscriptBuilder, action: &NormalizedAction) {
    match action {
        NormalizedAction::Fold => builder.append_u8(0),
        NormalizedAction::Check => builder.append_u8(1),
        NormalizedAction::Call {
            call_amount,
            full_call,
        } => {
            builder.append_u8(2);
            builder.append_u64(*call_amount);
            builder.append_u8(*full_call as u8);
        }
        NormalizedAction::Bet { to } => {
            builder.append_u8(3);
            builder.append_u64(*to);
        }
        NormalizedAction::Raise {
            to,
            raise_amount,
            full_raise,
        } => {
            builder.append_u8(4);
            builder.append_u64(*to);
            builder.append_u64(*raise_amount);
            builder.append_u8(*full_raise as u8);
        }
        NormalizedAction::AllInAsCall {
            call_amount,
            full_call,
        } => {
            builder.append_u8(5);
            builder.append_u64(*call_amount);
            builder.append_u8(*full_call as u8);
        }
        NormalizedAction::AllInAsBet { to } => {
            builder.append_u8(6);
            builder.append_u64(*to);
        }
        NormalizedAction::AllInAsRaise {
            to,
            raise_amount,
            full_raise,
        } => {
            builder.append_u8(7);
            builder.append_u64(*to);
            builder.append_u64(*raise_amount);
            builder.append_u8(*full_raise as u8);
        }
    }
}

fn append_player_action<C>(builder: &mut TranscriptBuilder, event: &AnyPlayerActionMsg<C>)
where
    C: CurveGroup,
{
    match event {
        AnyPlayerActionMsg::Preflop(msg) => {
            builder.append_bytes(b"preflop");
            msg.write_transcript(builder);
        }
        AnyPlayerActionMsg::Flop(msg) => {
            builder.append_bytes(b"flop");
            msg.write_transcript(builder);
        }
        AnyPlayerActionMsg::Turn(msg) => {
            builder.append_bytes(b"turn");
            msg.write_transcript(builder);
        }
        AnyPlayerActionMsg::River(msg) => {
            builder.append_bytes(b"river");
            msg.write_transcript(builder);
        }
    }
}

fn serialize_hex<T>(value: &T) -> anyhow::Result<String>
where
    T: CanonicalSerialize,
{
    canonical_serialize_hex_prefixed(value).map_err(|err| anyhow!("serialization failed: {err}"))
}

fn ciphertext_to_json<C>(ciphertext: &ElGamalCiphertext<C>) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize,
{
    Ok(json!({
        "c1": serialize_hex(&ciphertext.c1)?,
        "c2": serialize_hex(&ciphertext.c2)?,
    }))
}

fn chaum_pedersen_to_json<C>(proof: &ChaumPedersenProof<C>) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: CanonicalSerialize,
{
    Ok(json!({
        "t_g": serialize_hex(&proof.t_g)?,
        "t_h": serialize_hex(&proof.t_h)?,
        "z": serialize_hex(&proof.z)?,
    }))
}

fn player_ciphertext_to_json<C>(
    ciphertext: &PlayerAccessibleCiphertext<C>,
) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: CanonicalSerialize,
{
    let proofs = ciphertext
        .shuffler_proofs
        .iter()
        .map(chaum_pedersen_to_json)
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(json!({
        "blinded_base": serialize_hex(&ciphertext.blinded_base)?,
        "blinded_message_with_player_key": serialize_hex(&ciphertext.blinded_message_with_player_key)?,
        "player_unblinding_helper": serialize_hex(&ciphertext.player_unblinding_helper)?,
        "shuffler_proofs": proofs,
    }))
}

fn blinding_contribution_to_json<C>(
    contrib: &PlayerTargetedBlindingContribution<C>,
) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: CanonicalSerialize,
{
    Ok(json!({
        "blinding_base_contribution": serialize_hex(&contrib.blinding_base_contribution)?,
        "blinding_combined_contribution": serialize_hex(&contrib.blinding_combined_contribution)?,
        "proof": chaum_pedersen_to_json(&contrib.proof)?,
    }))
}

fn community_share_to_json<C>(share: &CommunityDecryptionShare<C>) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: CanonicalSerialize,
{
    Ok(json!({
        "member_index": share.member_index,
        "share": serialize_hex(&share.share)?,
        "proof": chaum_pedersen_to_json(&share.proof)?,
    }))
}

fn shuffle_proof_to_json<C>(proof: &ShuffleProof<C>) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize,
    C::BaseField: CanonicalSerialize,
    C::ScalarField: CanonicalSerialize,
{
    let input_deck = proof
        .input_deck
        .iter()
        .map(ciphertext_to_json)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let sorted_deck = proof
        .sorted_deck
        .iter()
        .map(|(cipher, randomizer)| {
            let cipher_json = ciphertext_to_json(cipher)?;
            let randomizer_hex = serialize_hex(randomizer)?;
            Ok(json!({
                "ciphertext": cipher_json,
                "randomizer": randomizer_hex,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let rerandomization_values = proof
        .rerandomization_values
        .iter()
        .map(serialize_hex)
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(json!({
        "input_deck": input_deck,
        "sorted_deck": sorted_deck,
        "rerandomization_values": rerandomization_values,
    }))
}

fn shuffling_phase_payload<C>(shuffling: &ShufflingSnapshot<C>) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let initial_deck = shuffling
        .initial_deck
        .iter()
        .map(ciphertext_to_json)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let steps = shuffling
        .steps
        .iter()
        .map(|step| {
            let key_hex = serialize_hex(&step.shuffler_public_key)?;
            let proof_json = shuffle_proof_to_json(&step.proof)?;
            Ok(json!({
                "shuffler_public_key": key_hex,
                "proof": proof_json,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let final_deck = shuffling
        .final_deck
        .iter()
        .map(ciphertext_to_json)
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(json!({
        "initial_deck": initial_deck,
        "steps": steps,
        "final_deck": final_deck,
        "expected_order": shuffling.expected_order.clone(),
    }))
}

fn dealing_phase_payload<C>(
    dealing: &crate::ledger::snapshot::DealingSnapshot<C>,
) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
    C::Affine: Absorb,
{
    let assignments = dealing
        .assignments
        .iter()
        .map(|(&card, dealt)| {
            let cipher_json = ciphertext_to_json(&dealt.cipher)?;
            Ok(json!({
                "card": card,
                "ciphertext": cipher_json,
                "source_index": dealt.source_index,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let player_ciphertexts = dealing
        .player_ciphertexts
        .iter()
        .map(|(&(seat, hole_index), cipher)| {
            let cipher_json = player_ciphertext_to_json(cipher)?;
            Ok(json!({
                "seat": seat,
                "hole_index": hole_index,
                "ciphertext": cipher_json,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let player_blinding_contribs = dealing
        .player_blinding_contribs
        .iter()
        .map(|(&(shuffler_id, seat, hole_index), contrib)| {
            let contrib_json = blinding_contribution_to_json(contrib)?;
            Ok(json!({
                "shuffler_id": shuffler_id,
                "seat": seat,
                "hole_index": hole_index,
                "contribution": contrib_json,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let player_unblinding_shares = dealing
        .player_unblinding_shares
        .iter()
        .map(|(&(seat, hole_index), shares)| {
            let share_entries = shares
                .iter()
                .map(|(&member_index, share)| {
                    Ok(json!({
                        "member_index": member_index,
                        "share": serialize_hex(&share.share)?,
                    }))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            Ok(json!({
                "seat": seat,
                "hole_index": hole_index,
                "shares": share_entries,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let player_unblinding_combined = dealing
        .player_unblinding_combined
        .iter()
        .map(|(&(seat, hole_index), combined)| {
            Ok(json!({
                "seat": seat,
                "hole_index": hole_index,
                "combined": serialize_hex(combined)?,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let community_shares = dealing
        .community_decryption_shares
        .iter()
        .map(|(&(shuffler_id, card_index), share)| {
            let share_json = community_share_to_json(share)?;
            Ok(json!({
                "shuffler_id": shuffler_id,
                "card_index": card_index,
                "share": share_json,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let community_cards = dealing
        .community_cards
        .iter()
        .map(|(&card_index, &value)| {
            json!({
                "card_index": card_index,
                "value": value,
            })
        })
        .collect::<Vec<_>>();

    let card_plan = dealing
        .card_plan
        .iter()
        .map(|(&card, destination)| {
            let destination_json = match destination {
                CardDestination::Hole { seat, hole_index } => json!({
                    "type": "hole",
                    "seat": seat,
                    "hole_index": hole_index,
                }),
                CardDestination::Board { board_index } => json!({
                    "type": "board",
                    "board_index": board_index,
                }),
                CardDestination::Burn => json!({ "type": "burn" }),
                CardDestination::Unused => json!({ "type": "unused" }),
            };
            Ok(json!({
                "card": card,
                "destination": destination_json,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(json!({
        "assignments": assignments,
        "player_ciphertexts": player_ciphertexts,
        "player_blinding_contributions": player_blinding_contribs,
        "player_unblinding_shares": player_unblinding_shares,
        "player_unblinding_combined": player_unblinding_combined,
        "community_decryption_shares": community_shares,
        "community_cards": community_cards,
        "card_plan": card_plan,
    }))
}

fn player_bet_action_to_json(action: &PlayerBetAction) -> JsonValue {
    match action {
        PlayerBetAction::Fold => json!({"type": "fold"}),
        PlayerBetAction::Check => json!({"type": "check"}),
        PlayerBetAction::Call => json!({"type": "call"}),
        PlayerBetAction::BetTo { to } => json!({"type": "bet_to", "to": to}),
        PlayerBetAction::RaiseTo { to } => json!({"type": "raise_to", "to": to}),
        PlayerBetAction::AllIn => json!({"type": "all_in"}),
    }
}

fn normalized_action_to_json(action: &NormalizedAction) -> JsonValue {
    match action {
        NormalizedAction::Fold => json!({"type": "fold"}),
        NormalizedAction::Check => json!({"type": "check"}),
        NormalizedAction::Call {
            call_amount,
            full_call,
        } => json!({
            "type": "call",
            "call_amount": call_amount,
            "full_call": full_call,
        }),
        NormalizedAction::Bet { to } => json!({
            "type": "bet",
            "to": to,
        }),
        NormalizedAction::Raise {
            to,
            raise_amount,
            full_raise,
        } => json!({
            "type": "raise",
            "to": to,
            "raise_amount": raise_amount,
            "full_raise": full_raise,
        }),
        NormalizedAction::AllInAsCall {
            call_amount,
            full_call,
        } => json!({
            "type": "all_in_as_call",
            "call_amount": call_amount,
            "full_call": full_call,
        }),
        NormalizedAction::AllInAsBet { to } => json!({
            "type": "all_in_as_bet",
            "to": to,
        }),
        NormalizedAction::AllInAsRaise {
            to,
            raise_amount,
            full_raise,
        } => json!({
            "type": "all_in_as_raise",
            "to": to,
            "raise_amount": raise_amount,
            "full_raise": full_raise,
        }),
    }
}

fn action_log_entry_to_json(entry: &EngineActionLogEntry) -> JsonValue {
    json!({
        "street": street_label(entry.street),
        "seat": entry.seat,
        "action": normalized_action_to_json(&entry.action),
        "price_to_call_before": entry.price_to_call_before,
        "current_bet_to_match_after": entry.current_bet_to_match_after,
    })
}

fn player_state_to_json(player: &EnginePlayerState) -> JsonValue {
    json!({
        "seat": player.seat,
        "player_id": player.player_id,
        "stack": player.stack,
        "committed_this_round": player.committed_this_round,
        "committed_total": player.committed_total,
        "status": player_status_label(player.status),
        "has_acted_this_round": player.has_acted_this_round,
    })
}

fn pot_to_json(pot: &EnginePot) -> JsonValue {
    json!({
        "amount": pot.amount,
        "eligible": pot.eligible,
    })
}

fn pots_to_json(pots: &EnginePots) -> JsonValue {
    let sides: Vec<JsonValue> = pots.sides.iter().map(pot_to_json).collect();
    json!({
        "main": pot_to_json(&pots.main),
        "sides": sides,
    })
}

fn hand_config_to_json(cfg: &HandConfig) -> JsonValue {
    json!({
        "stakes": {
            "small_blind": cfg.stakes.small_blind,
            "big_blind": cfg.stakes.big_blind,
            "ante": cfg.stakes.ante,
        },
        "button": cfg.button,
        "small_blind_seat": cfg.small_blind_seat,
        "big_blind_seat": cfg.big_blind_seat,
        "check_raise_allowed": cfg.check_raise_allowed,
    })
}

fn betting_state_to_json(state: &BettingState) -> JsonValue {
    let players: Vec<JsonValue> = state.players.iter().map(player_state_to_json).collect();
    let pending: Vec<_> = state.pending_to_match.clone();
    let action_log: Vec<JsonValue> = state
        .action_log
        .0
        .iter()
        .map(action_log_entry_to_json)
        .collect();

    json!({
        "street": street_label(state.street),
        "button": state.button,
        "first_to_act": state.first_to_act,
        "to_act": state.to_act,
        "current_bet_to_match": state.current_bet_to_match,
        "last_full_raise_amount": state.last_full_raise_amount,
        "last_aggressor": state.last_aggressor,
        "voluntary_bet_opened": state.voluntary_bet_opened,
        "players": players,
        "pots": pots_to_json(&state.pots),
        "hand_config": hand_config_to_json(&state.cfg),
        "pending_to_match": pending,
        "betting_locked_all_in": state.betting_locked_all_in,
        "action_log": action_log,
    })
}

fn player_action_msg_to_json<C>(msg: &AnyPlayerActionMsg<C>) -> JsonValue
where
    C: CurveGroup,
{
    match msg {
        AnyPlayerActionMsg::Preflop(action) => json!({
            "street": "preflop",
            "action": player_bet_action_to_json(&action.action),
        }),
        AnyPlayerActionMsg::Flop(action) => json!({
            "street": "flop",
            "action": player_bet_action_to_json(&action.action),
        }),
        AnyPlayerActionMsg::Turn(action) => json!({
            "street": "turn",
            "action": player_bet_action_to_json(&action.action),
        }),
        AnyPlayerActionMsg::River(action) => json!({
            "street": "river",
            "action": player_bet_action_to_json(&action.action),
        }),
    }
}

fn betting_phase_payload<C>(betting: &BettingSnapshot<C>) -> anyhow::Result<JsonValue>
where
    C: CurveGroup,
{
    let last_events: Vec<JsonValue> = betting
        .last_events
        .iter()
        .map(player_action_msg_to_json)
        .collect();

    Ok(json!({
        "state": betting_state_to_json(&betting.state),
        "last_events": last_events,
    }))
}

fn reveals_phase_payload<C>(reveals: &RevealsSnapshot<C>) -> anyhow::Result<JsonValue>
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: CanonicalSerialize,
{
    let revealed_holes = reveals
        .revealed_holes
        .iter()
        .map(|(&seat, hand)| {
            let hole_ciphertexts = hand
                .hole_ciphertexts
                .iter()
                .map(player_ciphertext_to_json)
                .collect::<anyhow::Result<Vec<_>>>()?;

            Ok(json!({
                "seat": seat,
                "hole": hand.hole,
                "hole_ciphertexts": hole_ciphertexts,
                "best_five": hand.best_five,
                "best_category": hand_category_label(hand.best_category),
                "best_tiebreak": hand.best_tiebreak,
                "best_score": hand.best_score,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(json!({
        "board": reveals.board.clone(),
        "revealed_holes": revealed_holes,
    }))
}

fn serialize_player_stacks(stacks: &PlayerStacks) -> JsonValue {
    let entries: Vec<JsonValue> = stacks
        .iter()
        .map(|(&seat, info)| {
            json!({
                "seat": seat,
                "player_id": info.player_id,
                "starting_stack": info.starting_stack,
                "committed_blind": info.committed_blind,
                "status": player_status_label(info.status),
            })
        })
        .collect();
    JsonValue::from(entries)
}

fn player_status_label(status: EnginePlayerStatus) -> &'static str {
    match status {
        EnginePlayerStatus::Active => "active",
        EnginePlayerStatus::Folded => "folded",
        EnginePlayerStatus::AllIn => "all_in",
        EnginePlayerStatus::SittingOut => "sitting_out",
    }
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

fn cast_sequence(sequence: SnapshotSeq) -> anyhow::Result<i32> {
    i32::try_from(sequence).map_err(|_| anyhow!("snapshot sequence {} exceeds i32::MAX", sequence))
}

pub(super) async fn persist_prepared_snapshot(
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
