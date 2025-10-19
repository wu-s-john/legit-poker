use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockWriteGuard};

use ark_ec::CurveGroup;
use thiserror::Error;

use crate::engine::nl::actions::PlayerBetAction;
use crate::engine::nl::legals::{legal_actions_for, LegalActions};
use crate::engine::nl::types::{PlayerId, PlayerStatus, SeatId};
use crate::ledger::actor::{AnyActor, PlayerActor, ShufflerActor};
use crate::ledger::messages::{
    AnyGameMessage, AnyMessageEnvelope, GameBlindingDecryptionMessage,
    GamePartialUnblindingShareMessage, GameShowdownMessage, GameShuffleMessage,
};
use crate::ledger::snapshot::{
    AnyTableSnapshot, CardDestination, PlayerIdentity, PlayerRoster, PlayerStacks, SeatingMap,
    ShufflerRoster, TableAtDealing, TableAtShowdown, TableAtShuffling,
};
use crate::ledger::state::LedgerState;
use crate::ledger::types::{EntityKind, GameId, HandId, NonceKey, ShufflerId};
use crate::showdown::choose_best5_from7;

pub trait Verifier<C>
where
    C: CurveGroup,
{
    fn verify(
        &self,
        hand_id: HandId,
        envelope: AnyMessageEnvelope<C>,
    ) -> Result<AnyMessageEnvelope<C>, VerifyError>;
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("unauthorized actor")]
    Unauthorized,
    #[error("invalid signature")]
    BadSignature,
    #[error("phase mismatch")]
    PhaseMismatch,
    #[error("nonce conflict")]
    NonceConflict,
    #[error("invalid message")]
    InvalidMessage,
}

pub trait SignatureValidator<C: CurveGroup>: Send + Sync {
    fn verify(&self, public_key: &C, transcript: &[u8], signature: &[u8]) -> bool;
}

#[derive(Debug, Default)]
pub struct TranscriptSignatureValidator;

impl<C: CurveGroup> SignatureValidator<C> for TranscriptSignatureValidator {
    fn verify(&self, _public_key: &C, transcript: &[u8], signature: &[u8]) -> bool {
        signature == transcript
    }
}

pub struct LedgerVerifier<C: CurveGroup> {
    state: Arc<LedgerState<C>>,
    signature: Arc<dyn SignatureValidator<C>>,
    nonces: RwLock<HashMap<NonceKey, u64>>,
}

impl<C: CurveGroup> LedgerVerifier<C> {
    pub fn new(state: Arc<LedgerState<C>>) -> Self {
        Self::with_signature_validator(state, Arc::new(TranscriptSignatureValidator::default()))
    }

    pub fn with_signature_validator(
        state: Arc<LedgerState<C>>,
        signature: Arc<dyn SignatureValidator<C>>,
    ) -> Self {
        Self {
            state,
            signature,
            nonces: RwLock::new(HashMap::new()),
        }
    }
}

impl<C: CurveGroup> Verifier<C> for LedgerVerifier<C> {
    fn verify(
        &self,
        hand_id: HandId,
        envelope: AnyMessageEnvelope<C>,
    ) -> Result<AnyMessageEnvelope<C>, VerifyError> {
        if envelope.hand_id != hand_id {
            return Err(VerifyError::InvalidMessage);
        }

        let snapshot = self
            .state
            .tip_snapshot(hand_id)
            .map(|(_, snapshot)| snapshot)
            .ok_or(VerifyError::PhaseMismatch)?;

        let (snapshot_game_id, snapshot_hand_id) = snapshot_ids(&snapshot);
        if let Some(snapshot_hand_id) = snapshot_hand_id {
            if snapshot_hand_id != hand_id {
                return Err(VerifyError::PhaseMismatch);
            }
        }
        if envelope.game_id != snapshot_game_id {
            return Err(VerifyError::InvalidMessage);
        }

        self.signature
            .verify(
                &envelope.public_key,
                &envelope.message.transcript,
                &envelope.message.signature,
            )
            .then_some(())
            .ok_or(VerifyError::BadSignature)?;

        let (players, shufflers, seating, stacks) = snapshot_common(&snapshot);

        let actor_ctx = resolve_actor(
            players,
            shufflers,
            seating,
            &envelope.public_key,
            envelope.actor,
        )?;

        let nonce_reservation = enforce_nonce(&self.nonces, hand_id, &actor_ctx, envelope.nonce)?;

        match (&snapshot, &envelope.message.value, &actor_ctx) {
            (
                AnyTableSnapshot::Shuffling(table),
                AnyGameMessage::Shuffle(msg),
                ActorContext::Shuffler { shuffler_id, .. },
            ) => {
                let actor = ShufflerActor {
                    shuffler_id: *shuffler_id,
                };
                validate_shuffle(table, shufflers, &actor, msg)?;
            }
            (
                AnyTableSnapshot::Dealing(table),
                AnyGameMessage::Blinding(msg),
                ActorContext::Shuffler { shuffler_id, .. },
            ) => {
                let actor = ShufflerActor {
                    shuffler_id: *shuffler_id,
                };
                validate_blinding(table, seating, players, shufflers, &actor, msg)?;
            }
            (
                AnyTableSnapshot::Dealing(table),
                AnyGameMessage::PartialUnblinding(msg),
                ActorContext::Shuffler { shuffler_id, .. },
            ) => {
                let actor = ShufflerActor {
                    shuffler_id: *shuffler_id,
                };
                validate_partial_unblinding(&table, seating, &msg, &actor)?;
            }
            (
                AnyTableSnapshot::Preflop(table),
                AnyGameMessage::PlayerPreflop(msg),
                ActorContext::Player {
                    seat, player_id, ..
                },
            ) => {
                let actor = PlayerActor {
                    seat_id: *seat,
                    player_id: *player_id,
                };
                validate_player_action::<C>(&table.betting.state, stacks, &actor, &msg.action)?;
            }
            (
                AnyTableSnapshot::Flop(table),
                AnyGameMessage::PlayerFlop(msg),
                ActorContext::Player {
                    seat, player_id, ..
                },
            ) => {
                let actor = PlayerActor {
                    seat_id: *seat,
                    player_id: *player_id,
                };
                validate_player_action::<C>(&table.betting.state, stacks, &actor, &msg.action)?;
            }
            (
                AnyTableSnapshot::Turn(table),
                AnyGameMessage::PlayerTurn(msg),
                ActorContext::Player {
                    seat, player_id, ..
                },
            ) => {
                let actor = PlayerActor {
                    seat_id: *seat,
                    player_id: *player_id,
                };
                validate_player_action::<C>(&table.betting.state, stacks, &actor, &msg.action)?;
            }
            (
                AnyTableSnapshot::River(table),
                AnyGameMessage::PlayerRiver(msg),
                ActorContext::Player {
                    seat, player_id, ..
                },
            ) => {
                let actor = PlayerActor {
                    seat_id: *seat,
                    player_id: *player_id,
                };
                validate_player_action::<C>(&table.betting.state, stacks, &actor, &msg.action)?;
            }
            (
                AnyTableSnapshot::Showdown(table),
                AnyGameMessage::Showdown(msg),
                ActorContext::Player {
                    seat, player_id, ..
                },
            ) => {
                let actor = PlayerActor {
                    seat_id: *seat,
                    player_id: *player_id,
                };
                validate_showdown(&table, seating, players, &actor, &msg)?;
            }
            (AnyTableSnapshot::Complete(_), _, _) => return Err(VerifyError::PhaseMismatch),
            _ => return Err(VerifyError::PhaseMismatch),
        }

        nonce_reservation.commit();

        Ok(envelope)
    }
}

fn snapshot_common<'a, C: CurveGroup>(
    snapshot: &'a AnyTableSnapshot<C>,
) -> (
    &'a PlayerRoster<C>,
    &'a ShufflerRoster<C>,
    &'a SeatingMap,
    &'a PlayerStacks,
) {
    match snapshot {
        AnyTableSnapshot::Shuffling(table) => (
            table.players.as_ref(),
            table.shufflers.as_ref(),
            table.seating.as_ref(),
            table.stacks.as_ref(),
        ),
        AnyTableSnapshot::Dealing(table) => (
            table.players.as_ref(),
            table.shufflers.as_ref(),
            table.seating.as_ref(),
            table.stacks.as_ref(),
        ),
        AnyTableSnapshot::Preflop(table) => (
            table.players.as_ref(),
            table.shufflers.as_ref(),
            table.seating.as_ref(),
            table.stacks.as_ref(),
        ),
        AnyTableSnapshot::Flop(table) => (
            table.players.as_ref(),
            table.shufflers.as_ref(),
            table.seating.as_ref(),
            table.stacks.as_ref(),
        ),
        AnyTableSnapshot::Turn(table) => (
            table.players.as_ref(),
            table.shufflers.as_ref(),
            table.seating.as_ref(),
            table.stacks.as_ref(),
        ),
        AnyTableSnapshot::River(table) => (
            table.players.as_ref(),
            table.shufflers.as_ref(),
            table.seating.as_ref(),
            table.stacks.as_ref(),
        ),
        AnyTableSnapshot::Showdown(table) => (
            table.players.as_ref(),
            table.shufflers.as_ref(),
            table.seating.as_ref(),
            table.stacks.as_ref(),
        ),
        AnyTableSnapshot::Complete(table) => (
            table.players.as_ref(),
            table.shufflers.as_ref(),
            table.seating.as_ref(),
            table.stacks.as_ref(),
        ),
    }
}

fn snapshot_ids<C: CurveGroup>(snapshot: &AnyTableSnapshot<C>) -> (GameId, Option<HandId>) {
    match snapshot {
        AnyTableSnapshot::Shuffling(table) => (table.game_id, table.hand_id),
        AnyTableSnapshot::Dealing(table) => (table.game_id, table.hand_id),
        AnyTableSnapshot::Preflop(table) => (table.game_id, table.hand_id),
        AnyTableSnapshot::Flop(table) => (table.game_id, table.hand_id),
        AnyTableSnapshot::Turn(table) => (table.game_id, table.hand_id),
        AnyTableSnapshot::River(table) => (table.game_id, table.hand_id),
        AnyTableSnapshot::Showdown(table) => (table.game_id, table.hand_id),
        AnyTableSnapshot::Complete(table) => (table.game_id, table.hand_id),
    }
}

enum ActorContext<'a, C: CurveGroup> {
    Player {
        seat: SeatId,
        player_id: PlayerId,
        identity: &'a PlayerIdentity<C>,
    },
    Shuffler {
        shuffler_id: ShufflerId,
    },
}

impl<'a, C: CurveGroup> ActorContext<'a, C> {
    fn entity_kind(&self) -> EntityKind {
        match self {
            ActorContext::Player { .. } => EntityKind::Player,
            ActorContext::Shuffler { .. } => EntityKind::Shuffler,
        }
    }

    fn entity_id(&self) -> i64 {
        match self {
            ActorContext::Player { player_id, .. } => *player_id as i64,
            ActorContext::Shuffler { shuffler_id } => *shuffler_id,
        }
    }

    fn initial_nonce(&self) -> Option<u64> {
        match self {
            ActorContext::Player { identity, .. } => Some(identity.nonce),
            ActorContext::Shuffler { .. } => None,
        }
    }
}

fn resolve_actor<'a, C: CurveGroup>(
    players: &'a PlayerRoster<C>,
    shufflers: &'a ShufflerRoster<C>,
    seating: &'a SeatingMap,
    public_key: &C,
    actor: AnyActor,
) -> Result<ActorContext<'a, C>, VerifyError> {
    match actor {
        AnyActor::Player { seat_id, player_id } => {
            let identity = players.get(&player_id).ok_or(VerifyError::Unauthorized)?;
            if identity.seat != seat_id {
                return Err(VerifyError::Unauthorized);
            }
            if seating
                .get(&seat_id)
                .copied()
                .flatten()
                .filter(|pid| *pid == player_id)
                .is_none()
            {
                return Err(VerifyError::Unauthorized);
            }
            if identity.public_key != *public_key {
                return Err(VerifyError::Unauthorized);
            }
            Ok(ActorContext::Player {
                seat: seat_id,
                player_id,
                identity,
            })
        }
        AnyActor::Shuffler { shuffler_id } => {
            let identity = shufflers
                .get(&shuffler_id)
                .ok_or(VerifyError::Unauthorized)?;
            if identity.public_key != *public_key {
                return Err(VerifyError::Unauthorized);
            }
            Ok(ActorContext::Shuffler { shuffler_id })
        }
        AnyActor::None => Err(VerifyError::Unauthorized),
    }
}

fn enforce_nonce<'a, C: CurveGroup>(
    cache: &'a RwLock<HashMap<NonceKey, u64>>,
    hand_id: HandId,
    actor_ctx: &ActorContext<C>,
    nonce: u64,
) -> Result<NonceReservation<'a>, VerifyError> {
    let key = NonceKey {
        hand_id,
        entity_kind: actor_ctx.entity_kind(),
        entity_id: actor_ctx.entity_id(),
    };
    let guard = cache.write().expect("nonce cache poisoned");
    let baseline = guard
        .get(&key)
        .copied()
        .or_else(|| actor_ctx.initial_nonce());
    let expected = baseline.map(|last| last.saturating_add(1)).unwrap_or(0);
    if nonce != expected {
        return Err(VerifyError::NonceConflict);
    }
    Ok(NonceReservation { guard, key, nonce })
}

struct NonceReservation<'a> {
    guard: RwLockWriteGuard<'a, HashMap<NonceKey, u64>>,
    key: NonceKey,
    nonce: u64,
}

impl<'a> NonceReservation<'a> {
    fn commit(mut self) {
        self.guard.insert(self.key, self.nonce);
    }
}

fn validate_shuffle<C: CurveGroup>(
    table: &TableAtShuffling<C>,
    _shufflers: &ShufflerRoster<C>,
    actor: &ShufflerActor,
    message: &GameShuffleMessage<C>,
) -> Result<(), VerifyError> {
    let expected_order = &table.shuffling.expected_order;
    let next_index = table.shuffling.steps.len();
    if next_index >= expected_order.len() {
        return Err(VerifyError::InvalidMessage);
    }
    if usize::from(message.turn_index) != next_index {
        return Err(VerifyError::InvalidMessage);
    }
    if expected_order[next_index] != actor.shuffler_id {
        return Err(VerifyError::InvalidMessage);
    }
    if next_index > 0 && table.shuffling.final_deck != message.deck_in {
        return Err(VerifyError::InvalidMessage);
    }
    Ok(())
}

fn validate_blinding<C: CurveGroup>(
    table: &TableAtDealing<C>,
    seating: &SeatingMap,
    players: &PlayerRoster<C>,
    shufflers: &ShufflerRoster<C>,
    actor: &ShufflerActor,
    message: &GameBlindingDecryptionMessage<C>,
) -> Result<(), VerifyError> {
    let Some(card_ref) = message.card_in_deck_position.checked_add(1) else {
        return Err(VerifyError::InvalidMessage);
    };
    let destination = table
        .dealing
        .card_plan
        .get(&card_ref)
        .ok_or(VerifyError::InvalidMessage)?;
    let (seat, hole_index) = match destination {
        CardDestination::Hole { seat, hole_index } => (seat, *hole_index),
        _ => return Err(VerifyError::InvalidMessage),
    };
    if table
        .dealing
        .player_blinding_contribs
        .contains_key(&(actor.shuffler_id, *seat, hole_index))
    {
        return Err(VerifyError::InvalidMessage);
    }
    let player_id = seating
        .get(&seat)
        .copied()
        .flatten()
        .ok_or(VerifyError::InvalidMessage)?;
    let player_identity = players.get(&player_id).ok_or(VerifyError::InvalidMessage)?;
    if player_identity.public_key != message.target_player_public_key {
        return Err(VerifyError::InvalidMessage);
    }
    let _shuffler_identity = shufflers
        .get(&actor.shuffler_id)
        .ok_or(VerifyError::InvalidMessage)?;
    Ok(())
}

fn validate_partial_unblinding<C: CurveGroup>(
    table: &TableAtDealing<C>,
    seating: &SeatingMap,
    message: &GamePartialUnblindingShareMessage<C>,
    actor: &ShufflerActor,
) -> Result<(), VerifyError> {
    let Some(card_ref) = message.card_in_deck_position.checked_add(1) else {
        return Err(VerifyError::InvalidMessage);
    };
    let destination = table
        .dealing
        .card_plan
        .get(&card_ref)
        .ok_or(VerifyError::InvalidMessage)?;
    let (seat, hole_index) = match destination {
        CardDestination::Hole { seat, hole_index } => (seat, *hole_index),
        _ => return Err(VerifyError::InvalidMessage),
    };
    if seating.get(&seat).copied().flatten().is_none() {
        return Err(VerifyError::InvalidMessage);
    }
    let player_id = seating
        .get(&seat)
        .copied()
        .flatten()
        .ok_or(VerifyError::InvalidMessage)?;
    let player_identity = table
        .players
        .get(&player_id)
        .ok_or(VerifyError::InvalidMessage)?;
    if player_identity.public_key != message.target_player_public_key {
        return Err(VerifyError::InvalidMessage);
    }
    if let Some(existing) = table
        .dealing
        .player_unblinding_shares
        .get(&(*seat, hole_index))
    {
        if existing.contains_key(&message.share.member_index)
            || existing.len() >= table.shufflers.len()
        {
            return Err(VerifyError::InvalidMessage);
        }
    }
    // Ensure member index within bounds
    if message.share.member_index >= table.shufflers.len() {
        return Err(VerifyError::InvalidMessage);
    }

    let expected_index = table
        .shufflers
        .keys()
        .enumerate()
        .find_map(|(idx, shuffler_id)| {
            if *shuffler_id == actor.shuffler_id {
                Some(idx)
            } else {
                None
            }
        })
        .ok_or(VerifyError::InvalidMessage)?;
    if expected_index != message.share.member_index {
        return Err(VerifyError::InvalidMessage);
    }

    Ok(())
}

fn validate_player_action<C: CurveGroup>(
    state: &crate::engine::nl::state::BettingState,
    stacks: &PlayerStacks,
    actor: &PlayerActor,
    action: &PlayerBetAction,
) -> Result<(), VerifyError> {
    let seat_entry = stacks
        .get(&actor.seat_id)
        .ok_or(VerifyError::Unauthorized)?;
    if seat_entry.status != PlayerStatus::Active && seat_entry.status != PlayerStatus::AllIn {
        return Err(VerifyError::InvalidMessage);
    }
    let legals = legal_actions_for(state, actor.seat_id);
    if !is_action_legal(action, &legals) {
        return Err(VerifyError::InvalidMessage);
    }
    Ok(())
}

fn is_action_legal(action: &PlayerBetAction, legals: &LegalActions) -> bool {
    match action {
        PlayerBetAction::Fold => legals.may_fold,
        PlayerBetAction::Check => legals.may_check,
        PlayerBetAction::Call => legals.call_amount.is_some(),
        PlayerBetAction::BetTo { to } => legals
            .bet_to_range
            .as_ref()
            .map(|range| range.contains(to))
            .unwrap_or(false),
        PlayerBetAction::RaiseTo { to } => legals
            .raise_to_range
            .as_ref()
            .map(|range| range.contains(to))
            .unwrap_or(false),
        PlayerBetAction::AllIn => {
            legals.call_amount.is_some()
                || legals.bet_to_range.is_some()
                || legals.raise_to_range.is_some()
        }
    }
}

fn validate_showdown<C>(
    table: &TableAtShowdown<C>,
    seating: &SeatingMap,
    players: &PlayerRoster<C>,
    actor: &PlayerActor,
    message: &GameShowdownMessage<C>,
) -> Result<(), VerifyError>
where
    C: CurveGroup,
{
    if table.reveals.revealed_holes.contains_key(&actor.seat_id) {
        return Err(VerifyError::InvalidMessage);
    }
    let player_id = seating
        .get(&actor.seat_id)
        .copied()
        .flatten()
        .ok_or(VerifyError::InvalidMessage)?;
    if player_id != actor.player_id {
        return Err(VerifyError::Unauthorized);
    }
    let _player_identity = players.get(&player_id).ok_or(VerifyError::InvalidMessage)?;
    let mut seen_cards = [0u8; 2];
    for (idx, (&deck_pos, provided_cipher)) in message
        .card_in_deck_position
        .iter()
        .zip(message.hole_ciphertexts.iter())
        .enumerate()
    {
        let Some(card_ref) = deck_pos.checked_add(1) else {
            return Err(VerifyError::InvalidMessage);
        };
        let destination = table
            .dealing
            .card_plan
            .get(&card_ref)
            .ok_or(VerifyError::InvalidMessage)?;
        let (seat, hole_index) = match destination {
            CardDestination::Hole { seat, hole_index } => (seat, *hole_index),
            _ => return Err(VerifyError::InvalidMessage),
        };
        if *seat != actor.seat_id || hole_index != idx as u8 {
            return Err(VerifyError::InvalidMessage);
        }
        let stored_cipher = table
            .dealing
            .player_ciphertexts
            .get(&(*seat, hole_index))
            .ok_or(VerifyError::InvalidMessage)?;
        if stored_cipher.blinded_base != provided_cipher.blinded_base
            || stored_cipher.player_unblinding_helper != provided_cipher.player_unblinding_helper
        {
            return Err(VerifyError::InvalidMessage);
        }

        table
            .dealing
            .player_unblinding_combined
            .get(&(*seat, hole_index))
            .ok_or(VerifyError::InvalidMessage)?;

        seen_cards[idx] = deck_pos;
    }

    // Additional sanity: ensure we can derive best 5 (board + hole)
    let mut seven_cards = [0u8; 7];
    let board = &table.reveals.board;
    if board.len() != 5 {
        return Err(VerifyError::InvalidMessage);
    }
    seven_cards[..5].copy_from_slice(&board[..5]);
    seven_cards[5] = seen_cards[0] + 1;
    seven_cards[6] = seen_cards[1] + 1;
    let _ = choose_best5_from7(seven_cards);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaum_pedersen::ChaumPedersenProof;
    use crate::engine::nl::state::BettingState;
    use crate::engine::nl::types::{ActionLog, HandConfig, PlayerState, PlayerStatus, TableStakes};
    use crate::ledger::hash::LedgerHasher;
    use crate::ledger::messages::{GamePlayerMessage, PreflopStreet};
    use crate::ledger::snapshot::{
        build_default_card_plan, BettingSnapshot, CardPlan, DealingSnapshot, DealtCard,
        RevealsSnapshot, ShufflerIdentity, ShufflingSnapshot, ShufflingStep, SnapshotStatus,
        TableSnapshot,
    };
    use crate::ledger::types::{GameId, StateHash};
    use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
    use crate::shuffling::player_decryption::{
        PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
    };
    use crate::signing::Signable;
    use ark_bn254::G1Projective as Curve;
    use ark_ff::Zero;
    use std::collections::BTreeMap;

    const GAME_ID: GameId = 1;
    const HAND_ID: HandId = 99;
    const PLAYER_ID: PlayerId = 7;
    const PLAYER_SEAT: SeatId = 1;
    const SHUFFLER_ID: ShufflerId = 3;
    const SECOND_SHUFFLER_ID: ShufflerId = 7;

    #[test]
    fn rejects_invalid_signatures() {
        let harness = TestHarness::preflop();
        let mut envelope = harness.player_envelope();
        envelope.message.signature.clear();
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::BadSignature)));
    }

    #[test]
    fn rejects_unauthorized_actors() {
        let mut harness = TestHarness::base(TestPhase::Preflop);
        harness.players.clear();
        harness.push_snapshot();
        let envelope = harness.player_envelope();
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::Unauthorized)));
    }

    #[test]
    fn rejects_phase_turn_mismatches() {
        let harness = TestHarness::shuffling();
        let envelope = harness.player_envelope();
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::PhaseMismatch)));
    }

    #[test]
    fn rejects_stale_or_future_nonces() {
        let harness = TestHarness::preflop();
        let verifier = harness.verifier();
        let envelope = harness.player_envelope();
        let _ = verifier.verify(HAND_ID, envelope.clone()).unwrap();

        // stale (duplicate)
        let result = verifier.verify(HAND_ID, envelope.clone());
        assert!(matches!(result, Err(VerifyError::NonceConflict)));

        // future (skip)
        let mut future = envelope.clone();
        future.nonce = 3;
        let result = verifier.verify(HAND_ID, future);
        assert!(matches!(result, Err(VerifyError::NonceConflict)));
    }

    #[test]
    fn catches_malformed_payloads() {
        let harness = TestHarness::dealing();
        let mut envelope = harness.blinding_envelope();
        if let AnyGameMessage::Blinding(ref mut msg) = envelope.message.value {
            msg.card_in_deck_position = 200; // invalid
        }
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));
    }

    #[test]
    fn rejects_mismatched_hand_id() {
        let harness = TestHarness::preflop();
        let mut envelope = harness.player_envelope();
        envelope.hand_id = HAND_ID + 1;
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));
    }

    #[test]
    fn rejects_mismatched_game_id() {
        let harness = TestHarness::preflop();
        let mut envelope = harness.player_envelope();
        envelope.game_id = GAME_ID + 1;
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));
    }

    #[test]
    fn does_not_consume_nonce_on_invalid_message() {
        let mut harness = TestHarness::preflop_with_to_act(2);
        let envelope = harness.player_envelope();
        let verifier = harness.verifier();

        let result = verifier.verify(HAND_ID, envelope.clone());
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));

        harness.override_to_act = None;
        harness.push_snapshot();

        let result = verifier.verify(HAND_ID, envelope);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_valid_envelopes() {
        let harness = TestHarness::preflop();
        let envelope = harness.player_envelope();
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope.clone());
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_out_of_turn_betting() {
        let harness = TestHarness::preflop_with_to_act(2);
        let envelope = harness.player_envelope();
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));
    }

    #[test]
    fn rejects_partial_unblinding_from_wrong_member_index() {
        let mut harness = TestHarness::base(TestPhase::Dealing);
        harness.shufflers.insert(
            SECOND_SHUFFLER_ID,
            ShufflerIdentity {
                public_key: Curve::zero(),
                aggregated_public_key: Curve::zero(),
            },
        );
        harness.push_snapshot();
        let envelope = harness.partial_unblinding_envelope(SECOND_SHUFFLER_ID, 0, 0);
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));
    }

    #[test]
    fn accepts_partial_unblinding_with_matching_member_index() {
        let mut harness = TestHarness::base(TestPhase::Dealing);
        harness.shufflers.insert(
            SECOND_SHUFFLER_ID,
            ShufflerIdentity {
                public_key: Curve::zero(),
                aggregated_public_key: Curve::zero(),
            },
        );
        harness.push_snapshot();
        let envelope = harness.partial_unblinding_envelope(SECOND_SHUFFLER_ID, 1, 0);
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_shuffle_not_matching_sequence() {
        let mut harness = TestHarness::base(TestPhase::Shuffling);
        harness.shufflers.insert(
            SECOND_SHUFFLER_ID,
            ShufflerIdentity {
                public_key: Curve::zero(),
                aggregated_public_key: Curve::zero(),
            },
        );
        harness.override_shuffler_order(vec![SECOND_SHUFFLER_ID, SHUFFLER_ID]);
        harness.push_snapshot();
        let verifier = harness.verifier();
        let envelope = harness.shuffle_envelope(SHUFFLER_ID);
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));
    }

    #[test]
    fn rejects_shuffle_with_wrong_turn_index() {
        let mut harness = TestHarness::base(TestPhase::Shuffling);
        harness.push_snapshot();
        let shuffler_identity = harness
            .shufflers
            .get(&SHUFFLER_ID)
            .expect("primary shuffler identity to exist")
            .public_key
            .clone();
        let deck_in = sample_deck();
        let deck_out = deck_in.clone();
        let message = AnyGameMessage::Shuffle(GameShuffleMessage::new(
            deck_in,
            deck_out,
            sample_shuffle_proof(),
            1,
        ));
        let envelope = build_envelope(
            HAND_ID,
            message,
            AnyActor::Shuffler {
                shuffler_id: SHUFFLER_ID,
            },
            shuffler_identity,
            0,
        );
        let verifier = harness.verifier();
        let result = verifier.verify(HAND_ID, envelope);
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));
    }

    // --- Test harness ----------------------------------------------------------------------

    struct TestHarness {
        state: Arc<LedgerState<Curve>>,
        hasher: Arc<dyn LedgerHasher + Send + Sync>,
        players: PlayerRoster<Curve>,
        shufflers: ShufflerRoster<Curve>,
        seating: SeatingMap,
        stacks: PlayerStacks,
        phase: TestPhase,
        override_to_act: Option<SeatId>,
        shuffler_order_override: Option<Vec<ShufflerId>>,
    }

    enum TestPhase {
        Shuffling,
        Dealing,
        Preflop,
    }

    impl TestHarness {
        fn shuffling() -> Self {
            let mut harness = Self::base(TestPhase::Shuffling);
            harness.push_snapshot();
            harness
        }

        fn dealing() -> Self {
            let mut harness = Self::base(TestPhase::Dealing);
            harness.push_snapshot();
            harness
        }

        fn preflop() -> Self {
            let mut harness = Self::base(TestPhase::Preflop);
            harness.push_snapshot();
            harness
        }

        fn preflop_with_to_act(to_act: SeatId) -> Self {
            let mut harness = Self::base(TestPhase::Preflop);
            harness.override_to_act = Some(to_act);
            harness.push_snapshot();
            harness
        }

        fn base(phase: TestPhase) -> Self {
            let state = Arc::new(LedgerState::<Curve>::new());
            let hasher = state.hasher();
            let mut players = PlayerRoster::new();
            players.insert(
                PLAYER_ID,
                PlayerIdentity {
                    public_key: Curve::zero(),
                    nonce: 0,
                    seat: PLAYER_SEAT,
                },
            );
            let mut shufflers = ShufflerRoster::new();
            shufflers.insert(
                SHUFFLER_ID,
                ShufflerIdentity {
                    public_key: Curve::zero(),
                    aggregated_public_key: Curve::zero(),
                },
            );
            let mut seating = SeatingMap::new();
            seating.insert(PLAYER_SEAT, Some(PLAYER_ID));
            let mut stacks = PlayerStacks::new();
            stacks.insert(
                PLAYER_SEAT,
                crate::ledger::snapshot::PlayerStackInfo {
                    seat: PLAYER_SEAT,
                    player_id: Some(PLAYER_ID),
                    starting_stack: 100,
                    committed_blind: 0,
                    status: PlayerStatus::Active,
                },
            );

            Self {
                state,
                hasher,
                players,
                shufflers,
                seating,
                stacks,
                phase,
                override_to_act: None,
                shuffler_order_override: None,
            }
        }

        fn verifier(&self) -> LedgerVerifier<Curve> {
            LedgerVerifier::new(Arc::clone(&self.state))
        }

        fn player_envelope(&self) -> AnyMessageEnvelope<Curve> {
            let message = AnyGameMessage::PlayerPreflop(
                GamePlayerMessage::<PreflopStreet, Curve>::new(PlayerBetAction::Check),
            );
            build_envelope(
                HAND_ID,
                message,
                AnyActor::Player {
                    seat_id: PLAYER_SEAT,
                    player_id: PLAYER_ID,
                },
                Curve::zero(),
                1,
            )
        }

        fn blinding_envelope(&self) -> AnyMessageEnvelope<Curve> {
            let target_player_public_key = self
                .players
                .get(&PLAYER_ID)
                .expect("player identity")
                .public_key
                .clone();
            let message = AnyGameMessage::Blinding(GameBlindingDecryptionMessage::new(
                0,
                dummy_blinding_share(),
                target_player_public_key,
            ));
            build_envelope(
                HAND_ID,
                message,
                AnyActor::Shuffler {
                    shuffler_id: SHUFFLER_ID,
                },
                Curve::zero(),
                0,
            )
        }

        fn partial_unblinding_envelope(
            &self,
            shuffler_id: ShufflerId,
            member_index: usize,
            nonce: u64,
        ) -> AnyMessageEnvelope<Curve> {
            let message =
                AnyGameMessage::PartialUnblinding(GamePartialUnblindingShareMessage::new(
                    0,
                    PartialUnblindingShare {
                        share: Curve::zero(),
                        member_index,
                    },
                    self.players
                        .get(&PLAYER_ID)
                        .expect("player identity")
                        .public_key
                        .clone(),
                ));
            build_envelope(
                HAND_ID,
                message,
                AnyActor::Shuffler { shuffler_id },
                Curve::zero(),
                nonce,
            )
        }

        fn push_snapshot(&mut self) {
            match self.phase {
                TestPhase::Shuffling => self.push_shuffling(),
                TestPhase::Dealing => self.push_dealing(),
                TestPhase::Preflop => self.push_preflop(),
            }
        }

        fn expected_shuffler_order(&self) -> Vec<ShufflerId> {
            if let Some(order) = &self.shuffler_order_override {
                return order.clone();
            }
            self.shufflers.keys().copied().collect()
        }

        fn override_shuffler_order(&mut self, order: Vec<ShufflerId>) {
            self.shuffler_order_override = Some(order);
        }

        fn push_shuffling(&mut self) {
            let mut snapshot = TableSnapshot {
                game_id: GAME_ID,
                hand_id: Some(HAND_ID),
                sequence: 0,
                cfg: Arc::new(default_hand_config()),
                shufflers: Arc::new(self.shufflers.clone()),
                players: Arc::new(self.players.clone()),
                seating: Arc::new(self.seating.clone()),
                stacks: Arc::new(self.stacks.clone()),
                previous_hash: None,
                state_hash: StateHash::default(),
                status: SnapshotStatus::Success,
                shuffling: ShufflingSnapshot {
                    initial_deck: sample_deck(),
                    steps: Vec::new(),
                    final_deck: sample_deck(),
                    expected_order: self.expected_shuffler_order(),
                },
                dealing: (),
                betting: (),
                reveals: (),
            };
            snapshot.initialize_hash(self.hasher.as_ref());
            self.state
                .upsert_snapshot(HAND_ID, AnyTableSnapshot::Shuffling(snapshot), true);
        }

        fn push_dealing(&mut self) {
            let plan = build_default_card_plan(&default_hand_config(), &self.seating);
            let mut dealing = DealingSnapshot {
                assignments: plan
                    .iter()
                    .map(|(k, _)| {
                        (
                            *k,
                            DealtCard {
                                cipher: sample_cipher(),
                                source_index: Some((k - 1) as u8),
                            },
                        )
                    })
                    .collect(),
                player_ciphertexts: std::iter::repeat_with(|| {
                    (
                        (PLAYER_SEAT, 0u8),
                        PlayerAccessibleCiphertext {
                            blinded_base: Curve::zero(),
                            blinded_message_with_player_key: Curve::zero(),
                            player_unblinding_helper: Curve::zero(),
                            shuffler_proofs: Vec::new(),
                        },
                    )
                })
                .take(1)
                .collect(),
                player_blinding_contribs: Default::default(),
                community_decryption_shares: Default::default(),
                community_cards: Default::default(),
                card_plan: plan,
                player_unblinding_shares: Default::default(),
                player_unblinding_combined: Default::default(),
            };
            dealing
                .player_unblinding_combined
                .insert((PLAYER_SEAT, 0), Curve::zero());
            let mut snapshot = TableSnapshot {
                game_id: GAME_ID,
                hand_id: Some(HAND_ID),
                sequence: 0,
                cfg: Arc::new(default_hand_config()),
                shufflers: Arc::new(self.shufflers.clone()),
                players: Arc::new(self.players.clone()),
                seating: Arc::new(self.seating.clone()),
                stacks: Arc::new(self.stacks.clone()),
                previous_hash: None,
                state_hash: StateHash::default(),
                status: SnapshotStatus::Success,
                shuffling: ShufflingSnapshot {
                    initial_deck: sample_deck(),
                    steps: vec![ShufflingStep {
                        shuffler_public_key: Curve::zero(),
                        proof: sample_shuffle_proof(),
                    }],
                    final_deck: sample_deck(),
                    expected_order: self.expected_shuffler_order(),
                },
                dealing,
                betting: (),
                reveals: (),
            };
            snapshot.initialize_hash(self.hasher.as_ref());
            self.state
                .upsert_snapshot(HAND_ID, AnyTableSnapshot::Dealing(snapshot), true);
        }

        fn push_preflop(&mut self) {
            let mut betting_state = default_betting_state();
            if let Some(to_act) = self.override_to_act {
                betting_state.to_act = to_act;
            }
            let betting = BettingSnapshot {
                state: betting_state,
                last_events: Vec::new(),
            };
            let mut snapshot = TableSnapshot {
                game_id: GAME_ID,
                hand_id: Some(HAND_ID),
                sequence: 0,
                cfg: Arc::new(default_hand_config()),
                shufflers: Arc::new(self.shufflers.clone()),
                players: Arc::new(self.players.clone()),
                seating: Arc::new(self.seating.clone()),
                stacks: Arc::new(self.stacks.clone()),
                previous_hash: None,
                state_hash: StateHash::default(),
                status: SnapshotStatus::Success,
                shuffling: ShufflingSnapshot {
                    initial_deck: sample_deck(),
                    steps: vec![ShufflingStep {
                        shuffler_public_key: Curve::zero(),
                        proof: sample_shuffle_proof(),
                    }],
                    final_deck: sample_deck(),
                    expected_order: self.expected_shuffler_order(),
                },
                dealing: DealingSnapshot {
                    assignments: BTreeMap::new(),
                    player_ciphertexts: Default::default(),
                    player_blinding_contribs: Default::default(),
                    community_decryption_shares: Default::default(),
                    community_cards: Default::default(),
                    card_plan: CardPlan::new(),
                    player_unblinding_shares: Default::default(),
                    player_unblinding_combined: Default::default(),
                },
                betting,
                reveals: RevealsSnapshot {
                    board: Vec::from([1, 2, 3, 4, 5]),
                    revealed_holes: Default::default(),
                },
            };
            snapshot.initialize_hash(self.hasher.as_ref());
            self.state
                .upsert_snapshot(HAND_ID, AnyTableSnapshot::Preflop(snapshot), true);
        }

        fn shuffle_envelope(&self, shuffler_id: ShufflerId) -> AnyMessageEnvelope<Curve> {
            let deck_in = sample_deck();
            let deck_out = deck_in.clone();
            let turn_index = self
                .expected_shuffler_order()
                .iter()
                .position(|&id| id == shuffler_id)
                .unwrap_or(0) as u16;
            let message = AnyGameMessage::Shuffle(GameShuffleMessage::new(
                deck_in,
                deck_out,
                sample_shuffle_proof(),
                turn_index,
            ));
            let identity = self
                .shufflers
                .get(&shuffler_id)
                .expect("shuffler identity to exist");
            build_envelope(
                HAND_ID,
                message,
                AnyActor::Shuffler { shuffler_id },
                identity.public_key.clone(),
                0,
            )
        }
    }

    fn sample_cipher() -> ElGamalCiphertext<Curve> {
        ElGamalCiphertext::new(Curve::zero(), Curve::zero())
    }

    fn sample_deck() -> [ElGamalCiphertext<Curve>; DECK_SIZE] {
        std::array::from_fn(|_| sample_cipher())
    }

    fn sample_shuffle_proof() -> ShuffleProof<Curve> {
        ShuffleProof::new(
            sample_deck().to_vec(),
            vec![(sample_cipher(), <Curve as CurveGroup>::BaseField::zero(),); DECK_SIZE],
            vec![<Curve as ark_ec::PrimeGroup>::ScalarField::zero(); DECK_SIZE],
        )
        .unwrap()
    }

    fn default_hand_config() -> HandConfig {
        HandConfig {
            stakes: TableStakes {
                small_blind: 1,
                big_blind: 2,
                ante: 0,
            },
            button: 0,
            small_blind_seat: 0,
            big_blind_seat: 1,
            check_raise_allowed: true,
        }
    }

    fn default_betting_state() -> BettingState {
        BettingState {
            street: crate::engine::nl::types::Street::Preflop,
            button: 0,
            first_to_act: PLAYER_SEAT,
            to_act: PLAYER_SEAT,
            current_bet_to_match: 0,
            last_full_raise_amount: 0,
            last_aggressor: None,
            voluntary_bet_opened: false,
            players: vec![PlayerState {
                seat: PLAYER_SEAT,
                player_id: Some(PLAYER_ID),
                stack: 100,
                committed_this_round: 0,
                committed_total: 0,
                status: PlayerStatus::Active,
                has_acted_this_round: false,
            }],
            pots: crate::engine::nl::types::Pots {
                main: crate::engine::nl::types::Pot {
                    amount: 0,
                    eligible: vec![PLAYER_SEAT],
                },
                sides: Vec::new(),
            },
            cfg: default_hand_config(),
            pending_to_match: vec![PLAYER_SEAT],
            betting_locked_all_in: false,
            action_log: ActionLog::default(),
        }
    }

    fn build_envelope<C: CurveGroup>(
        hand_id: HandId,
        message: AnyGameMessage<C>,
        actor: AnyActor,
        public_key: C,
        nonce: u64,
    ) -> AnyMessageEnvelope<C> {
        let transcript = message.to_signing_bytes();
        AnyMessageEnvelope {
            hand_id,
            game_id: GAME_ID,
            actor,
            nonce,
            public_key,
            message: crate::signing::WithSignature {
                value: message,
                signature: transcript.clone(),
                transcript,
            },
        }
    }

    fn dummy_blinding_share<C: CurveGroup>() -> PlayerTargetedBlindingContribution<C> {
        PlayerTargetedBlindingContribution {
            blinding_base_contribution: C::zero(),
            blinding_combined_contribution: C::zero(),
            proof: ChaumPedersenProof {
                t_g: C::zero(),
                t_h: C::zero(),
                z: Default::default(),
            },
        }
    }
}
