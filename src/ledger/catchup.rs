use anyhow::Context;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use thiserror::Error;

use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::events;
use crate::ledger::actor::AnyActor;
use crate::ledger::hash::LedgerHasher;
use crate::ledger::messages::{AnyGameMessage, EnvelopedMessage, FinalizedAnyMessageEnvelope};
use crate::ledger::snapshot::{clone_snapshot_for_failure, AnyTableSnapshot, SnapshotStatus};
use crate::ledger::store::event::model_to_envelope;
use crate::ledger::store::snapshot::SharedSnapshotStore;
use crate::ledger::transition::apply_transition;
use crate::ledger::types::HandId;
use crate::ledger::{PlayerActor, ShufflerActor};
use crate::signing::WithSignature;

const CATCHUP_LOG_TARGET: &str = "ledger::catchup";

/// Errors that can occur during ledger catchup operations.
#[derive(Debug, Error)]
pub enum CatchupError {
    /// Failed to query the database for snapshots or messages.
    #[error("database query failed: {0}")]
    DatabaseQuery(#[from] sea_orm::DbErr),

    /// Failed to load or deserialize a snapshot from the database.
    #[error("snapshot load failed: {0}")]
    SnapshotLoad(#[source] anyhow::Error),

    /// Failed to deserialize a message from the database.
    #[error("message deserialization failed: {0}")]
    MessageDeserialization(#[source] anyhow::Error),

    /// Failed to apply a transition to the snapshot.
    #[error("transition application failed at sequence {sequence}: {source}")]
    TransitionApplication {
        sequence: i64,
        #[source]
        source: anyhow::Error,
    },

    /// Snapshot or message sequence discontinuity detected.
    #[error("sequence discontinuity: expected {expected}, found {found}")]
    Discontinuity { expected: i64, found: i64 },

    /// No snapshot found for the hand, and messages exist without a starting point.
    #[error("no snapshot found for hand {hand_id}, cannot replay {message_count} messages")]
    NoSnapshotAvailable { hand_id: HandId, message_count: usize },

    /// Failed to send result through channel (receiver dropped).
    #[error("failed to send catchup result: receiver dropped")]
    ChannelSendFailed,

    /// Generic catchup error.
    #[error("catchup failed: {0}")]
    Other(#[from] anyhow::Error),
}

impl CatchupError {
    /// Create a transition application error with sequence context.
    pub fn transition_failed(sequence: i64, source: anyhow::Error) -> Self {
        Self::TransitionApplication { sequence, source }
    }

    /// Create a discontinuity error.
    pub fn discontinuity(expected: i64, found: i64) -> Self {
        Self::Discontinuity { expected, found }
    }

    /// Create a no snapshot error.
    pub fn no_snapshot(hand_id: HandId, message_count: usize) -> Self {
        Self::NoSnapshotAvailable {
            hand_id,
            message_count,
        }
    }
}

/// Result type for catchup operations.
pub type CatchupResult<T> = Result<T, CatchupError>;

/// A request to perform catchup for a specific hand.
#[derive(Debug, Clone)]
pub struct CatchupRequest {
    /// The hand to catch up.
    pub hand_id: HandId,
    /// Optional starting sequence number (inclusive).
    /// If None, starts from the latest snapshot.
    pub from_sequence: Option<i64>,
}

/// Helper to remap a signature from one message type to another.
fn remap_signature<C, T>(
    original: &WithSignature<Vec<u8>, AnyGameMessage<C>>,
    new_value: T,
) -> WithSignature<Vec<u8>, T>
where
    C: CurveGroup,
    T: CanonicalSerialize + crate::signing::DomainSeparated,
{
    WithSignature {
        value: new_value,
        signature: original.signature.clone(),
    }
}

/// Applies a single ledger message to a snapshot, using the same dispatch
/// logic as LedgerState::apply_message.
///
/// This function matches on the message variant and snapshot phase, then
/// delegates to the appropriate strongly-typed transition handler.
fn apply_message_dispatch<C>(
    snapshot: AnyTableSnapshot<C>,
    finalized: &FinalizedAnyMessageEnvelope<C>,
    hasher: &dyn LedgerHasher,
) -> CatchupResult<AnyTableSnapshot<C>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    let sequence = finalized.snapshot_sequence_id as i64;
    let event = &finalized.envelope;

    tracing::debug!(
        target: CATCHUP_LOG_TARGET,
        sequence = sequence,
        message_type = ?event.message.value,
        "applying message to snapshot"
    );

    let result = match &event.message.value {
        AnyGameMessage::Shuffle(message) => {
            let table = match snapshot {
                AnyTableSnapshot::Shuffling(table) => table,
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("shuffle message can only be applied during shuffling phase"),
                    ))
                }
            };

            let actor = match &event.actor {
                AnyActor::Shuffler {
                    shuffler_id,
                    shuffler_key,
                } => ShufflerActor {
                    shuffler_id: *shuffler_id,
                    shuffler_key: shuffler_key.clone(),
                },
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("shuffle message must originate from a shuffler"),
                    ))
                }
            };

            let envelope = EnvelopedMessage {
                hand_id: event.hand_id,
                game_id: event.game_id,
                actor,
                nonce: event.nonce,
                public_key: event.public_key.clone(),
                message: remap_signature(&event.message, message.clone()),
            };

            apply_transition(table, &envelope, hasher)
        }
        AnyGameMessage::Blinding(message) => {
            let table = match snapshot {
                AnyTableSnapshot::Dealing(table) => table,
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("blinding decryption message can only be applied during dealing phase"),
                    ))
                }
            };

            let actor = match &event.actor {
                AnyActor::Shuffler {
                    shuffler_id,
                    shuffler_key,
                } => ShufflerActor {
                    shuffler_id: *shuffler_id,
                    shuffler_key: shuffler_key.clone(),
                },
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("blinding decryption message must originate from a shuffler"),
                    ))
                }
            };

            let envelope = EnvelopedMessage {
                hand_id: event.hand_id,
                game_id: event.game_id,
                actor,
                nonce: event.nonce,
                public_key: event.public_key.clone(),
                message: remap_signature(&event.message, message.clone()),
            };

            apply_transition(table, &envelope, hasher)
        }
        AnyGameMessage::PartialUnblinding(message) => {
            let table = match snapshot {
                AnyTableSnapshot::Dealing(table) => table,
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("partial unblinding message can only be applied during dealing phase"),
                    ))
                }
            };

            let actor = match &event.actor {
                AnyActor::Shuffler {
                    shuffler_id,
                    shuffler_key,
                } => ShufflerActor {
                    shuffler_id: *shuffler_id,
                    shuffler_key: shuffler_key.clone(),
                },
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("partial unblinding message must originate from a shuffler"),
                    ))
                }
            };

            let envelope = EnvelopedMessage {
                hand_id: event.hand_id,
                game_id: event.game_id,
                actor,
                nonce: event.nonce,
                public_key: event.public_key.clone(),
                message: remap_signature(&event.message, message.clone()),
            };

            apply_transition(table, &envelope, hasher)
        }
        AnyGameMessage::PlayerPreflop(message) => {
            let table = match snapshot {
                AnyTableSnapshot::Preflop(table) => table,
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("preflop player message can only be applied during preflop phase"),
                    ))
                }
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
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("player message must originate from a player"),
                    ))
                }
            };

            let envelope = EnvelopedMessage {
                hand_id: event.hand_id,
                game_id: event.game_id,
                actor,
                nonce: event.nonce,
                public_key: event.public_key.clone(),
                message: remap_signature(&event.message, message.clone()),
            };

            apply_transition(table, &envelope, hasher)
        }
        AnyGameMessage::PlayerFlop(message) => {
            let table = match snapshot {
                AnyTableSnapshot::Flop(table) => table,
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("flop player message can only be applied during flop phase"),
                    ))
                }
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
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("player message must originate from a player"),
                    ))
                }
            };

            let envelope = EnvelopedMessage {
                hand_id: event.hand_id,
                game_id: event.game_id,
                actor,
                nonce: event.nonce,
                public_key: event.public_key.clone(),
                message: remap_signature(&event.message, message.clone()),
            };

            apply_transition(table, &envelope, hasher)
        }
        AnyGameMessage::PlayerTurn(message) => {
            let table = match snapshot {
                AnyTableSnapshot::Turn(table) => table,
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("turn player message can only be applied during turn phase"),
                    ))
                }
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
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("player message must originate from a player"),
                    ))
                }
            };

            let envelope = EnvelopedMessage {
                hand_id: event.hand_id,
                game_id: event.game_id,
                actor,
                nonce: event.nonce,
                public_key: event.public_key.clone(),
                message: remap_signature(&event.message, message.clone()),
            };

            apply_transition(table, &envelope, hasher)
        }
        AnyGameMessage::PlayerRiver(message) => {
            let table = match snapshot {
                AnyTableSnapshot::River(table) => table,
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("river player message can only be applied during river phase"),
                    ))
                }
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
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("player message must originate from a player"),
                    ))
                }
            };

            let envelope = EnvelopedMessage {
                hand_id: event.hand_id,
                game_id: event.game_id,
                actor,
                nonce: event.nonce,
                public_key: event.public_key.clone(),
                message: remap_signature(&event.message, message.clone()),
            };

            apply_transition(table, &envelope, hasher)
        }
        AnyGameMessage::Showdown(message) => {
            let table = match snapshot {
                AnyTableSnapshot::Showdown(table) => table,
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("showdown message can only be applied during showdown phase"),
                    ))
                }
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
                _ => {
                    return Err(CatchupError::transition_failed(
                        sequence,
                        anyhow::anyhow!("showdown message must originate from a player"),
                    ))
                }
            };

            let envelope = EnvelopedMessage {
                hand_id: event.hand_id,
                game_id: event.game_id,
                actor,
                nonce: event.nonce,
                public_key: event.public_key.clone(),
                message: remap_signature(&event.message, message.clone()),
            };

            apply_transition(table, &envelope, hasher)
        }
    };

    result.map_err(|e| CatchupError::transition_failed(sequence, e))
}

/// Replays a sequence of messages onto a starting snapshot.
///
/// This is the core replay logic that iterates through messages and applies
/// transitions, validating sequence continuity along the way.
///
/// Returns the final snapshot after all messages have been applied.
fn replay_messages<C>(
    mut snapshot: AnyTableSnapshot<C>,
    messages: Vec<FinalizedAnyMessageEnvelope<C>>,
    hasher: &dyn LedgerHasher,
) -> CatchupResult<AnyTableSnapshot<C>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    if messages.is_empty() {
        tracing::info!(
            target: CATCHUP_LOG_TARGET,
            "no messages to replay, returning snapshot as-is"
        );
        return Ok(snapshot);
    }

    let message_count = messages.len();

    tracing::info!(
        target: CATCHUP_LOG_TARGET,
        message_count = message_count,
        first_sequence = messages.first().map(|m| m.snapshot_sequence_id),
        last_sequence = messages.last().map(|m| m.snapshot_sequence_id),
        "starting message replay"
    );

    let mut last_sequence = messages.first().unwrap().snapshot_sequence_id as i64 - 1;

    for message in messages {
        let sequence = message.snapshot_sequence_id as i64;

        // Validate sequence continuity
        if sequence != last_sequence + 1 {
            return Err(CatchupError::discontinuity(last_sequence + 1, sequence));
        }

        // Branch on success/failure status to mirror LedgerState::replay behavior.
        // For successful messages, apply the transition normally.
        // For failed messages, clone the snapshot and mark it as failed without
        // applying the transition. This mirrors what the original ledger did when
        // the message first failed - it never applied the transition, just recorded
        // the failure. During catchup we must do the same, otherwise we'll try to
        // re-run the failed transition and hit the same validation error.
        snapshot = match &message.snapshot_status {
            SnapshotStatus::Success => {
                apply_message_dispatch(snapshot, &message, hasher)?
            }
            SnapshotStatus::Failure(reason) => {
                clone_snapshot_for_failure(&snapshot, hasher, reason.clone())
            }
        };

        last_sequence = sequence;

        tracing::trace!(
            target: CATCHUP_LOG_TARGET,
            sequence = sequence,
            status = ?message.snapshot_status,
            "message processed successfully"
        );
    }

    tracing::info!(
        target: CATCHUP_LOG_TARGET,
        messages_applied = message_count,
        final_sequence = last_sequence,
        "message replay completed"
    );

    Ok(snapshot)
}

/// Performs catchup for a hand by loading the latest snapshot and replaying
/// subsequent messages from the database.
///
/// This is the main entry point for database-driven catchup. It:
/// 1. Loads the latest snapshot (if any)
/// 2. Queries for messages starting from the appropriate sequence
/// 3. Replays the messages
/// 4. Returns the reconstructed state
///
/// # Parameters
///
/// - `from_sequence`: Optional starting sequence for replay. When specified:
///   - Replay begins at this sequence, not at snapshot.sequence() + 1
///   - The snapshot must be at or before from_sequence - 1
///   - If the latest snapshot is already at or past from_sequence, returns an error
///   - Useful for partial catchup when you already have state up to a certain point
/// - When `from_sequence` is None, replay starts immediately after the latest snapshot
pub async fn catchup_hand_from_db<C, H>(
    hand_id: HandId,
    from_sequence: Option<i64>,
    snapshot_store: &SharedSnapshotStore<C>,
    conn: &DatabaseConnection,
    hasher: &H,
) -> CatchupResult<AnyTableSnapshot<C>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField + CanonicalSerialize + CanonicalDeserialize,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize + CanonicalDeserialize,
    C::Affine: Absorb,
    H: LedgerHasher,
{
    tracing::info!(
        target: CATCHUP_LOG_TARGET,
        hand_id = hand_id,
        ?from_sequence,
        "starting catchup from database"
    );

    // Load the latest snapshot
    let snapshot_opt = snapshot_store
        .load_latest_snapshot(hand_id)
        .await
        .map_err(CatchupError::SnapshotLoad)?;

    // Determine starting sequence and snapshot
    let (starting_snapshot, start_sequence) = match (snapshot_opt, from_sequence) {
        (Some(snapshot), Some(requested_seq)) => {
            let snapshot_seq = snapshot.sequence() as i64;

            // Validate that snapshot is at or before the requested starting point
            if snapshot_seq >= requested_seq {
                return Err(anyhow::anyhow!(
                    "cannot replay from sequence {} when latest snapshot is already at sequence {} for hand {}",
                    requested_seq,
                    snapshot_seq,
                    hand_id
                )
                .into());
            }

            tracing::info!(
                target: CATCHUP_LOG_TARGET,
                hand_id = hand_id,
                snapshot_sequence = snapshot_seq,
                requested_start = requested_seq,
                "loaded snapshot, will replay from requested sequence"
            );

            // Start from the requested sequence, not from snapshot + 1
            (snapshot, requested_seq)
        }
        (Some(snapshot), None) => {
            let seq = snapshot.sequence() as i64;
            tracing::info!(
                target: CATCHUP_LOG_TARGET,
                hand_id = hand_id,
                snapshot_sequence = seq,
                "loaded snapshot from database"
            );
            (snapshot, seq + 1)
        }
        (None, Some(seq)) => {
            return Err(anyhow::anyhow!(
                "from_sequence={} specified but no snapshot available for hand {}",
                seq,
                hand_id
            )
            .into());
        }
        (None, None) => {
            return Err(anyhow::anyhow!(
                "no snapshot available and no from_sequence specified for hand {}",
                hand_id
            )
            .into());
        }
    };

    // Query for events after the snapshot sequence
    tracing::debug!(
        target: CATCHUP_LOG_TARGET,
        hand_id = hand_id,
        start_sequence = start_sequence,
        "querying events from database"
    );

    let event_rows = events::Entity::find()
        .filter(events::Column::HandId.eq(hand_id))
        .filter(events::Column::SnapshotNumber.gte(start_sequence as i32))
        .order_by_asc(events::Column::SnapshotNumber)
        .order_by_asc(events::Column::Nonce)
        .all(conn)
        .await
        .context("failed to query events for catchup")?;

    if event_rows.is_empty() {
        tracing::info!(
            target: CATCHUP_LOG_TARGET,
            hand_id = hand_id,
            "no events found after snapshot, returning snapshot as-is"
        );
        return Ok(starting_snapshot);
    }

    tracing::info!(
        target: CATCHUP_LOG_TARGET,
        hand_id = hand_id,
        event_count = event_rows.len(),
        "loaded events from database"
    );

    // Convert database rows to finalized envelopes
    let finalized_envelopes: Vec<FinalizedAnyMessageEnvelope<C>> = event_rows
        .into_iter()
        .map(|row| {
            model_to_envelope(row)
                .map_err(|e| CatchupError::MessageDeserialization(e))
        })
        .collect::<CatchupResult<Vec<_>>>()?;

    // Validate that the first event matches our expected starting sequence.
    // This is critical because replay_messages only checks continuity BETWEEN events,
    // not whether the first event matches the expected starting point.
    //
    // Example bug this prevents:
    //   - Snapshot at sequence 10, start_sequence = 11
    //   - Database has events [12, 13, 14] (event 11 missing)
    //   - Without this check: replay_messages would seed last_sequence=11 and accept
    //     event 12 as valid (12 == 11+1), silently skipping event 11
    //   - With this check: we detect the gap and return Discontinuity(11, 12)
    if let Some(first_envelope) = finalized_envelopes.first() {
        let first_sequence = first_envelope.snapshot_sequence_id as i64;
        if first_sequence != start_sequence {
            return Err(CatchupError::discontinuity(start_sequence, first_sequence));
        }
    }

    // Replay the messages
    let final_snapshot = replay_messages(starting_snapshot, finalized_envelopes, hasher)?;

    tracing::info!(
        target: CATCHUP_LOG_TARGET,
        hand_id = hand_id,
        final_sequence = final_snapshot.sequence(),
        final_phase = ?final_snapshot.event_phase(),
        "catchup completed successfully"
    );

    Ok(final_snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::snapshot::AnyTableSnapshot;
    use crate::ledger::test_support::{fixture_shuffling_snapshot, FixtureContext};
    use ark_bn254::G1Projective as TestCurve;

    fn setup_test_context() -> FixtureContext<TestCurve> {
        // Create a context with 3 players and 2 shufflers
        FixtureContext::new(&[0, 1, 2], &[0, 1])
    }

    #[test]
    fn test_replay_messages_empty_list() {
        use crate::ledger::hash::default_poseidon_hasher;
        use ark_bn254::Fq as TestBaseField;

        let ctx = setup_test_context();
        let hasher = default_poseidon_hasher::<TestBaseField>();

        // Start with a shuffling snapshot
        let shuffling_snapshot = fixture_shuffling_snapshot(&ctx);
        let starting_snapshot = AnyTableSnapshot::Shuffling(shuffling_snapshot);

        // Empty message list
        let messages: Vec<FinalizedAnyMessageEnvelope<TestCurve>> = vec![];

        let result = replay_messages(starting_snapshot.clone(), messages, hasher.as_ref());

        assert!(result.is_ok(), "replay_messages should succeed with empty message list");
        let final_snapshot = result.unwrap();

        // With no messages, snapshot should be unchanged
        assert_eq!(
            final_snapshot.sequence(),
            starting_snapshot.sequence(),
            "sequence should be unchanged with no messages"
        );
    }

    // Note: More comprehensive tests for message replay with valid transitions
    // would require creating properly structured messages with valid proofs,
    // which is complex. The integration tests will cover the full DB catchup flow.
    //
    // The discontinuity test is handled by the integration test for sequence
    // discontinuity detection since it requires setting up a proper database
    // with messages.
}
