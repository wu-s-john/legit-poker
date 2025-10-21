use std::sync::Arc;

use ark_ec::CurveGroup;
use thiserror::Error;

use crate::ledger::{
    snapshot::{AnyTableSnapshot, SnapshotSeq, SnapshotStatus},
    state::LedgerState,
    types::{EventPhase, GameId, HandId, StateHash},
};

#[derive(Clone)]
pub struct LatestSnapshotQuery<C>
where
    C: CurveGroup,
{
    state: Arc<LedgerState<C>>,
}

#[derive(Clone, Debug)]
pub struct LatestSnapshot {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub sequence: SnapshotSeq,
    pub state_hash: StateHash,
    pub previous_hash: Option<StateHash>,
    pub phase: EventPhase,
    pub status: SnapshotStatus,
    pub snapshot_debug: String,
}

impl<C> LatestSnapshotQuery<C>
where
    C: CurveGroup,
{
    pub fn new(state: Arc<LedgerState<C>>) -> Self {
        Self { state }
    }

    pub fn execute(
        &self,
        game_id: GameId,
        hand_id: HandId,
    ) -> Result<LatestSnapshot, LatestSnapshotError> {
        let (state_hash, snapshot) = self
            .state
            .tip_snapshot(hand_id)
            .ok_or(LatestSnapshotError::HandNotFound { hand_id })?;

        let (snapshot_game_id, snapshot_hand_id) = snapshot_ids(&snapshot);
        let actual_hand_id =
            snapshot_hand_id.ok_or(LatestSnapshotError::MissingHandId { requested: hand_id })?;

        if snapshot_game_id != game_id {
            return Err(LatestSnapshotError::GameMismatch {
                requested: game_id,
                actual: snapshot_game_id,
                hand_id: actual_hand_id,
            });
        }

        if actual_hand_id != hand_id {
            return Err(LatestSnapshotError::HandMismatch {
                requested: hand_id,
                actual: actual_hand_id,
            });
        }

        Ok(LatestSnapshot {
            game_id: snapshot_game_id,
            hand_id: actual_hand_id,
            sequence: snapshot.sequence(),
            state_hash,
            previous_hash: snapshot.previous_hash(),
            phase: snapshot.event_phase(),
            status: snapshot.status().clone(),
            snapshot_debug: format!("{snapshot:?}"),
        })
    }
}

#[derive(Debug, Error)]
pub enum LatestSnapshotError {
    #[error("no snapshot found for hand {hand_id}")]
    HandNotFound { hand_id: HandId },
    #[error("latest snapshot for hand {hand_id} belongs to game {actual}, not {requested}")]
    GameMismatch {
        requested: GameId,
        actual: GameId,
        hand_id: HandId,
    },
    #[error("latest snapshot for hand {requested} does not report a hand id")]
    MissingHandId { requested: HandId },
    #[error("latest snapshot hand id mismatch: requested {requested}, actual {actual}")]
    HandMismatch { requested: HandId, actual: HandId },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::state::LedgerState;
    use crate::ledger::test_support::{fixture_shuffling_snapshot, FixtureContext};
    use ark_bn254::G1Projective as Curve;

    #[test]
    fn returns_latest_snapshot_for_hand() {
        let ctx = FixtureContext::<Curve>::new(&[1, 2, 3], &[10, 11, 12]);
        let snapshot_ref = fixture_shuffling_snapshot(&ctx);
        let state = Arc::new(LedgerState::with_hasher(Arc::clone(&ctx.hasher)));
        state.upsert_snapshot(
            ctx.hand_id,
            AnyTableSnapshot::Shuffling(snapshot_ref.clone()),
            true,
        );

        let query = LatestSnapshotQuery::new(Arc::clone(&state));
        let snapshot = query
            .execute(ctx.game_id, ctx.hand_id)
            .expect("snapshot should exist");

        assert_eq!(snapshot.game_id, ctx.game_id);
        assert_eq!(snapshot.hand_id, ctx.hand_id);
        assert_eq!(snapshot.sequence, snapshot_ref.sequence);
        assert_eq!(snapshot.state_hash, snapshot_ref.state_hash);
        assert_eq!(snapshot.previous_hash, snapshot_ref.previous_hash);
        assert!(snapshot.snapshot_debug.contains("TableSnapshot"));
    }
}
