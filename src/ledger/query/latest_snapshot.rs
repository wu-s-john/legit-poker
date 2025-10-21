use std::sync::Arc;

use ark_ec::CurveGroup;
use serde::Serialize;
use thiserror::Error;

use crate::ledger::{
    snapshot::{AnyTableSnapshot, SnapshotStatus},
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
    ) -> Result<LatestSnapshotDto, LatestSnapshotError> {
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

        Ok(LatestSnapshotDto {
            game_id: snapshot_game_id,
            hand_id: actual_hand_id,
            sequence: snapshot.sequence(),
            state_hash: encode_hash(state_hash),
            previous_hash: snapshot.previous_hash().map(encode_hash),
            phase: SnapshotPhaseDto::from(snapshot.event_phase()),
            status: SnapshotStatusDto::from(snapshot.status()),
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

#[derive(Clone, Debug, Serialize)]
pub struct LatestSnapshotDto {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub sequence: u32,
    pub state_hash: String,
    pub previous_hash: Option<String>,
    pub phase: SnapshotPhaseDto,
    pub status: SnapshotStatusDto,
    pub snapshot_debug: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPhaseDto {
    Pending,
    Shuffling,
    Dealing,
    Betting,
    Reveals,
    Showdown,
    Complete,
    Cancelled,
}

impl From<EventPhase> for SnapshotPhaseDto {
    fn from(phase: EventPhase) -> Self {
        match phase {
            EventPhase::Pending => SnapshotPhaseDto::Pending,
            EventPhase::Shuffling => SnapshotPhaseDto::Shuffling,
            EventPhase::Dealing => SnapshotPhaseDto::Dealing,
            EventPhase::Betting => SnapshotPhaseDto::Betting,
            EventPhase::Reveals => SnapshotPhaseDto::Reveals,
            EventPhase::Showdown => SnapshotPhaseDto::Showdown,
            EventPhase::Complete => SnapshotPhaseDto::Complete,
            EventPhase::Cancelled => SnapshotPhaseDto::Cancelled,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatusDto {
    Success,
    Failure { reason: String },
}

impl SnapshotStatusDto {
    fn from_status(status: &SnapshotStatus) -> Self {
        match status {
            SnapshotStatus::Success => SnapshotStatusDto::Success,
            SnapshotStatus::Failure(reason) => SnapshotStatusDto::Failure {
                reason: reason.clone(),
            },
        }
    }
}

impl From<&SnapshotStatus> for SnapshotStatusDto {
    fn from(status: &SnapshotStatus) -> Self {
        SnapshotStatusDto::from_status(status)
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

fn encode_hash(hash: StateHash) -> String {
    hex::encode(hash.into_bytes())
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
        let snapshot = fixture_shuffling_snapshot(&ctx);
        let state = Arc::new(LedgerState::with_hasher(Arc::clone(&ctx.hasher)));
        state.upsert_snapshot(
            ctx.hand_id,
            AnyTableSnapshot::Shuffling(snapshot.clone()),
            true,
        );

        let query = LatestSnapshotQuery::new(Arc::clone(&state));
        let dto = query
            .execute(ctx.game_id, ctx.hand_id)
            .expect("snapshot should exist");

        assert_eq!(dto.game_id, ctx.game_id);
        assert_eq!(dto.hand_id, ctx.hand_id);
        assert_eq!(dto.sequence, snapshot.sequence);
        assert_eq!(
            dto.state_hash,
            hex::encode(snapshot.state_hash.into_bytes())
        );
        assert_eq!(dto.previous_hash, snapshot.previous_hash.map(encode_hash));
        assert!(dto.snapshot_debug.contains("TableSnapshot"));
    }

    #[test]
    fn errors_when_hand_missing() {
        let ctx = FixtureContext::<Curve>::new(&[1, 2, 3], &[10, 11, 12]);
        let state = Arc::new(LedgerState::<Curve>::with_hasher(Arc::clone(&ctx.hasher)));
        let query = LatestSnapshotQuery::new(state);

        let err = query
            .execute(ctx.game_id, ctx.hand_id)
            .expect_err("missing hand should error");
        assert!(matches!(err, LatestSnapshotError::HandNotFound { .. }));
    }
}
