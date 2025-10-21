use std::marker::PhantomData;
use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use axum::extract::{Path, Query};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;

use crate::curve_absorb::CurveAbsorb;
use crate::game::coordinator::GameCoordinator;
use crate::ledger::query::{HandMessagesQuery, LatestSnapshotQuery, SequenceBounds};
use crate::ledger::snapshot::SnapshotSeq;
use crate::ledger::store::EventStore;
use crate::ledger::types::{GameId, HandId};

use super::dto::{HandMessagesResponse, LatestSnapshotResponse};
use super::error::ApiError;

#[derive(Clone)]
pub struct ServerContext<C>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    pub coordinator: Arc<GameCoordinator<C>>,
    pub event_store: Arc<dyn EventStore<C>>,
}

pub struct LegitPokerServer<C>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    router: Router,
    marker: PhantomData<C>,
}

impl<C> LegitPokerServer<C>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    pub fn new(coordinator: Arc<GameCoordinator<C>>, event_store: Arc<dyn EventStore<C>>) -> Self {
        let context = Arc::new(ServerContext {
            coordinator,
            event_store,
        });

        let router = Router::new()
            .route(
                "/game/:game_id/hand/:hand_id/snapshot",
                get(get_hand_snapshot::<C>),
            )
            .route(
                "/game/:game_id/hand/:hand_id/messages",
                get(get_hand_messages::<C>),
            )
            .layer(Extension(context));

        Self {
            router,
            marker: PhantomData,
        }
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub fn into_router(self) -> Router {
        self.router
    }
}

#[derive(Debug, Deserialize)]
struct HandPath {
    game_id: GameId,
    hand_id: HandId,
}

#[derive(Debug, Default, Deserialize)]
struct MessagesQuery {
    from_sequence: Option<u32>,
    to_sequence: Option<u32>,
}

async fn get_hand_snapshot<C>(
    Extension(ctx): Extension<Arc<ServerContext<C>>>,
    Path(path): Path<HandPath>,
) -> Result<Json<LatestSnapshotResponse>, ApiError>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    let ledger_state = ctx.coordinator.state();
    let query = LatestSnapshotQuery::new(ledger_state);
    let snapshot = query
        .execute(path.game_id, path.hand_id)
        .map_err(ApiError::from)?;
    Ok(Json(LatestSnapshotResponse::from_domain(snapshot)))
}

async fn get_hand_messages<C>(
    Extension(ctx): Extension<Arc<ServerContext<C>>>,
    Path(path): Path<HandPath>,
    Query(query): Query<MessagesQuery>,
) -> Result<Json<HandMessagesResponse>, ApiError>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    let bounds = SequenceBounds::new(
        query.from_sequence.map(snapshot_seq_from_u32),
        query.to_sequence.map(snapshot_seq_from_u32),
    )
    .map_err(|err| ApiError::bad_request(err.to_string()))?;

    let messages_query = HandMessagesQuery::new(Arc::clone(&ctx.event_store));
    let events = messages_query
        .execute(path.hand_id, &bounds)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;

    let response = HandMessagesResponse::try_from_events(path.game_id, path.hand_id, events)
        .map_err(|err| ApiError::internal(err.to_string()))?;

    Ok(Json(response))
}

#[inline]
fn snapshot_seq_from_u32(value: u32) -> SnapshotSeq {
    value
}
