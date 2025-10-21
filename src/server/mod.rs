use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use tracing::error;

use crate::{
    curve_absorb::CurveAbsorb,
    game::coordinator::GameCoordinator,
    ledger::{
        query::{LatestSnapshotError, LatestSnapshotQuery},
        types::{GameId, HandId},
    },
};

/// Axum server facade hosting coordinator-backed APIs.
pub struct LegitPokerServer<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    router: Router<Arc<GameCoordinator<C>>>,
    coordinator: Arc<GameCoordinator<C>>,
}

impl<C> LegitPokerServer<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    pub fn new(coordinator: Arc<GameCoordinator<C>>) -> Self {
        let router: Router<Arc<GameCoordinator<C>>> = Router::new().route(
            "/game/:game_id/hand/:hand_id/snapshot",
            get(get_hand_snapshot::<C>),
        );

        Self {
            router,
            coordinator,
        }
    }

    pub fn router(&self) -> Router {
        self.router
            .clone()
            .with_state::<()>(Arc::clone(&self.coordinator))
    }

    pub fn into_router(self) -> Router {
        self.router.with_state::<()>(self.coordinator)
    }
}

#[derive(Debug, Deserialize)]
struct SnapshotPath {
    game_id: GameId,
    hand_id: HandId,
}

async fn get_hand_snapshot<C>(
    State(coordinator): State<Arc<GameCoordinator<C>>>,
    Path(path): Path<SnapshotPath>,
) -> Result<Json<crate::ledger::query::LatestSnapshotDto>, ApiError>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb,
{
    let ledger_state = coordinator.state();
    let query = LatestSnapshotQuery::new(ledger_state);
    query
        .execute(path.game_id, path.hand_id)
        .map(Json)
        .map_err(ApiError::from)
}

#[derive(Debug)]
enum ApiError {
    NotFound,
    InvalidSnapshot(String),
}

impl From<LatestSnapshotError> for ApiError {
    fn from(err: LatestSnapshotError) -> Self {
        match err {
            LatestSnapshotError::HandNotFound { .. }
            | LatestSnapshotError::GameMismatch { .. }
            | LatestSnapshotError::HandMismatch { .. } => ApiError::NotFound,
            LatestSnapshotError::MissingHandId { requested } => {
                ApiError::InvalidSnapshot(format!("hand {requested} missing hand id"))
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ApiError::InvalidSnapshot(reason) => {
                error!(target = "server::snapshot", %reason, "invalid snapshot data");
                (StatusCode::INTERNAL_SERVER_ERROR, reason).into_response()
            }
        }
    }
}
