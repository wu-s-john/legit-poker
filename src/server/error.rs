use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::error;

use crate::ledger::query::LatestSnapshotError;

const LOG_TARGET: &str = "server::error";

#[derive(Debug)]
pub enum ApiError {
    NotFound,
    BadRequest(String),
    Internal(String),
}

impl ApiError {
    pub fn not_found(message: impl Into<String>) -> Self {
        // For now, we'll use BadRequest with a not found message
        // Could extend the enum to have NotFound(String) variant
        ApiError::NotFound
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError::BadRequest(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        ApiError::Internal(message.into())
    }
}

impl From<LatestSnapshotError> for ApiError {
    fn from(err: LatestSnapshotError) -> Self {
        match err {
            LatestSnapshotError::HandNotFound { .. }
            | LatestSnapshotError::GameMismatch { .. }
            | LatestSnapshotError::HandMismatch { .. } => ApiError::NotFound,
            LatestSnapshotError::MissingHandId { requested } => ApiError::internal(format!(
                "hand {requested} missing hand id in latest snapshot"
            )),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            ApiError::Internal(message) => {
                error!(target = LOG_TARGET, %message, "internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}
