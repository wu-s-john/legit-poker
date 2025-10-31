use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use axum::extract::{Extension, Path};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::hash::LedgerHasherSha256;
use crate::ledger::snapshot::AnyTableSnapshot;

use super::dto::CreateDemoResponse;
use super::phase_execution::{execute_deal_phase, execute_shuffle_phase};
use super::session_factory::create_demo_session;
use super::session_store::DemoSessionStore;
use super::state::DemoPhase;
use super::stream_event::DemoStreamEvent;
use crate::server::error::ApiError;

const LOG_TARGET: &str = "legit_poker::server::demo::handlers";
const CHANNEL_BUFFER_SIZE: usize = 512;

/// POST /games/demo - Create a new interactive demo session
pub async fn create_demo<C>(
    Extension(store): Extension<Arc<DemoSessionStore<C>>>,
) -> Result<Json<CreateDemoResponse<C>>, ApiError>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    info!(target: LOG_TARGET, "Creating new demo session");

    // Create demo session in blocking task
    let state = tokio::task::spawn_blocking(create_demo_session::<C>)
        .await
        .map_err(|e| ApiError::internal(format!("Task join error: {}", e)))?
        .map_err(|e| ApiError::internal(format!("Demo creation failed: {}", e)))?;

    let demo_id = state.id;
    let game_id = state.game_id;
    let hand_id = state.hand_id;

    // Extract viewer public key (player 0)
    let viewer_public_key = state.player_keys[0].1.clone();

    // Extract initial snapshot
    let initial_snapshot = match &state.snapshot {
        AnyTableSnapshot::Shuffling(snapshot) => snapshot.clone(),
        _ => {
            return Err(ApiError::internal(
                "Expected shuffling snapshot after demo creation",
            ));
        }
    };

    // Store session
    store.create_session(state).await;

    info!(
        target: LOG_TARGET,
        demo_id = %demo_id,
        game_id = game_id,
        hand_id = hand_id,
        "✅ Demo session created"
    );

    Ok(Json(CreateDemoResponse::new(
        demo_id,
        game_id,
        hand_id,
        viewer_public_key,
        initial_snapshot,
    )))
}

/// GET /games/demo/:id/shuffle - Stream shuffle phase events
pub async fn stream_shuffle<C>(
    Extension(store): Extension<Arc<DemoSessionStore<C>>>,
    Path(demo_id): Path<Uuid>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    info!(
        target: LOG_TARGET,
        demo_id = %demo_id,
        "Starting shuffle stream"
    );

    // Validate phase and transition to Shuffling
    let phase_valid = store
        .with_session(demo_id, |state| {
            if state.phase != DemoPhase::Initialized {
                return Err(format!(
                    "Invalid phase for shuffle: expected Initialized, got {:?}",
                    state.phase
                ));
            }
            state
                .transition_to(DemoPhase::Shuffling)
                .map_err(|e| e.to_string())
        })
        .await
        .ok_or_else(|| ApiError::not_found("Demo session not found"))?;

    phase_valid.map_err(|e| ApiError::bad_request(e))?;

    // Take the session out of the store for execution
    let state = store
        .take_session(demo_id)
        .await
        .ok_or_else(|| ApiError::not_found("Demo session disappeared"))?;

    let (event_tx, event_rx) = mpsc::channel::<DemoStreamEvent<C>>(CHANNEL_BUFFER_SIZE);

    // Execute shuffle phase in blocking task
    let store_clone = Arc::clone(&store);
    tokio::task::spawn_blocking(move || {
        let hasher = LedgerHasherSha256;

        match execute_shuffle_phase(state, &hasher, &event_tx) {
            Ok(mut updated_state) => {
                info!(
                    target: LOG_TARGET,
                    demo_id = %demo_id,
                    "Shuffle phase completed successfully"
                );

                // Transition to ShuffleComplete
                if let Err(e) = updated_state.transition_to(DemoPhase::ShuffleComplete) {
                    error!(
                        target: LOG_TARGET,
                        demo_id = %demo_id,
                        error = %e,
                        "Failed to transition to ShuffleComplete"
                    );
                } else {
                    // Re-insert session back into store (it was taken out earlier)
                    let rt = tokio::runtime::Handle::current();
                    let session_id = rt.block_on(store_clone.create_session(updated_state));
                    info!(
                        target: LOG_TARGET,
                        demo_id = %session_id,
                        "Re-inserted session into store after shuffle"
                    );
                }
            }
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    demo_id = %demo_id,
                    error = %e,
                    "Shuffle phase failed"
                );
            }
        }
    });

    // Convert events to SSE
    let sse_stream = ReceiverStream::new(event_rx).map(|event| {
        let event_name = event.event_name();
        let data = serde_json::to_string(&event)
            .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string());
        Ok::<Event, Infallible>(Event::default().event(event_name).data(data))
    });

    Ok(Sse::new(sse_stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text(":")))
}

/// GET /games/demo/:id/deal - Stream deal phase events
pub async fn stream_deal<C>(
    Extension(store): Extension<Arc<DemoSessionStore<C>>>,
    Path(demo_id): Path<Uuid>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    info!(
        target: LOG_TARGET,
        demo_id = %demo_id,
        "Starting deal stream"
    );

    // Validate phase and transition to Dealing
    let phase_valid = store
        .with_session(demo_id, |state| {
            if state.phase != DemoPhase::ShuffleComplete {
                return Err(format!(
                    "Invalid phase for deal: expected ShuffleComplete, got {:?}",
                    state.phase
                ));
            }
            state
                .transition_to(DemoPhase::Dealing)
                .map_err(|e| e.to_string())
        })
        .await
        .ok_or_else(|| ApiError::not_found("Demo session not found"))?;

    phase_valid.map_err(|e| ApiError::bad_request(e))?;

    // Take the session out of the store for execution
    let state = store
        .take_session(demo_id)
        .await
        .ok_or_else(|| ApiError::not_found("Demo session disappeared"))?;

    let (event_tx, event_rx) = mpsc::channel::<DemoStreamEvent<C>>(CHANNEL_BUFFER_SIZE);

    // Execute deal phase in blocking task
    let store_clone = Arc::clone(&store);
    tokio::task::spawn_blocking(move || {
        let hasher = LedgerHasherSha256;

        match execute_deal_phase(state, &hasher, &event_tx) {
            Ok(mut updated_state) => {
                info!(
                    target: LOG_TARGET,
                    demo_id = %demo_id,
                    "Deal phase completed successfully"
                );

                // Transition to Complete
                if let Err(e) = updated_state.transition_to(DemoPhase::Complete) {
                    error!(
                        target: LOG_TARGET,
                        demo_id = %demo_id,
                        error = %e,
                        "Failed to transition to Complete"
                    );
                } else {
                    // Remove session immediately after completion
                    let rt = tokio::runtime::Handle::current();
                    if rt.block_on(store_clone.remove_session(demo_id)) {
                        info!(
                            target: LOG_TARGET,
                            demo_id = %demo_id,
                            "Demo session removed after completion"
                        );
                    } else {
                        warn!(
                            target: LOG_TARGET,
                            demo_id = %demo_id,
                            "Failed to remove session after completion"
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    demo_id = %demo_id,
                    error = %e,
                    "Deal phase failed"
                );
            }
        }
    });

    // Convert events to SSE
    let sse_stream = ReceiverStream::new(event_rx).map(|event| {
        let event_name = event.event_name();
        let data = serde_json::to_string(&event)
            .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string());
        Ok::<Event, Infallible>(Event::default().event(event_name).data(data))
    });

    Ok(Sse::new(sse_stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text(":")))
}
