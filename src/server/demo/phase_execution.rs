use anyhow::Result;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tokio::sync::mpsc;
use tracing::info;

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::AnyTableSnapshot;
use crate::shuffler::{run_dealing_phase, run_shuffling_phase};

use super::state::DemoState;
use super::stream_event::DemoStreamEvent;

const LOG_TARGET: &str = "legit_poker::server::demo::phase_execution";

type Schnorr254<C> = Schnorr<C, Sha256>;

/// Execute the shuffling phase for a demo session.
/// Consumes the DemoState and returns an updated version with the dealing snapshot.
pub fn execute_shuffle_phase<C>(
    mut state: DemoState<C>,
    hasher: &dyn LedgerHasher,
    event_tx: &mpsc::Sender<DemoStreamEvent<C>>,
) -> Result<DemoState<C>>
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
        demo_id = %state.id,
        game_id = state.game_id,
        hand_id = state.hand_id,
        "🔄 Starting shuffle phase"
    );

    // Extract shuffling snapshot from state
    let shuffling_snapshot = match &state.snapshot {
        AnyTableSnapshot::Shuffling(snapshot) => snapshot.clone(),
        other => {
            return Err(anyhow::anyhow!(
                "Invalid snapshot type for shuffle phase: {:?}",
                std::mem::discriminant(other)
            ));
        }
    };

    // Execute shuffle phase
    let dealing_snapshot = run_shuffling_phase(
        shuffling_snapshot,
        &state.shuffler_engines,
        &mut state.shuffler_states,
        hasher,
        event_tx,
    )?;

    info!(
        target: LOG_TARGET,
        demo_id = %state.id,
        sequence = dealing_snapshot.sequence,
        "✅ Shuffle phase completed"
    );

    // Update state with dealing snapshot
    state.snapshot = AnyTableSnapshot::Dealing(dealing_snapshot);

    Ok(state)
}

/// Execute the dealing phase for a demo session.
/// Consumes the DemoState and returns an updated version.
pub fn execute_deal_phase<C>(
    mut state: DemoState<C>,
    hasher: &dyn LedgerHasher,
    event_tx: &mpsc::Sender<DemoStreamEvent<C>>,
) -> Result<DemoState<C>>
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
        demo_id = %state.id,
        game_id = state.game_id,
        hand_id = state.hand_id,
        "🎴 Starting deal phase"
    );

    // Extract dealing snapshot from state
    let mut dealing_snapshot = match &state.snapshot {
        AnyTableSnapshot::Dealing(snapshot) => snapshot.clone(),
        other => {
            return Err(anyhow::anyhow!(
                "Invalid snapshot type for deal phase: {:?}",
                std::mem::discriminant(other)
            ));
        }
    };

    // Execute dealing phase
    run_dealing_phase(
        &mut dealing_snapshot,
        &state.shuffler_engines,
        &state.player_records,
        &state.player_keys,
        &state.aggregated_public_key,
        &mut state.rng,
        hasher,
        Some(event_tx),
    )?;

    info!(
        target: LOG_TARGET,
        demo_id = %state.id,
        "✅ Deal phase completed"
    );

    // Update snapshot (may have transitioned to Preflop but we keep it as Dealing for now)
    state.snapshot = AnyTableSnapshot::Dealing(dealing_snapshot);

    Ok(state)
}
