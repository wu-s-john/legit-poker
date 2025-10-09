use std::marker::PhantomData;

use ark_ec::CurveGroup;

use super::{BettingSnapshot, DealingSnapshot, RevealsSnapshot, ShufflingSnapshot};

/// Trait implemented by each hand phase, exposing the snapshot types stored in `TableSnapshot`.
pub trait HandPhase<C: CurveGroup> {
    type ShufflingS;
    type DealingS;
    type BettingS;
    type RevealsS;
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseShuffling;

impl<C: CurveGroup> HandPhase<C> for PhaseShuffling {
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = ();
    type BettingS = ();
    type RevealsS = ();
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseDealing;

impl<C: CurveGroup> HandPhase<C> for PhaseDealing {
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = DealingSnapshot<C>;
    type BettingS = ();
    type RevealsS = ();
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseBetting<R>(pub PhantomData<R>);

impl<R, C> HandPhase<C> for PhaseBetting<R>
where
    C: CurveGroup,
{
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = DealingSnapshot<C>;
    type BettingS = BettingSnapshot<C>;
    type RevealsS = RevealsSnapshot<C>;
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseShowdown;

impl<C: CurveGroup> HandPhase<C> for PhaseShowdown {
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = DealingSnapshot<C>;
    type BettingS = BettingSnapshot<C>;
    type RevealsS = RevealsSnapshot<C>;
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseComplete;

impl<C: CurveGroup> HandPhase<C> for PhaseComplete {
    type ShufflingS = ShufflingSnapshot<C>;
    type DealingS = DealingSnapshot<C>;
    type BettingS = BettingSnapshot<C>;
    type RevealsS = RevealsSnapshot<C>;
}
