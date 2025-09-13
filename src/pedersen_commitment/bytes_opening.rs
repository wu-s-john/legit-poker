//! Pedersen commitment opening (bytes-only)
//!
//! This module provides helpers to prove/verify a Pedersen commitment opening
//! when the committed message is a byte slice. It wraps arkworks' Pedersen
//! commitment primitives and in-circuit gadgets. Unlike the scalar-vector
//! opening protocol under `opening_proof`, this module is strictly for bytes.

use ark_crypto_primitives::commitment::pedersen::{
    constraints::CommGadget as PedersenCommGadget, Commitment as PedersenCommitment,
    Parameters as PedersenParameters, Randomness as PedersenRandomness, Window as PedersenWindow,
};
use ark_crypto_primitives::commitment::{CommitmentGadget, CommitmentScheme};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use rand::{CryptoRng, RngCore};

// Re-export window types from dedicated module so existing imports
// like `pedersen_commitment::bytes_opening::DeckHashWindow` keep working.
pub use super::windows::{DeckHashWindow, PedersenWin, ReencryptionWindow};

/// Internal helper: compute Pedersen commitment in-circuit from bytes
fn pedersen_commitment_gadget<G, GG, W>(
    cs: ConstraintSystemRef<G::BaseField>,
    params: &PedersenParameters<G>,
    message: &[u8],
    randomness: &PedersenRandomness<G>,
) -> Result<GG, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    W: PedersenWindow,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, G, GG>,
{
    // Allocate params and randomness as witnesses
    type CG<G, GG, W> = PedersenCommGadget<G, GG, W>;
    type Scheme<G, W> = PedersenCommitment<G, W>;

    let params_var =
        <CG<G, GG, W> as CommitmentGadget<Scheme<G, W>, G::BaseField>>::ParametersVar::new_witness(
            ark_relations::ns!(cs, "pedersen_params"),
            || Ok(params),
        )?;

    let rand_var =
        <CG<G, GG, W> as CommitmentGadget<Scheme<G, W>, G::BaseField>>::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "pedersen_randomness"),
            || Ok(randomness),
        )?;

    // Allocate message bytes as witnesses
    let input_var: Vec<UInt8<G::BaseField>> = message
        .iter()
        .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)))
        .collect::<Result<_, _>>()?;

    // Commit in-circuit
    <CG<G, GG, W> as CommitmentGadget<Scheme<G, W>, G::BaseField>>::commit(
        &params_var,
        &input_var,
        &rand_var,
    )
}

/// Gadget function that verifies a Pedersen commitment opening (bytes)
///
/// Computes the commitment from the opening and enforces equality with the expected commitment.
pub fn verify_pedersen_commitment_gadget<G, GG, W>(
    cs: ConstraintSystemRef<G::BaseField>,
    params: &PedersenParameters<G>,
    message: &[u8],
    randomness: &PedersenRandomness<G>,
    expected_commitment: &G::Affine,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    W: PedersenWindow,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, G, GG>,
{
    let computed_var =
        pedersen_commitment_gadget::<G, GG, W>(cs.clone(), params, message, randomness)?;

    // Allocate the expected commitment as PUBLIC INPUT
    let expected_var = GG::new_input(ark_relations::ns!(cs, "commitment_input"), || {
        Ok(*expected_commitment)
    })?;

    computed_var.enforce_equal(&expected_var)?;
    Ok(())
}

/// Setup Pedersen parameters for the commitment scheme (bytes)
pub fn pedersen_setup<G, W, R>(rng: &mut R) -> PedersenParameters<G>
where
    G: CurveGroup,
    W: PedersenWindow,
    R: RngCore + CryptoRng,
{
    PedersenCommitment::<G, W>::setup(rng).expect("pedersen parameter generation should not fail")
}

/// Compute a native Pedersen commitment (bytes)
pub fn pedersen_commit<G, W>(
    params: &PedersenParameters<G>,
    message: &[u8],
    randomness: &PedersenRandomness<G>,
) -> G::Affine
where
    G: CurveGroup,
    W: PedersenWindow,
{
    PedersenCommitment::<G, W>::commit(params, message, randomness)
        .expect("native pedersen commit should not fail")
}
