//! Bayer-Groth permutation equality proof implementation
//!
//! This module implements the permutation equality proof from the Bayer-Groth shuffle protocol,
//! providing both native (non-SNARK) and circuit gadget implementations.
//!
//! ## Overview
//!
//! The Bayer-Groth shuffle proof demonstrates that a set of output ciphertexts C' is a valid
//! permutation and rerandomization of input ciphertexts C, without revealing the permutation π.
//!
//! ## Key Components
//!
//! ### Native Implementation (`linking_rs_native.rs`, `sigma_protocol.rs`)
//! - `compute_permutation_proof`: Generates proof of permutation equality
//! - `prove_sigma_linkage_ni`: Non-interactive Σ-protocol prover
//! - `verify_sigma_linkage_ni`: Non-interactive Σ-protocol verifier
//! - Multi-scalar multiplication and aggregation helpers
//!
//! ### Circuit Gadgets (`gadgets.rs`, `sigma_gadgets.rs`)
//! - `verify_permutation_equality_gadget`: In-circuit permutation verification
//! - `verify_sigma_linkage_gadget_ni`: In-circuit Σ-protocol verification
//! - `enforce_sigma_witness_constraints`: Witness consistency enforcement
//! - Circuit-compatible MSM and commitment gadgets
//!
//! ### Fiat-Shamir (`fiat_shamir.rs`)
//! - `BayerGrothTranscript`: Manages non-interactive challenge generation
//! - Provides consistent transcript absorption across native and circuit
//!
//! ## Security Properties
//!
//! 1. **Completeness**: Valid shuffle always produces accepting proof
//! 2. **Soundness**: Invalid shuffle cannot produce accepting proof (except with negligible probability)
//! 3. **Zero-Knowledge**: Proof reveals nothing about permutation π or rerandomization factors
//! 4. **Non-Interactive**: Uses Fiat-Shamir transform with Poseidon hash

pub mod bg_setup;
pub mod bg_setup_gadget;
pub mod linking_rs_gadgets;
pub mod linking_rs_native;
pub mod reencryption_gadgets;
pub mod reencryption_protocol;
pub mod utils;

pub use bg_setup::{BayerGrothSetupParameters, BayerGrothTranscript};
pub use bg_setup_gadget::BayerGrothTranscriptGadget;
pub use linking_rs_gadgets::compute_permutation_proof_gadget;
pub use linking_rs_native::{
    compute_left_product, compute_linear_blend, compute_permutation_proof, compute_right_product,
    fixed_base_scalar_mul,
};

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Proof data for Bayer-Groth permutation equality
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PermutationProof<F: PrimeField, G: CurveGroup> {
    /// Commitment to permutation vector a (passed in, not computed)
    pub c_a: G,

    /// Commitment to vector b (passed in, not computed)
    pub c_b: G,

    /// Blinding factor for c_a (derived from Fiat-Shamir)
    pub r: F,

    /// Blinding factor for c_b (derived from Fiat-Shamir)
    pub s: F,

    /// Challenge x
    pub x: F,

    /// Challenge y
    pub y: F,

    /// Challenge zO
    pub z: F,

    /// Left product L = ∏(d_i - z)
    pub left_product: F,

    /// Right product R = ∏(y*i + x^i - z)
    pub right_product: F,

    /// Elliptic curve point P = [L]G
    pub curve_point: G,
}
