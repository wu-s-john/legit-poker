//! VRF (Verifiable Random Function) implementation for fair random number generation
//!
//! This module provides a VRF based on Schnorr/DLEQ proof over circuit-friendly Edwards curves.
//! The implementation is optimized for SNARK circuits by using prove_vrf inside the circuit
//! rather than verify_vrf, as it requires fewer variable-base scalar multiplications.

pub mod cofactor;
pub mod gadgets;
pub mod native;
#[cfg(test)]
mod tests;

use crate::poseidon_config;
use ark_crypto_primitives::crh::pedersen;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// Re-export main functions
pub use native::{prove_vrf, verify_vrf};

// Domain separation tags
pub const DST_CHALLENGE: &[u8] = b"VRF-CHALLENGE-v1";
pub const DST_NONCE: &[u8] = b"VRF-NONCE-v1";
pub const DST_BETA: &[u8] = b"VRF-OUTPUT-v1";

/// Precomputed domain separation tag digest for challenge
/// Used as constant in SNARKs to avoid constraint costs
pub fn dst_challenge_digest<F: PrimeField + Absorb>() -> F {
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);
    for byte in DST_CHALLENGE {
        sponge.absorb(&F::from(*byte as u64));
    }
    sponge.squeeze_field_elements(1)[0]
}

/// Precomputed domain separation tag digest for nonce
/// Used as constant in SNARKs to avoid constraint costs
pub fn dst_nonce_digest<F: PrimeField + Absorb>() -> F {
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);
    for byte in DST_NONCE {
        sponge.absorb(&F::from(*byte as u64));
    }
    sponge.squeeze_field_elements(1)[0]
}

/// Precomputed domain separation tag digest for beta output
/// Used as constant in SNARKs to avoid constraint costs
pub fn dst_beta_digest<F: PrimeField + Absorb>() -> F {
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);
    for byte in DST_BETA {
        sponge.absorb(&F::from(*byte as u64));
    }
    sponge.squeeze_field_elements(1)[0]
}

/// VRF proof containing (Γ, c, s) for Schnorr-style DLEQ proof
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VrfProof<C: CurveGroup> {
    /// Γ = x * H(m)
    pub gamma: C,
    /// Challenge c in scalar field
    pub c: C::ScalarField,
    /// Response s = k + c*x (mod r)
    pub s: C::ScalarField,
}

/// Pedersen window configuration for hash-to-curve
/// 4-bit window with 256 windows = 1024 bits capacity
#[derive(Clone)]
pub struct VrfPedersenWindow;

impl pedersen::Window for VrfPedersenWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

/// VRF parameters containing Pedersen CRH setup for hash-to-curve and sponge config
#[derive(Clone)]
pub struct VrfParams<C, SP = ark_crypto_primitives::sponge::poseidon::PoseidonConfig<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>>
where
    C: CurveGroup,
    SP: Clone,
{
    pub pedersen_crh_params: pedersen::Parameters<C>,
    pub sponge_params: SP,
}

impl<C, SP> VrfParams<C, SP>
where
    C: CurveGroup,
    SP: Clone,
{
    /// Create VRF parameters with custom Pedersen and sponge parameters
    pub fn new(pedersen_crh_params: pedersen::Parameters<C>, sponge_params: SP) -> Self {
        Self {
            pedersen_crh_params,
            sponge_params,
        }
    }
}

impl<C> VrfParams<C, ark_crypto_primitives::sponge::poseidon::PoseidonConfig<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>>
where
    C: CurveGroup,
    <<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField: PrimeField,
{
    /// Setup VRF parameters with random Pedersen generators and default Poseidon config
    pub fn setup<R: ark_std::rand::Rng>(rng: &mut R) -> Self {
        use ark_crypto_primitives::crh::CRHScheme;
        let pedersen_crh_params = <pedersen::CRH<C, VrfPedersenWindow> as CRHScheme>::setup(rng)
            .expect("Pedersen CRH setup should not fail");
        let sponge_params = poseidon_config::<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>();
        Self {
            pedersen_crh_params,
            sponge_params,
        }
    }
}
