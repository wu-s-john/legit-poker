//! Native VRF implementation (off-circuit)

use super::{
    dst_beta_digest, dst_challenge_digest, dst_nonce_digest, VrfParams, VrfPedersenWindow, VrfProof,
};
use crate::poseidon_config;
use ark_crypto_primitives::crh::{pedersen, CRHScheme};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

const LOG_TARGET: &str = "vrf::native";

/// Hash message to curve point using Pedersen CRH + cofactor clearing
pub fn hash_to_curve<C: CurveGroup>(params: &VrfParams<C>, msg: &[u8]) -> C {
    let p = pedersen::CRH::<C, VrfPedersenWindow>::evaluate(&params.pedersen_crh_params, msg)
        .expect("Pedersen hash-to-curve should not fail");

    // Cofactor clear (e.g., 8 for Grumpkin/Jubjub, 4 for Bandersnatch)
    // This ensures the point is in the prime-order subgroup
    p.mul_by_cofactor().into()
}

/// Generate deterministic nonce k using Poseidon sponge
pub fn generate_nonce<C>(sk: &C::ScalarField, h: &C, msg: &[u8]) -> C::ScalarField
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb,
{
    let config = poseidon_config::<C::ScalarField>();
    let mut sponge = PoseidonSponge::new(&config);

    // Use precomputed digest for efficiency and consistency with circuit
    let dst_digest = dst_nonce_digest::<C::ScalarField>();
    tracing::debug!(target: LOG_TARGET, "absorbing digest {}", dst_digest);
    sponge.absorb(&dst_digest);

    // Absorb secret key
    tracing::debug!(target: LOG_TARGET, "absorbing sk {}", sk);
    sponge.absorb(sk);

    // Serialize and absorb curve point H
    let mut h_bytes = Vec::new();
    h.serialize_compressed(&mut h_bytes)
        .expect("Curve point serialization should not fail");

    tracing::debug!(target: LOG_TARGET, "absorbing bytes {:?}", h_bytes);
    for byte in &h_bytes {
        sponge.absorb(&C::ScalarField::from(*byte as u64));
    }

    // Absorb message in chunks to avoid overflow
    for chunk in msg.chunks(31) {
        let mut b = [0u8; 32];
        b[..chunk.len()].copy_from_slice(chunk);
        let fe = C::ScalarField::from_le_bytes_mod_order(&b);
        sponge.absorb(&fe);
    }

    tracing::debug!(target: LOG_TARGET, "absorbing message {:?}", msg);

    tracing::trace!(
        target: LOG_TARGET,
        "Nonce generation: absorbed {} bytes of message",
        msg.len()
    );

    sponge.squeeze_field_elements(1)[0]
}

/// Generate challenge c from transcript using Poseidon
pub fn generate_challenge<C>(pk: &C, h: &C, gamma: &C, u: &C, v: &C) -> C::ScalarField
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb,
{
    let config = poseidon_config::<C::ScalarField>();
    let mut sponge = PoseidonSponge::new(&config);

    // Use precomputed digest for efficiency and consistency with circuit
    let dst_digest = dst_challenge_digest::<C::ScalarField>();
    tracing::trace!(target: LOG_TARGET, "digest challenge {}", dst_digest);
    sponge.absorb(&dst_digest);

    // Absorb all points in order: pk, H, Γ, U, V
    for p in [pk, h, gamma, u, v] {
        let mut bytes = Vec::new();
        p.serialize_compressed(&mut bytes)
            .expect("Curve point serialization should not fail");
        for byte in &bytes {
            sponge.absorb(&C::ScalarField::from(*byte as u64));
        }
    }

    tracing::trace!(target: LOG_TARGET, "Challenge generation: absorbed 5 curve points {:?}", [pk, h, gamma, u, v]);

    sponge.squeeze_field_elements(1)[0]
}

/// Compute β from Γ using Poseidon over base field
pub fn beta_from_gamma<C>(gamma: &C) -> C::BaseField
where
    C: CurveGroup + CanonicalSerialize,
    C::BaseField: PrimeField + Absorb,
{
    let config = poseidon_config::<C::BaseField>();
    let mut sponge = PoseidonSponge::new(&config);

    // Use precomputed digest for efficiency and consistency with circuit
    let dst_digest = dst_beta_digest::<C::BaseField>();
    sponge.absorb(&dst_digest);

    // Serialize and absorb gamma
    let mut gamma_bytes = Vec::new();
    gamma
        .serialize_compressed(&mut gamma_bytes)
        .expect("Curve point serialization should not fail");
    for byte in &gamma_bytes {
        sponge.absorb(&C::BaseField::from(*byte as u64));
    }

    tracing::trace!(target: LOG_TARGET, "Beta computation: absorbed gamma point");

    sponge.squeeze_field_elements(1)[0]
}

/// Native VRF proving
///
/// Computes proof π = (Γ, c, s) and output β
///
/// # Arguments
/// * `params` - VRF parameters (Pedersen CRH setup)
/// * `pk` - Public key (provided to avoid recomputation)
/// * `sk` - Secret key scalar
/// * `msg` - VRF input message
///
/// # Returns
/// * `(VrfProof, beta)` - The proof and VRF output
pub fn prove_vrf<C>(
    params: &VrfParams<C>,
    pk: &C,
    sk: C::ScalarField,
    msg: &[u8],
) -> (VrfProof<C>, C::BaseField)
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb,
    C::BaseField: PrimeField + Absorb,
{
    tracing::debug!(target: LOG_TARGET, "Starting VRF proof generation");

    // H = HashToCurve(msg)
    let h = hash_to_curve::<C>(params, msg);
    tracing::debug!(target: LOG_TARGET, "Hash to curve {}", h);

    // Γ = x * H
    let gamma = h * sk;
    tracing::debug!(target: LOG_TARGET, "Gamma in SNARK: {:?}", gamma);

    // Generate deterministic nonce k
    let k = generate_nonce::<C>(&sk, &h, msg);
    tracing::debug!(target: LOG_TARGET, "Generated nonce {}", k);

    // U = k * G
    let u = C::generator() * k;

    // V = k * H
    let v = h * k;

    // c = H(pk, H, Γ, U, V)
    let c = generate_challenge::<C>(pk, &h, &gamma, &u, &v);
    tracing::debug!(target: LOG_TARGET, "Generated challenge {}", c);

    // s = k + c * x (mod r)
    let s = k + c * sk;

    // β = HashToOutput(Γ)
    let beta = beta_from_gamma::<C>(&gamma);
    tracing::debug!(target: LOG_TARGET, "Generated beta {}", beta);

    tracing::debug!(
        target: LOG_TARGET,
        "VRF proof generated successfully for message of {} bytes",
        msg.len()
    );

    (VrfProof { gamma, c, s }, beta)
}

/// Native VRF verification
///
/// Verifies proof π = (Γ, c, s) and returns β on success
///
/// # Arguments
/// * `params` - VRF parameters (Pedersen CRH setup)
/// * `pk` - Public key
/// * `msg` - VRF input message
/// * `proof` - VRF proof to verify
///
/// # Returns
/// * `Some(beta)` if proof is valid
/// * `None` if proof is invalid
pub fn verify_vrf<C>(
    params: &VrfParams<C>,
    pk: &C,
    msg: &[u8],
    proof: &VrfProof<C>,
) -> Option<C::BaseField>
where
    C: CurveGroup + CanonicalSerialize,
    C::ScalarField: PrimeField + Absorb,
    C::BaseField: PrimeField + Absorb,
{
    tracing::debug!(target: LOG_TARGET, "Starting VRF proof verification");

    // H = HashToCurve(msg)
    let h = hash_to_curve::<C>(params, msg);

    // U' = s * G - c * pk
    let u_prime = C::generator() * proof.s - *pk * proof.c;

    // V' = s * H - c * Γ
    let v_prime = h * proof.s - proof.gamma * proof.c;

    // c' = H(pk, H, Γ, U', V')
    let c_prime = generate_challenge::<C>(pk, &h, &proof.gamma, &u_prime, &v_prime);

    // Check c' == c
    if c_prime == proof.c {
        let beta = beta_from_gamma::<C>(&proof.gamma);
        tracing::debug!(target: LOG_TARGET, "VRF proof verification successful");
        Some(beta)
    } else {
        tracing::warn!(
            target: LOG_TARGET,
            "VRF proof verification failed: challenge mismatch"
        );
        None
    }
}
