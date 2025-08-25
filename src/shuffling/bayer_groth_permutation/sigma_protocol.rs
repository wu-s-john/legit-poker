//! Non-interactive single Σ-protocol for Bayer–Groth shuffle rerandomization proof
//!
//! This module implements a type-safe non-interactive Σ-protocol that proves, in one shot:
//!
//!     output_ciphertext_aggregator = E_pk(1; ρ) · ∏_j input_ciphertexts[j]^{b_j}    with    b_vector_commitment = com(b; b_commitment_blinding_factor)
//!
//! where
//!   - a = (x^1, x^2, …, x^N) with x←FS, i.e., a_i = x^{i} in 1-based math; in code we use a_i = x^{i+1} for 0-based indices,
//!   - b_j = x^{π^{-1}(j)} (again 1-based math; in code b_j = x^{π^{-1}(j)+1}),
//!   - ρ = Σ_i x^i ρ_i is the aggregate rerandomization.
//!
//! ## Math identity proved by the Σ‑protocol
//!
//! Given a correct shuffle  C'_i = C_{π(i)} · E(1; ρ_i), define a_i := x^{i} and b_j := x^{π^{-1}(j)} (1-based).
//! Then:
//!
//!   ∏_i (C'_i)^{a_i}
//! = ∏_i (C_{π(i)} · E(1; ρ_i))^{x^{i}}
//! = (∏_i C_{π(i)}^{x^{i}}) · E(1; Σ_i x^{i}ρ_i)
//! = (∏_j C_j^{x^{π^{-1}(j)}}) · E(1; ρ)         [reindex j = π(i)]
//! = E(1; ρ) · ∏_j C_j^{b_j}.
//!
//! Our Σ‑protocol proves knowledge of (b, s_B, ρ) such that
//!
//!   C'^a = E(1; ρ) · ∏_j C_j^{b_j}    and    c_B = com(b; s_B)
//!
//! using two Schnorr-style equalities (Fiat–Shamir to make it non-interactive):
//!
//!   com(z_b; z_s) = T_com · c_B^c                      (commitment side)
//!   E(1; z_ρ) · ∏_j C_j^{z_{b,j}} = T_grp · (C'^a)^c   (group side)
//!
//! **Important:** `com(·)` must be a *linear vector Pedersen* over field scalars, not a byte-Pedersen hash,
//! so that com(t + c·b; t_s + c·s_B) = com(t; t_s) · com(b; s_B)^c holds coordinate-wise.
//!
//! ## Security Properties
//! - Completeness: Honest prover always convinces honest verifier.
//! - Special soundness: Two accepting transcripts with different challenges extract (b, s_B, ρ).
//! - HVZK (with FS): Transcript is simulatable; the commitments are perfectly hiding.
//!
//! ## Implementation Details
//! - Uses const generics (N) for compile-time size checking and type safety.
//! - `a_i` is implemented as x^(i+1) for i=0..N-1 (so it matches the 1-based math above).
//! - The Pedersen commitment here is a *scalar-vector* Pedersen over N coordinates.

use crate::shuffling::curve_absorb::CurveAbsorb;
use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalKeys};
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::{
    commitment::pedersen::{Commitment as PedersenCommitment, Parameters, Window},
    sponge::{poseidon::PoseidonSponge, CryptographicSponge},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::Zero;
use ark_std::{rand::Rng, vec::Vec};

/// Logging target for this module
const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::sigma_protocol";

/// Window type for Pedersen parameters (we only use it to generate a large pool of bases).
#[derive(Clone)]
pub struct SigmaWindow;

impl Window for SigmaWindow {
    const WINDOW_SIZE: usize = 4;
    // Large enough that setup() yields many generators; > N is sufficient (we use ~52 max).
    const NUM_WINDOWS: usize = 416;
}

/// Type alias for arkworks’ byte-oriented Pedersen; we only use its parameters to source bases.
pub type Pedersen<G> = PedersenCommitment<G, SigmaWindow>;

/// Σ‑protocol proof object.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[allow(non_snake_case)]
pub struct SigmaProof<G: CurveGroup, const N: usize> {
    /// Commitment to random vector t: sigma_commitment_T = com(t; t_s).
    pub blinding_factor_commitment: G,
    /// Group-side randomizer: sigma_ciphertext_T = E(1; t_ρ) · ∏ C_j^{t_j}.
    pub blinding_rerandomization_commitment: G,
    /// Response vector sigma_response_b = t + c·b (length N).
    pub sigma_response_b: [G::ScalarField; N],
    /// Response for commitment randomness: sigma_response_blinding = t_s + c·s_B.
    pub sigma_response_blinding: G::ScalarField,
    /// Response for rerandomization: sigma_response_rerand = t_ρ + c·ρ where ρ = Σ(b_j * r_j^in).
    pub sigma_response_rerand: G::ScalarField,
}

// TODO: transcripts should not absorb entire vectors. Rather, they should absorb the commitments of the vectors since it is very computationally expensive
// That being said, we need a new type where you pass in a variable with its commitments

#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
///
/// Prover: Generate a non-interactive Σ‑proof that
///
///     output_ciphertext_aggregator = E_pk(1; ρ) · ∏_j input_ciphertexts[j]^{b_j}
///
/// with a commitment c_B = com(b; s_B).
///
/// **Inputs**
/// - `keys`: ElGamal keys (public key used in E(1; ·)).
/// - `pedersen_params`: parameters used to derive the linear vector-Pedersen bases.
/// - `input_ciphertexts`: input ciphertexts (length N).
/// - `output_ciphertexts`: output ciphertexts (length N).
/// - `x`: Fiat–Shamir scalar; we use a_i = x^(i+1).
/// - `b_vector_commitment`: Pedersen commitment to b (computed with the same `pedersen_params`).
/// - `b`: witness vector b_j = x^{π^{-1}(j)+1}.
/// - `b_commitment_blinding_factor`: commitment randomness for b_vector_commitment.
/// - `rho`: aggregate rerandomization ρ = Σ_i x^{i+1} ρ_i (matches a_i).
/// - `transcript`: sponge to derive the challenge.
/// - `rng`: RNG.
///
/// **Returns:** `SigmaProof`.
#[allow(non_snake_case)]
pub fn prove_sigma_linkage_ni<G, const N: usize>(
    keys: &ElGamalKeys<G>,
    pedersen_params: &Parameters<G>,
    input_ciphertexts: &[ElGamalCiphertext<G>; N],
    output_ciphertexts: &[ElGamalCiphertext<G>; N],
    x: G::ScalarField,
    b_vector_commitment: &G,
    b: &[G::ScalarField; N],
    b_commitment_blinding_factor: G::ScalarField,
    rerandomization_scalars: &[G::ScalarField; N], // These are the rerandomization scalars
    transcript: &mut PoseidonSponge<G::BaseField>,
    rng: &mut impl Rng,
) -> SigmaProof<G, N>
where
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    G: CurveGroup + CurveAbsorb<G::BaseField>,
{
    tracing::debug!(target: LOG_TARGET, N = N, "Starting non-interactive proof generation");

    // Compute aggregators C^a and C'^a where a_i = x^(i+1) (zero-based loop)
    let input_ciphertext_aggregator = compute_output_aggregator(input_ciphertexts, x);
    let output_ciphertext_aggregator = compute_output_aggregator(output_ciphertexts, x);

    // Absorb public inputs into transcript
    absorb_public_inputs(
        transcript,
        &input_ciphertext_aggregator,
        &output_ciphertext_aggregator,
        b_vector_commitment,
    );

    // Log the aggregator for debugging
    tracing::debug!(
        target: LOG_TARGET,
        "Computed input_ciphertext_aggregator: {:?}",
        input_ciphertext_aggregator
    );
    tracing::debug!(
        target: LOG_TARGET,
        "Computed output_ciphertext_aggregator: {:?}",
        output_ciphertext_aggregator
    );
    tracing::debug!(
        target: LOG_TARGET,
        "Computed b_vector_commitment: {:?}",
        b_vector_commitment
    );

    // --- Commit phase: pick random blinds ---
    let blinding_factors: [G::ScalarField; N] = std::array::from_fn(|_| G::ScalarField::rand(rng));
    let blinding_factor_for_blinding_factor_commitment = G::ScalarField::rand(rng); // Blinding factor used for the blinding commitment
    let ciphertext_masking_rerand = G::ScalarField::rand(rng);

    // sigma_commitment_T = com(t; commitment_masking_blinding) using a linear vector-Pedersen over scalars
    let blinding_factor_commitment = commit_vector(
        pedersen_params,
        &blinding_factors,
        blinding_factor_for_blinding_factor_commitment,
    );

    tracing::debug!(
        target: LOG_TARGET,
        blinding_factor_commitment = ?blinding_factor_commitment,
        "Computed blinding factor commitment"
    );

    // sigma_ciphertext_T = E_pk(1; ciphertext_masking_rerand) · ∏ C_j^{t_j}
    // This is also T_grp = E_pk(1;t_ρ) · ∏_{j=1}^N C_j^{t_j}
    let blinding_rerandomization_commitment: G = encrypt_one_and_combine(
        keys,
        ciphertext_masking_rerand,
        input_ciphertexts,
        &blinding_factors,
    );

    tracing::debug!(
        target: LOG_TARGET,
        blinding_rerandomization_commitment = ?blinding_rerandomization_commitment,
        "Computed blinding rerandomization commitment"
    );

    // Absorb commitments and derive challenge
    absorb_point(transcript, &blinding_factor_commitment);
    absorb_point(transcript, &blinding_rerandomization_commitment);

    let c: G::ScalarField = transcript.squeeze_field_elements(1)[0];
    tracing::debug!(
        target: LOG_TARGET,
        challenge = ?c,
        output_ciphertext_aggregator = ?output_ciphertext_aggregator,
        blinding_factor_commitment = ?blinding_factor_commitment,
        blinding_rerandomization_commitment = ?blinding_rerandomization_commitment,
        "Generated challenge after absorbing commitments"
    );

    // --- Responses ---
    // Compute aggregate rerandomizer ρ = Σ(b_j * r_j^in)
    let rho: G::ScalarField = (0..N).map(|j| b[j] * rerandomization_scalars[j]).sum();

    let sigma_response_b: [G::ScalarField; N] = (0..N)
        .map(|j| blinding_factors[j] + c * b[j])
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let sigma_response_blinding =
        blinding_factor_for_blinding_factor_commitment + c * b_commitment_blinding_factor;
    // z_ρ = t_ρ + c·ρ where ρ is the aggregate rerandomizer
    let sigma_response_rerand = ciphertext_masking_rerand + c * rho;

    SigmaProof {
        blinding_factor_commitment,
        blinding_rerandomization_commitment,
        sigma_response_b,
        sigma_response_blinding,
        sigma_response_rerand,
    }
}

#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
///
/// Verifier: Check the two Schnorr equalities
///
///   1) com(sigma_response_b; sigma_response_blinding)  ==  sigma_commitment_T · b_vector_commitment^c
///   2) E(1; sigma_response_rerand) · ∏ C_j^{sigma_response_b[j]}  ==  sigma_ciphertext_T · (output_ciphertext_aggregator)^c
///
/// **Returns:** true iff both hold.
#[allow(non_snake_case)]
pub fn verify_sigma_linkage_ni<G: CurveGroup, const N: usize>(
    keys: &ElGamalKeys<G>,
    pedersen_params: &Parameters<G>,
    input_ciphertexts: &[ElGamalCiphertext<G>; N],
    output_ciphertexts: &[ElGamalCiphertext<G>; N],
    x: G::ScalarField,
    b_vector_commitment: &G,
    proof: &SigmaProof<G, N>,
    transcript: &mut PoseidonSponge<G::BaseField>,
) -> bool
where
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G: CurveAbsorb<G::BaseField>,
{
    tracing::debug!(target: LOG_TARGET, N = N, "Starting non-interactive verification");

    tracing::debug!(
        target: LOG_TARGET,
        "Transcript state before absorbing ciphertext inputs and outputs: {:?}",
        transcript.state
    );

    // Recompute aggregators C^a and C'^a where a_i = x^(i+1)
    let input_ciphertext_aggregator = compute_output_aggregator(input_ciphertexts, x);
    let output_ciphertext_aggregator = compute_output_aggregator(output_ciphertexts, x);

    // Rebuild transcript
    absorb_public_inputs(
        transcript,
        &input_ciphertext_aggregator,
        &output_ciphertext_aggregator,
        b_vector_commitment,
    );

    tracing::debug!(
        target: LOG_TARGET,
        "Computed input_ciphertext_aggregator: {:?}",
        input_ciphertext_aggregator
    );
    tracing::debug!(
        target: LOG_TARGET,
        "Computed output_ciphertext_aggregator: {:?}",
        output_ciphertext_aggregator
    );
    tracing::debug!(
        target: LOG_TARGET,
        "Computed b_vector_commitment: {:?}",
        b_vector_commitment
    );

    // Absorb aggregator and proof commitments
    absorb_point(transcript, &proof.blinding_factor_commitment);
    absorb_point(transcript, &proof.blinding_rerandomization_commitment);

    // Derive challenge
    let challenge: G::ScalarField = transcript.squeeze_field_elements(1)[0];

    tracing::debug!(
        target: LOG_TARGET,
        challenge = ?challenge,
        output_ciphertext_aggregator = ?output_ciphertext_aggregator,
        blinding_factor_commitment = ?proof.blinding_factor_commitment,
        blinding_rerandomization_commitment = ?proof.blinding_rerandomization_commitment,
        "Recomputing challenge"
    );

    // 1) Commitment-side equality
    let lhs_com = commit_vector(
        pedersen_params,
        &proof.sigma_response_b,
        proof.sigma_response_blinding,
    );
    let rhs_com = proof.blinding_factor_commitment + *b_vector_commitment * challenge;

    if lhs_com != rhs_com {
        tracing::error!(target: LOG_TARGET, "Commitment equality check failed");
        return false;
    } else {
        tracing::debug!(target: LOG_TARGET, "com(z_b; z_s) = T_com · c_B^c (V1): lhs_com = {:?}", lhs_com);
    }

    // 2) Group-side equality
    // E_pk(1; sigma_response_rerand) · ∏ C_j^{sigma_response_b[j]}
    let lhs_grp = encrypt_one_and_combine(
        keys,
        proof.sigma_response_rerand, // Now a single scalar
        input_ciphertexts,
        &proof.sigma_response_b,
    );

    // rhs = blinding_rerandomization_commitment + (c1 + c2) of output_ciphertext_aggregator * c
    let rhs_grp = proof.blinding_rerandomization_commitment
        + (output_ciphertext_aggregator.c1 + output_ciphertext_aggregator.c2) * challenge;

    if lhs_grp != rhs_grp {
        tracing::error!(target: LOG_TARGET, "Ciphertext equality check failed");
        return false;
    }

    true
}

#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
///
/// Compute the public aggregator:
///     output_ciphertext_aggregator := ∏_{i=0}^{N-1} (output_ciphertexts[i])^{x^{i+1}}.
/// (We use 0-based loop; mathematically this is x^1,…,x^N.)
pub fn compute_output_aggregator<G: CurveGroup, const N: usize>(
    output_ciphertexts: &[ElGamalCiphertext<G>; N],
    x: G::ScalarField,
) -> ElGamalCiphertext<G>
where
    G::ScalarField: PrimeField,
{
    let mut powers = [G::ScalarField::zero(); N];
    let mut x_power = x; // x^(1)
    for i in 0..N {
        powers[i] = x_power; // a_i = x^(i+1)
        x_power *= x;
    }
    msm_ciphertexts(output_ciphertexts, &powers)
}

#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
/// MSM over ciphertexts: ∏ (ciphertexts[i])^{scalars[i]} in EC additive notation:
/// accumulates (Σ scalars[i]·c1_i,  Σ scalars[i]·c2_i).
pub fn msm_ciphertexts<G: CurveGroup, const N: usize>(
    ciphertexts: &[ElGamalCiphertext<G>; N],
    scalars: &[G::ScalarField; N],
) -> ElGamalCiphertext<G>
where
{
    let mut result = ElGamalCiphertext {
        c1: G::zero(),
        c2: G::zero(),
    };
    for i in 0..N {
        result.c1 += ciphertexts[i].c1 * scalars[i];
        result.c2 += ciphertexts[i].c2 * scalars[i];
    }
    result
}

/// Compute E_pk(1; randomness) · ∏ C_j^{scalar_factors[j]} and return as a single point
/// by adding the two components of the resulting ciphertext.
///
/// Returns: c1 + c2 where (c1, c2) = E_pk(1; randomness) · ∏ C_j^{scalar_factors[j]}
pub fn encrypt_one_and_combine<G: CurveGroup, const N: usize>(
    keys: &ElGamalKeys<G>,
    randomness: G::ScalarField,
    ciphertexts: &[ElGamalCiphertext<G>; N],
    scalar_factors: &[G::ScalarField; N],
) -> G
where
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
{
    let curve_generator = G::generator();

    // E_pk(1; randomness) = (g^randomness, pk^randomness · g)
    let rerand_c1 = curve_generator * randomness;
    let rerand_c2 = keys.public_key * randomness + curve_generator;

    // ∏ C_j^{scalar_factors[j]}
    let msm = msm_ciphertexts(ciphertexts, scalar_factors);

    // Combine and return as single point
    rerand_c1 + msm.c1 + rerand_c2 + msm.c2
}

/// Extract N bases for a linear (scalar-vector) Pedersen commitment from the Pedersen parameters.
/// We reuse the window generators as a long list of bases.
/// Returns (H, [G_1..G_N]) such that com(v;r) = H^r * Π_j G_j^{v_j}.
pub fn vector_commit_bases<G, const N: usize>(params: &Parameters<G>) -> (G, [G; N])
where
    G: CurveGroup,
{
    // Use the first element of randomness_generator as H
    let pedersen_blinding_base = params.randomness_generator[0];

    // Flatten the 2D generator table and take the first N bases
    let mut it = params.generators.iter().flat_map(|row| row.iter()).cloned();

    let bases: [G; N] = core::array::from_fn(|_| {
        it.next()
            .expect("Not enough Pedersen generators for the requested N")
    });

    (pedersen_blinding_base, bases)
}

#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
///
/// Linear (coordinate-wise) Pedersen commitment over field elements:
///     com(values; randomness) = H^{randomness} * Π_j G_j^{values[j]}.
/// This *replaces* a byte-Pedersen hash to ensure linearity required by the Σ-protocol.
pub fn commit_vector<G: CurveGroup, const N: usize>(
    params: &Parameters<G>,
    values: &[G::ScalarField; N],
    randomness: G::ScalarField,
) -> G {
    let (pedersen_blinding_base, bases) = vector_commit_bases::<G, N>(params);
    let mut acc = pedersen_blinding_base * randomness;
    for j in 0..N {
        acc += bases[j] * values[j];
    }
    acc
}

/// Absorb all public inputs into the transcript in a consistent order.
/// Takes pre-computed aggregators to reduce computational cost.
fn absorb_public_inputs<G: CurveGroup>(
    transcript: &mut PoseidonSponge<G::BaseField>,
    c_in_aggregator: &ElGamalCiphertext<G>,
    c_out_aggregator: &ElGamalCiphertext<G>,
    c_b: &G,
) where
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    G: CurveAbsorb<G::BaseField>,
{
    // Absorb aggregated input ciphertexts (c1 + c2)
    let c_in_aggregate = c_in_aggregator.c1 + c_in_aggregator.c2;
    c_in_aggregate.curve_absorb(transcript);

    // Absorb aggregated output ciphertexts (c1 + c2)
    let c_out_aggregate = c_out_aggregator.c1 + c_out_aggregator.c2;
    c_out_aggregate.curve_absorb(transcript);

    // Absorb the commitment
    absorb_point(transcript, c_b);
}

/// Absorb a curve point using the CurveAbsorb trait.
fn absorb_point<G>(transcript: &mut PoseidonSponge<G::BaseField>, point: &G)
where
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    G: CurveGroup + CurveAbsorb<G::BaseField>,
{
    point.curve_absorb(transcript);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::test_utils::{
        generate_random_ciphertexts, shuffle_and_rerandomize_random,
    };
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_crypto_primitives::commitment::CommitmentScheme;
    use ark_ff::{Field, UniformRand, Zero};
    use ark_std::test_rng;

    #[test]
    fn test_proof_generation_and_verification() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();

        const N: usize = 4;
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let keys = ElGamalKeys::new(sk);

        // Pedersen parameters (used only to source linear bases)
        let pedersen_params = Pedersen::<G1Projective>::setup(&mut rng).unwrap();

        // Inputs
        let (input_ciphertexts, _) =
            generate_random_ciphertexts::<G1Projective, N>(&keys, &mut rng);

        // Permutation: reverse
        let pi: [usize; N] = core::array::from_fn(|i| N - 1 - i);
        let mut pi_inv = [0usize; N];
        for i in 0..N {
            pi_inv[pi[i]] = i;
        }

        // Shuffle + rerandomize
        let (output_ciphertexts, rerand) =
            shuffle_and_rerandomize_random(&input_ciphertexts, &pi, keys.public_key, &mut rng);

        // FS challenge and vectors
        let x = Fr::from(2u64);

        // b[j] = x^{pi_inv[j] + 1}  (since we use a_i = x^{i+1})
        let mut b = [Fr::zero(); N];
        for j in 0..N {
            b[j] = x.pow(&[(pi_inv[j] as u64) + 1]);
        }

        // b_vector_commitment = com(b; b_commitment_blinding_factor)
        let b_commitment_blinding_factor = Fr::rand(&mut rng);
        let b_vector_commitment = commit_vector(&pedersen_params, &b, b_commitment_blinding_factor);

        // Compute input-indexed rerandomization scalars: r_j^in = rerand[pi_inv[j]]
        let mut rerandomization_scalars = [Fr::zero(); N];
        for j in 0..N {
            rerandomization_scalars[j] = rerand[pi_inv[j]];
        }

        // Prove
        let config = crate::config::poseidon_config::<Fq>();
        let mut prover_transcript = PoseidonSponge::new(&config);
        let proof = prove_sigma_linkage_ni(
            &keys,
            &pedersen_params,
            &input_ciphertexts,
            &output_ciphertexts,
            x,
            &b_vector_commitment,
            &b,
            b_commitment_blinding_factor,
            &rerandomization_scalars,
            &mut prover_transcript,
            &mut rng,
        );

        // Verify
        let mut verifier_transcript = PoseidonSponge::new(&config);
        let ok = verify_sigma_linkage_ni(
            &keys,
            &pedersen_params,
            &input_ciphertexts,
            &output_ciphertexts,
            x,
            &b_vector_commitment,
            &proof,
            &mut verifier_transcript,
        );
        assert!(ok, "verification failed");
    }
}
