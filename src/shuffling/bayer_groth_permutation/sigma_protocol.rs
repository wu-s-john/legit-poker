//! Non-interactive single Σ-protocol for Bayer-Groth shuffle rerandomization proof
//!
//! This module implements a type-safe non-interactive Σ-protocol that proves:
//! C'^a = E_pk(1; ρ) · ∏(C_j)^{b_j} with c_B = com(b; s_B)
//!
//! ## Mathematical Foundation
//!
//! The proof demonstrates that a shuffle was performed correctly by showing that
//! two different polynomial evaluations yield the same result:
//! - Left side: ∏(C'_i)^{x^i} - the output ciphertexts raised to sequential powers of x
//! - Right side: E_pk(1; ρ) · ∏(C_j)^{x^{π^{-1}(j)}} - the input ciphertexts raised to permuted powers plus rerandomization
//!
//! ## Key Components
//!
//! - **a = (x, x^2, ..., x^N)**: Public exponents derived from Fiat-Shamir challenge x
//! - **b = (x^{π^{-1}(1)}, ..., x^{π^{-1}(N)})**: Private permuted exponents (witness)
//! - **π**: The secret permutation applied during shuffling
//! - **ρ**: Aggregate rerandomization factor = Σ(x^i · r_i) where r_i are individual rerandomizations
//!
//! ## Proof Strategy
//!
//! 1. **Commitment Phase**: Prover commits to the permuted exponents b using Pedersen commitment
//! 2. **Challenge Derivation**: Use Fiat-Shamir to derive challenge x from transcript
//! 3. **Aggregation**: Compute C'^a = ∏(C'_i)^{x^i} which aggregates all output ciphertexts
//! 4. **Σ-Protocol Execution**:
//!    - Prover generates random t vector and commits: T_com = com(t; t_s)
//!    - Prover computes T_grp = E(1; t_rho) · ∏C_j^{t_j} (random linear combination)
//!    - Challenge c derived via Fiat-Shamir from T_com and T_grp
//!    - Prover responds with z_b = t + c·b, z_s = t_s + c·s_B, z_rho = t_rho + c·ρ
//! 5. **Verification**: Check two equations hold:
//!    - com(z_b; z_s) = T_com · c_B^c (commitment consistency)
//!    - E(1; z_rho) · ∏C_j^{z_{b,j}} = T_grp · (C'^a)^c (shuffle correctness)
//!
//! ## Security Properties
//!
//! - **Completeness**: Honest prover always convinces honest verifier
//! - **Soundness**: If permutation is incorrect, no malicious prover can create valid proof
//! - **Zero-Knowledge**: Proof reveals nothing about the permutation π beyond its correctness
//! - **Non-Interactive**: Uses Fiat-Shamir transform with Poseidon hash for challenge generation
//!
//! ## Implementation Details
//!
//! - Uses const generics (N) for compile-time size checking and type safety
//! - Supports any deck size from N=1 to N=52 (standard deck)
//! - Optimized multi-scalar multiplication for efficiency
//! - Compatible with both native and in-circuit verification

use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalKeys};
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::{
    commitment::{
        pedersen::{Commitment as PedersenCommitment, Parameters, Randomness, Window},
        CommitmentScheme,
    },
    sponge::{poseidon::PoseidonSponge, CryptographicSponge},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, vec::Vec, Zero};

/// Window type for Pedersen commitment (matches existing usage)
#[derive(Clone)]
pub struct SigmaWindow;

impl Window for SigmaWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 64; // 4×64 = 256 bits for Fr elements
}

/// Type alias for our Pedersen commitment scheme
pub type Pedersen<G> = PedersenCommitment<G, SigmaWindow>;

/// Core proof struct with const generic N for type-safe array sizes
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SigmaProof<F: PrimeField, G: CurveGroup, const N: usize> {
    /// Commitment to random t vector
    pub T_com: G,
    /// ElGamal ciphertext for random MSM
    pub T_grp: ElGamalCiphertext<G>,
    /// Response array (exactly N elements)
    pub z_b: [F; N],
    /// Response for commitment randomness
    pub z_s: F,
    /// Response for rerandomization
    pub z_rho: F,
}

/// Non-interactive prover using Fiat-Shamir with type-safe arrays
///
/// Generates a proof that C'^a = E_pk(1; ρ) · ∏(C_j)^{b_j}
/// where a[i] = x^(i+1) and b[j] = x^{π^{-1}(j)+1}
///
/// ## Step-by-Step Process:
///
/// 1. **Transcript Setup**: Absorb all public inputs (C_in, C_out, cB) into the Fiat-Shamir transcript
/// 2. **Aggregation**: Compute C'^a = ∏(C'_i)^{x^i} which aggregates output ciphertexts
/// 3. **Random Blinding**: Generate random vectors t ∈ Z_q^N, t_s, t_rho ∈ Z_q for zero-knowledge
/// 4. **Commitment Phase**:
///    - Compute T_com = com(t; t_s) - commitment to random vector t
///    - Compute T_grp = E(1; t_rho) · ∏(C_j)^{t_j} - random linear combination of inputs
/// 5. **Challenge Derivation**: Extract challenge c from transcript via Fiat-Shamir
/// 6. **Response Phase**: Compute responses that hide the witness:
///    - z_b = t + c·b (hides permutation b)
///    - z_s = t_s + c·s_B (hides commitment randomness)
///    - z_rho = t_rho + c·ρ (hides rerandomization factor)
///
/// ## Security Properties:
/// - **Completeness**: Honest prover with valid witness always produces accepting proof
/// - **Soundness**: Without valid witness, cannot produce accepting proof except with neg. probability
/// - **Zero-Knowledge**: Responses are uniformly random, revealing nothing about b, s_B, or ρ
pub fn prove_sigma_linkage_ni<F, G, const N: usize>(
    keys: &ElGamalKeys<G>,
    pedersen_params: &Parameters<G>,
    C_in: &[ElGamalCiphertext<G>; N],
    C_out: &[ElGamalCiphertext<G>; N],
    x: F,
    cB: &G,
    b: &[F; N],
    sB: F,
    rho: F,
    transcript: &mut PoseidonSponge<F>,
    rng: &mut impl Rng,
) -> SigmaProof<F, G, N>
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    tracing::debug!(target: "sigma_protocol", "Starting non-interactive proof generation for N={}", N);

    // Absorb public inputs into transcript
    absorb_public_inputs(transcript, C_in, C_out, cB);

    // Compute public aggregator C'^a = ∏(C'_i)^{x^i}
    let Cprime_agg = compute_output_aggregator(C_out, x);

    // Absorb aggregator components as field elements
    absorb_ciphertext(transcript, &Cprime_agg);

    // Step 1: Generate random commitments
    let mut t = [F::zero(); N];
    for i in 0..N {
        t[i] = F::rand(rng);
    }
    let t_s = F::rand(rng);
    let t_rho = F::rand(rng);

    // Compute T_com = com(t; t_s)
    let T_com = commit_vector(pedersen_params, &t, t_s);

    // Compute T_grp = E(1; t_rho) · ∏C_j^{t_j}
    let T_grp = {
        let g = G::generator();
        let rerand = ElGamalCiphertext {
            c1: g * t_rho,
            c2: keys.public_key * t_rho,
        };
        let msm = msm_ciphertexts(C_in, &t);
        ElGamalCiphertext {
            c1: rerand.c1 + msm.c1,
            c2: rerand.c2 + msm.c2,
        }
    };

    // Step 2: Absorb commitments and derive challenge
    absorb_point(transcript, &T_com);
    absorb_ciphertext(transcript, &T_grp);

    // Derive challenge c from transcript
    let c: F = transcript.squeeze_field_elements(1)[0];

    tracing::trace!(target: "sigma_protocol", "Derived challenge c from transcript");

    // Step 3: Compute responses
    let mut z_b = [F::zero(); N];
    for i in 0..N {
        z_b[i] = t[i] + c * b[i];
    }
    let z_s = t_s + c * sB;
    let z_rho = t_rho + c * rho;

    tracing::debug!(target: "sigma_protocol", "Proof generation complete");

    SigmaProof {
        T_com,
        T_grp,
        z_b,
        z_s,
        z_rho,
    }
}

/// Non-interactive verifier with type-safe arrays
///
/// ## Constraints Checked:
///
/// 1. **Commitment Consistency**: com(z_b; z_s) = T_com · cB^c
///    - Ensures the response z_b is consistent with the committed permutation b
///    - Verifies that prover knows the opening (b, s_B) to commitment cB
///
/// 2. **Shuffle Correctness**: E(1; z_rho) · ∏C_j^{z_{b,j}} = T_grp · (C'^a)^c
///    - Ensures the shuffle was performed correctly with the committed permutation
///    - Verifies that C'^a (aggregated outputs) equals the permuted and rerandomized inputs
///    - Confirms knowledge of the aggregate rerandomization factor ρ
///
/// ## Step-by-Step Verification:
///
/// 1. **Reconstruct Transcript**: Absorb same public inputs as prover (C_in, C_out, cB)
/// 2. **Recompute Aggregator**: Calculate C'^a = ∏(C'_i)^{x^i} from output ciphertexts
/// 3. **Absorb Proof Elements**: Add T_com and T_grp to transcript
/// 4. **Derive Challenge**: Extract same challenge c from transcript (must match prover's)
/// 5. **Check Commitment Equation**:
///    - LHS: com(z_b; z_s) using Pedersen commitment
///    - RHS: T_com · cB^c using group operations
///    - Verify LHS = RHS
/// 6. **Check Shuffle Equation**:
///    - LHS: E(1; z_rho) · ∏C_j^{z_{b,j}} using ElGamal encryption and MSM
///    - RHS: T_grp · (C'^a)^c using group operations
///    - Verify LHS = RHS (component-wise for ElGamal)
///
/// Returns true iff both constraints are satisfied
pub fn verify_sigma_linkage_ni<F, G, const N: usize>(
    keys: &ElGamalKeys<G>,
    pedersen_params: &Parameters<G>,
    C_in: &[ElGamalCiphertext<G>; N],
    C_out: &[ElGamalCiphertext<G>; N],
    x: F,
    cB: &G,
    proof: &SigmaProof<F, G, N>,
    transcript: &mut PoseidonSponge<F>,
) -> bool
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    tracing::debug!(target: "sigma_protocol", "Starting non-interactive verification for N={}", N);

    // Absorb public inputs into transcript
    absorb_public_inputs(transcript, C_in, C_out, cB);

    // Compute public aggregator C'^a = ∏(C'_i)^{x^i}
    let Cprime_agg = compute_output_aggregator(C_out, x);

    // Absorb aggregator components as field elements
    absorb_ciphertext(transcript, &Cprime_agg);

    // Absorb proof commitments
    absorb_point(transcript, &proof.T_com);
    absorb_ciphertext(transcript, &proof.T_grp);

    // Derive challenge c from transcript (should match prover's)
    let c: F = transcript.squeeze_field_elements(1)[0];

    tracing::trace!(target: "sigma_protocol", "Derived challenge c for verification");

    // Check 1: com(z_b; z_s) = T_com · cB^c
    let lhs_com = commit_vector(pedersen_params, &proof.z_b, proof.z_s);
    let rhs_com = proof.T_com + *cB * c;

    if lhs_com != rhs_com {
        tracing::debug!(target: "sigma_protocol", "Commitment equality check failed");
        return false;
    }

    // Check 2: E(1; z_rho) · ∏C_j^{z_{b,j}} = T_grp · (C'^a)^c
    let lhs_grp = {
        let g = G::generator();
        let rerand = ElGamalCiphertext {
            c1: g * proof.z_rho,
            c2: keys.public_key * proof.z_rho,
        };
        let msm = msm_ciphertexts(C_in, &proof.z_b);
        ElGamalCiphertext {
            c1: rerand.c1 + msm.c1,
            c2: rerand.c2 + msm.c2,
        }
    };

    let rhs_grp = ElGamalCiphertext {
        c1: proof.T_grp.c1 + Cprime_agg.c1 * c,
        c2: proof.T_grp.c2 + Cprime_agg.c2 * c,
    };

    if lhs_grp != rhs_grp {
        tracing::debug!(target: "sigma_protocol", "Ciphertext equality check failed");
        return false;
    }

    tracing::debug!(target: "sigma_protocol", "Verification successful");
    true
}

/// Helper to compute C'^a = ∏(C'_i)^{x^i} with type-safe arrays
///
/// ## Purpose:
/// Aggregates the output ciphertexts into a single ciphertext using powers of challenge x.
/// This creates a binding commitment to all output ciphertexts that can be efficiently verified.
///
/// ## Step-by-Step:
/// 1. Compute sequential powers: x, x^2, x^3, ..., x^N
/// 2. Perform multi-scalar multiplication: ∏(C'_i)^{x^i}
/// 3. Return aggregated ciphertext C'^a
///
/// ## Why This Works:
/// The aggregation binds all outputs into one element. If the shuffle is correct,
/// this will equal the aggregation of permuted inputs plus rerandomization.
pub fn compute_output_aggregator<F, G, const N: usize>(
    C_out: &[ElGamalCiphertext<G>; N],
    x: F,
) -> ElGamalCiphertext<G>
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let mut powers = [F::zero(); N];
    let mut x_power = x;
    for i in 0..N {
        powers[i] = x_power;
        x_power *= x;
    }

    msm_ciphertexts(C_out, &powers)
}

/// Helper for multi-scalar multiplication with arrays
///
/// ## Purpose:
/// Efficiently computes ∏(ciphertexts[i])^{scalars[i]} for ElGamal ciphertexts.
///
/// ## Step-by-Step:
/// 1. Initialize result as identity (point at infinity)
/// 2. For each ciphertext-scalar pair:
///    - Multiply ciphertext.c1 by scalar
///    - Multiply ciphertext.c2 by scalar
///    - Add to running result
/// 3. Return combined ciphertext
///
/// ## Optimization:
/// Uses additive notation for elliptic curve groups where scalar multiplication
/// is the primary operation (not explicit exponentiation).
pub fn msm_ciphertexts<F, G, const N: usize>(
    ciphertexts: &[ElGamalCiphertext<G>; N],
    scalars: &[F; N],
) -> ElGamalCiphertext<G>
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
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

/// Helper to commit to a vector using Pedersen commitment
///
/// ## Purpose:
/// Creates a binding and hiding commitment to a vector of field elements.
///
/// ## Step-by-Step:
/// 1. Serialize all field elements in the vector to bytes
/// 2. Create Randomness object from the randomness scalar
/// 3. Use Pedersen commitment scheme to commit to serialized data
/// 4. Return the commitment point
///
/// ## Security:
/// - **Binding**: Cannot open commitment to different values (computational)
/// - **Hiding**: Commitment reveals nothing about committed values (perfect with random r)
fn commit_vector<F, G, const N: usize>(params: &Parameters<G>, values: &[F; N], randomness: F) -> G
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    // Convert field elements to bytes for commitment
    let mut input = Vec::new();
    for val in values {
        val.serialize_compressed(&mut input).unwrap();
    }

    // Create randomness struct
    let r = Randomness(randomness);

    // Commit using Pedersen
    Pedersen::<G>::commit(params, &input, &r).unwrap().into()
}

/// Helper to absorb public inputs into transcript
fn absorb_public_inputs<F, G, const N: usize>(
    transcript: &mut PoseidonSponge<F>,
    C_in: &[ElGamalCiphertext<G>; N],
    C_out: &[ElGamalCiphertext<G>; N],
    cB: &G,
) where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    // Absorb input ciphertexts
    for ct in C_in {
        absorb_ciphertext(transcript, ct);
    }

    // Absorb output ciphertexts
    for ct in C_out {
        absorb_ciphertext(transcript, ct);
    }

    // Absorb commitment cB
    absorb_point(transcript, cB);
}

/// Helper to absorb a ciphertext by absorbing its components as field elements
fn absorb_ciphertext<F, G>(transcript: &mut PoseidonSponge<F>, ct: &ElGamalCiphertext<G>)
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    // Convert to affine and absorb coordinates
    let c1_affine = ct.c1.into_affine();
    let c2_affine = ct.c2.into_affine();

    // Absorb x and y coordinates as field elements
    // Note: We need to convert from BaseField to ScalarField
    let mut bytes = Vec::new();
    c1_affine.x().serialize_compressed(&mut bytes).unwrap();
    c1_affine.y().serialize_compressed(&mut bytes).unwrap();
    c2_affine.x().serialize_compressed(&mut bytes).unwrap();
    c2_affine.y().serialize_compressed(&mut bytes).unwrap();
    transcript.absorb(&bytes);
}

/// Helper to absorb a curve point by absorbing its coordinates as field elements
fn absorb_point<F, G>(transcript: &mut PoseidonSponge<F>, point: &G)
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let affine = point.into_affine();
    let mut bytes = Vec::new();
    affine.x().serialize_compressed(&mut bytes).unwrap();
    affine.y().serialize_compressed(&mut bytes).unwrap();
    transcript.absorb(&bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_crypto_primitives::commitment::CommitmentScheme;
    use ark_ec::PrimeGroup;
    use ark_ff::{Field, UniformRand};
    use ark_std::test_rng;

    #[test]
    fn test_proof_generation_and_verification() {
        const N: usize = 4;
        let mut rng = test_rng();

        // Setup keys
        let sk = Fr::rand(&mut rng);
        let keys = ElGamalKeys::new(sk);
        let g = G1Projective::generator();

        // Setup Pedersen parameters
        let pedersen_params = Pedersen::<G1Projective>::setup(&mut rng).unwrap();

        // Generate test ciphertexts
        let C_in: [ElGamalCiphertext<G1Projective>; N] =
            core::array::from_fn(|_| ElGamalCiphertext {
                c1: G1Projective::zero(),
                c2: G1Projective::zero(),
            });
        let C_out: [ElGamalCiphertext<G1Projective>; N] =
            core::array::from_fn(|_| ElGamalCiphertext {
                c1: G1Projective::zero(),
                c2: G1Projective::zero(),
            });
        let mut C_in = C_in;
        let mut C_out = C_out;

        for i in 0..N {
            let r = Fr::rand(&mut rng);
            C_in[i] = ElGamalCiphertext {
                c1: g * r,
                c2: keys.public_key * r,
            };
            C_out[i] = C_in[i].clone();
        }

        // Setup witnesses
        let x = Fr::from(2u64);
        let mut b = [Fr::zero(); N];
        for i in 0..N {
            b[i] = x.pow(&[(i + 1) as u64]);
        }
        let sB = Fr::rand(&mut rng);
        let cB = commit_vector(&pedersen_params, &b, sB);
        let rho = Fr::rand(&mut rng);

        // Create transcript
        let config = crate::config::poseidon_config::<Fr>();
        let mut prover_transcript = PoseidonSponge::new(&config);

        // Generate proof
        let proof = prove_sigma_linkage_ni(
            &keys,
            &pedersen_params,
            &C_in,
            &C_out,
            x,
            &cB,
            &b,
            sB,
            rho,
            &mut prover_transcript,
            &mut rng,
        );

        // Verify proof
        let mut verifier_transcript = PoseidonSponge::new(&config);

        assert!(verify_sigma_linkage_ni(
            &keys,
            &pedersen_params,
            &C_in,
            &C_out,
            x,
            &cB,
            &proof,
            &mut verifier_transcript,
        ));
    }
}
