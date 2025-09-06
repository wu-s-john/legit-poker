//! Utility functions for Bayer-Groth permutation protocols

use crate::shuffling::data_structures::ElGamalCiphertext;
use ark_crypto_primitives::commitment::pedersen::Parameters;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
#[cfg(test)]
use ark_r1cs_std::fields::fp::FpVar;
#[cfg(test)]
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// Compute the power sequence [x^1, x^2, ..., x^N] efficiently for SNARKs
///
/// This function avoids using `pow()` which is inefficient in SNARKs.
/// Instead, it uses iterative multiplication which is much cheaper in constraints.
///
/// # Parameters
/// - `x`: The base value to compute powers of
///
/// # Returns
/// An array [x^1, x^2, ..., x^N]
///
/// # Example
/// ```
/// let x = Fr::from(2u64);
/// let powers = compute_powers_sequence::<Fr, 4>(x);
/// // powers = [2, 4, 8, 16]
/// ```
pub(crate) fn compute_powers_sequence_with_index_1<F: PrimeField, const N: usize>(x: F) -> [F; N] {
    // Use scan pattern to accumulate powers
    let mut powers = Vec::with_capacity(N);
    let mut current = x;
    powers.push(current);

    for _ in 1..N {
        current *= x;
        powers.push(current);
    }

    powers
        .try_into()
        .expect("Vector length should match array size N")
}

/// Compute the power sequence [x^1, x^2, ..., x^N] inside a SNARK circuit
///
/// This is the circuit version of `compute_powers_sequence` that efficiently
/// computes powers using iterative multiplication rather than bit decomposition.
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `x`: The base value as a circuit variable
///
/// # Returns
/// An array of circuit variables representing [x^1, x^2, ..., x^N]
///
/// # Constraints
/// Enforces N-1 multiplication constraints: x_{i+1} = x_i * x
#[cfg(test)]
pub fn compute_powers_sequence_gadget<F: PrimeField, const N: usize>(
    _cs: ConstraintSystemRef<F>,
    x: &FpVar<F>,
) -> Result<[FpVar<F>; N], SynthesisError> {
    // Use scan pattern to accumulate powers in circuit
    let mut powers = Vec::with_capacity(N);
    let mut current = x.clone();
    powers.push(current.clone());

    for _ in 1..N {
        current = &current * x;
        powers.push(current.clone());
    }

    powers.try_into().map_err(|_| SynthesisError::Unsatisfiable)
}

/// Compute the permutation power vector = (x^π(1), ..., x^π(N))
///
/// Given a permutation π and a challenge x, this computes the power vector
/// where the i-th element is x raised to the power of π(i).
///
/// # Parameters
/// - `permutation`: The permutation π (1-indexed values)
/// - `perm_power_challenge`: The challenge x derived from Fiat-Shamir (in scalar field)
///
/// # Returns
/// An array where `power_vector[i] = x^π(i)` for i = 0..N-1
pub(crate) fn compute_perm_power_vector<F: PrimeField, const N: usize>(
    permutation: &[usize; N],
    perm_power_challenge: F,
) -> [F; N] {
    // power_vector[i] = x^π(i)
    // Note: permutation contains 1-indexed values
    let power_vector: Vec<F> = permutation
        .iter()
        .map(|&pi| perm_power_challenge.pow(&[pi as u64]))
        .collect();

    tracing::debug!(
        target: "bayer_groth::setup",
        "Computed permutation power vector of length {}",
        power_vector.len()
    );

    power_vector
        .try_into()
        .expect("Vector length should match array size N")
}

/// Compute the power permutation vector b = (x^{π(0)+1}, ..., x^{π(N-1)+1})
///
/// Given a permutation π and a challenge x, this computes the power vector
/// where the i-th element is x raised to the power of (π(i) + 1).
/// This uses 1-based indexing for the powers.
///
/// # Parameters
/// - `permutation`: The permutation π (0-indexed array with 0-indexed values)
/// - `perm_power_challenge`: The challenge x derived from Fiat-Shamir (in scalar field)
///
/// # Returns
/// An array where `b[i] = x^{π(i)+1}` for i = 0..N-1
#[cfg(test)]
pub(crate) fn compute_power_permutation_vector<F: PrimeField, const N: usize>(
    permutation: &[usize; N],
    perm_power_challenge: F,
) -> [F; N] {
    // b[i] = x^{π(i)+1} with 1-based indexing
    std::array::from_fn(|i| perm_power_challenge.pow(&[(permutation[i] + 1) as u64]))
}

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::utils";

#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
/// MSM over ciphertexts: ∏ (ciphertexts[i])^{scalars[i]} in EC additive notation:
/// accumulates (Σ scalars[i]·c1_i,  Σ scalars[i]·c2_i).
pub(crate) fn msm_ciphertexts<G: CurveGroup, const N: usize>(
    ciphertexts: &[ElGamalCiphertext<G>; N],
    scalars: &[G::ScalarField; N],
) -> ElGamalCiphertext<G> {
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

/// Extract N bases for a linear (scalar-vector) Pedersen commitment from the Pedersen parameters.
/// We reuse the window generators as a long list of bases.
/// Returns (H, [G_1..G_N]) such that com(v;r) = H^r * Π_j G_j^{v_j}.
///
/// This provides the bases for a linearly homomorphic Pedersen commitment over scalar field elements,
/// which is required for the Sigma protocol's algebraic structure.
///
/// IMPORTANT: Normalizes all bases to affine form to ensure consistent representation
/// between native and circuit implementations.
pub(crate) fn extract_pedersen_bases<G, const N: usize>(params: &Parameters<G>) -> (G, [G; N])
where
    G: CurveGroup,
{
    // Use the first element of randomness_generator as H (blinding base)
    // Normalize to affine and back to projective to ensure Z=1
    let blinding_base = params.randomness_generator[0].into_affine().into();

    // Flatten the 2D generator table and take the first N bases for message elements
    // Normalize each base to ensure consistent representation
    let mut generator_iter = params.generators.iter().flat_map(|row| row.iter());

    let message_bases: [G; N] = std::array::from_fn(|_| {
        let base = generator_iter
            .next()
            .expect("Not enough Pedersen generators for the requested N");
        // Normalize to affine and back to projective to ensure Z=1
        base.into_affine().into()
    });

    (blinding_base, message_bases)
}

#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
/// Compute a linearly homomorphic Pedersen commitment over scalar field elements.
///
/// This implements the standard Pedersen commitment formula:
///     com(values; randomness) = H^{randomness} * Π_j G_j^{values[j]}
///
/// This commitment scheme is linearly homomorphic, which is essential for the Sigma protocol:
///     com(v1; r1) * com(v2; r2) = com(v1 + v2; r1 + r2)
///
/// Note: This differs from arkworks' byte-oriented `PedersenCommitment::commit` which
/// is designed for arbitrary byte data. Here we need direct scalar field element commitments
/// to preserve the algebraic structure required by the protocol.
pub(crate) fn pedersen_commit_scalars<G: CurveGroup, const N: usize>(
    params: &Parameters<G>,
    values: &[G::ScalarField; N],
    randomness: G::ScalarField,
) -> G {
    let (blinding_base, message_bases) = extract_pedersen_bases::<G, N>(params);

    // Compute: H^randomness * Π_j G_j^{values[j]}
    // Using fold for more functional style
    let commitment = message_bases
        .iter()
        .zip(values.iter())
        .fold(blinding_base * randomness, |acc, (base, value)| {
            acc + (*base * value)
        });

    commitment
}

/// Helper function to verify the shuffle relation:
/// ∏_j C_j^{x^{j+1}} = E_pk(0; -ρ) · ∏_i (C'_i)^{b_i}
/// where ρ = ∑_i b_i * ρ_i
#[cfg(test)]
pub(crate) fn verify_shuffle_relation<G: CurveGroup, const N: usize>(
    public_key: &G,
    input_ciphertexts: &[ElGamalCiphertext<G>; N],
    output_ciphertexts: &[ElGamalCiphertext<G>; N],
    x: G::ScalarField,
    b: &[G::ScalarField; N],
    rerandomization_scalars: &[G::ScalarField; N],
) -> bool {
    const LOG_TARGET: &str = "test::shuffle_relation";

    // Compute left side: ∏_j C_j^{x^{j+1}}
    let powers = compute_powers_sequence_with_index_1::<G::ScalarField, N>(x);
    let input_aggregator = msm_ciphertexts(input_ciphertexts, &powers);

    // Compute aggregate rerandomizer: ρ = ∑_i b_i * ρ_i
    let rho: G::ScalarField = (0..N)
        .map(|i| b[i] * rerandomization_scalars[i])
        .sum::<G::ScalarField>();

    // Compute E_pk(0; -ρ)
    // Note: For E_pk(0; r) we have (g*r, pk*r) - no generator term in c2
    let g = G::generator();
    let enc_zero_minus_rho = ElGamalCiphertext {
        c1: g * (-rho),
        c2: *public_key * (-rho), // No 'g +' term - this is E_pk(0; -ρ)
    };

    // Compute ∏_i (C'_i)^{b_i}
    let output_aggregator = msm_ciphertexts(output_ciphertexts, b);

    // Compute right side: E_pk(0; -ρ) · ∏_i (C'_i)^{b_i}
    let rhs = ElGamalCiphertext {
        c1: enc_zero_minus_rho.c1 + output_aggregator.c1,
        c2: enc_zero_minus_rho.c2 + output_aggregator.c2,
    };

    tracing::info!(
        target: LOG_TARGET,
        ?powers,
        ?b,
        ?rerandomization_scalars,
        ?rho,
        ?input_aggregator,
        ?rhs,
        "Verifying shuffle relation"
    );

    let result = input_aggregator == rhs;
    if result {
        tracing::info!(target: LOG_TARGET, "✓ Shuffle relation holds!");
    } else {
        tracing::error!(target: LOG_TARGET, "✗ Shuffle relation does NOT hold!");
        tracing::error!(target: LOG_TARGET, "  LHS != RHS");
    }

    result
}
