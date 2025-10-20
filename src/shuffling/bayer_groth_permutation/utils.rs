//! Utility functions for Bayer-Groth permutation protocols

#[cfg(test)]
use crate::{shuffling::pedersen_commitment::msm_ciphertexts, ElGamalCiphertext};
#[cfg(test)]
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
#[cfg(test)]
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
#[cfg(test)]
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// Compute the power sequence [x^0, x^1, ..., x^{N-1}] efficiently for SNARKs
///
/// This function avoids using `pow()` which is inefficient in SNARKs.
/// Instead, it uses iterative multiplication which is much cheaper in constraints.
///
/// # Parameters
/// - `x`: The base value to compute powers of
///
/// # Returns
/// An array [x^0, x^1, ..., x^{N-1}]
///
pub(crate) fn compute_powers_sequence<F: PrimeField, const N: usize>(x: F) -> [F; N] {
    // Use scan pattern to accumulate powers starting at exponent 0
    let mut powers = Vec::with_capacity(N);
    let mut current = F::one();
    powers.push(current);

    for _ in 1..N {
        current *= x;
        powers.push(current);
    }

    powers
        .try_into()
        .expect("Vector length should match array size N")
}

/// Compute the power sequence [x^0, x^1, ..., x^{N-1}] inside a SNARK circuit
///
/// This is the circuit version of `compute_powers_sequence` that efficiently
/// computes powers using iterative multiplication rather than bit decomposition.
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `x`: The base value as a circuit variable
///
/// # Returns
/// An array of circuit variables representing [x^0, x^1, ..., x^{N-1}]
///
/// # Constraints
/// Enforces N-1 multiplication constraints: x_{i+1} = x_i * x
#[cfg(test)]
pub fn compute_powers_sequence_gadget<F: PrimeField, const N: usize>(
    cs: ConstraintSystemRef<F>,
    x: &FpVar<F>,
) -> Result<[FpVar<F>; N], SynthesisError> {
    // Use scan pattern to accumulate powers in circuit starting at exponent 0
    let mut powers = Vec::with_capacity(N);
    let mut current = FpVar::new_constant(cs.clone(), F::one())?;
    powers.push(current.clone());

    for _ in 1..N {
        current = &current * x;
        powers.push(current.clone());
    }

    powers.try_into().map_err(|_| SynthesisError::Unsatisfiable)
}

/// Compute the permutation power vector = (x^{π(0)}, ..., x^{π(N-1)})
///
/// Given a permutation π and a challenge x, this computes the power vector
/// where the i-th element is x raised to the power of π(i).
///
/// # Parameters
/// - `permutation`: The permutation π (0-indexed values)
/// - `perm_power_challenge`: The challenge x derived from Fiat-Shamir (in scalar field)
///
/// # Returns
/// An array where `power_vector[i] = x^{π(i)}` for i = 0..N-1
pub(crate) fn compute_perm_power_vector<F: PrimeField, const N: usize>(
    permutation: &[usize; N],
    perm_power_challenge: F,
) -> [F; N] {
    // power_vector[i] = x^{π(i)} with 0-indexed permutation values
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

/// Compute the permutation power vector in base field
///
/// This is the base field version of compute_perm_power_vector, used for
/// efficient circuit computation without field conversion.
///
/// # Parameters
/// - `permutation`: The permutation π (0-indexed values)
/// - `power_challenge`: The challenge x in base field
///
/// # Returns
/// An array where `power_vector[i] = x^π(i)` for i = 0..N-1, all in base field
pub(crate) fn compute_perm_power_vector_base_field<F: PrimeField, const N: usize>(
    permutation: &[usize; N],
    power_challenge: F,
) -> [F; N] {
    // power_vector[i] = x^{π(i)} in base field
    std::array::from_fn(|i| power_challenge.pow(&[permutation[i] as u64]))
}

/// Compute the power permutation vector b = (x^{π(0)}, ..., x^{π(N-1)})
///
/// Given a permutation π and a challenge x, this computes the power vector
/// where the i-th element is x raised to the power of π(i).
/// This uses 0-based indexing for the powers.
///
/// # Parameters
/// - `permutation`: The permutation π (0-indexed array with 0-indexed values)
/// - `perm_power_challenge`: The challenge x derived from Fiat-Shamir (in scalar field)
///
/// # Returns
/// An array where `b[i] = x^{π(i)}` for i = 0..N-1
#[cfg(test)]
pub(crate) fn compute_power_permutation_vector<F: PrimeField, const N: usize>(
    permutation: &[usize; N],
    perm_power_challenge: F,
) -> [F; N] {
    // b[i] = x^{π(i)} with 0-based indexing
    std::array::from_fn(|i| perm_power_challenge.pow(&[permutation[i] as u64]))
}

/// Helper function to verify the shuffle relation:
/// ∏_j C_j^{x^{j}} = E_pk(0; -ρ) · ∏_i (C'_i)^{b_i}
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

    // Compute left side: ∏_j C_j^{x^{j}}
    let powers = compute_powers_sequence::<G::ScalarField, N>(x);
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
