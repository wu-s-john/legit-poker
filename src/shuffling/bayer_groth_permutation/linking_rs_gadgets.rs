//! Circuit gadgets for Bayer-Groth permutation equality proof

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::{fp::FpVar, FieldOpsBounds, FieldVar},
    groups::{CurveVar, GroupOpsBounds},
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use std::ops::Mul;

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::linking_rs_gadgets";

/// Complete permutation equality proof gadget
///
/// Computes and verifies the permutation proof in-circuit
pub fn compute_permutation_proof_gadget<F, C, CV, FV, const N: usize>(
    cs: ConstraintSystemRef<F>,
    perm_vector: &[FV; N],
    perm_mixing_challenge_y: &FV,
    perm_offset_challenge_z: &FV,
    perm_power_challenge: &FV,
    generator: &CV,
) -> Result<CV, SynthesisError>
where
    F: PrimeField,
    C: CurveGroup,
    CV: CurveVar<C, F>,
    FV: FieldVar<C::ScalarField, F>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    for<'a> &'a FV: FieldOpsBounds<'a, C::ScalarField, FV>,
{
    // Step 1: Compute power vector x^π(i) for each element. It's the vector b in the BG paper
    let perm_power_vector = compute_perm_power_vector::<C::ScalarField, F, FV, N>(
        cs.clone(),
        perm_vector,
        perm_power_challenge,
    )?;

    // Step 2: Linear blend
    let d = linear_blend_gadget(perm_vector, &perm_power_vector, perm_mixing_challenge_y)?;

    // Step 3: Left product
    let left = left_product_gadget(&d, perm_offset_challenge_z)?;

    // Step 4: Right product
    let right = right_product_gadget(
        cs.clone(),
        perm_mixing_challenge_y,
        perm_power_challenge,
        perm_offset_challenge_z,
        N,
    )?;

    // Step 5: Verify equality
    left.enforce_equal(&right)?;

    // Step 6: Fixed-base scalar multiplication
    // Convert scalar to bits for multiplication
    let scalar_bits = left.to_bits_le()?;
    let point = generator.scalar_mul_le(scalar_bits.iter())?;

    // Return the computed point
    Ok(point)
}

/// Gadget for computing linear blend: d_i = perm_mixing_challenge_y * perm_vector_i + perm_power_vector_i
fn linear_blend_gadget<F: PrimeField, ConstraintF: PrimeField, FV, const N: usize>(
    perm_vector: &[FV; N],
    perm_power_vector: &[FV; N],
    perm_mixing_challenge_y: &FV,
) -> Result<Vec<FV>, SynthesisError>
where
    FV: FieldVar<F, ConstraintF>,
    for<'a> &'a FV: FieldOpsBounds<'a, F, FV>,
{
    assert_eq!(
        perm_vector.len(),
        perm_power_vector.len(),
        "Permutation vector and power vector must have same length"
    );

    let d: Vec<_> = perm_vector
        .iter()
        .zip(perm_power_vector.iter())
        .enumerate()
        .map(|(i, (perm_i, power_i))| {
            tracing::trace!(target: LOG_TARGET, "d[{}] = perm_mixing_challenge_y * perm_vector[{}] + perm_power_vector[{}]", i, i, i);
            perm_mixing_challenge_y * perm_i + power_i
        })
        .collect();

    Ok(d)
}

/// Dynamic version of linear_blend_gadget for use with runtime-sized vectors
#[allow(dead_code)]
pub(crate) fn linear_blend_gadget_dynamic<F: PrimeField, ConstraintF: PrimeField, FV>(
    perm_vector: &[FV],
    perm_power_vector: &[FV],
    perm_mixing_challenge_y: &FV,
) -> Result<Vec<FV>, SynthesisError>
where
    FV: FieldVar<F, ConstraintF>,
    for<'a> &'a FV: FieldOpsBounds<'a, F, FV>,
{
    assert_eq!(
        perm_vector.len(),
        perm_power_vector.len(),
        "Permutation vector and power vector must have same length"
    );

    let d: Vec<_> = perm_vector
        .iter()
        .zip(perm_power_vector.iter())
        .enumerate()
        .map(|(i, (perm_i, power_i))| {
            tracing::trace!(target: LOG_TARGET, "d[{}] = perm_mixing_challenge_y * perm_vector[{}] + perm_power_vector[{}]", i, i, i);
            perm_mixing_challenge_y * perm_i + power_i
        })
        .collect();

    Ok(d)
}

/// Gadget for computing left product: L = ∏_{i=1}^N (d_i - perm_offset_challenge_z)
pub(crate) fn left_product_gadget<F: PrimeField, ConstraintF: PrimeField, FV>(
    d: &[FV],
    perm_offset_challenge_z: &FV,
) -> Result<FV, SynthesisError>
where
    FV: FieldVar<F, ConstraintF>,
    for<'a> &'a FV: FieldOpsBounds<'a, F, FV>,
{
    let product = d
        .iter()
        .enumerate()
        .fold(FV::one(), |acc, (i, d_i)| {
            tracing::trace!(target: LOG_TARGET, "L partial product at {}: (d[{}] - perm_offset_challenge_z)", i, i);
            acc * (d_i - perm_offset_challenge_z)
        });

    Ok(product)
}

/// Gadget for computing right product: R = ∏_{i=1}^N (perm_mixing_challenge_y*i + perm_power_challenge^i - perm_offset_challenge_z)
/// Uses running power computation for efficiency
pub(crate) fn right_product_gadget<F: PrimeField, ConstraintF: PrimeField, FV>(
    cs: ConstraintSystemRef<ConstraintF>,
    perm_mixing_challenge_y: &FV,
    perm_power_challenge: &FV,
    perm_offset_challenge_z: &FV,
    n: usize,
) -> Result<FV, SynthesisError>
where
    FV: FieldVar<F, ConstraintF>,
    for<'a> &'a FV: FieldOpsBounds<'a, F, FV>,
{
    let mut product = FV::one();
    let mut power_of_challenge = FV::one(); // perm_power_challenge^0 = 1

    for i in 1..=n {
        // Update running power: perm_power_challenge^i = perm_power_challenge^(i-1) * perm_power_challenge
        power_of_challenge *= perm_power_challenge;

        // Compute i as field element
        let i_const = FV::new_constant(cs.clone(), F::from(i as u64))?;

        // Compute term: perm_mixing_challenge_y*i + perm_power_challenge^i - perm_offset_challenge_z
        let term =
            perm_mixing_challenge_y * &i_const + &power_of_challenge - perm_offset_challenge_z;

        // Update product
        product *= &term;

        tracing::trace!(target: LOG_TARGET, "R partial at {}: perm_mixing_challenge_y*{} + perm_power_challenge^{} - perm_offset_challenge_z", i, i, i);
    }

    Ok(product)
}

/// Compute the blinded Pedersen commitment to the vector (d - z)
/// where:
/// - d_i = y*a_i + b_i (linear blend of permutation and power vectors)
/// - Each element becomes d_i - z
/// - Blinding factor: t = y*r + s
///
/// Returns: C_d = Com(d - z; t) = ∑(d_i - z)*G_i + t*G_blinding
pub fn compute_blinded_commitment_to_d_minus_z_gadget<F, C, CV, FV, const N: usize>(
    generator: &CV,
    permutation: &[FV; N],        // a vector (π(1), ..., π(N))
    perm_power_vector: &[FV; N],  // b vector (x^π(1), ..., x^π(N))
    perm_mixing_challenge_y: &FV, // y challenge
    perm_offset_challenge_z: &FV, // z challenge
    blinding_r: &FV,              // blinding factor r for permutation
    blinding_s: &FV,              // blinding factor s for power vector
) -> Result<CV, SynthesisError>
where
    F: PrimeField,
    C: CurveGroup,
    CV: CurveVar<C, F> + for<'a> Mul<&'a FV, Output = CV>,
    FV: FieldVar<C::ScalarField, F>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    for<'a> &'a FV: FieldOpsBounds<'a, C::ScalarField, FV>,
{
    // Step 1: Compute d vector: d_i = y*a_i + b_i
    let d_vector = linear_blend_gadget(permutation, perm_power_vector, perm_mixing_challenge_y)?;

    // Step 2: Compute d - z vector: (d_1 - z, ..., d_N - z)
    let d_minus_z_vector: Vec<FV> = d_vector
        .iter()
        .map(|d_i| d_i - perm_offset_challenge_z)
        .collect();

    // Step 3: Compute blinding factor t = y*r + s
    let blinding_factor_t: FV = perm_mixing_challenge_y * blinding_r + blinding_s;

    // Step 4: Compute the Pedersen commitment
    // Since we're using a single generator, we compute:
    // C = (∑(d_i - z)) * G + t * G = (∑(d_i - z) + t) * G
    // First accumulate the scalar, then do one scalar multiplication
    let mut sum = blinding_factor_t.clone();
    for elem in d_minus_z_vector.iter() {
        sum = sum + elem;
    }

    // Now do scalar multiplication using the Mul trait
    let commitment = generator.clone() * &sum;

    tracing::debug!(target: LOG_TARGET, "Computed blinded commitment to (d - z) with blinding factor t = y*r + s");

    Ok(commitment)
}

/// Helper function to compute base^exponent in-circuit
///
/// Computes base^exponent where the exponent is assumed to be small (e.g., permutation indices).
/// Currently uses witness generation with native field exponentiation.
/// TODO: Add proper constraints using bit decomposition and repeated squaring.
fn compute_power_gadget<F: PrimeField, ConstraintF: PrimeField, FV>(
    cs: ConstraintSystemRef<ConstraintF>,
    base: &FV,
    exponent: &FV,
) -> Result<FV, SynthesisError>
where
    FV: FieldVar<F, ConstraintF>,
    for<'a> &'a FV: FieldOpsBounds<'a, F, FV>,
{
    // Compute the witness value for the result
    let result_value = || -> Result<F, SynthesisError> {
        let exp_val = exponent.value()?;
        let base_val = base.value()?;

        // Convert exponent to u64 (assumes small value like permutation index)
        let exp_u64 = exp_val.into_bigint().as_ref()[0];

        // Compute base^exponent
        Ok(base_val.pow(&[exp_u64]))
    };

    // Allocate the result as a witness variable
    FV::new_witness(cs, result_value)
}

/// Compute the randomness factor gadget: generator^(y*r + s)
/// This represents the blinding component of the proof in-circuit
pub fn compute_randomness_factor_gadget<F, C, CV, FV>(
    _cs: ConstraintSystemRef<F>,
    generator: &CV,
    y: &FV,
    blinding_r: &FV,
    blinding_s: &FV,
) -> Result<CV, SynthesisError>
where
    F: PrimeField,
    C: CurveGroup,
    CV: CurveVar<C, F>,
    FV: FieldVar<C::ScalarField, F>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    for<'a> &'a FV: FieldOpsBounds<'a, C::ScalarField, FV>,
{
    // Compute exponent: y * r + s (in scalar field)
    let exponent = y * blinding_r + blinding_s;

    // Convert to bits for scalar multiplication
    let exponent_bits = exponent.to_bits_le()?;

    // Compute generator^exponent using scalar multiplication
    let randomness_factor = generator.scalar_mul_le(exponent_bits.iter())?;

    Ok(randomness_factor)
}

/// Compute the permutation power vector = (x^π(1), ..., x^π(N)) in-circuit
///
/// Parameters:
/// - cs: Constraint system reference
/// - permutation: The permutation π as circuit variables (values 1 to N)
/// - perm_power_challenge: The challenge x derived from Fiat-Shamir
///
/// Returns: Power vector as circuit variables
pub fn compute_perm_power_vector<F: PrimeField, ConstraintF: PrimeField, FV, const N: usize>(
    cs: ConstraintSystemRef<ConstraintF>,
    permutation: &[FV; N],
    perm_power_challenge: &FV,
) -> Result<[FV; N], SynthesisError>
where
    FV: FieldVar<F, ConstraintF>,
    for<'a> &'a FV: FieldOpsBounds<'a, F, FV>,
{
    // Use functional array construction to compute x^π(i) for each element
    let result = permutation
        .iter()
        .enumerate()
        .map(|(i, pi)| {
            tracing::trace!(target: LOG_TARGET, "Computing power_vector[{}] = x^π({})", i, i);
            compute_power_gadget(cs.clone(), perm_power_challenge, pi)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let power_vector: [FV; N] = result
        .try_into()
        .map_err(|_| SynthesisError::Unsatisfiable)?;

    tracing::debug!(target: LOG_TARGET, "Computed permutation power vector of length {}", N);

    Ok(power_vector)
}

/// Allocate a vector of field elements as circuit variables
#[allow(dead_code)]
pub(crate) fn alloc_vector<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    values: &[F],
    mode: AllocationMode,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    values
        .iter()
        .enumerate()
        .map(|(_i, &v)| FpVar::new_variable(cs.clone(), || Ok(v), mode))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::bayer_groth_permutation::linking_rs_native as native;
    use ark_bn254::Fr;
    use ark_ff::{Field, One};
    use ark_r1cs_std::{eq::EqGadget, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{rand::RngCore, test_rng, UniformRand};

    /// Generate a random permutation of 1..=n
    fn random_permutation(n: usize, rng: &mut impl RngCore) -> Vec<usize> {
        let mut perm: Vec<usize> = (1..=n).collect();

        // Fisher-Yates shuffle
        for i in (1..n).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            perm.swap(i, j);
        }

        perm
    }

    #[test]
    fn test_linear_blend_gadget() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let n = 5;
        let a_vals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b_vals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let y_val = Fr::rand(&mut rng);

        // Allocate as circuit variables
        let a = alloc_vector(cs.clone(), &a_vals, AllocationMode::Witness)?;
        let b = alloc_vector(cs.clone(), &b_vals, AllocationMode::Witness)?;
        let y = FpVar::new_witness(cs.clone(), || Ok(y_val))?;

        // Compute in circuit
        let d = linear_blend_gadget_dynamic(&a, &b, &y)?;

        // Check each value
        for i in 0..n {
            let expected = y_val * a_vals[i] + b_vals[i];
            assert_eq!(d[i].value()?, expected);
        }

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_permutation_equality_gadget() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create a small permutation
        let perm = vec![2, 1, 3];
        let n = perm.len();

        // Generate challenges
        let x_val = Fr::rand(&mut rng);
        let y_val = Fr::rand(&mut rng);
        let z_val = Fr::rand(&mut rng);

        // Create vectors
        let a_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();
        let b_vals: Vec<Fr> = perm.iter().map(|&i| x_val.pow(&[i as u64])).collect();

        // Allocate circuit variables
        let a = alloc_vector(cs.clone(), &a_vals, AllocationMode::Witness)?;
        let b = alloc_vector(cs.clone(), &b_vals, AllocationMode::Witness)?;
        let x = FpVar::new_witness(cs.clone(), || Ok(x_val))?;
        let y = FpVar::new_witness(cs.clone(), || Ok(y_val))?;
        let z = FpVar::new_witness(cs.clone(), || Ok(z_val))?;

        // Compute products
        let d = linear_blend_gadget_dynamic(&a, &b, &y)?;
        let left = left_product_gadget(&d, &z)?;
        let right = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

        // Verify equality
        left.enforce_equal(&right)?;

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    /// Test that native and circuit implementations produce the same results
    #[test]
    fn test_native_vs_circuit_basic() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        let n = 10;

        // Generate random permutation
        let perm = random_permutation(n, &mut rng);

        // Create vector a from permutation
        let a_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

        // Generate challenges
        let x_val = Fr::rand(&mut rng);
        let y_val = Fr::rand(&mut rng);
        let z_val = Fr::rand(&mut rng);

        // Compute hidden vector b = (x^π(1), ..., x^π(n))
        let b_vals: Vec<Fr> = perm.iter().map(|&i| x_val.pow(&[i as u64])).collect();

        // Native implementation
        let d_native = native::compute_linear_blend(&a_vals, &b_vals, y_val);
        let left_native = native::compute_left_product(&d_native, z_val);
        let right_native = native::compute_right_product(y_val, x_val, z_val, n);

        // Circuit implementation
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = alloc_vector(cs.clone(), &a_vals, AllocationMode::Witness)?;
        let b = alloc_vector(cs.clone(), &b_vals, AllocationMode::Witness)?;
        let x = FpVar::new_witness(cs.clone(), || Ok(x_val))?;
        let y = FpVar::new_witness(cs.clone(), || Ok(y_val))?;
        let z = FpVar::new_witness(cs.clone(), || Ok(z_val))?;

        let d_circuit = linear_blend_gadget_dynamic(&a, &b, &y)?;
        let left_circuit = left_product_gadget(&d_circuit, &z)?;
        let right_circuit = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

        // Compare results
        assert_eq!(left_circuit.value()?, left_native);
        assert_eq!(right_circuit.value()?, right_native);

        // For valid permutation, left should equal right
        assert_eq!(left_native, right_native);
        assert_eq!(left_circuit.value()?, right_circuit.value()?);

        // Verify constraints are satisfied
        left_circuit.enforce_equal(&right_circuit)?;
        assert!(cs.is_satisfied()?);

        tracing::debug!(
            target = LOG_TARGET,
            "✓ Native and circuit implementations match for n={}",
            n
        );

        Ok(())
    }

    /// Test with various permutation sizes
    #[test]
    fn test_multiple_sizes() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        let sizes = vec![3, 5, 10, 20, 52];

        for n in sizes {
            let perm = random_permutation(n, &mut rng);
            let a_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

            let x_val = Fr::rand(&mut rng);
            let y_val = Fr::rand(&mut rng);
            let z_val = Fr::rand(&mut rng);

            let b_vals: Vec<Fr> = perm.iter().map(|&i| x_val.pow(&[i as u64])).collect();

            // Native
            let d_native = native::compute_linear_blend(&a_vals, &b_vals, y_val);
            let left_native = native::compute_left_product(&d_native, z_val);
            let right_native = native::compute_right_product(y_val, x_val, z_val, n);

            // Circuit
            let cs = ConstraintSystem::<Fr>::new_ref();

            let a = alloc_vector(cs.clone(), &a_vals, AllocationMode::Witness)?;
            let b = alloc_vector(cs.clone(), &b_vals, AllocationMode::Witness)?;
            let y = FpVar::new_witness(cs.clone(), || Ok(y_val))?;
            let x = FpVar::new_witness(cs.clone(), || Ok(x_val))?;
            let z = FpVar::new_witness(cs.clone(), || Ok(z_val))?;

            let d_circuit = linear_blend_gadget_dynamic(&a, &b, &y)?;
            let left_circuit = left_product_gadget(&d_circuit, &z)?;
            let right_circuit = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

            // Verify equality
            assert_eq!(left_circuit.value()?, left_native);
            assert_eq!(right_circuit.value()?, right_native);
            assert_eq!(left_native, right_native);

            left_circuit.enforce_equal(&right_circuit)?;
            assert!(cs.is_satisfied()?);

            tracing::debug!(target = LOG_TARGET, "✓ Test passed for n={}", n);
        }

        Ok(())
    }

    /// Test that invalid permutations fail
    #[test]
    fn test_invalid_permutation_fails() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        let n = 5;

        // Create an INVALID "permutation" with a repeated element
        let invalid_perm = vec![1, 2, 2, 4, 5]; // 2 appears twice, 3 is missing

        let a_vals: Vec<Fr> = invalid_perm.iter().map(|&i| Fr::from(i as u64)).collect();

        let x_val = Fr::rand(&mut rng);
        let y_val = Fr::rand(&mut rng);
        let z_val = Fr::rand(&mut rng);

        // Compute b with the invalid permutation
        let b_vals: Vec<Fr> = invalid_perm
            .iter()
            .map(|&i| x_val.pow(&[i as u64]))
            .collect();

        // Native computation
        let d_native = native::compute_linear_blend(&a_vals, &b_vals, y_val);
        let left_native = native::compute_left_product(&d_native, z_val);
        let right_native = native::compute_right_product(y_val, x_val, z_val, n);

        // These should NOT be equal for invalid permutation
        assert_ne!(left_native, right_native);

        // Circuit should also detect this
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = alloc_vector(cs.clone(), &a_vals, AllocationMode::Witness)?;
        let b = alloc_vector(cs.clone(), &b_vals, AllocationMode::Witness)?;
        let y = FpVar::new_witness(cs.clone(), || Ok(y_val))?;
        let x = FpVar::new_witness(cs.clone(), || Ok(x_val))?;
        let z = FpVar::new_witness(cs.clone(), || Ok(z_val))?;

        let d_circuit = linear_blend_gadget_dynamic(&a, &b, &y)?;
        let left_circuit = left_product_gadget(&d_circuit, &z)?;
        let right_circuit = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

        // Values should not match
        assert_ne!(left_circuit.value()?, right_circuit.value()?);

        // Trying to enforce equality should make constraints unsatisfied
        left_circuit.enforce_equal(&right_circuit)?;
        assert!(!cs.is_satisfied()?);

        tracing::debug!(
            target = LOG_TARGET,
            "✓ Invalid permutation correctly detected"
        );

        Ok(())
    }

    /// Test edge cases
    #[test]
    fn test_edge_cases() -> Result<(), SynthesisError> {
        let mut rng = test_rng();

        // Test with n=1 (trivial permutation)
        {
            let n = 1;
            let _perm = vec![1];
            let a_vals = vec![Fr::one()];

            let x_val = Fr::rand(&mut rng);
            let y_val = Fr::rand(&mut rng);
            let z_val = Fr::rand(&mut rng);

            let b_vals = vec![x_val];

            let left = native::compute_left_product(
                &native::compute_linear_blend(&a_vals, &b_vals, y_val),
                z_val,
            );
            let right = native::compute_right_product(y_val, x_val, z_val, n);

            assert_eq!(left, right);
            tracing::debug!(target = LOG_TARGET, "✓ Edge case n=1 passed");
        }

        // Test with identity permutation
        {
            let n = 5;
            let perm: Vec<usize> = (1..=n).collect();
            let a_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

            let x_val = Fr::rand(&mut rng);
            let y_val = Fr::rand(&mut rng);
            let z_val = Fr::rand(&mut rng);

            let b_vals: Vec<Fr> = perm.iter().map(|&i| x_val.pow(&[i as u64])).collect();

            let left = native::compute_left_product(
                &native::compute_linear_blend(&a_vals, &b_vals, y_val),
                z_val,
            );
            let right = native::compute_right_product(y_val, x_val, z_val, n);

            assert_eq!(left, right);
            tracing::debug!(target = LOG_TARGET, "✓ Identity permutation passed");
        }

        // Test with reverse permutation
        {
            let n = 5;
            let perm: Vec<usize> = (1..=n).rev().collect();
            let a_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

            let x_val = Fr::rand(&mut rng);
            let y_val = Fr::rand(&mut rng);
            let z_val = Fr::rand(&mut rng);

            let b_vals: Vec<Fr> = perm.iter().map(|&i| x_val.pow(&[i as u64])).collect();

            let left = native::compute_left_product(
                &native::compute_linear_blend(&a_vals, &b_vals, y_val),
                z_val,
            );
            let right = native::compute_right_product(y_val, x_val, z_val, n);

            assert_eq!(left, right);
            tracing::debug!(target = LOG_TARGET, "✓ Reverse permutation passed");
        }

        Ok(())
    }
}
