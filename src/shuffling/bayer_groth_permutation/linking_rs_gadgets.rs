//! Circuit gadgets for Bayer-Groth permutation equality proof

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::{CurveVar, GroupOpsBounds},
    prelude::*,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::linking_rs_gadgets";

/// Gadget for computing linear blend: d_i = perm_mixing_challenge_y * perm_vector_i + perm_power_vector_i
pub fn linear_blend_gadget<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    perm_vector: &[FpVar<F>],
    perm_power_vector: &[FpVar<F>],
    perm_mixing_challenge_y: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    assert_eq!(
        perm_vector.len(),
        perm_power_vector.len(),
        "Permutation vector and power vector must have same length"
    );

    let mut d = Vec::with_capacity(perm_vector.len());

    for (i, (perm_i, power_i)) in perm_vector.iter().zip(perm_power_vector.iter()).enumerate() {
        // d_i = perm_mixing_challenge_y * perm_vector_i + perm_power_vector_i
        let term = perm_mixing_challenge_y * perm_i + power_i;
        d.push(term);

        tracing::trace!(target: LOG_TARGET, "d[{}] = perm_mixing_challenge_y * perm_vector[{}] + perm_power_vector[{}]", i, i, i);
    }

    Ok(d)
}

/// Gadget for computing left product: L = ∏_{i=1}^N (d_i - perm_offset_challenge_z)
pub fn left_product_gadget<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    d: &[FpVar<F>],
    perm_offset_challenge_z: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let mut product = FpVar::<F>::one();

    for (i, d_i) in d.iter().enumerate() {
        // Compute d_i - perm_offset_challenge_z
        let diff = d_i - perm_offset_challenge_z;

        // Update product: product *= (d_i - perm_offset_challenge_z)
        product *= &diff;

        tracing::trace!(target: LOG_TARGET, "L partial product at {}: (d[{}] - perm_offset_challenge_z)", i, i);
    }

    Ok(product)
}

/// Gadget for computing right product: R = ∏_{i=1}^N (perm_mixing_challenge_y*i + perm_power_challenge^i - perm_offset_challenge_z)
/// Uses running power computation for efficiency
pub fn right_product_gadget<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    perm_mixing_challenge_y: &FpVar<F>,
    perm_power_challenge: &FpVar<F>,
    perm_offset_challenge_z: &FpVar<F>,
    n: usize,
) -> Result<FpVar<F>, SynthesisError> {
    let mut product = FpVar::<F>::one();
    let mut power_of_challenge = FpVar::<F>::one(); // perm_power_challenge^0 = 1

    for i in 1..=n {
        // Update running power: perm_power_challenge^i = perm_power_challenge^(i-1) * perm_power_challenge
        power_of_challenge *= perm_power_challenge;

        // Compute i as field element
        let i_const = FpVar::<F>::new_constant(cs.clone(), F::from(i as u64))?;

        // Compute term: perm_mixing_challenge_y*i + perm_power_challenge^i - perm_offset_challenge_z
        let term =
            perm_mixing_challenge_y * &i_const + &power_of_challenge - perm_offset_challenge_z;

        // Update product
        product *= &term;

        tracing::trace!(target: LOG_TARGET, "R partial at {}: perm_mixing_challenge_y*{} + perm_power_challenge^{} - perm_offset_challenge_z", i, i, i);
    }

    Ok(product)
}

/// Gadget for verifying permutation equality: enforce L == R
pub fn verify_permutation_equality_gadget<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    left_product: &FpVar<F>,
    right_product: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // Enforce the constraint: L = R
    left_product.enforce_equal(right_product)?;

    tracing::debug!(target: LOG_TARGET, "Enforced L == R constraint");

    Ok(())
}

/// Fixed-base scalar multiplication gadget: P = [scalar]G
/// Uses precomputed tables for efficiency in circuits
pub fn fixed_base_scalar_mul_gadget<C, CV>(
    _cs: ConstraintSystemRef<C::ScalarField>,
    scalar: &FpVar<C::ScalarField>,
    base: &CV,
) -> Result<CV, SynthesisError>
where
    C: ark_ec::CurveGroup,
    CV: CurveVar<C, C::ScalarField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // Use precomputed base scalar multiplication for efficiency
    // We need to create pairs of (bit, generator) for each bit position
    let scalar_bits = scalar.to_bits_le()?;

    // Get the base point value for precomputation
    let base_value = base.value().unwrap_or_default();

    // Precompute powers of the base: [G, 2G, 4G, 8G, ...]
    let mut bases = Vec::with_capacity(scalar_bits.len());
    let mut current_base = base_value;
    for _ in 0..scalar_bits.len() {
        bases.push(current_base);
        current_base = current_base.double();
    }

    // Create iterator of (bit, &base) pairs
    let bases_and_bits = scalar_bits
        .into_iter()
        .zip(bases.iter())
        .map(|(bit, base_ref)| (bit, base_ref));

    // Start from zero and accumulate the result
    let mut result = CV::zero();
    result.precomputed_base_scalar_mul_le(bases_and_bits)?;

    tracing::debug!(target: LOG_TARGET, "Computed fixed-base scalar mul P = [L]G");

    Ok(result)
}

/// Complete permutation equality proof gadget
///
/// Computes and verifies the permutation proof in-circuit
pub fn compute_permutation_proof_gadget<F, C, CV>(
    cs: ConstraintSystemRef<F>,
    perm_vector: &[FpVar<F>],
    perm_power_vector: &[FpVar<F>],
    perm_mixing_challenge_y: &FpVar<F>,
    perm_offset_challenge_z: &FpVar<F>,
    perm_power_challenge: &FpVar<F>,
    generator: &CV,
) -> Result<CV, SynthesisError>
where
    F: PrimeField,
    C: ark_ec::CurveGroup<ScalarField = F>,
    CV: CurveVar<C, F>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    let n = perm_vector.len();
    assert_eq!(
        perm_power_vector.len(),
        n,
        "Permutation vector and power vector must have same length"
    );

    // Step 1: Linear blend
    let d = linear_blend_gadget(
        cs.clone(),
        perm_vector,
        perm_power_vector,
        perm_mixing_challenge_y,
    )?;

    // Step 2: Left product
    let left = left_product_gadget(cs.clone(), &d, perm_offset_challenge_z)?;

    // Step 3: Right product
    let right = right_product_gadget(
        cs.clone(),
        perm_mixing_challenge_y,
        perm_power_challenge,
        perm_offset_challenge_z,
        n,
    )?;

    // Step 4: Verify equality
    verify_permutation_equality_gadget(cs.clone(), &left, &right)?;

    // Step 5: Fixed-base scalar multiplication
    let point = fixed_base_scalar_mul_gadget::<C, CV>(cs, &left, generator)?;

    // Return the computed point
    Ok(point)
}

/// Allocate a vector of field elements as circuit variables
pub fn alloc_vector<F: PrimeField>(
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
        let d = linear_blend_gadget(cs.clone(), &a, &b, &y)?;

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
        let d = linear_blend_gadget(cs.clone(), &a, &b, &y)?;
        let left = left_product_gadget(cs.clone(), &d, &z)?;
        let right = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

        // Verify equality
        verify_permutation_equality_gadget(cs.clone(), &left, &right)?;

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

        let d_circuit = linear_blend_gadget(cs.clone(), &a, &b, &y)?;
        let left_circuit = left_product_gadget(cs.clone(), &d_circuit, &z)?;
        let right_circuit = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

        // Compare results
        assert_eq!(left_circuit.value()?, left_native);
        assert_eq!(right_circuit.value()?, right_native);

        // For valid permutation, left should equal right
        assert_eq!(left_native, right_native);
        assert_eq!(left_circuit.value()?, right_circuit.value()?);

        // Verify constraints are satisfied
        verify_permutation_equality_gadget(cs.clone(), &left_circuit, &right_circuit)?;
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

            let d_circuit = linear_blend_gadget(cs.clone(), &a, &b, &y)?;
            let left_circuit = left_product_gadget(cs.clone(), &d_circuit, &z)?;
            let right_circuit = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

            // Verify equality
            assert_eq!(left_circuit.value()?, left_native);
            assert_eq!(right_circuit.value()?, right_native);
            assert_eq!(left_native, right_native);

            verify_permutation_equality_gadget(cs.clone(), &left_circuit, &right_circuit)?;
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

        let d_circuit = linear_blend_gadget(cs.clone(), &a, &b, &y)?;
        let left_circuit = left_product_gadget(cs.clone(), &d_circuit, &z)?;
        let right_circuit = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

        // Values should not match
        assert_ne!(left_circuit.value()?, right_circuit.value()?);

        // Trying to enforce equality should make constraints unsatisfied
        verify_permutation_equality_gadget(cs.clone(), &left_circuit, &right_circuit)?;
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
