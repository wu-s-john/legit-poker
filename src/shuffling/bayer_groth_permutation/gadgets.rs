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

/// Gadget for computing linear blend: d_i = y * a_i + b_i
pub fn linear_blend_gadget<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    a: &[FpVar<F>],
    b: &[FpVar<F>],
    y: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    assert_eq!(a.len(), b.len(), "Vectors a and b must have same length");

    let mut d = Vec::with_capacity(a.len());

    for (i, (a_i, b_i)) in a.iter().zip(b.iter()).enumerate() {
        // d_i = y * a_i + b_i
        let term = y * a_i + b_i;
        d.push(term);

        tracing::trace!(target: "bayer_groth", "d[{}] = y * a[{}] + b[{}]", i, i, i);
    }

    Ok(d)
}

/// Gadget for computing left product: L = ∏_{i=1}^N (d_i - z)
pub fn left_product_gadget<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    d: &[FpVar<F>],
    z: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let mut product = FpVar::<F>::one();

    for (i, d_i) in d.iter().enumerate() {
        // Compute d_i - z
        let diff = d_i - z;

        // Update product: product *= (d_i - z)
        product *= &diff;

        tracing::trace!(target: "bayer_groth", "L partial product at {}: (d[{}] - z)", i, i);
    }

    Ok(product)
}

/// Gadget for computing right product: R = ∏_{i=1}^N (y*i + x^i - z)
/// Uses running power computation for efficiency
pub fn right_product_gadget<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    y: &FpVar<F>,
    x: &FpVar<F>,
    z: &FpVar<F>,
    n: usize,
) -> Result<FpVar<F>, SynthesisError> {
    let mut product = FpVar::<F>::one();
    let mut x_power = FpVar::<F>::one(); // x^0 = 1

    for i in 1..=n {
        // Update running power: x^i = x^(i-1) * x
        x_power *= x;

        // Compute i as field element
        let i_const = FpVar::<F>::new_constant(cs.clone(), F::from(i as u64))?;

        // Compute term: y*i + x^i - z
        let term = y * &i_const + &x_power - z;

        // Update product
        product *= &term;

        tracing::trace!(target: "bayer_groth", "R partial at {}: y*{} + x^{} - z", i, i, i);
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

    tracing::debug!(target: "bayer_groth", "Enforced L == R constraint");

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
    // For circuit implementation, we use scalar multiplication
    // In production, this would use windowed multiplication with precomputed tables
    let result = base.scalar_mul_le(scalar.to_bits_le()?.iter())?;

    tracing::debug!(target: "bayer_groth", "Computed fixed-base scalar mul P = [L]G");

    Ok(result)
}

/// Complete permutation equality proof gadget
///
/// Computes and verifies the permutation proof in-circuit
pub fn compute_permutation_proof_gadget<F, C, CV>(
    cs: ConstraintSystemRef<F>,
    a: &[FpVar<F>],
    b: &[FpVar<F>],
    y: &FpVar<F>,
    z: &FpVar<F>,
    x: &FpVar<F>,
    generator: &CV,
) -> Result<(FpVar<F>, FpVar<F>, CV), SynthesisError>
where
    F: PrimeField,
    C: ark_ec::CurveGroup<ScalarField = F>,
    CV: CurveVar<C, F>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    let n = a.len();
    assert_eq!(b.len(), n, "Vectors a and b must have same length");

    // Step 1: Linear blend
    let d = linear_blend_gadget(cs.clone(), a, b, y)?;

    // Step 2: Left product
    let left = left_product_gadget(cs.clone(), &d, z)?;

    // Step 3: Right product
    let right = right_product_gadget(cs.clone(), y, x, z, n)?;

    // Step 4: Verify equality
    verify_permutation_equality_gadget(cs.clone(), &left, &right)?;

    // Step 5: Fixed-base scalar multiplication
    let point = fixed_base_scalar_mul_gadget::<C, CV>(cs, &left, generator)?;

    Ok((left, right, point))
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
    use ark_bn254::Fr;
    use ark_ff::Field;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand};

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
}
