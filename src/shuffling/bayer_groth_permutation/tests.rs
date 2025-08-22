//! Tests comparing native and circuit implementations of Bayer-Groth permutation proof

#[cfg(test)]
mod sigma_tests;

use crate::shuffling::bayer_groth_permutation::{
    fiat_shamir::BayerGrothTranscript,
    gadgets::{self, alloc_vector},
    native,
};
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_ff::{Field, One};
use ark_r1cs_std::{
    alloc::AllocVar, fields::fp::FpVar,
    prelude::*,
};
use ark_relations::gr1cs::SynthesisError;
use ark_relations::gr1cs::ConstraintSystem;
use ark_std::{rand::RngCore, test_rng, vec::Vec, UniformRand};

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

    let d_circuit = gadgets::linear_blend_gadget(cs.clone(), &a, &b, &y)?;
    let left_circuit = gadgets::left_product_gadget(cs.clone(), &d_circuit, &z)?;
    let right_circuit = gadgets::right_product_gadget(cs.clone(), &y, &x, &z, n)?;

    // Compare results
    assert_eq!(left_circuit.value()?, left_native);
    assert_eq!(right_circuit.value()?, right_native);

    // For valid permutation, left should equal right
    assert_eq!(left_native, right_native);
    assert_eq!(left_circuit.value()?, right_circuit.value()?);

    // Verify constraints are satisfied
    gadgets::verify_permutation_equality_gadget(cs.clone(), &left_circuit, &right_circuit)?;
    assert!(cs.is_satisfied()?);

    println!("✓ Native and circuit implementations match for n={}", n);

    Ok(())
}

/// Test complete Bayer-Groth protocol with Fiat-Shamir
#[test]
fn test_complete_protocol() -> Result<(), SynthesisError> {
    let mut rng = test_rng();
    let n = 52; // Standard deck size

    // Generate random permutation (shuffle)
    let perm = random_permutation(n, &mut rng);

    // Create vector a from permutation
    let a_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

    // Simulate external commitment to a (in practice, this is expensive)
    let c_a = G1Projective::rand(&mut rng);

    // Initialize Fiat-Shamir transcript
    let mut transcript = BayerGrothTranscript::<Fr>::new(b"BayerGroth-Test");

    // Step 1: Absorb commitment to a and derive x, r
    transcript.absorb_commitment_a(&c_a);
    let (x_val, _r_val) = transcript.derive_challenge_x_and_blinding();

    // Step 2: Compute hidden vector b
    let b_vals = transcript.compute_hidden_vector_b(&perm, x_val);

    // Simulate external commitment to b
    let c_b = G1Projective::rand(&mut rng);

    // Step 3: Absorb commitment to b and derive s
    transcript.absorb_commitment_b(&c_b);
    let _s_val = transcript.derive_blinding_factor_s();

    // Step 4: Derive final challenges y, z
    let (y_val, z_val) = transcript.derive_challenges_y_z();

    // Native computation
    let (left_native, right_native, _) = native::compute_permutation_proof::<Fr, G1Projective>(
        &a_vals,
        &b_vals,
        y_val,
        z_val,
        x_val,
        G1Affine::generator(),
    );

    // Circuit computation
    let cs = ConstraintSystem::<Fr>::new_ref();

    let a = alloc_vector(cs.clone(), &a_vals, AllocationMode::Witness)?;
    let b = alloc_vector(cs.clone(), &b_vals, AllocationMode::Witness)?;
    let x = FpVar::new_witness(cs.clone(), || Ok(x_val))?;
    let y = FpVar::new_witness(cs.clone(), || Ok(y_val))?;
    let z = FpVar::new_witness(cs.clone(), || Ok(z_val))?;

    // For this test, we'll skip the curve point computation since it requires
    // proper curve variable setup. We'll just test the field operations.
    let d = gadgets::linear_blend_gadget(
cs.clone(), &a, &b, &y)?;
    let left_circuit = gadgets::left_product_gadget(cs.clone(), &d, &z)?;
    let right_circuit = gadgets::right_product_gadget(cs.clone(), &y, &x, &z, n)?;

    // Verify results match
    assert_eq!(left_circuit.value()?, left_native);
    assert_eq!(right_circuit.value()?, right_native);
    assert_eq!(left_native, right_native);

    // Check constraint satisfaction
    assert!(cs.is_satisfied()?);

    println!("✓ Complete Bayer-Groth protocol test passed for n={}", n);
    println!("  Constraints: {}", cs.num_constraints());
    println!("  Variables: {}", cs.num_witness_variables());

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

        let d_circuit = gadgets::linear_blend_gadget(cs.clone(), &a, &b, &y)?;
        let left_circuit = gadgets::left_product_gadget(cs.clone(), &d_circuit, &z)?;
        let right_circuit = gadgets::right_product_gadget(cs.clone(), &y, &x, &z, n)?;

        // Verify equality
        assert_eq!(left_circuit.value()?, left_native);
        assert_eq!(right_circuit.value()?, right_native);
        assert_eq!(left_native, right_native);

        gadgets::verify_permutation_equality_gadget(cs.clone(), &left_circuit, &right_circuit)?;
        assert!(cs.is_satisfied()?);

        println!("✓ Test passed for n={}", n);
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

    let d_circuit = gadgets::linear_blend_gadget(cs.clone(), &a, &b, &y)?;
    let left_circuit = gadgets::left_product_gadget(cs.clone(), &d_circuit, &z)?;
    let right_circuit = gadgets::right_product_gadget(cs.clone(), &y, &x, &z, n)?;

    // Values should not match
    assert_ne!(left_circuit.value()?, right_circuit.value()?);

    // Trying to enforce equality should make constraints unsatisfied
    gadgets::verify_permutation_equality_gadget(cs.clone(), &left_circuit, &right_circuit)?;
    assert!(!cs.is_satisfied()?);

    println!("✓ Invalid permutation correctly detected");

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
        println!("✓ Edge case n=1 passed");
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
        println!("✓ Identity permutation passed");
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
        println!("✓ Reverse permutation passed");
    }

    Ok(())
}
