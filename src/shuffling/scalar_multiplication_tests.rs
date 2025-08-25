//! Tests for different scalar multiplication methods in SNARK circuits
//!
//! This module tests various approaches to scalar multiplication on elliptic curves
//! within SNARK circuits, comparing circuit results with native computation.

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_r1cs_std::{
        alloc::{AllocVar, AllocationMode},
        eq::EqGadget,
        fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
        groups::curves::short_weierstrass::ProjectiveVar,
        GR1CSVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;

    /// Test 1: Multiply two scalar field values in EmulatedFieldVar, then scalar multiply with generator
    ///
    /// Process:
    /// 1. Draw two random scalars s1, s2 in Fr (scalar field)
    /// 2. Native: Compute s3 = s1 * s2, then G * s3
    /// 3. Circuit: Compute s3 = s1 * s2 in EmulatedFieldVar, convert to bits, scalar multiply
    /// 4. Compare results
    #[test]
    fn test_emulated_field_multiplication_then_scalar_mul() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Generate random scalars in Fr (scalar field)
        let s1 = Fr::rand(&mut rng);
        let s2 = Fr::rand(&mut rng);

        // Generate random generator point
        let generator = G1Projective::rand(&mut rng);

        // Native computation: s3 = s1 * s2, then G * s3
        let s3_native = s1 * s2;
        let result_native = generator * s3_native;

        // Circuit computation
        // Allocate scalars as EmulatedFieldVar (Fr emulated in Fq)
        let s1_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(s1), AllocationMode::Witness)
                .unwrap();

        let s2_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(s2), AllocationMode::Witness)
                .unwrap();

        // Multiply in circuit: s3 = s1 * s2
        let s3_var = &s1_var * &s2_var;

        // Allocate generator point
        let generator_var =
            G1Var::new_variable(cs.clone(), || Ok(generator), AllocationMode::Witness).unwrap();

        // Perform scalar multiplication in circuit
        let result_var = generator_var * s3_var;

        // Extract the result and compare
        let result_circuit = result_var.value().unwrap();

        assert_eq!(
            result_native.into_affine(),
            result_circuit.into_affine(),
            "Test 1 failed: Emulated field multiplication then scalar mul"
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
        println!("✅ Test 1 passed: Emulated field multiplication then scalar multiplication");
    }

    /// Test 2: Sequential scalar multiplication with two EmulatedFieldVar values
    ///
    /// Process:
    /// 1. Draw two random scalars s1, s2 in Fr
    /// 2. Native: Compute G * (s1 * s2)
    /// 3. Circuit: Compute P1 = G * s1, then P2 = P1 * s2 (each requiring bit decomposition)
    /// 4. Compare results
    #[test]
    fn test_sequential_scalar_multiplication_emulated() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Generate random scalars
        let s1 = Fr::rand(&mut rng);
        let s2 = Fr::rand(&mut rng);

        // Generate random generator
        let generator = G1Projective::rand(&mut rng);

        // Native computation: G * (s1 * s2)
        let result_native = generator * (s1 * s2);

        // Circuit computation
        let s1_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(s1), AllocationMode::Witness)
                .unwrap();

        let s2_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(s2), AllocationMode::Witness)
                .unwrap();

        let generator_var =
            G1Var::new_variable(cs.clone(), || Ok(generator), AllocationMode::Witness).unwrap();

        // First scalar multiplication: P1 = G * s1
        let p1_var = generator_var * s1_var;

        // Second scalar multiplication: P2 = P1 * s2
        let result_var = p1_var * s2_var;

        // Extract and compare
        let result_circuit = result_var.value().unwrap();

        assert_eq!(
            result_native.into_affine(),
            result_circuit.into_affine(),
            "Test 2 failed: Sequential scalar multiplication with emulated fields"
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
        println!("✅ Test 2 passed: Sequential scalar multiplication with emulated fields");
    }

    /// Test 3: Scalar field multiplication, convert to bits, then scalar multiply
    ///
    /// Process:
    /// 1. Draw two values f1, f2 in Fr (scalar field)
    /// 2. Native: Compute f3 = f1 * f2 in Fr, then G * f3
    /// 3. Circuit: Compute f3 = f1 * f2 in EmulatedFpVar<Fr, Fq>, then scalar multiply
    /// 4. Note: We use EmulatedFpVar to represent Fr in a Fq constraint system
    #[test]
    fn test_scalar_field_multiplication_then_scalar_mul() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Generate random field elements in Fr (scalar field)
        let f1 = Fr::rand(&mut rng);
        let f2 = Fr::rand(&mut rng);

        // Generate random generator
        let generator = G1Projective::rand(&mut rng);

        // Native computation: f3 = f1 * f2 in Fr, then G * f3
        let f3_native = f1 * f2;
        let result_native = generator * f3_native;

        // Circuit computation using EmulatedFpVar for Fr in Fq constraint system
        let f1_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(f1), AllocationMode::Witness)
                .unwrap();

        let f2_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(f2), AllocationMode::Witness)
                .unwrap();

        // Multiply in scalar field
        let f3_var = &f1_var * &f2_var;

        // Allocate generator
        let generator_var =
            G1Var::new_variable(cs.clone(), || Ok(generator), AllocationMode::Witness).unwrap();

        // Perform scalar multiplication in circuit
        let result_var = generator_var * f3_var;

        // Extract and compare
        let result_circuit = result_var.value().unwrap();

        assert_eq!(
            result_native.into_affine(),
            result_circuit.into_affine(),
            "Test 3 failed: Scalar field multiplication then scalar mul"
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
        println!("✅ Test 3 passed: Scalar field multiplication then scalar multiplication");
    }

    /// Test 4: Sequential scalar multiplication with scalar field values
    ///
    /// Process:
    /// 1. Draw two values f1, f2 in Fr (scalar field)
    /// 2. Native: Compute G * (f1 * f2)
    /// 3. Circuit: P1 = G * f1, then P2 = P1 * f2 using EmulatedFpVar
    /// 4. Compare results
    #[test]
    fn test_sequential_scalar_multiplication_scalar_field() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Generate random field elements in Fr (scalar field)
        let f1 = Fr::rand(&mut rng);
        let f2 = Fr::rand(&mut rng);

        // Generate random generator
        let generator = G1Projective::rand(&mut rng);

        // Native computation: G * (f1 * f2)
        let result_native = generator * (f1 * f2);

        // Circuit computation using EmulatedFpVar
        let f1_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(f1), AllocationMode::Witness)
                .unwrap();

        let f2_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(f2), AllocationMode::Witness)
                .unwrap();

        let generator_var =
            G1Var::new_variable(cs.clone(), || Ok(generator), AllocationMode::Witness).unwrap();

        // First scalar multiplication: P1 = G * f1
        let p1_var = generator_var * f1_var;

        // Second scalar multiplication: P2 = P1 * f2
        let result_var = p1_var * f2_var;

        // Extract and compare
        let result_circuit = result_var.value().unwrap();

        assert_eq!(
            result_native.into_affine(),
            result_circuit.into_affine(),
            "Test 4 failed: Sequential scalar multiplication with scalar field"
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
        println!("✅ Test 4 passed: Sequential scalar multiplication with scalar field values");
    }

    /// Test 5: Field addition vs Point addition (Distributivity)
    ///
    /// Process:
    /// 1. Draw two values f1, f2 in Fr (scalar field)
    /// 2. Method A (Native): (f1 + f2) * G
    /// 3. Method B (Native): f1 * G + f2 * G
    /// 4. Circuit: Implement both methods using EmulatedFpVar
    /// 5. Verify distributivity: (f1 + f2) * G = f1 * G + f2 * G
    #[test]
    fn test_field_addition_vs_point_addition() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Generate random field elements in Fr (scalar field)
        let f1 = Fr::rand(&mut rng);
        let f2 = Fr::rand(&mut rng);

        // Generate random generator
        let generator = G1Projective::rand(&mut rng);

        // Native computation - Method A: (f1 + f2) * G
        let f3_native = f1 + f2;
        let result_method_a_native = generator * f3_native;

        // Native computation - Method B: f1 * G + f2 * G
        let p1_native = generator * f1;
        let p2_native = generator * f2;
        let result_method_b_native = p1_native + p2_native;

        // Verify native computation consistency (distributivity)
        assert_eq!(
            result_method_a_native.into_affine(),
            result_method_b_native.into_affine(),
            "Native computation: distributivity should hold"
        );

        // Circuit computation using EmulatedFpVar
        let f1_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(f1), AllocationMode::Witness)
                .unwrap();

        let f2_var =
            EmulatedFpVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(f2), AllocationMode::Witness)
                .unwrap();

        let generator_var =
            G1Var::new_variable(cs.clone(), || Ok(generator), AllocationMode::Witness).unwrap();

        // Method A in circuit: Add fields first, then scalar multiply
        let f3_var = &f1_var + &f2_var;
        let result_method_a_var = generator_var.clone() * f3_var;

        // Method B in circuit: Scalar multiply separately, then add points
        let p1_var = generator_var.clone() * f1_var;
        let p2_var = generator_var * f2_var;

        let result_method_b_var = &p1_var + &p2_var;

        // Extract results
        let result_method_a_circuit = result_method_a_var.value().unwrap();
        let result_method_b_circuit = result_method_b_var.value().unwrap();

        // Compare Method A and B in circuit (should be equal due to distributivity)
        assert_eq!(
            result_method_a_circuit.into_affine(),
            result_method_b_circuit.into_affine(),
            "Circuit computation: distributivity should hold"
        );

        // Compare circuit with native
        assert_eq!(
            result_method_a_native.into_affine(),
            result_method_a_circuit.into_affine(),
            "Test 5 Method A failed: Field addition then scalar mul"
        );

        assert_eq!(
            result_method_b_native.into_affine(),
            result_method_b_circuit.into_affine(),
            "Test 5 Method B failed: Scalar mul then point addition"
        );

        // Verify in-circuit equality using constraints
        result_method_a_var
            .enforce_equal(&result_method_b_var)
            .unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
        println!("✅ Test 5 passed: Field addition vs Point addition (distributivity verified)");
    }

    // /// Additional test: Mixed scalar and base field operations
    // ///
    // /// This test combines EmulatedFieldVar (Fr) and FpVar (Fq) operations
    // #[test]
    // fn test_mixed_field_operations() {
    //     let mut rng = test_rng();
    //     let cs = ConstraintSystem::<Fq>::new_ref();

    //     // Generate values in different fields
    //     let scalar = Fr::rand(&mut rng); // Scalar field
    //     let base_elem = Fq::rand(&mut rng); // Base field

    //     // Generate random generator
    //     let generator = G1Projective::rand(&mut rng);

    //     // Native computation: First apply scalar (Fr), then apply base field element as scalar
    //     let p1_native = generator * scalar;
    //     let base_as_scalar = Fr::from_le_bytes_mod_order(&base_elem.into_bigint().to_bytes_le());
    //     let result_native = p1_native * base_as_scalar;

    //     // Circuit computation
    //     let scalar_var = EmulatedFieldVar::<Fr, Fq>::new_variable(
    //         cs.clone(),
    //         || Ok(scalar),
    //         AllocationMode::Witness,
    //     )
    //     .unwrap();

    //     let base_var =
    //         FpVar::<Fq>::new_variable(cs.clone(), || Ok(base_elem), AllocationMode::Witness)
    //             .unwrap();

    //     let generator_var =
    //         G1Var::new_variable(cs.clone(), || Ok(generator), AllocationMode::Witness).unwrap();

    //     // First multiplication with scalar field element (requires bit decomposition)
    //     let scalar_bits = scalar_var.to_bits_le().unwrap();
    //     let p1_var = generator_var.scalar_mul_le(scalar_bits.iter()).unwrap();

    //     // Second multiplication with base field element (requires bit decomposition)
    //     let base_bits = base_var.to_bits_le().unwrap();
    //     let result_var = p1_var.scalar_mul_le(base_bits.iter()).unwrap();

    //     // Extract and compare
    //     let result_circuit = result_var.value().unwrap();

    //     assert_eq!(
    //         result_native.into_affine(),
    //         result_circuit.into_affine(),
    //         "Mixed field test failed"
    //     );

    //     assert!(
    //         cs.is_satisfied().unwrap(),
    //         "Constraints should be satisfied"
    //     );
    //     println!("✅ Mixed field operations test passed");
    // }

    // /// Test edge cases: Zero and One scalars
    // #[test]
    // fn test_edge_cases() {
    //     let mut rng = test_rng();
    //     let cs = ConstraintSystem::<Fq>::new_ref();

    //     let generator = G1Projective::rand(&mut rng);

    //     // Test with zero scalar
    //     let zero = Fr::zero();
    //     let result_zero_native = generator * zero; // Should be identity/zero point

    //     let zero_var = EmulatedFieldVar::<Fr, Fq>::new_variable(
    //         cs.clone(),
    //         || Ok(zero),
    //         AllocationMode::Witness,
    //     )
    //     .unwrap();

    //     let generator_var =
    //         G1Var::new_variable(cs.clone(), || Ok(generator), AllocationMode::Witness).unwrap();

    //     let zero_bits = zero_var.to_bits_le().unwrap();
    //     let result_zero = generator_var.scalar_mul_le(zero_bits.iter()).unwrap();

    //     let result_zero_value = result_zero.value().unwrap();
    //     assert_eq!(
    //         result_zero_native.into_affine(),
    //         result_zero_value.into_affine(),
    //         "Scalar multiplication by zero failed"
    //     );
    //     assert!(
    //         result_zero_value.is_zero(),
    //         "Scalar multiplication by zero should yield identity"
    //     );

    //     // Test with one scalar
    //     let one = Fr::one();
    //     let result_one_native = generator * one; // Should be the generator itself

    //     let one_var = EmulatedFieldVar::<Fr, Fq>::new_variable(
    //         cs.clone(),
    //         || Ok(one),
    //         AllocationMode::Witness,
    //     )
    //     .unwrap();

    //     let one_bits = one_var.to_bits_le().unwrap();
    //     let result_one = generator_var.scalar_mul_le(one_bits.iter()).unwrap();

    //     let result_one_value = result_one.value().unwrap();
    //     assert_eq!(
    //         result_one_native.into_affine(),
    //         result_one_value.into_affine(),
    //         "Scalar multiplication by one failed"
    //     );
    //     assert_eq!(
    //         generator.into_affine(),
    //         result_one_value.into_affine(),
    //         "Scalar multiplication by one should yield the original point"
    //     );

    //     assert!(
    //         cs.is_satisfied().unwrap(),
    //         "Constraints should be satisfied"
    //     );
    //     println!("✅ Edge cases test passed (zero and one scalars)");
    // }

    // /// Test to verify bit decomposition correctness
    // #[test]
    // fn test_bit_decomposition_correctness() {
    //     let mut rng = test_rng();

    //     // Test with Fr constraint system and known scalar value
    //     {
    //         let cs = ConstraintSystem::<Fr>::new_ref();
    //         let scalar = Fr::from(12345u64);
    //         let generator = G1Projective::rand(&mut rng);

    //         // Native computation
    //         let result_native = generator * scalar;

    //         // Circuit computation with FpVar<Fr>
    //         let scalar_var =
    //             FpVar::<Fr>::new_variable(cs.clone(), || Ok(scalar), AllocationMode::Witness)
    //                 .unwrap();

    //         let generator_var = ProjectiveVar::<ark_bn254::g1::Config, FpVar<Fr>>::new_variable(
    //             cs.clone(),
    //             || Ok(generator),
    //             AllocationMode::Witness,
    //         )
    //         .unwrap();

    //         // Get bits and perform scalar multiplication
    //         let scalar_bits = scalar_var.to_bits_le().unwrap();
    //         let result_var = generator_var.scalar_mul_le(scalar_bits.iter()).unwrap();

    //         let result_circuit = result_var.value().unwrap();

    //         assert_eq!(
    //             result_native.into_affine(),
    //             result_circuit.into_affine(),
    //             "Fr bit decomposition test failed"
    //         );

    //         assert!(
    //             cs.is_satisfied().unwrap(),
    //             "Fr constraints should be satisfied"
    //         );
    //     }

    //     // Test with Fq constraint system and EmulatedFieldVar
    //     {
    //         let cs = ConstraintSystem::<Fq>::new_ref();
    //         let scalar = Fr::from(12345u64);
    //         let generator = G1Projective::rand(&mut rng);

    //         // Native computation
    //         let result_native = generator * scalar;

    //         // Circuit computation with EmulatedFieldVar
    //         let scalar_var = EmulatedFieldVar::<Fr, Fq>::new_variable(
    //             cs.clone(),
    //             || Ok(scalar),
    //             AllocationMode::Witness,
    //         )
    //         .unwrap();

    //         let generator_var =
    //             G1Var::new_variable(cs.clone(), || Ok(generator), AllocationMode::Witness).unwrap();

    //         // Get bits and perform scalar multiplication
    //         let scalar_bits = scalar_var.to_bits_le().unwrap();
    //         let result_var = generator_var.scalar_mul_le(scalar_bits.iter()).unwrap();

    //         let result_circuit = result_var.value().unwrap();

    //         assert_eq!(
    //             result_native.into_affine(),
    //             result_circuit.into_affine(),
    //             "EmulatedFieldVar bit decomposition test failed"
    //         );

    //         assert!(
    //             cs.is_satisfied().unwrap(),
    //             "Fq constraints should be satisfied"
    //         );
    //     }

    //     println!("✅ Bit decomposition correctness test passed");
    // }
}
