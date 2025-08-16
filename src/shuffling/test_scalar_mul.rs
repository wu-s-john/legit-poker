#[cfg(test)]
mod tests {
    use ark_ec::short_weierstrass::Projective;
    use ark_ec::{CurveConfig, PrimeGroup};
    use ark_ff::{PrimeField, UniformRand};
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::fp::FpVar,
        groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
        prelude::*,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use ark_std::{One, Zero};

    /// Test that scalar multiplication using BigInt outside the circuit
    /// matches scalar multiplication using bit decomposition inside the circuit
    #[test]
    fn test_scalar_mul_consistency() {
        // We'll use BN254's G1 curve for this test
        type TestCurve = ark_bn254::g1::Config;
        type G = Projective<TestCurve>;
        type Fq = <TestCurve as CurveConfig>::BaseField;

        let mut rng = test_rng();

        // Generate a random scalar in the base field
        let base_field_scalar: Fq = UniformRand::rand(&mut rng);

        // Generate a random point
        let random_point = G::rand(&mut rng);

        // Method 1: Scalar multiplication using BigInt (outside circuit)
        let scalar_bigint = base_field_scalar.into_bigint();
        let result_outside = random_point.mul_bigint(scalar_bigint);

        // Method 2: Scalar multiplication using bit decomposition (inside circuit)
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate the scalar as a field variable
        let scalar_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(base_field_scalar)).unwrap();

        // Allocate the point as a curve variable
        let point_var = <ProjectiveVar<TestCurve, FpVar<Fq>> as AllocVar<G, Fq>>::new_witness(
            cs.clone(),
            || Ok(random_point),
        )
        .unwrap();

        // Convert scalar to bits
        let scalar_bits = scalar_var.to_bits_le().unwrap();

        // Perform scalar multiplication using bits
        let result_inside_var = point_var.scalar_mul_le(scalar_bits.iter()).unwrap();

        // Extract the result from the circuit
        let result_inside = result_inside_var.value().unwrap();

        // Compare the results
        assert_eq!(
            result_outside, result_inside,
            "Scalar multiplication results should match!\n\
             Outside circuit (mul_bigint): {:?}\n\
             Inside circuit (scalar_mul_le): {:?}",
            result_outside, result_inside
        );

        // Also verify the constraint system is satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );

        println!("✓ Scalar multiplication consistency test passed!");
        println!("  Base field scalar: {:?}", base_field_scalar);
        println!("  Result: {:?}", result_outside);
        println!("  Constraints generated: {}", cs.num_constraints());
    }

    /// Test edge cases for scalar multiplication
    #[test]
    fn test_scalar_mul_edge_cases() {
        type TestCurve = ark_bn254::g1::Config;
        type G = Projective<TestCurve>;
        type Fq = <TestCurve as CurveConfig>::BaseField;

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Test case 1: Multiplication by zero
        let zero_scalar = Fq::zero();
        let point = G::generator();

        let zero_bigint = zero_scalar.into_bigint();
        let result_outside = point.mul_bigint(zero_bigint);

        let scalar_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(zero_scalar)).unwrap();
        let point_var = <ProjectiveVar<TestCurve, FpVar<Fq>> as AllocVar<G, Fq>>::new_witness(
            cs.clone(),
            || Ok(point),
        )
        .unwrap();

        let scalar_bits = scalar_var.to_bits_le().unwrap();
        let result_inside_var = point_var.scalar_mul_le(scalar_bits.iter()).unwrap();
        let result_inside = result_inside_var.value().unwrap();

        assert_eq!(result_outside, result_inside);
        assert_eq!(
            result_outside,
            G::zero(),
            "Multiplication by zero should give identity"
        );

        // Test case 2: Multiplication by one
        let one_scalar = Fq::one();
        let one_bigint = one_scalar.into_bigint();
        let result_outside = point.mul_bigint(one_bigint);

        let scalar_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(one_scalar)).unwrap();
        let scalar_bits = scalar_var.to_bits_le().unwrap();
        let result_inside_var = point_var.scalar_mul_le(scalar_bits.iter()).unwrap();
        let result_inside = result_inside_var.value().unwrap();

        assert_eq!(result_outside, result_inside);
        assert_eq!(
            result_outside, point,
            "Multiplication by one should give the same point"
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
        println!("✓ Edge cases test passed!");
    }

    /// Test that demonstrates the conversion process used in the actual code
    #[test]
    fn test_elgamal_scalar_conversion() {
        type TestCurve = ark_bn254::g1::Config;
        type G = Projective<TestCurve>;
        type Fq = <TestCurve as CurveConfig>::BaseField;

        let mut rng = test_rng();

        // Simulate the ElGamal encryption scenario
        let generator = G::generator();
        let private_key: Fq = UniformRand::rand(&mut rng);
        let randomness: Fq = UniformRand::rand(&mut rng);

        // Outside circuit: using mul_bigint
        let private_key_bigint = private_key.into_bigint();
        let public_key = generator.mul_bigint(private_key_bigint);

        let randomness_bigint = randomness.into_bigint();
        let r_times_g = generator.mul_bigint(randomness_bigint);
        let r_times_pk = public_key.mul_bigint(randomness_bigint);

        // Inside circuit: using bit decomposition
        let cs = ConstraintSystem::<Fq>::new_ref();

        let private_key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();
        let randomness_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(randomness)).unwrap();

        let generator_var = <ProjectiveVar<TestCurve, FpVar<Fq>> as AllocVar<G, Fq>>::new_constant(
            cs.clone(),
            generator,
        )
        .unwrap();

        // Compute public key in circuit
        let private_key_bits = private_key_var.to_bits_le().unwrap();
        let public_key_var = generator_var
            .scalar_mul_le(private_key_bits.iter())
            .unwrap();
        let public_key_circuit = public_key_var.value().unwrap();

        // Compute r*G and r*PK in circuit
        let randomness_bits = randomness_var.to_bits_le().unwrap();
        let r_times_g_var = generator_var.scalar_mul_le(randomness_bits.iter()).unwrap();
        let r_times_pk_var = public_key_var
            .scalar_mul_le(randomness_bits.iter())
            .unwrap();

        let r_times_g_circuit = r_times_g_var.value().unwrap();
        let r_times_pk_circuit = r_times_pk_var.value().unwrap();

        // Verify all computations match
        assert_eq!(
            public_key, public_key_circuit,
            "Public key computation should match"
        );
        assert_eq!(r_times_g, r_times_g_circuit, "r*G computation should match");
        assert_eq!(
            r_times_pk, r_times_pk_circuit,
            "r*PK computation should match"
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );

        println!("✓ ElGamal scalar conversion test passed!");
        println!("  Constraints generated: {}", cs.num_constraints());
    }
}
