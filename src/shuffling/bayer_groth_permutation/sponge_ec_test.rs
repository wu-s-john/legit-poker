//! Test comparing native and SNARK circuit sponge absorption on elliptic curve points
//!
//! This test verifies that absorbing an affine elliptic curve point into a Poseidon sponge
//! produces identical results in both native code and SNARK circuit code.

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, G1Affine, G1Projective};
    
    const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::linking_rs_gadgets";
    use ark_crypto_primitives::sponge::{
        constraints::CryptographicSpongeVar,
        poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
        CryptographicSponge,
    };
    use ark_ff::UniformRand;
    use ark_r1cs_std::{
        alloc::{AllocVar, AllocationMode},
        fields::fp::FpVar,
        groups::curves::short_weierstrass::ProjectiveVar,
        prelude::*,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;

    #[test]
    fn test_ec_sponge_absorption_native_vs_circuit() {
        // Generate a random elliptic curve point in affine representation
        let mut rng = test_rng();
        let random_point = G1Affine::rand(&mut rng);

        // Setup Poseidon config over Fq (base field)
        let config = crate::config::poseidon_config::<Fq>();

        // ============= Native Sponge Absorption =============
        let mut native_sponge = PoseidonSponge::<Fq>::new(&config);

        // Absorb the affine point using the Absorb trait
        native_sponge.absorb(&random_point);

        // Squeeze out a field element as the result
        let native_result: Fq = native_sponge.squeeze_field_elements(1)[0];

        tracing::debug!(target = LOG_TARGET, "Native sponge result: {:?}", native_result);

        // ============= SNARK Circuit Sponge Absorption =============
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate the point as a projective variable
        let projective_point = ProjectiveVar::<ark_bn254::g1::Config, FpVar<Fq>>::new_variable(
            cs.clone(),
            || Ok(G1Projective::from(random_point)),
            AllocationMode::Witness,
        )
        .unwrap();

        // Convert to affine for absorption
        let circuit_point = projective_point.to_affine().unwrap();

        // Create a circuit sponge with the same config
        let mut circuit_sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), &config);

        // Absorb the point in-circuit using AbsorbGadget trait
        circuit_sponge.absorb(&circuit_point).unwrap();

        // Squeeze out a field element variable
        let circuit_result_var = circuit_sponge.squeeze_field_elements(1).unwrap()[0].clone();

        // Extract the concrete value from the circuit variable
        let circuit_result = circuit_result_var.value().unwrap();

        tracing::debug!(target = LOG_TARGET, "Circuit sponge result: {:?}", circuit_result);

        // ============= Compare Results =============
        // Assert that native and circuit results are equal
        assert_eq!(
            native_result, circuit_result,
            "Native and circuit sponge results should be identical"
        );

        // Verify that the constraint system is satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "Constraint system should be satisfied"
        );

        tracing::debug!(target = LOG_TARGET, "✅ Test passed: Native and circuit sponge absorption produce identical results!");
    }

    #[test]
    fn test_multiple_ec_points_sponge_absorption() {
        // Test with multiple points to ensure consistency
        let mut rng = test_rng();
        let config = crate::config::poseidon_config::<Fq>();

        for i in 0..5 {
            tracing::debug!(target = LOG_TARGET, "\n--- Testing point {} ---", i + 1);

            // Generate random point
            let point = G1Affine::rand(&mut rng);

            // Native absorption
            let mut native_sponge = PoseidonSponge::<Fq>::new(&config);
            native_sponge.absorb(&point);
            let native_result: Fq = native_sponge.squeeze_field_elements(1)[0];

            // Circuit absorption
            let cs = ConstraintSystem::<Fq>::new_ref();
            let projective_point = ProjectiveVar::<ark_bn254::g1::Config, FpVar<Fq>>::new_variable(
                cs.clone(),
                || Ok(G1Projective::from(point)),
                AllocationMode::Witness,
            )
            .unwrap();
            let circuit_point = projective_point.to_affine().unwrap();

            let mut circuit_sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), &config);
            circuit_sponge.absorb(&circuit_point).unwrap();
            let circuit_result_var = circuit_sponge.squeeze_field_elements(1).unwrap()[0].clone();
            let circuit_result = circuit_result_var.value().unwrap();

            // Verify equality
            assert_eq!(native_result, circuit_result);
            assert!(cs.is_satisfied().unwrap());

            tracing::debug!(target = LOG_TARGET, "Point {} passed ✓", i + 1);
        }

        tracing::debug!(target = LOG_TARGET, "\n✅ All multiple point tests passed!");
    }

    #[test]
    fn test_identity_point_sponge_absorption() {
        // Test with the identity (point at infinity)
        let identity_point = G1Affine::identity();
        let config = crate::config::poseidon_config::<Fq>();

        // Native absorption
        let mut native_sponge = PoseidonSponge::<Fq>::new(&config);
        native_sponge.absorb(&identity_point);
        let native_result: Fq = native_sponge.squeeze_field_elements(1)[0];

        // Circuit absorption
        let cs = ConstraintSystem::<Fq>::new_ref();
        let projective_point = ProjectiveVar::<ark_bn254::g1::Config, FpVar<Fq>>::new_variable(
            cs.clone(),
            || Ok(G1Projective::from(identity_point)),
            AllocationMode::Witness,
        )
        .unwrap();
        let circuit_point = projective_point.to_affine().unwrap();

        let mut circuit_sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), &config);
        circuit_sponge.absorb(&circuit_point).unwrap();
        let circuit_result_var = circuit_sponge.squeeze_field_elements(1).unwrap()[0].clone();
        let circuit_result = circuit_result_var.value().unwrap();

        // Verify equality
        assert_eq!(
            native_result, circuit_result,
            "Identity point absorption should be consistent"
        );
        assert!(cs.is_satisfied().unwrap());

        tracing::debug!(target = LOG_TARGET, "✅ Identity point test passed!");
    }
}
