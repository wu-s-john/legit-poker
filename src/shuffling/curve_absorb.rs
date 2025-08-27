//! Custom absorption traits for elliptic curves in both native and circuit contexts
//!
//! This module provides `CurveAbsorb` and `CurveAbsorbGadget` traits that give
//! full control over how elliptic curve points are absorbed into cryptographic sponges.
//! This ensures consistency between native and SNARK circuit implementations.

use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
    CryptographicSponge,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_relations::gr1cs::SynthesisError;

/// Trait for absorbing native elliptic curve points into a sponge
pub trait CurveAbsorb<F: PrimeField> {
    /// Absorb this curve point into the given sponge
    fn curve_absorb(&self, sponge: &mut PoseidonSponge<F>);
}

/// Trait for absorbing circuit elliptic curve variables into a sponge
pub trait CurveAbsorbGadget<F: PrimeField> {
    /// Absorb this curve variable into the given sponge variable
    fn curve_absorb_gadget(&self, sponge: &mut PoseidonSpongeVar<F>) -> Result<(), SynthesisError>;
}

// ============================================================================
// Native implementation for BN254::G1Projective using Fq (base field)
// ============================================================================

impl CurveAbsorb<ark_bn254::Fq> for ark_bn254::G1Projective {
    fn curve_absorb(&self, sponge: &mut PoseidonSponge<ark_bn254::Fq>) {
        // Convert to affine representation
        let affine = self.into_affine();
        // Use the Absorb trait implementation for G1Affine which works with Fq
        sponge.absorb(&affine);
    }
}

// // ============================================================================
// // Native implementation for BN254::G1 using its scalar field Fr
// // This is needed for sigma protocols that operate over the scalar field
// // ============================================================================

// impl CurveAbsorb<ark_bn254::Fr> for ark_bn254::G1Projective {
//     fn curve_absorb(&self, sponge: &mut PoseidonSponge<ark_bn254::Fr>) {
//         // Convert to affine representation
//         let affine = self.into_affine();
//         // Use the Absorb trait implementation for G1Affine which works with Fr
//         sponge.absorb(&affine);
//     }
// }

// ============================================================================
// Native implementation for Grumpkin using its base field (BN254::Fr)
// Note: Grumpkin's base field is BN254::Fr (scalar field of BN254)
// ============================================================================

impl CurveAbsorb<ark_grumpkin::Fq> for ark_grumpkin::Projective {
    fn curve_absorb(&self, sponge: &mut PoseidonSponge<ark_grumpkin::Fq>) {
        // Convert to affine representation
        let affine = self.into_affine();
        // Use the Absorb trait implementation for Grumpkin Affine
        sponge.absorb(&affine);
    }
}

// ============================================================================
// Circuit implementation for ProjectiveVar<BN254>
// ============================================================================

use ark_r1cs_std::{fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar};

impl CurveAbsorbGadget<ark_bn254::Fq>
    for ProjectiveVar<ark_bn254::g1::Config, FpVar<ark_bn254::Fq>>
{
    fn curve_absorb_gadget(
        &self,
        sponge: &mut PoseidonSpongeVar<ark_bn254::Fq>,
    ) -> Result<(), SynthesisError> {
        // Convert to affine representation in-circuit
        let affine = self.to_affine()?;
        // Use the existing AbsorbGadget implementation for the affine variable
        sponge.absorb(&affine)?;
        Ok(())
    }
}

// ============================================================================
// Circuit implementation for Grumpkin ProjectiveVar
// Note: Grumpkin is a Short Weierstrass curve, not Twisted Edwards
// Grumpkin's base field is BN254::Fr
// ============================================================================

impl CurveAbsorbGadget<ark_bn254::Fr>
    for ProjectiveVar<ark_grumpkin::GrumpkinConfig, FpVar<ark_bn254::Fr>>
{
    fn curve_absorb_gadget(
        &self,
        sponge: &mut PoseidonSpongeVar<ark_bn254::Fr>,
    ) -> Result<(), SynthesisError> {
        // Convert to affine and absorb
        use ark_r1cs_std::convert::ToConstraintFieldGadget;
        let affine = self.to_affine()?;
        let coords = affine.to_constraint_field()?;
        sponge.absorb(&coords)?;
        Ok(())
    }
}

// ============================================================================
// Helper functions for convenient usage
// ============================================================================

/// Absorb a native curve point into a sponge using CurveAbsorb trait
pub fn absorb_curve_point<G, F>(sponge: &mut PoseidonSponge<F>, point: &G)
where
    G: CurveAbsorb<F>,
    F: PrimeField,
{
    point.curve_absorb(sponge);
}

/// Absorb a circuit curve variable into a sponge using CurveAbsorbGadget trait
pub fn absorb_curve_var<GG, F>(
    sponge: &mut PoseidonSpongeVar<F>,
    point: &GG,
) -> Result<(), SynthesisError>
where
    GG: CurveAbsorbGadget<F>,
    F: PrimeField,
{
    point.curve_absorb_gadget(sponge)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, G1Projective};
    use ark_ff::UniformRand;
    use ark_r1cs_std::GR1CSVar;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;
    use ark_std::Zero;

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;

    #[test]
    fn test_curve_absorb_consistency() {
        let mut rng = test_rng();

        // Generate a random curve point
        let point = G1Projective::rand(&mut rng);

        // Setup Poseidon config over Fq (base field)
        let config = crate::config::poseidon_config::<Fq>();

        // ============= Native Absorption =============
        let mut native_sponge = PoseidonSponge::<Fq>::new(&config);

        // Absorb using CurveAbsorb trait
        point.curve_absorb(&mut native_sponge);

        // Get the result
        let native_result: Fq = native_sponge.squeeze_field_elements(1)[0];

        println!("Native absorption result: {:?}", native_result);

        // ============= Circuit Absorption =============
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate the point as a circuit variable
        let point_var = G1Var::new_variable(
            cs.clone(),
            || Ok(point),
            ark_r1cs_std::alloc::AllocationMode::Witness,
        )
        .unwrap();

        // Create circuit sponge with the same config
        let mut circuit_sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), &config);

        // Absorb using CurveAbsorbGadget trait
        point_var.curve_absorb_gadget(&mut circuit_sponge).unwrap();

        // Get the result
        let circuit_result_var = circuit_sponge.squeeze_field_elements(1).unwrap()[0].clone();
        let circuit_result = circuit_result_var.value().unwrap();

        println!("Circuit absorption result: {:?}", circuit_result);

        // ============= Compare Results =============
        // Assert that native and circuit results are equal
        assert_eq!(
            native_result, circuit_result,
            "Native and circuit sponge results should be identical"
        );

        // Verify constraint system is satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "Circuit constraints should be satisfied"
        );

        println!("✅ Test passed: Native and circuit sponge absorption produce identical results!");
    }

    #[test]
    fn test_multiple_points_absorption() {
        let mut rng = test_rng();
        let config = crate::config::poseidon_config::<Fq>();

        for i in 0..3 {
            println!("\n--- Testing point {} ---", i + 1);

            let point = G1Projective::rand(&mut rng);

            // Native
            let mut native_sponge = PoseidonSponge::<Fq>::new(&config);
            absorb_curve_point(&mut native_sponge, &point);
            let native_result: Fq = native_sponge.squeeze_field_elements(1)[0];

            // Circuit
            let cs = ConstraintSystem::<Fq>::new_ref();
            let point_var = G1Var::new_variable(
                cs.clone(),
                || Ok(point),
                ark_r1cs_std::alloc::AllocationMode::Witness,
            )
            .unwrap();

            let mut circuit_sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), &config);
            absorb_curve_var(&mut circuit_sponge, &point_var).unwrap();
            let circuit_result_var = circuit_sponge.squeeze_field_elements(1).unwrap()[0].clone();
            let circuit_result = circuit_result_var.value().unwrap();

            // Verify equality
            assert_eq!(native_result, circuit_result);
            assert!(cs.is_satisfied().unwrap());
            println!("Point {} passed ✓", i + 1);
        }

        println!("\n✅ All multiple point tests passed!");
    }

    #[test]
    fn test_identity_point_absorption() {
        // Test with the identity (point at infinity)
        let identity_point = G1Projective::zero();
        let config = crate::config::poseidon_config::<Fq>();

        // Native absorption
        let mut native_sponge = PoseidonSponge::<Fq>::new(&config);
        identity_point.curve_absorb(&mut native_sponge);
        let native_result: Fq = native_sponge.squeeze_field_elements(1)[0];

        // Circuit absorption
        let cs = ConstraintSystem::<Fq>::new_ref();
        let identity_var = G1Var::new_variable(
            cs.clone(),
            || Ok(identity_point),
            ark_r1cs_std::alloc::AllocationMode::Witness,
        )
        .unwrap();

        let mut circuit_sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), &config);
        identity_var
            .curve_absorb_gadget(&mut circuit_sponge)
            .unwrap();
        let circuit_result_var = circuit_sponge.squeeze_field_elements(1).unwrap()[0].clone();
        let circuit_result = circuit_result_var.value().unwrap();

        // Verify equality
        assert_eq!(
            native_result, circuit_result,
            "Identity point absorption should be consistent"
        );
        assert!(cs.is_satisfied().unwrap());
        println!("✅ Identity point test passed!");
    }
}
