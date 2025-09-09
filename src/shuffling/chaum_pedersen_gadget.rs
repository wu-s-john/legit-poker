//! SNARK circuit gadgets for Chaum-Pedersen proof verification
//!
//! This module provides circuit gadgets for verifying Chaum-Pedersen proofs
//! inside a SNARK, ensuring discrete logarithm equality.

use crate::shuffling::chaum_pedersen::ChaumPedersenProof;
use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::{field_conversion_gadget::embed_to_emulated, poseidon_config};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::emulated_fp::EmulatedFpVar,
    groups::{CurveVar, GroupOpsBounds},
    prelude::*,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use tracing::instrument;

const LOG_TARGET: &str = "nexus_nova::shuffling::chaum_pedersen_gadget";

/// Circuit representation of Chaum-Pedersen proof
pub struct ChaumPedersenProofVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    /// First commitment: T_g = g^w
    pub t_g: CV,
    /// Second commitment: T_H = H^w
    pub t_h: CV,
    /// Response: z = w + c·secret (as bits for scalar multiplication)
    pub z_bits: Vec<Boolean<C::BaseField>>,
}

impl<C, CV> Clone for ChaumPedersenProofVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            t_g: self.t_g.clone(),
            t_h: self.t_h.clone(),
            z_bits: self.z_bits.clone(),
        }
    }
}

impl<C, CV> AllocVar<ChaumPedersenProof<C>, C::BaseField> for ChaumPedersenProofVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<ChaumPedersenProof<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let proof = f()?.borrow().clone();

        tracing::trace!(target: LOG_TARGET, "Allocating ChaumPedersenProofVar");

        // Allocate t_g as CurveVar
        let t_g = CV::new_variable(cs.clone(), || Ok(proof.t_g), mode)?;
        tracing::trace!(target: LOG_TARGET, "Allocated t_g: {:?}", t_g.value().ok());

        // Allocate t_h as CurveVar
        let t_h = CV::new_variable(cs.clone(), || Ok(proof.t_h), mode)?;
        tracing::trace!(target: LOG_TARGET, "Allocated t_h: {:?}", t_h.value().ok());

        // Allocate z as bits for scalar multiplication
        // proof.z is C::ScalarField, convert to bits for circuit operations
        let z_bits_values = proof.z.into_bigint().to_bits_le();
        let z_bits = z_bits_values
            .into_iter()
            .map(|bit| Boolean::new_variable(cs.clone(), || Ok(bit), mode))
            .collect::<Result<Vec<_>, _>>()?;
        tracing::trace!(target: LOG_TARGET, "Allocated z as {} bits", z_bits.len());

        Ok(Self { t_g, t_h, z_bits })
    }
}

/// Compute the Fiat-Shamir challenge from commitments in-circuit
#[instrument(target = LOG_TARGET, level = "debug", skip_all)]
fn compute_challenge_gadget<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    t_g: &CV,
    t_h: &CV,
) -> Result<EmulatedFpVar<C::ScalarField, C::BaseField>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>
        + CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
{
    tracing::debug!(target: LOG_TARGET, "Computing Fiat-Shamir challenge in-circuit");

    let config = poseidon_config::<C::BaseField>();
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

    // Absorb t_g using CurveAbsorbGadget
    tracing::debug!(target: LOG_TARGET, "Absorbing t_g: {:?}", t_g.value().ok());
    t_g.curve_absorb_gadget(&mut sponge)?;

    // Absorb t_h using CurveAbsorbGadget
    tracing::debug!(target: LOG_TARGET, "Absorbing t_h: {:?}", t_h.value().ok());
    t_h.curve_absorb_gadget(&mut sponge)?;

    // Squeeze challenge in base field
    let challenge_base = sponge.squeeze_field_elements(1)?[0].clone();
    tracing::debug!(target: LOG_TARGET, "Computed challenge (base field): {:?}", challenge_base.value().ok());

    let challenge: EmulatedFpVar<C::ScalarField, C::BaseField> =
        embed_to_emulated(cs, challenge_base)?;

    tracing::debug!(target: LOG_TARGET, "Converted challenge to scalar field: {:?}", challenge.value().ok());

    Ok(challenge)
}

impl<C, CV> ChaumPedersenProofVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>
        + CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    /// Verify a Chaum-Pedersen proof in-circuit
    ///
    /// # Arguments
    /// * `cs` - Constraint system reference
    /// * `g` - First base point
    /// * `h` - Second base point
    /// * `alpha` - First public value (should be g^secret)
    /// * `beta` - Second public value (should be h^secret)
    #[instrument(target = LOG_TARGET, level = "debug", skip_all)]
    pub fn verify_gadget(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        g: &CV,
        h: &CV,
        alpha: &CV,
        beta: &CV,
    ) -> Result<Boolean<C::BaseField>, SynthesisError> {
        tracing::debug!(target: LOG_TARGET, "Starting Chaum-Pedersen verification in-circuit");

        // Recompute the challenge from commitments
        tracing::debug!(target: LOG_TARGET, "Computing Fiat-Shamir challenge");
        let challenge = compute_challenge_gadget::<C, CV>(cs.clone(), &self.t_g, &self.t_h)?;

        // Verify equation 1: g^z = T_g · α^c
        tracing::debug!(target: LOG_TARGET, "Verifying equation 1: g^z = T_g · α^c");

        // Compute lhs1 = g^z (using scalar_mul_le with bits)
        let lhs1 = g.clone().scalar_mul_le(self.z_bits.iter())?;
        tracing::debug!(target: LOG_TARGET, "lhs1 (g^z) = {:?}", lhs1.value().ok());

        // Compute rhs1 = T_g + α^c
        let alpha_c = alpha.clone() * &challenge;
        let rhs1 = &self.t_g + &alpha_c;
        tracing::debug!(target: LOG_TARGET, "rhs1 (T_g · α^c) = {:?}", rhs1.value().ok());

        // Check equation 1
        let check1 = lhs1.is_eq(&rhs1)?;
        tracing::debug!(target: LOG_TARGET, "Equation 1 result: {:?}", check1.value().ok());

        // Verify equation 2: h^z = T_h · β^c
        tracing::debug!(target: LOG_TARGET, "Verifying equation 2: h^z = T_h · β^c");

        // Compute lhs2 = h^z (using scalar_mul_le with bits)
        let lhs2 = h.clone().scalar_mul_le(self.z_bits.iter())?;
        tracing::debug!(target: LOG_TARGET, "lhs2 (h^z) = {:?}", lhs2.value().ok());

        // Compute rhs2 = T_h + β^c
        let beta_c = beta.clone() * &challenge;
        let rhs2 = &self.t_h + &beta_c;
        tracing::debug!(target: LOG_TARGET, "rhs2 (T_h · β^c) = {:?}", rhs2.value().ok());

        // Check equation 2
        let check2 = lhs2.is_eq(&rhs2)?;
        tracing::debug!(target: LOG_TARGET, "Equation 2 result: {:?}", check2.value().ok());

        // Both checks must pass
        let result = Boolean::kary_and(&[check1, check2])?;
        tracing::debug!(target: LOG_TARGET, "Final verification result: {:?}", result.value().ok());

        Ok(result)
    }

    /// Verify a Chaum-Pedersen proof in-circuit with PoseidonSponge
    /// This is a convenience function for backward compatibility and tests
    #[instrument(target = LOG_TARGET, level = "debug", skip_all)]
    pub fn verify_gadget_with_poseidon(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        g: &CV,
        h: &CV,
        alpha: &CV,
        beta: &CV,
    ) -> Result<Boolean<C::BaseField>, SynthesisError>
    where
        CV: CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
    {
        self.verify_gadget(cs, g, h, alpha, beta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_crypto_primitives::sponge::CryptographicSponge;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;
    use crate::test_utils::setup_test_tracing;

    const TEST_TARGET: &str = "nexus_nova";

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;

    

    #[test]
    fn test_chaum_pedersen_native_vs_circuit() -> Result<(), SynthesisError> {
        let _guard = setup_test_tracing(TEST_TARGET);
        tracing::info!(target: TEST_TARGET, "Starting native vs circuit test");

        let mut rng = test_rng();

        // Setup
        let g = G1Projective::generator();
        let h_scalar = Fr::rand(&mut rng);
        let h = g * h_scalar;

        // Secret value
        let secret = Fr::rand(&mut rng);

        // Compute public values
        let alpha = g * secret;
        let beta = h * secret;

        tracing::info!(target: TEST_TARGET, "=== Native Proof Generation ===");
        // Generate proof natively using BN254 circuit-compatible functions
        //
        let config = crate::poseidon_config::<Fq>();
        let mut sponge = PoseidonSponge::new(&config);

        let proof = ChaumPedersenProof::prove(&mut sponge, secret, g, h, &mut rng);

        tracing::info!(target: TEST_TARGET, "=== Native Verification ===");
        // Verify natively using BN254 circuit-compatible verification
        let mut verify_sponge = PoseidonSponge::new(&config);
        let native_valid = proof.verify(&mut verify_sponge, g, h, alpha, beta);
        assert!(native_valid, "Native proof should verify");
        tracing::info!(target: TEST_TARGET, "Native verification passed: {}", native_valid);

        tracing::info!(target: TEST_TARGET, "=== Circuit Verification ===");
        // Create constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate base points as constants
        let g_var = G1Var::new_constant(cs.clone(), g)?;
        let h_var = G1Var::new_constant(cs.clone(), h)?;

        // Allocate public values as constants
        let alpha_var = G1Var::new_constant(cs.clone(), alpha)?;
        let beta_var = G1Var::new_constant(cs.clone(), beta)?;

        // Allocate proof as witness
        let proof_var = ChaumPedersenProofVar::<G1Projective, G1Var>::new_variable(
            cs.clone(),
            || Ok(proof.clone()),
            AllocationMode::Witness,
        )?;

        // Verify in circuit using the convenience function with PoseidonSponge
        let circuit_valid = proof_var.verify_gadget_with_poseidon(
            cs.clone(),
            &g_var,
            &h_var,
            &alpha_var,
            &beta_var,
        )?;

        // Enforce that verification passed
        circuit_valid.enforce_equal(&Boolean::constant(true))?;

        // Check constraint satisfaction
        let satisfied = cs.is_satisfied()?;
        tracing::info!(target: TEST_TARGET, "Circuit satisfied: {}", satisfied);
        tracing::info!(target: TEST_TARGET, "Total constraints: {}", cs.num_constraints());
        tracing::info!(target: TEST_TARGET, "Total witness variables: {}", cs.num_witness_variables());

        if !satisfied {
            if let Some(unsatisfied_path) = cs.which_is_unsatisfied()? {
                tracing::error!(target: TEST_TARGET, "First unsatisfied constraint: {}", unsatisfied_path);
            }
        }

        assert!(satisfied, "Circuit should be satisfied");

        tracing::info!(target: TEST_TARGET, "✅ Test passed: Native and circuit verification both succeed!");
        Ok(())
    }
}
