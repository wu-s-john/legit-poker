//! SNARK gadget version of Bayer-Groth transcript for in-circuit Fiat-Shamir

use crate::{shuffling::curve_absorb::CurveAbsorbGadget, track_constraints};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
    poseidon::PoseidonSponge, CryptographicSponge,
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar, FieldVar},
    prelude::*,
    uint8::UInt8,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth::bg_setup_gadget";

/// Output parameters from the Bayer-Groth setup protocol (gadget version)
///
/// Note: The challenges are now stored as EmulatedFpVar<ScalarField, F> (scalar field)
/// to match the native implementation. The conversion from base field happens
/// in the run_protocol function.
pub struct BayerGrothSetupParametersGadget<ScalarField: PrimeField, F: PrimeField, CG> {
    /// The power challenge x used to compute the power vector (scalar field representation)
    pub perm_power_challenge: EmulatedFpVar<ScalarField, F>,
    /// Commitment to the permutation vector
    pub c_perm: CG,
    /// Commitment to the power vector
    pub c_power: CG,
    /// The mixing challenge y (scalar field representation)
    pub perm_mixing_challenge_y: EmulatedFpVar<ScalarField, F>,
    /// The offset challenge z (scalar field representation)
    pub perm_offset_challenge_z: EmulatedFpVar<ScalarField, F>,
}

/// SNARK gadget version of Bayer-Groth transcript for in-circuit Fiat-Shamir
pub struct BayerGrothTranscriptGadget<
    F: PrimeField,
    S: CryptographicSponge = PoseidonSponge<F>,
    ROVar: CryptographicSpongeVar<F, S> = PoseidonSpongeVar<F>,
> {
    sponge: ROVar,
    _phantom: ark_std::marker::PhantomData<(F, S)>,
}

impl<F: PrimeField, S: CryptographicSponge, ROVar: CryptographicSpongeVar<F, S>>
    BayerGrothTranscriptGadget<F, S, ROVar>
{
    /// Create a new transcript gadget with domain separation
    pub fn new(
        cs: ConstraintSystemRef<F>,
        domain: &[u8],
        mut sponge: ROVar,
    ) -> Result<Self, SynthesisError> {
        // Domain separation - convert domain bytes to field elements for absorption
        let domain_bytes = domain
            .iter()
            .map(|&byte| UInt8::new_constant(cs.clone(), byte))
            .collect::<Result<Vec<_>, _>>()?;
        sponge.absorb(&domain_bytes)?;

        Ok(Self {
            sponge,
            _phantom: ark_std::marker::PhantomData,
        })
    }

    /// Absorb the commitment to the permutation vector using CurveAbsorbGadget
    fn absorb_perm_vector_commitment<CG>(&mut self, c_perm: &CG) -> Result<(), SynthesisError>
    where
        CG: CurveAbsorbGadget<F, ROVar>,
    {
        c_perm.curve_absorb_gadget(&mut self.sponge)?;

        // Note: We can't directly log the curve point value in a meaningful way
        tracing::debug!(target: LOG_TARGET, "Absorbed permutation vector commitment (curve point)");
        Ok(())
    }

    /// Derive permutation power challenge from the transcript
    /// Returns perm_power_challenge which is used to compute the power vector
    pub fn derive_perm_power_challenge(&mut self) -> Result<FpVar<F>, SynthesisError> {
        // Squeeze one field element
        let elements = self.sponge.squeeze_field_elements(1)?;
        let mut perm_power_challenge = elements[0].clone();

        // Ensure challenge is non-zero (∈ F_q*)
        let is_zero = perm_power_challenge.is_zero()?;
        let one = FpVar::<F>::one();
        perm_power_challenge = is_zero.select(&one, &perm_power_challenge)?;

        // Log the derived challenge value
        if let Ok(value) = perm_power_challenge.value() {
            tracing::debug!(target: LOG_TARGET, "Derived permutation power challenge: {:?}", value);
        } else {
            tracing::debug!(target: LOG_TARGET, "Derived permutation power challenge (value unavailable)");
        }

        Ok(perm_power_challenge)
    }

    /// Derive power challenge from a commitment to the permutation vector
    ///
    /// This is a minimal version for verifiers that only need the power challenge.
    /// It absorbs the permutation commitment and derives the power challenge.
    ///
    /// Parameters:
    /// - cs: Constraint system reference
    /// - permutation_commitment: Commitment to the permutation vector (curve point)
    ///
    /// Returns: The power challenge as EmulatedFpVar<ScalarField, F>
    pub fn derive_power_challenge_from_commitment<C, CG>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        permutation_commitment: &CG,
    ) -> Result<EmulatedFpVar<C::ScalarField, F>, SynthesisError>
    where
        C: CurveGroup,
        C::BaseField: PrimeField,
        CG: CurveAbsorbGadget<F, ROVar>,
    {
        // Step 1: Absorb commitment to permutation vector
        self.absorb_perm_vector_commitment(permutation_commitment)?;
        tracing::debug!(target: LOG_TARGET, "Absorbed permutation vector commitment");

        // Step 2: Derive power challenge in base field
        let perm_power_challenge = self.derive_perm_power_challenge()?;

        // Step 3: Convert from base field to scalar field
        let perm_power_challenge_scalar =
            EmulatedFpVar::<C::ScalarField, F>::new_witness(cs, || {
                let power_base = perm_power_challenge.value().unwrap_or_default();
                let power_scalar = C::ScalarField::from_le_bytes_mod_order(
                    &power_base.into_bigint().to_bytes_le(),
                );
                Ok(power_scalar)
            })?;

        tracing::debug!(target: LOG_TARGET,
            perm_power_challenge = ?perm_power_challenge_scalar.value().ok(),
            "Derived power challenge from commitment");

        Ok(perm_power_challenge_scalar)
    }

    /// Absorb the commitment to the power vector using CurveAbsorbGadget
    fn absorb_perm_power_vector_commitment<CG>(
        &mut self,
        c_power: &CG,
    ) -> Result<(), SynthesisError>
    where
        CG: CurveAbsorbGadget<F, ROVar>,
    {
        c_power.curve_absorb_gadget(&mut self.sponge)?;

        // Note: We can't directly log the curve point value in a meaningful way
        tracing::debug!(target: LOG_TARGET, "Absorbed power vector commitment (curve point)");
        Ok(())
    }

    /// Derive final challenges for permutation equality check
    /// Returns (mixing_challenge_y, offset_challenge_z)
    fn derive_perm_challenges_y_z(&mut self) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
        let elements = self.sponge.squeeze_field_elements(2)?;
        let perm_mixing_challenge_y = elements[0].clone();
        let perm_offset_challenge_z = elements[1].clone();

        // Log the derived challenge values
        if let (Ok(y_val), Ok(z_val)) = (
            perm_mixing_challenge_y.value(),
            perm_offset_challenge_z.value(),
        ) {
            tracing::debug!(target: LOG_TARGET, "Derived permutation mixing and offset challenges: y={:?}, z={:?}", y_val, z_val);
        } else {
            tracing::debug!(target: LOG_TARGET, "Derived permutation mixing and offset challenges (values unavailable)");
        }

        Ok((perm_mixing_challenge_y, perm_offset_challenge_z))
    }

    /// Complete Fiat-Shamir protocol for Bayer-Groth permutation proof (gadget version)
    ///
    /// This runs the full protocol in-circuit, mirroring the native version:
    /// 1. Absorb commitment to permutation vector
    /// 2. Derive power challenge
    /// 3. Compute permutation power vector (externally)
    /// 4. Absorb commitment to power vector
    /// 5. Derive mixing and offset challenges
    ///
    /// Type Parameters:
    /// - C: The curve group type
    /// - CG: The curve gadget type
    ///
    /// Parameters:
    /// - cs: Constraint system reference
    /// - c_perm: Commitment to permutation vector (curve point)
    /// - c_power: Commitment to power vector (curve point)
    ///
    /// Returns: BayerGrothSetupParametersGadget containing all protocol parameters
    pub fn run_protocol<C, CG>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        c_perm: &CG,
        c_power: &CG,
    ) -> Result<BayerGrothSetupParametersGadget<C::ScalarField, F, CG>, SynthesisError>
    where
        C: CurveGroup,
        C::BaseField: PrimeField,
        CG: CurveAbsorbGadget<F, ROVar> + Clone + ToBitsGadget<F> + GR1CSVar<F, Value = C>,
        for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
    {
        // Log the commitment values if available
        if let (Ok(c_perm_value), Ok(c_power_value)) = (c_perm.value(), c_power.value()) {
            tracing::debug!(
                target: LOG_TARGET,
                ?c_perm_value,
                ?c_power_value,
                "Gadget run_protocol called with commitments"
            );
        }

        let cs_clone = cs.clone();
        track_constraints!(cs_clone, "bg_setup_protocol", LOG_TARGET, {
            // Step 1 & 2: Use the new method to derive power challenge from commitment
            let perm_power_challenge_scalar = self.derive_power_challenge_from_commitment::<C, CG>(
                cs.clone(),
                c_perm,
            )?;
            tracing::debug!(target: LOG_TARGET,
                perm_power_challenge = ?perm_power_challenge_scalar.value().ok(),
                "Step 1-2: Derived power challenge from commitment");

            // Step 3: Absorb commitment to power vector
            self.absorb_perm_power_vector_commitment(c_power)?;
            tracing::debug!(target: LOG_TARGET,
                c_power = ?c_power.value().ok(),
                "Step 3: Absorbed power vector commitment");

            // Step 4: Derive mixing and offset challenges
            let (perm_mixing_challenge_y_base, perm_offset_challenge_z_base) =
                self.derive_perm_challenges_y_z()?;

            // Convert challenges from base field to scalar field

            let perm_mixing_challenge_y_scalar =
                EmulatedFpVar::<C::ScalarField, F>::new_witness(cs.clone(), || {
                    let y_base = perm_mixing_challenge_y_base.value().unwrap_or_default();
                    let y_scalar = C::ScalarField::from_le_bytes_mod_order(
                        &y_base.into_bigint().to_bytes_le(),
                    );
                    Ok(y_scalar)
                })?;

            let perm_offset_challenge_z_scalar =
                EmulatedFpVar::<C::ScalarField, F>::new_witness(cs.clone(), || {
                    let z_base = perm_offset_challenge_z_base.value().unwrap_or_default();
                    let z_scalar = C::ScalarField::from_le_bytes_mod_order(
                        &z_base.into_bigint().to_bytes_le(),
                    );
                    Ok(z_scalar)
                })?;

            tracing::debug!(target: LOG_TARGET,
                perm_mixing_challenge_y_base = ?perm_mixing_challenge_y_scalar.value().ok(),
                perm_offset_challenge_z_base = ?perm_offset_challenge_z_scalar.value().ok(),
                "Step 4: Derived mixing and offset challenges");

            Ok(BayerGrothSetupParametersGadget {
                perm_power_challenge: perm_power_challenge_scalar,
                c_perm: c_perm.clone(),
                c_power: c_power.clone(),
                perm_mixing_challenge_y: perm_mixing_challenge_y_scalar,
                perm_offset_challenge_z: perm_offset_challenge_z_scalar,
            })
        })
    }
}

/// Create a new transcript gadget with PoseidonSponge for backward compatibility
pub fn new_bayer_groth_transcript_gadget_with_poseidon<F>(
    cs: ConstraintSystemRef<F>,
    domain: &[u8],
) -> Result<BayerGrothTranscriptGadget<F, PoseidonSponge<F>, PoseidonSpongeVar<F>>, SynthesisError>
where
    F: PrimeField,
{
    let config = crate::config::poseidon_config::<F>();
    let sponge = PoseidonSpongeVar::new(cs.clone(), &config);
    BayerGrothTranscriptGadget::new(cs, domain, sponge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen_commitment_opening_proof::{DeckHashWindow, ReencryptionWindow};
    use crate::shuffling::bayer_groth_permutation::bg_setup::new_bayer_groth_transcript_with_poseidon;
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_crypto_primitives::commitment::{
        pedersen::Commitment as PedersenCommitment, CommitmentScheme,
    };
    use ark_r1cs_std::{
        alloc::AllocVar, fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar,
        alloc::AllocationMode,
    };
    use ark_relations::gr1cs::{ConstraintSystem, SynthesisError};
    use ark_std::{rand::SeedableRng, test_rng, UniformRand};
    use rand::rngs::StdRng;

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;

    /// Test that the gadget's derive_power_challenge_from_commitment produces the same
    /// power challenge as the native prover logic
    #[test]
    fn test_derive_power_challenge_consistency() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        let perm: [usize; 5] = [3, 1, 4, 2, 5];
        let prover_blinding_r = Fr::rand(&mut rng);
        let prover_blinding_s = Fr::rand(&mut rng);

        // Create Pedersen parameters
        let mut deck_rng = StdRng::seed_from_u64(42);
        let perm_params = PedersenCommitment::<G1Projective, DeckHashWindow>::setup(&mut deck_rng)
            .expect("Failed to setup DeckHashWindow Pedersen parameters");
        let mut power_rng = StdRng::seed_from_u64(43);
        let power_params =
            PedersenCommitment::<G1Projective, ReencryptionWindow>::setup(&mut power_rng)
                .expect("Failed to setup ReencryptionWindow Pedersen parameters");

        // ============= Native Prover =============
        let mut native_transcript = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");
        let (_, native_setup) = native_transcript.compute_power_challenge_setup::<G1Projective, 5>(
            &perm_params,
            &power_params,
            &perm,
            prover_blinding_r,
            prover_blinding_s,
        );

        // Extract the native power challenge (in scalar field Fr)
        let native_power_challenge: Fr = native_setup.power_challenge;
        let native_c_perm = native_setup.permutation_commitment;

        tracing::debug!(
            target: "test",
            ?native_power_challenge,
            ?native_c_perm,
            "Native prover results"
        );

        // ============= Gadget Verifier =============
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate the permutation commitment as a circuit variable
        let c_perm_var = G1Var::new_variable(
            cs.clone(),
            || Ok(native_c_perm),
            AllocationMode::Witness,
        )?;

        // Create gadget transcript and derive power challenge from commitment
        let mut gadget_transcript = new_bayer_groth_transcript_gadget_with_poseidon::<Fq>(
            cs.clone(),
            b"test-domain",
        )?;

        let gadget_power_challenge = gadget_transcript
            .derive_power_challenge_from_commitment::<G1Projective, G1Var>(
                cs.clone(),
                &c_perm_var,
            )?;

        // Extract the gadget power challenge value
        let gadget_power_challenge_value: Fr = gadget_power_challenge.value()?;

        tracing::debug!(
            target: "test",
            ?gadget_power_challenge_value,
            "Gadget verifier result"
        );

        // ============= Verify Consistency =============
        assert_eq!(
            native_power_challenge, gadget_power_challenge_value,
            "Native and gadget power challenges should be identical"
        );

        // Verify constraint system is satisfied
        assert!(
            cs.is_satisfied()?,
            "Circuit constraints should be satisfied"
        );

        tracing::info!(
            target: "test",
            "✅ Test passed: Gadget derives same power challenge as native prover"
        );

        Ok(())
    }
}
