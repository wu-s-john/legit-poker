//! SNARK gadget version of Bayer-Groth transcript for in-circuit Fiat-Shamir

use crate::{shuffling::curve_absorb::CurveAbsorbGadget, track_constraints};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
    prelude::*,
    uint8::UInt8,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

const LOG_TARGET: &str = "bayer_groth::fiat_shamir_gadget";

/// Output parameters from the Bayer-Groth setup protocol (gadget version)
pub struct BayerGrothSetupParametersGadget<F: PrimeField, CG> {
    /// The power challenge x used to compute the power vector
    pub perm_power_challenge: FpVar<F>,
    /// Commitment to the permutation vector
    pub c_perm: CG,
    /// Commitment to the power vector
    pub c_power: CG,
    /// The mixing challenge y
    pub perm_mixing_challenge_y: FpVar<F>,
    /// The offset challenge z
    pub perm_offset_challenge_z: FpVar<F>,
}

/// SNARK gadget version of Bayer-Groth transcript for in-circuit Fiat-Shamir
pub struct BayerGrothTranscriptGadget<F: PrimeField> {
    sponge: PoseidonSpongeVar<F>,
}

impl<F: PrimeField> BayerGrothTranscriptGadget<F> {
    /// Create a new transcript gadget with domain separation
    pub fn new(cs: ConstraintSystemRef<F>, domain: &[u8]) -> Result<Self, SynthesisError> {
        let config = crate::config::poseidon_config::<F>();
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

        // Domain separation - convert domain bytes to field elements for absorption
        let domain_bytes = domain
            .iter()
            .map(|&byte| UInt8::new_constant(cs.clone(), byte))
            .collect::<Result<Vec<_>, _>>()?;
        sponge.absorb(&domain_bytes)?;

        Ok(Self { sponge })
    }

    /// Absorb the commitment to the permutation vector using CurveAbsorbGadget
    fn absorb_perm_vector_commitment<CG>(&mut self, c_perm: &CG) -> Result<(), SynthesisError>
    where
        CG: CurveAbsorbGadget<F>,
    {
        c_perm.curve_absorb_gadget(&mut self.sponge)?;

        // Note: We can't directly log the curve point value in a meaningful way
        tracing::debug!(target: LOG_TARGET, "Absorbed permutation vector commitment (curve point)");
        Ok(())
    }

    /// Derive permutation power challenge from the transcript
    /// Returns perm_power_challenge which is used to compute the power vector
    fn derive_perm_power_challenge(&mut self) -> Result<FpVar<F>, SynthesisError> {
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

    /// Absorb the commitment to the power vector using CurveAbsorbGadget
    fn absorb_perm_power_vector_commitment<CG>(
        &mut self,
        c_power: &CG,
    ) -> Result<(), SynthesisError>
    where
        CG: CurveAbsorbGadget<F>,
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
    /// Parameters:
    /// - cs: Constraint system reference
    /// - c_perm: Commitment to permutation vector (curve point)
    /// - c_power: Commitment to power vector (curve point)
    /// - permutation: The permutation values for computing power vector
    ///
    /// Returns: BayerGrothSetupParametersGadget containing all protocol parameters
    pub fn run_protocol<CG>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        c_perm: &CG,
        c_power: &CG,
    ) -> Result<BayerGrothSetupParametersGadget<F, CG>, SynthesisError>
    where
        CG: CurveAbsorbGadget<F> + Clone,
    {
        track_constraints!(cs, "bg_setup_protocol", LOG_TARGET, {
            // Step 1: Absorb commitment to permutation vector
            self.absorb_perm_vector_commitment(c_perm)?;
            tracing::debug!(target: LOG_TARGET, "Step 1: Absorbed permutation vector commitment");

            // Step 2: Derive power challenge
            let perm_power_challenge = self.derive_perm_power_challenge()?;
            tracing::debug!(target: LOG_TARGET, "Step 2: Derived power challenge");

            // Step 3: Absorb commitment to power vector
            self.absorb_perm_power_vector_commitment(c_power)?;
            tracing::debug!(target: LOG_TARGET, "Step 3: Absorbed power vector commitment");

            // Step 4: Derive mixing and offset challenges
            let (perm_mixing_challenge_y, perm_offset_challenge_z) =
                self.derive_perm_challenges_y_z()?;
            tracing::debug!(target: LOG_TARGET, "Step 4: Derived mixing and offset challenges");

            Ok(BayerGrothSetupParametersGadget {
                perm_power_challenge,
                c_perm: c_perm.clone(),
                c_power: c_power.clone(),
                perm_mixing_challenge_y,
                perm_offset_challenge_z,
            })
        })
    }
}
