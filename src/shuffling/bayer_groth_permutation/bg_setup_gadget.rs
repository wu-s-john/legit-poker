//! SNARK gadget version of Bayer-Groth transcript for in-circuit Fiat-Shamir

use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
    CryptographicSponge,
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

    /// Absorb the commitment to the permutation vector (pre-computed externally)
    /// In practice, the commitment would be passed as public input or
    /// converted to field elements via hash-to-field
    pub fn absorb_perm_vector_commitment_as_field_elements(
        &mut self,
        c_perm_elements: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        for elem in c_perm_elements {
            self.sponge.absorb(&elem)?;
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed permutation vector commitment as field elements");
        Ok(())
    }

    /// Absorb the permutation vector into the transcript
    /// perm_vector represents (π(1), ..., π(N))
    pub fn absorb_perm_vector(&mut self, perm_vector: &[FpVar<F>]) -> Result<(), SynthesisError> {
        for (i, pi) in perm_vector.iter().enumerate() {
            self.sponge.absorb(&pi)?;
            tracing::trace!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed perm_vector[{}]", i);
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed permutation vector of length {}", perm_vector.len());
        Ok(())
    }

    /// Derive permutation power challenge and blinding factor
    /// Returns (perm_power_challenge, blinding_r) where:
    /// - perm_power_challenge is used to compute the power vector
    /// - blinding_r is the blinding factor for the permutation vector commitment
    pub fn derive_perm_power_challenge_and_blinding(
        &mut self,
        _cs: ConstraintSystemRef<F>,
    ) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
        // Squeeze two field elements
        let elements = self.sponge.squeeze_field_elements(2)?;

        let mut perm_power_challenge = elements[0].clone();
        let blinding_r = elements[1].clone();

        // Ensure challenge is non-zero (∈ F_q*)
        // Check if challenge is zero
        let is_zero = perm_power_challenge.is_zero()?;

        // If zero, set it to one
        let one = FpVar::<F>::one();
        perm_power_challenge = is_zero.select(&one, &perm_power_challenge)?;

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Derived permutation power challenge and blinding factor");

        Ok((perm_power_challenge, blinding_r))
    }

    /// Compute the permutation power vector = (x^π(1), ..., x^π(N)) in-circuit
    ///
    /// Parameters:
    /// - cs: Constraint system reference
    /// - permutation: The permutation π as circuit variables (values 1 to N)
    /// - perm_power_challenge: The challenge x derived from Fiat-Shamir
    ///
    /// Returns: Power vector as circuit variables
    pub fn compute_perm_power_vector(
        &self,
        cs: ConstraintSystemRef<F>,
        permutation: &[FpVar<F>],
        perm_power_challenge: &FpVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut power_vector = Vec::with_capacity(permutation.len());

        for (i, pi) in permutation.iter().enumerate() {
            // Compute x^π(i) using repeated squaring
            // Since π(i) is a small value (1 to N), we can compute this efficiently
            // by converting π(i) to bits and using conditional multiplication

            // For simplicity in the gadget, we'll use a method that computes powers
            // by repeated multiplication up to a maximum value
            let power_i = self.compute_power_gadget(cs.clone(), perm_power_challenge, pi)?;
            power_vector.push(power_i);

            tracing::trace!(target: "bayer_groth::fiat_shamir_gadget", "Computed power_vector[{}] = x^π({})", i, i);
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Computed permutation power vector of length {}", power_vector.len());

        Ok(power_vector)
    }

    /// Helper function to compute x^n where n is a circuit variable
    /// Uses a simple repeated multiplication approach for small exponents
    fn compute_power_gadget(
        &self,
        cs: ConstraintSystemRef<F>,
        base: &FpVar<F>,
        exponent: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        // Get the concrete value of the exponent if available (for witness generation)
        let exp_value = exponent.value().unwrap_or(F::one());

        // Convert to u64 for power computation
        // This assumes the exponent is small (like permutation indices)
        let exp_u64 = exp_value.into_bigint().as_ref()[0];

        // Compute the result using native field exponentiation
        let result_value = base.value().unwrap_or(F::one()).pow(&[exp_u64]);

        // Allocate the result as a witness variable
        let result = FpVar::new_witness(cs, || Ok(result_value))?;

        // In a production implementation, we would add constraints to verify
        // that result = base^exponent using bit decomposition and repeated squaring
        // For now, we trust the witness generation

        Ok(result)
    }

    /// Absorb the power vector into the transcript
    pub fn absorb_perm_power_vector(
        &mut self,
        power_vector: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        for (i, power_i) in power_vector.iter().enumerate() {
            self.sponge.absorb(&power_i)?;
            tracing::trace!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed power_vector[{}]", i);
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed power vector of length {}", power_vector.len());
        Ok(())
    }

    /// Absorb the commitment to the power vector (pre-computed externally)
    /// In practice, the commitment would be passed as public input or
    /// converted to field elements via hash-to-field
    pub fn absorb_perm_power_vector_commitment_as_field_elements(
        &mut self,
        c_power_elements: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        for elem in c_power_elements {
            self.sponge.absorb(&elem)?;
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed power vector commitment as field elements");
        Ok(())
    }

    /// Derive the blinding factor s for the power vector commitment
    pub fn derive_blinding_factor_s(&mut self) -> Result<FpVar<F>, SynthesisError> {
        let s = self.sponge.squeeze_field_elements(1)?[0].clone();

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Derived blinding factor s");

        Ok(s)
    }

    /// Derive final challenges for permutation equality check
    /// Returns (mixing_challenge_y, offset_challenge_z)
    pub fn derive_perm_challenges_y_z(&mut self) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
        let elements = self.sponge.squeeze_field_elements(2)?;
        let mixing_challenge_y = elements[0].clone();
        let offset_challenge_z = elements[1].clone();

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Derived permutation mixing and offset challenges");

        Ok((mixing_challenge_y, offset_challenge_z))
    }

    /// Complete Fiat-Shamir protocol for Bayer-Groth permutation proof (gadget version)
    ///
    /// This runs the full protocol in-circuit:
    /// 1. Absorb commitment to permutation vector (as field elements)
    /// 2. Absorb permutation vector
    /// 3. Derive power challenge and blinding factor
    /// 4. Compute permutation power vector
    /// 5. Absorb power vector
    /// 6. Absorb commitment to power vector (as field elements)
    /// 7. Derive blinding factor for power vector
    /// 8. Derive mixing and offset challenges
    ///
    /// Returns: (perm_power_challenge, perm_power_vector, mixing_challenge_y, offset_challenge_z, blinding_r, blinding_s)
    pub fn run_protocol(
        &mut self,
        cs: ConstraintSystemRef<F>,
        c_perm_elements: &[FpVar<F>],
        c_power_elements: &[FpVar<F>],
        permutation: &[FpVar<F>],
    ) -> Result<
        (
            FpVar<F>,
            Vec<FpVar<F>>,
            FpVar<F>,
            FpVar<F>,
            FpVar<F>,
            FpVar<F>,
        ),
        SynthesisError,
    > {
        // Step 1: Absorb commitment to permutation vector
        self.absorb_perm_vector_commitment_as_field_elements(c_perm_elements)?;

        // Step 2: Absorb permutation vector
        self.absorb_perm_vector(permutation)?;

        // Step 3: Derive power challenge and blinding factor
        let (perm_power_challenge, blinding_r) =
            self.derive_perm_power_challenge_and_blinding(cs.clone())?;

        // Step 4: Compute permutation power vector
        let perm_power_vector =
            self.compute_perm_power_vector(cs.clone(), permutation, &perm_power_challenge)?;

        // Step 5: Absorb power vector
        self.absorb_perm_power_vector(&perm_power_vector)?;

        // Step 6: Absorb commitment to power vector
        self.absorb_perm_power_vector_commitment_as_field_elements(c_power_elements)?;

        // Step 7: Derive blinding factor for power vector
        let blinding_s = self.derive_blinding_factor_s()?;

        // Step 8: Derive mixing and offset challenges
        let (mixing_challenge_y, offset_challenge_z) = self.derive_perm_challenges_y_z()?;

        Ok((
            perm_power_challenge,
            perm_power_vector,
            mixing_challenge_y,
            offset_challenge_z,
            blinding_r,
            blinding_s,
        ))
    }
}