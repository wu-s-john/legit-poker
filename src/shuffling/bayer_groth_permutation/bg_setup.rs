//! Fiat-Shamir challenge derivation for Bayer-Groth permutation proof

use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
    CryptographicSponge,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
    prelude::*,
    uint8::UInt8,
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::vec::Vec;

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::linking_rs_gadgets";

/// Output structure for the Bayer-Groth protocol execution
pub struct BayerGrothProtocolOutput<F: PrimeField> {
    /// The Fiat-Shamir challenge x ∈ F_q* used to compute powers x^π(i)
    /// This challenge is derived from the commitment to the permutation vector
    pub perm_power_challenge: F,
    /// Blinding factor r for commitment to the permutation vector
    pub blinding_r: F,
    /// Vector of powers (x^π(1), ..., x^π(N)) where π is the permutation
    /// Each element is the challenge raised to the power of the corresponding permutation value
    pub perm_power_vector: Vec<F>,
    /// Blinding factor s for commitment to the power vector
    pub blinding_s: F,
    /// Challenge y for linear combination in the permutation equality check
    /// Used to mix the permutation vector with the power vector: y*π(i) + x^π(i)
    pub perm_mixing_challenge_y: F,
    /// Offset challenge z for polynomial evaluation in the permutation check
    /// Subtracted from each term in the product: ∏(term_i - z)
    pub perm_offset_challenge_z: F,
}

/// Transcript for Bayer-Groth permutation proof using Fiat-Shamir
pub struct BayerGrothTranscript<F: PrimeField> {
    sponge: PoseidonSponge<F>,
}

impl<F: PrimeField> BayerGrothTranscript<F> {
    /// Create a new transcript with domain separation
    pub fn new(domain: &[u8]) -> Self {
        let config = crate::config::poseidon_config::<F>();
        let mut sponge = PoseidonSponge::new(&config);

        // Domain separation
        sponge.absorb(&domain);

        Self { sponge }
    }

    /// Absorb the commitment to the permutation vector (pre-computed externally)
    /// This commitment is expensive to compute, so it's passed in
    pub fn absorb_perm_vector_commitment<G: CurveGroup>(&mut self, c_perm: &G) {
        let mut bytes = Vec::new();
        c_perm.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);

        tracing::debug!(target: LOG_TARGET, "Absorbed permutation vector commitment");
    }

    /// Derive permutation power challenge and blinding factor
    /// Returns (perm_power_challenge, blinding_r) where:
    /// - perm_power_challenge is used to compute the power vector
    /// - blinding_r is the blinding factor for the permutation vector commitment
    pub fn derive_perm_power_challenge_and_blinding(&mut self) -> (F, F) {
        // Squeeze two field elements
        let elements = self.sponge.squeeze_field_elements(2);

        let mut perm_power_challenge: F = elements[0];
        let blinding_r = elements[1];

        // Ensure challenge is non-zero (∈ F_q*)
        if perm_power_challenge.is_zero() {
            perm_power_challenge = F::one();
        }

        tracing::debug!(target: LOG_TARGET, "Derived permutation power challenge and blinding factor");

        (perm_power_challenge, blinding_r)
    }

    /// Compute the permutation power vector = (x^π(1), ..., x^π(N))
    ///
    /// Parameters:
    /// - permutation: The permutation π (1-indexed values)
    /// - perm_power_challenge: The challenge x derived from Fiat-Shamir
    ///
    /// Returns: Power vector (not the commitment, which is computed externally)
    pub fn compute_perm_power_vector(
        &self,
        permutation: &[usize],
        perm_power_challenge: F,
    ) -> Vec<F> {
        // power_vector[i] = x^π(i)
        // Note: permutation contains 1-indexed values
        let power_vector: Vec<F> = permutation
            .iter()
            .map(|&pi| perm_power_challenge.pow(&[pi as u64]))
            .collect();

        tracing::debug!(target: LOG_TARGET, "Computed permutation power vector of length {}", power_vector.len());

        power_vector
    }

    /// Absorb the commitment to the power vector (pre-computed externally)
    /// This commitment is expensive to compute, so it's passed in
    pub fn absorb_perm_power_vector_commitment<G: CurveGroup>(&mut self, c_power: &G) {
        let mut bytes = Vec::new();
        c_power.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);

        tracing::debug!(target: LOG_TARGET, "Absorbed power vector commitment");
    }

    /// Derive the blinding factor s for the power vector commitment
    pub fn derive_blinding_factor_s(&mut self) -> F {
        let s = self.sponge.squeeze_field_elements(1)[0];

        tracing::debug!(target: LOG_TARGET, "Derived blinding factor s");

        s
    }

    /// Derive final challenges for permutation equality check
    /// Returns (mixing_challenge_y, offset_challenge_z)
    pub fn derive_perm_challenges_y_z(&mut self) -> (F, F) {
        let elements = self.sponge.squeeze_field_elements(2);
        let mixing_challenge_y = elements[0];
        let offset_challenge_z = elements[1];

        tracing::debug!(target: LOG_TARGET, "Derived permutation mixing and offset challenges");

        (mixing_challenge_y, offset_challenge_z)
    }

    /// Complete Fiat-Shamir protocol for Bayer-Groth permutation proof
    ///
    /// This is a convenience function that runs the full protocol:
    /// 1. Absorb commitment to permutation vector
    /// 2. Derive power challenge and blinding factor
    /// 3. Compute permutation power vector
    /// 4. Absorb commitment to power vector
    /// 5. Derive blinding factor for power vector
    /// 6. Derive mixing and offset challenges
    ///
    /// Returns: BayerGrothProtocolOutput containing all protocol values
    pub fn run_protocol<G: CurveGroup>(
        &mut self,
        c_perm: &G,
        c_power: &G,
        permutation: &[usize],
    ) -> BayerGrothProtocolOutput<F> {
        // Step 1: Absorb commitment to permutation vector
        self.absorb_perm_vector_commitment(c_perm);

        // Step 2: Derive power challenge and blinding factor
        let (perm_power_challenge, blinding_r) = self.derive_perm_power_challenge_and_blinding();

        // Step 3: Compute permutation power vector
        let perm_power_vector = self.compute_perm_power_vector(permutation, perm_power_challenge);

        // Step 4: Absorb commitment to power vector
        self.absorb_perm_power_vector_commitment(c_power);

        // Step 5: Derive blinding factor for power vector
        let blinding_s = self.derive_blinding_factor_s();

        // Step 6: Derive mixing and offset challenges
        let (perm_mixing_challenge_y, perm_offset_challenge_z) = self.derive_perm_challenges_y_z();

        BayerGrothProtocolOutput {
            perm_power_challenge,
            blinding_r,
            perm_power_vector,
            blinding_s,
            perm_mixing_challenge_y,
            perm_offset_challenge_z,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::shuffling::bayer_groth_permutation::bg_setup_gadget::BayerGrothTranscriptGadget;
    use ark_bn254::{Fr, G1Projective};
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::Zero;
    use ark_std::{test_rng, UniformRand};
    use rand::RngCore;

    #[test]
    fn test_fiat_shamir_deterministic() {
        let mut rng = test_rng();

        // Create identical inputs
        let c_a = G1Projective::rand(&mut rng);
        let c_b = G1Projective::rand(&mut rng);
        let perm = vec![3, 1, 4, 2, 5];

        // Run protocol twice with same inputs
        let mut transcript1 = BayerGrothTranscript::<Fr>::new(b"test-domain");
        let output1 = transcript1.run_protocol(&c_a, &c_b, &perm);

        let mut transcript2 = BayerGrothTranscript::<Fr>::new(b"test-domain");
        let output2 = transcript2.run_protocol(&c_a, &c_b, &perm);

        // Should get identical outputs
        assert_eq!(output1.perm_power_challenge, output2.perm_power_challenge);
        assert_eq!(output1.blinding_r, output2.blinding_r);
        assert_eq!(output1.perm_power_vector, output2.perm_power_vector);
        assert_eq!(output1.blinding_s, output2.blinding_s);
        assert_eq!(
            output1.perm_mixing_challenge_y,
            output2.perm_mixing_challenge_y
        );
        assert_eq!(
            output1.perm_offset_challenge_z,
            output2.perm_offset_challenge_z
        );
    }

    #[test]
    fn test_different_commitments_different_challenges() {
        let mut rng = test_rng();

        let c_a1 = G1Projective::rand(&mut rng);
        let c_a2 = G1Projective::rand(&mut rng);
        let c_b = G1Projective::rand(&mut rng);
        let perm = vec![2, 1, 3];

        // Run with different c_a commitments
        let mut transcript1 = BayerGrothTranscript::<Fr>::new(b"test-domain");
        let output1 = transcript1.run_protocol(&c_a1, &c_b, &perm);

        let mut transcript2 = BayerGrothTranscript::<Fr>::new(b"test-domain");
        let output2 = transcript2.run_protocol(&c_a2, &c_b, &perm);

        // Should get different challenges
        assert_ne!(output1.perm_power_challenge, output2.perm_power_challenge);
    }

    #[test]
    fn test_perm_power_vector_computation() {
        let transcript = BayerGrothTranscript::<Fr>::new(b"test");

        let perm = vec![3, 1, 4, 2, 5];
        let perm_power_challenge = Fr::from(2u64);

        let power_vector = transcript.compute_perm_power_vector(&perm, perm_power_challenge);

        // Verify power_vector[i] = x^π(i)
        assert_eq!(power_vector[0], Fr::from(8u64)); // 2^3 = 8
        assert_eq!(power_vector[1], Fr::from(2u64)); // 2^1 = 2
        assert_eq!(power_vector[2], Fr::from(16u64)); // 2^4 = 16
        assert_eq!(power_vector[3], Fr::from(4u64)); // 2^2 = 4
        assert_eq!(power_vector[4], Fr::from(32u64)); // 2^5 = 32
    }

    #[test]
    fn test_perm_power_challenge_nonzero() {
        // Test that perm_power_challenge is always non-zero
        let mut transcript = BayerGrothTranscript::<Fr>::new(b"test");

        // Even if the sponge would produce zero, we should get one
        for _ in 0..10 {
            let (perm_power_challenge, _) = transcript.derive_perm_power_challenge_and_blinding();
            assert!(!perm_power_challenge.is_zero());
        }
    }

    #[test]
    fn test_gadget_fiat_shamir() -> Result<(), SynthesisError> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test data
        let perm = vec![3, 1, 4, 2, 5];
        let perm_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

        // Allocate permutation as circuit variables
        let perm_vars = perm_vals
            .iter()
            .map(|&val| FpVar::new_witness(cs.clone(), || Ok(val)))
            .collect::<Result<Vec<_>, _>>()?;

        // Create gadget transcript
        let mut transcript_gadget =
            BayerGrothTranscriptGadget::<Fr>::new(cs.clone(), b"test-domain")?;

        // For testing, we'll skip the commitment absorption since it requires
        // cross-field operations. In practice, commitments would be handled
        // differently (e.g., via hash-to-field or public inputs).

        // Test absorbing permutation
        transcript_gadget.absorb_perm_vector(&perm_vars)?;

        // Derive challenges
        let (perm_power_challenge_var, _r_var) =
            transcript_gadget.derive_perm_power_challenge_and_blinding(cs.clone())?;

        // Compute permutation power vector
        let power_vector_vars = transcript_gadget.compute_perm_power_vector(
            cs.clone(),
            &perm_vars,
            &perm_power_challenge_var,
        )?;

        // Absorb power vector
        transcript_gadget.absorb_perm_power_vector(&power_vector_vars)?;

        // Derive remaining challenges
        let _s_var = transcript_gadget.derive_blinding_factor_s()?;
        let (_y_var, _z_var) = transcript_gadget.derive_perm_challenges_y_z()?;

        // Check constraint satisfaction
        assert!(cs.is_satisfied()?);

        // Verify outputs are non-zero (basic sanity check)
        assert!(!perm_power_challenge_var.value()?.is_zero());
        assert_eq!(power_vector_vars.len(), perm.len());

        tracing::debug!(target = LOG_TARGET, "✓ Gadget Fiat-Shamir test passed");
        tracing::debug!(
            target = LOG_TARGET,
            "  Constraints: {}",
            cs.num_constraints()
        );
        tracing::debug!(
            target = LOG_TARGET,
            "  Variables: {}",
            cs.num_witness_variables()
        );

        Ok(())
    }

    #[test]
    fn test_gadget_deterministic() -> Result<(), SynthesisError> {
        // Create identical inputs
        let perm = vec![2, 1, 3];
        let perm_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

        // Run protocol twice with same inputs
        let mut first_x = None;
        for i in 0..2 {
            let cs = ConstraintSystem::<Fr>::new_ref();

            let perm_vars = perm_vals
                .iter()
                .map(|&val| FpVar::new_witness(cs.clone(), || Ok(val)))
                .collect::<Result<Vec<_>, _>>()?;

            let mut transcript = BayerGrothTranscriptGadget::<Fr>::new(cs.clone(), b"test-domain")?;

            // Absorb permutation
            transcript.absorb_perm_vector(&perm_vars)?;

            // Derive perm_power_challenge
            let (perm_power_challenge_var, _) =
                transcript.derive_perm_power_challenge_and_blinding(cs.clone())?;

            // Check constraint satisfaction
            assert!(cs.is_satisfied()?);
            assert!(!perm_power_challenge_var.value()?.is_zero());

            // Store first perm_power_challenge value for comparison
            if i == 0 {
                first_x = Some(perm_power_challenge_var.value()?);
            } else {
                // Should get identical perm_power_challenge values for identical inputs
                assert_eq!(first_x.unwrap(), perm_power_challenge_var.value()?);
            }
        }

        tracing::debug!(target = LOG_TARGET, "✓ Gadget deterministic test passed");
        Ok(())
    }

    /// Test complete Bayer-Groth protocol with Fiat-Shamir
    #[test]
    fn test_complete_protocol() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        let n = 52; // Standard deck size

        // Generate random permutation (shuffle)
        let mut perm: Vec<usize> = (1..=n).collect();
        // Fisher-Yates shuffle
        for i in (1..n).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            perm.swap(i, j);
        }

        // Create permutation vector from permutation
        let perm_vector_vals: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

        // Simulate external commitment to permutation vector (in practice, this is expensive)
        let c_perm = G1Projective::rand(&mut rng);

        // Initialize Fiat-Shamir transcript
        let mut transcript = BayerGrothTranscript::<Fr>::new(b"BayerGroth-Test");

        // Step 1: Absorb commitment to permutation vector and derive power challenge
        transcript.absorb_perm_vector_commitment(&c_perm);
        let (perm_power_challenge_val, _r_val) =
            transcript.derive_perm_power_challenge_and_blinding();

        // Step 2: Compute permutation power vector
        let perm_power_vector_vals =
            transcript.compute_perm_power_vector(&perm, perm_power_challenge_val);

        // Simulate external commitment to power vector
        let c_power = G1Projective::rand(&mut rng);

        // Step 3: Absorb commitment to power vector and derive s
        transcript.absorb_perm_power_vector_commitment(&c_power);
        let _s_val = transcript.derive_blinding_factor_s();

        // Step 4: Derive final challenges
        let (perm_mixing_challenge_y_val, perm_offset_challenge_z_val) =
            transcript.derive_perm_challenges_y_z();

        // Native computation - import from crate
        use crate::shuffling::bayer_groth_permutation::linking_rs_native as native;
        use ark_bn254::G1Affine;
        use ark_ec::AffineRepr;

        let (left_native, right_native, _) = native::compute_permutation_proof::<Fr, G1Projective>(
            &perm_vector_vals,
            &perm_power_vector_vals,
            perm_mixing_challenge_y_val,
            perm_offset_challenge_z_val,
            perm_power_challenge_val,
            G1Affine::generator(),
        );

        // Circuit computation
        let cs = ConstraintSystem::<Fr>::new_ref();

        use crate::shuffling::bayer_groth_permutation::linking_rs_gadgets::{
            alloc_vector, left_product_gadget, linear_blend_gadget, right_product_gadget,
        };

        let perm_vector = alloc_vector(cs.clone(), &perm_vector_vals, AllocationMode::Witness)?;
        let perm_power_vector =
            alloc_vector(cs.clone(), &perm_power_vector_vals, AllocationMode::Witness)?;
        let perm_power_challenge = FpVar::new_witness(cs.clone(), || Ok(perm_power_challenge_val))?;
        let perm_mixing_challenge_y =
            FpVar::new_witness(cs.clone(), || Ok(perm_mixing_challenge_y_val))?;
        let perm_offset_challenge_z =
            FpVar::new_witness(cs.clone(), || Ok(perm_offset_challenge_z_val))?;

        // For this test, we'll skip the curve point computation since it requires
        // proper curve variable setup. We'll just test the field operations.
        let d = linear_blend_gadget(
            cs.clone(),
            &perm_vector,
            &perm_power_vector,
            &perm_mixing_challenge_y,
        )?;
        let left_circuit = left_product_gadget(cs.clone(), &d, &perm_offset_challenge_z)?;
        let right_circuit = right_product_gadget(
            cs.clone(),
            &perm_mixing_challenge_y,
            &perm_power_challenge,
            &perm_offset_challenge_z,
            n,
        )?;

        // Verify results match
        assert_eq!(left_circuit.value()?, left_native);
        assert_eq!(right_circuit.value()?, right_native);
        assert_eq!(left_native, right_native);

        // Check constraint satisfaction
        assert!(cs.is_satisfied()?);

        tracing::debug!(
            target = LOG_TARGET,
            "✓ Complete Bayer-Groth protocol test passed for n={}",
            n
        );
        tracing::debug!(
            target = LOG_TARGET,
            "  Constraints: {}",
            cs.num_constraints()
        );
        tracing::debug!(
            target = LOG_TARGET,
            "  Variables: {}",
            cs.num_witness_variables()
        );

        Ok(())
    }
}
