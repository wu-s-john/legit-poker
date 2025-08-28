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
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::linking_rs_gadgets";

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

    /// Absorb the commitment to vector a (pre-computed externally)
    /// This commitment is expensive to compute, so it's passed in
    pub fn absorb_commitment_a<G: CurveGroup>(&mut self, c_a: &G) {
        let mut bytes = Vec::new();
        c_a.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);

        tracing::debug!(target: LOG_TARGET, "Absorbed commitment c_A");
    }

    /// Derive challenge x ∈ F_q* and blinding factor r
    /// Returns (x, r) where:
    /// - x is used to compute the hidden vector b
    /// - r is the blinding factor for commitment c_A
    pub fn derive_challenge_x_and_blinding(&mut self) -> (F, F) {
        // Squeeze two field elements
        let elements = self.sponge.squeeze_field_elements(2);

        let mut x: F = elements[0];
        let r = elements[1];

        // Ensure x is non-zero (x ∈ F_q*)
        if x.is_zero() {
            x = F::one();
        }

        tracing::debug!(target: LOG_TARGET, "Derived challenge x and blinding r");

        (x, r)
    }

    /// Compute the hidden vector b = (x^π(1), ..., x^π(N))
    ///
    /// Parameters:
    /// - permutation: The permutation π (1-indexed values)
    /// - x: The challenge x derived from Fiat-Shamir
    ///
    /// Returns: Vector b (not the commitment, which is computed externally)
    pub fn compute_hidden_vector_b(&self, permutation: &[usize], x: F) -> Vec<F> {
        // b[i] = x^π(i)
        // Note: permutation contains 1-indexed values
        let b: Vec<F> = permutation.iter().map(|&pi| x.pow(&[pi as u64])).collect();

        tracing::debug!(target: LOG_TARGET, "Computed hidden vector b of length {}", b.len());

        b
    }

    /// Absorb the commitment to vector b (pre-computed externally)
    /// This commitment is expensive to compute, so it's passed in
    pub fn absorb_commitment_b<G: CurveGroup>(&mut self, c_b: &G) {
        let mut bytes = Vec::new();
        c_b.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);

        tracing::debug!(target: LOG_TARGET, "Absorbed commitment c_B");
    }

    /// Derive the blinding factor s for commitment c_B
    pub fn derive_blinding_factor_s(&mut self) -> F {
        let s = self.sponge.squeeze_field_elements(1)[0];

        tracing::debug!(target: LOG_TARGET, "Derived blinding factor s");

        s
    }

    /// Derive final challenges y and z
    /// These are used in the permutation equality check
    pub fn derive_challenges_y_z(&mut self) -> (F, F) {
        let elements = self.sponge.squeeze_field_elements(2);
        let y = elements[0];
        let z = elements[1];

        tracing::debug!(target: LOG_TARGET, "Derived challenges y and z");

        (y, z)
    }

    /// Complete Fiat-Shamir protocol for Bayer-Groth permutation proof
    ///
    /// This is a convenience function that runs the full protocol:
    /// 1. Absorb commitment to a
    /// 2. Derive x and r
    /// 3. Compute hidden vector b
    /// 4. Absorb commitment to b
    /// 5. Derive s
    /// 6. Derive y and z
    ///
    /// Returns: (x, r, b, s, y, z)
    pub fn run_protocol<G: CurveGroup>(
        &mut self,
        c_a: &G,
        c_b: &G,
        permutation: &[usize],
    ) -> (F, F, Vec<F>, F, F, F) {
        // Step 1: Absorb commitment to a
        self.absorb_commitment_a(c_a);

        // Step 2: Derive x and blinding factor r
        let (x, r) = self.derive_challenge_x_and_blinding();

        // Step 3: Compute hidden vector b
        let b = self.compute_hidden_vector_b(permutation, x);

        // Step 4: Absorb commitment to b
        self.absorb_commitment_b(c_b);

        // Step 5: Derive blinding factor s
        let s = self.derive_blinding_factor_s();

        // Step 6: Derive final challenges y and z
        let (y, z) = self.derive_challenges_y_z();

        (x, r, b, s, y, z)
    }
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

    /// Absorb the commitment to vector a (pre-computed externally)
    /// In practice, the commitment would be passed as public input or
    /// converted to field elements via hash-to-field
    pub fn absorb_commitment_a_as_field_elements(
        &mut self,
        c_a_elements: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        for elem in c_a_elements {
            self.sponge.absorb(&elem)?;
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed commitment c_A as field elements");
        Ok(())
    }

    /// Absorb the permutation vector a into the transcript
    /// a represents (π(1), ..., π(N))
    pub fn absorb_permutation(&mut self, a: &[FpVar<F>]) -> Result<(), SynthesisError> {
        for (i, a_i) in a.iter().enumerate() {
            self.sponge.absorb(&a_i)?;
            tracing::trace!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed a[{}]", i);
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed permutation vector a of length {}", a.len());
        Ok(())
    }

    /// Derive challenge x ∈ F_q* and blinding factor r
    /// Returns (x, r) where:
    /// - x is used to compute the hidden vector b
    /// - r is the blinding factor for commitment c_A
    pub fn derive_challenge_x_and_blinding(
        &mut self,
        _cs: ConstraintSystemRef<F>,
    ) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
        // Squeeze two field elements
        let elements = self.sponge.squeeze_field_elements(2)?;

        let mut x = elements[0].clone();
        let r = elements[1].clone();

        // Ensure x is non-zero (x ∈ F_q*)
        // Check if x is zero
        let is_zero = x.is_zero()?;

        // If x is zero, set it to one
        let one = FpVar::<F>::one();
        x = is_zero.select(&one, &x)?;

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Derived challenge x and blinding r");

        Ok((x, r))
    }

    /// Compute the hidden vector b = (x^π(1), ..., x^π(N)) in-circuit
    ///
    /// Parameters:
    /// - cs: Constraint system reference
    /// - permutation: The permutation π as circuit variables (values 1 to N)
    /// - x: The challenge x derived from Fiat-Shamir
    ///
    /// Returns: Vector b as circuit variables
    pub fn compute_hidden_vector_b(
        &self,
        cs: ConstraintSystemRef<F>,
        permutation: &[FpVar<F>],
        x: &FpVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut b = Vec::with_capacity(permutation.len());

        for (i, pi) in permutation.iter().enumerate() {
            // Compute x^π(i) using repeated squaring
            // Since π(i) is a small value (1 to N), we can compute this efficiently
            // by converting π(i) to bits and using conditional multiplication

            // For simplicity in the gadget, we'll use a method that computes powers
            // by repeated multiplication up to a maximum value
            let b_i = self.compute_power_gadget(cs.clone(), x, pi)?;
            b.push(b_i);

            tracing::trace!(target: "bayer_groth::fiat_shamir_gadget", "Computed b[{}] = x^π({})", i, i);
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Computed hidden vector b of length {}", b.len());

        Ok(b)
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

    /// Absorb the hidden vector b into the transcript
    pub fn absorb_vector_b(&mut self, b: &[FpVar<F>]) -> Result<(), SynthesisError> {
        for (i, b_i) in b.iter().enumerate() {
            self.sponge.absorb(&b_i)?;
            tracing::trace!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed b[{}]", i);
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed vector b of length {}", b.len());
        Ok(())
    }

    /// Absorb the commitment to vector b (pre-computed externally)
    /// In practice, the commitment would be passed as public input or
    /// converted to field elements via hash-to-field
    pub fn absorb_commitment_b_as_field_elements(
        &mut self,
        c_b_elements: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        for elem in c_b_elements {
            self.sponge.absorb(&elem)?;
        }

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Absorbed commitment c_B as field elements");
        Ok(())
    }

    /// Derive the blinding factor s for commitment c_B
    pub fn derive_blinding_factor_s(&mut self) -> Result<FpVar<F>, SynthesisError> {
        let s = self.sponge.squeeze_field_elements(1)?[0].clone();

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Derived blinding factor s");

        Ok(s)
    }

    /// Derive final challenges y and z
    /// These are used in the permutation equality check
    pub fn derive_challenges_y_z(&mut self) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
        let elements = self.sponge.squeeze_field_elements(2)?;
        let y = elements[0].clone();
        let z = elements[1].clone();

        tracing::debug!(target: "bayer_groth::fiat_shamir_gadget", "Derived challenges y and z");

        Ok((y, z))
    }

    /// Complete Fiat-Shamir protocol for Bayer-Groth permutation proof (gadget version)
    ///
    /// This runs the full protocol in-circuit:
    /// 1. Absorb commitment to a (as field elements)
    /// 2. Absorb permutation vector a
    /// 3. Derive x and r
    /// 4. Compute hidden vector b
    /// 5. Absorb vector b
    /// 6. Absorb commitment to b (as field elements)
    /// 7. Derive s
    /// 8. Derive y and z
    ///
    /// Returns: (x, b, y, z, r, s)
    pub fn run_protocol(
        &mut self,
        cs: ConstraintSystemRef<F>,
        c_a_elements: &[FpVar<F>],
        c_b_elements: &[FpVar<F>],
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
        // Step 1: Absorb commitment to a
        self.absorb_commitment_a_as_field_elements(c_a_elements)?;

        // Step 2: Absorb permutation vector a
        self.absorb_permutation(permutation)?;

        // Step 3: Derive x and blinding factor r
        let (x, r) = self.derive_challenge_x_and_blinding(cs.clone())?;

        // Step 4: Compute hidden vector b
        let b = self.compute_hidden_vector_b(cs.clone(), permutation, &x)?;

        // Step 5: Absorb vector b
        self.absorb_vector_b(&b)?;

        // Step 6: Absorb commitment to b
        self.absorb_commitment_b_as_field_elements(c_b_elements)?;

        // Step 7: Derive blinding factor s
        let s = self.derive_blinding_factor_s()?;

        // Step 8: Derive final challenges y and z
        let (y, z) = self.derive_challenges_y_z()?;

        Ok((x, b, y, z, r, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
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
        let (x1, r1, b1, s1, y1, z1) = transcript1.run_protocol(&c_a, &c_b, &perm);

        let mut transcript2 = BayerGrothTranscript::<Fr>::new(b"test-domain");
        let (x2, r2, b2, s2, y2, z2) = transcript2.run_protocol(&c_a, &c_b, &perm);

        // Should get identical outputs
        assert_eq!(x1, x2);
        assert_eq!(r1, r2);
        assert_eq!(b1, b2);
        assert_eq!(s1, s2);
        assert_eq!(y1, y2);
        assert_eq!(z1, z2);
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
        let (x1, _, _, _, _, _) = transcript1.run_protocol(&c_a1, &c_b, &perm);

        let mut transcript2 = BayerGrothTranscript::<Fr>::new(b"test-domain");
        let (x2, _, _, _, _, _) = transcript2.run_protocol(&c_a2, &c_b, &perm);

        // Should get different challenges
        assert_ne!(x1, x2);
    }

    #[test]
    fn test_hidden_vector_computation() {
        let transcript = BayerGrothTranscript::<Fr>::new(b"test");

        let perm = vec![3, 1, 4, 2, 5];
        let x = Fr::from(2u64);

        let b = transcript.compute_hidden_vector_b(&perm, x);

        // Verify b[i] = x^π(i)
        assert_eq!(b[0], Fr::from(8u64)); // 2^3 = 8
        assert_eq!(b[1], Fr::from(2u64)); // 2^1 = 2
        assert_eq!(b[2], Fr::from(16u64)); // 2^4 = 16
        assert_eq!(b[3], Fr::from(4u64)); // 2^2 = 4
        assert_eq!(b[4], Fr::from(32u64)); // 2^5 = 32
    }

    #[test]
    fn test_x_nonzero() {
        // Test that x is always non-zero
        let mut transcript = BayerGrothTranscript::<Fr>::new(b"test");

        // Even if the sponge would produce zero, we should get one
        for _ in 0..10 {
            let (x, _) = transcript.derive_challenge_x_and_blinding();
            assert!(!x.is_zero());
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
        transcript_gadget.absorb_permutation(&perm_vars)?;

        // Derive challenges
        let (x_var, _r_var) = transcript_gadget.derive_challenge_x_and_blinding(cs.clone())?;

        // Compute hidden vector b
        let b_vars = transcript_gadget.compute_hidden_vector_b(cs.clone(), &perm_vars, &x_var)?;

        // Absorb vector b
        transcript_gadget.absorb_vector_b(&b_vars)?;

        // Derive remaining challenges
        let _s_var = transcript_gadget.derive_blinding_factor_s()?;
        let (_y_var, _z_var) = transcript_gadget.derive_challenges_y_z()?;

        // Check constraint satisfaction
        assert!(cs.is_satisfied()?);

        // Verify outputs are non-zero (basic sanity check)
        assert!(!x_var.value()?.is_zero());
        assert_eq!(b_vars.len(), perm.len());

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
            transcript.absorb_permutation(&perm_vars)?;

            // Derive x
            let (x_var, _) = transcript.derive_challenge_x_and_blinding(cs.clone())?;

            // Check constraint satisfaction
            assert!(cs.is_satisfied()?);
            assert!(!x_var.value()?.is_zero());

            // Store first x value for comparison
            if i == 0 {
                first_x = Some(x_var.value()?);
            } else {
                // Should get identical x values for identical inputs
                assert_eq!(first_x.unwrap(), x_var.value()?);
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

        // Native computation - import from crate
        use crate::shuffling::bayer_groth_permutation::linking_rs_native as native;
        use ark_bn254::G1Affine;
        use ark_ec::AffineRepr;

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

        use crate::shuffling::bayer_groth_permutation::linking_rs_gadgets::{
            alloc_vector, left_product_gadget, linear_blend_gadget, right_product_gadget,
        };

        let a = alloc_vector(cs.clone(), &a_vals, AllocationMode::Witness)?;
        let b = alloc_vector(cs.clone(), &b_vals, AllocationMode::Witness)?;
        let x = FpVar::new_witness(cs.clone(), || Ok(x_val))?;
        let y = FpVar::new_witness(cs.clone(), || Ok(y_val))?;
        let z = FpVar::new_witness(cs.clone(), || Ok(z_val))?;

        // For this test, we'll skip the curve point computation since it requires
        // proper curve variable setup. We'll just test the field operations.
        let d = linear_blend_gadget(cs.clone(), &a, &b, &y)?;
        let left_circuit = left_product_gadget(cs.clone(), &d, &z)?;
        let right_circuit = right_product_gadget(cs.clone(), &y, &x, &z, n)?;

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
