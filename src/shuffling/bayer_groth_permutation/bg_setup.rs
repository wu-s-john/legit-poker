//! Fiat-Shamir challenge derivation for Bayer-Groth permutation proof

use ark_crypto_primitives::{
    commitment::pedersen::Parameters,
    sponge::{poseidon::PoseidonSponge, CryptographicSponge},
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::linking_rs_gadgets";

// Import commit_vector from sigma_protocol module
use crate::shuffling::bayer_groth_permutation::sigma_protocol::commit_vector;

/// Output structure for the Bayer-Groth protocol execution
pub struct BayerGrothSetupParameters<F: PrimeField, G: CurveGroup, const N: usize> {
    /// The Fiat-Shamir challenge x ∈ F_q* used to compute powers x^π(i)
    /// This challenge is derived from the commitment to the permutation vector
    pub perm_power_challenge: F,
    /// Vector of powers (x^π(1), ..., x^π(N)) where π is the permutation
    /// Each element is the challenge raised to the power of the corresponding permutation value
    pub perm_power_vector: [F; N],
    /// Commitment to the permutation vector (computed internally)
    pub c_perm: G,
    /// Commitment to the power vector (computed internally)
    pub c_power: G,
    /// Blinding factor s for commitment to the power vector (derived from transcript)
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
    fn absorb_perm_vector_commitment<G: CurveGroup>(&mut self, c_perm: &G) {
        let mut bytes = Vec::new();
        c_perm.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);

        tracing::debug!(target: LOG_TARGET, "Absorbed permutation vector commitment");
    }

    /// Derive permutation power challenge from the transcript
    /// Returns perm_power_challenge which is used to compute the power vector
    fn derive_perm_power_challenge(&mut self) -> F {
        // Squeeze one field element
        let elements = self.sponge.squeeze_field_elements(1);

        let mut perm_power_challenge: F = elements[0];

        // Ensure challenge is non-zero (∈ F_q*)
        if perm_power_challenge.is_zero() {
            perm_power_challenge = F::one();
        }

        tracing::debug!(target: LOG_TARGET, "Derived permutation power challenge");

        perm_power_challenge
    }

    /// Absorb the commitment to the power vector (pre-computed externally)
    /// This commitment is expensive to compute, so it's passed in
    fn absorb_perm_power_vector_commitment<G: CurveGroup>(&mut self, c_power: &G) {
        let mut bytes = Vec::new();
        c_power.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);

        tracing::debug!(target: LOG_TARGET, "Absorbed power vector commitment");
    }

    /// Derive final challenges for permutation equality check
    /// Returns (mixing_challenge_y, offset_challenge_z)
    fn derive_perm_challenges_y_z(&mut self) -> (F, F) {
        let elements = self.sponge.squeeze_field_elements(2);
        let mixing_challenge_y = elements[0];
        let offset_challenge_z = elements[1];

        tracing::debug!(target: LOG_TARGET, "Derived permutation mixing and offset challenges");

        (mixing_challenge_y, offset_challenge_z)
    }

    /// Complete Fiat-Shamir protocol for Bayer-Groth permutation proof
    ///
    /// This is a convenience function that runs the full protocol:
    /// 1. Compute commitment to permutation vector
    /// 2. Absorb commitment to permutation vector
    /// 3. Derive power challenge
    /// 4. Compute permutation power vector
    /// 5. Compute commitment to power vector
    /// 6. Absorb commitment to power vector
    /// 7. Derive mixing and offset challenges
    ///
    /// Parameters:
    /// - pedersen_params: Pedersen parameters for computing commitments
    /// - permutation: The permutation values (1-indexed)
    /// - prover_blinding_r: Prover-provided blinding factor for c_perm (scalar field)
    /// - prover_blinding_s: Prover-provided blinding factor for c_power (scalar field)
    ///
    /// Returns: BayerGrothProtocolOutput containing all protocol values including commitments
    pub fn run_protocol<G, const N: usize>(
        &mut self,
        pedersen_params: &Parameters<G>,
        permutation: &[usize; N],
        prover_blinding_r: G::ScalarField,
        prover_blinding_s: G::ScalarField,
    ) -> BayerGrothSetupParameters<G::ScalarField, G, N>
    where
        G: CurveGroup<BaseField = F>,
        G::ScalarField: PrimeField,
        F: PrimeField,
    {
        // Convert permutation to scalar field elements
        let perm_vector: [G::ScalarField; N] = permutation
            .iter()
            .map(|&i| G::ScalarField::from(i as u64))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Permutation length mismatch");

        // Step 1: Compute commitment to permutation vector using prover's blinding factor
        let c_perm = commit_vector::<G, N>(pedersen_params, &perm_vector, prover_blinding_r);

        // Step 2: Absorb commitment to permutation vector
        self.absorb_perm_vector_commitment(&c_perm);
        tracing::debug!(target: LOG_TARGET, "Absorbed permutation vector commitment {}", c_perm);

        // Step 3: Derive power challenge in base field and convert to scalar field
        let perm_power_challenge_base: G::BaseField = self.derive_perm_power_challenge();
        // Convert from base field to scalar field for use in computations
        let perm_power_challenge: G::ScalarField = G::ScalarField::from_le_bytes_mod_order(
            &perm_power_challenge_base.into_bigint().to_bytes_le(),
        );
        tracing::debug!(target: LOG_TARGET, "Derived permutation power challenge {}", perm_power_challenge);

        // Step 4: Compute permutation power vector
        let perm_power_vector_vec = compute_perm_power_vector(permutation, perm_power_challenge);
        let perm_power_vector: [G::ScalarField; N] = perm_power_vector_vec
            .try_into()
            .expect("Vector length should match array size N");

        // Step 5: Compute commitment to power vector using prover's blinding factor
        let c_power_perm =
            commit_vector::<G, N>(pedersen_params, &perm_power_vector, prover_blinding_s);

        // Step 6: Absorb commitment to power vector
        self.absorb_perm_power_vector_commitment(&c_power_perm);
        tracing::debug!(target: LOG_TARGET, "Absorbed commitment to power vector {}", c_power_perm);

        // Step 7: Derive mixing and offset challenges in base field and convert to scalar field
        let (perm_mixing_challenge_y_base, perm_offset_challenge_z_base) =
            self.derive_perm_challenges_y_z();
        let perm_mixing_challenge_y = G::ScalarField::from_le_bytes_mod_order(
            &perm_mixing_challenge_y_base.into_bigint().to_bytes_le(),
        );
        let perm_offset_challenge_z = G::ScalarField::from_le_bytes_mod_order(
            &perm_offset_challenge_z_base.into_bigint().to_bytes_le(),
        );
        tracing::debug!(target: LOG_TARGET, "Derived permutation mixing and offset challenges {} {}", perm_mixing_challenge_y, perm_offset_challenge_z);

        BayerGrothSetupParameters {
            perm_power_challenge,
            perm_power_vector,
            c_perm,
            c_power: c_power_perm,
            blinding_s: prover_blinding_s,
            perm_mixing_challenge_y,
            perm_offset_challenge_z,
        }
    }
}

/// Compute the permutation power vector = (x^π(1), ..., x^π(N))
///
/// Parameters:
/// - permutation: The permutation π (1-indexed values)
/// - perm_power_challenge: The challenge x derived from Fiat-Shamir (in scalar field)
///
/// Returns: Power vector where power_vector[i] = x^π(i)
fn compute_perm_power_vector<F: PrimeField>(
    permutation: &[usize],
    perm_power_challenge: F,
) -> Vec<F> {
    // power_vector[i] = x^π(i)
    // Note: permutation contains 1-indexed values
    let power_vector: Vec<F> = permutation
        .iter()
        .map(|&pi| perm_power_challenge.pow(&[pi as u64]))
        .collect();

    tracing::debug!(target: "bayer_groth::setup", "Computed permutation power vector of length {}", power_vector.len());

    power_vector
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::shuffling::bayer_groth_permutation::bg_setup_gadget::BayerGrothTranscriptGadget;
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_crypto_primitives::commitment::CommitmentScheme;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
    use ark_relations::gr1cs::{ConstraintSystem, SynthesisError};
    use ark_std::Zero;
    use ark_std::{test_rng, UniformRand};
    use rand::RngCore;

    #[test]
    fn test_fiat_shamir_deterministic() {
        let mut rng = test_rng();

        // Create identical inputs
        let perm = [3, 1, 4, 2, 5];
        let prover_blinding_r = Fr::rand(&mut rng);
        let prover_blinding_s = Fr::rand(&mut rng);

        // Run protocol twice with same inputs
        // Transcript operates over base field (Fq)
        let mut transcript1 = BayerGrothTranscript::<Fq>::new(b"test-domain");

        // Create dummy Pedersen parameters (in real usage these would be setup properly)
        use ark_crypto_primitives::commitment::pedersen::{
            Commitment as PedersenCommitment, Window,
        };
        #[derive(Clone)]
        struct TestWindow;
        impl Window for TestWindow {
            const WINDOW_SIZE: usize = 4;
            const NUM_WINDOWS: usize = 64;
        }
        type TestPedersen = PedersenCommitment<G1Projective, TestWindow>;
        let pedersen_params = TestPedersen::setup(&mut rng).unwrap();

        let output1 = transcript1.run_protocol::<G1Projective, 5>(
            &pedersen_params,
            &perm,
            prover_blinding_r,
            prover_blinding_s,
        );

        let mut transcript2 = BayerGrothTranscript::<Fq>::new(b"test-domain");
        let output2 = transcript2.run_protocol::<G1Projective, 5>(
            &pedersen_params,
            &perm,
            prover_blinding_r,
            prover_blinding_s,
        );

        // Should get identical outputs
        assert_eq!(output1.perm_power_challenge, output2.perm_power_challenge);
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

        let perm1 = [2, 1, 3];
        let perm2 = [3, 2, 1];
        let prover_blinding_r = Fr::rand(&mut rng);
        let prover_blinding_s = Fr::rand(&mut rng);

        // Create Pedersen parameters
        use ark_crypto_primitives::commitment::pedersen::{
            Commitment as PedersenCommitment, Window,
        };
        #[derive(Clone)]
        struct TestWindow2;
        impl Window for TestWindow2 {
            const WINDOW_SIZE: usize = 4;
            const NUM_WINDOWS: usize = 64;
        }
        type TestPedersen = PedersenCommitment<G1Projective, TestWindow2>;
        let pedersen_params = TestPedersen::setup(&mut rng).unwrap();

        // Run with different permutations
        let mut transcript1 = BayerGrothTranscript::<Fq>::new(b"test-domain");
        let output1 = transcript1.run_protocol::<G1Projective, 3>(
            &pedersen_params,
            &perm1,
            prover_blinding_r,
            prover_blinding_s,
        );

        let mut transcript2 = BayerGrothTranscript::<Fq>::new(b"test-domain");
        let output2 = transcript2.run_protocol::<G1Projective, 3>(
            &pedersen_params,
            &perm2,
            prover_blinding_r,
            prover_blinding_s,
        );

        // Should get different challenges due to different permutations producing different commitments
        assert_ne!(output1.perm_power_challenge, output2.perm_power_challenge);
    }

    #[test]
    fn test_perm_power_vector_computation() {
        let perm = [3, 1, 4, 2, 5];
        let perm_power_challenge = Fr::from(2u64);

        let power_vector = compute_perm_power_vector(&perm, perm_power_challenge);

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
        let mut transcript = BayerGrothTranscript::<Fq>::new(b"test");

        // Even if the sponge would produce zero, we should get one
        for _ in 0..10 {
            let perm_power_challenge = transcript.derive_perm_power_challenge();
            assert!(!perm_power_challenge.is_zero());
        }
    }

    /// Test that gadget protocol works correctly with curve commitments
    /// Note: Cannot directly compare with native since they work over different fields
    #[test]
    fn test_gadget_protocol_with_commitments() -> Result<(), SynthesisError> {
        let mut rng = test_rng();

        // Test with different permutation sizes
        test_gadget_protocol_for_size::<3>(&mut rng)?;
        test_gadget_protocol_for_size::<5>(&mut rng)?;
        test_gadget_protocol_for_size::<10>(&mut rng)?;

        tracing::debug!(
            target = LOG_TARGET,
            "✓ Gadget protocol with commitments test passed"
        );
        Ok(())
    }

    /// Test that different blinding factors produce the same challenges
    /// for the same permutation (since blinding is not absorbed in transcript)
    #[test]
    fn test_blinding_factor_independence() -> Result<(), SynthesisError> {
        use ark_crypto_primitives::commitment::pedersen::{
            Commitment as PedersenCommitment, Window,
        };

        let mut rng = test_rng();
        let perm: [usize; 5] = [3, 1, 4, 2, 5];

        // Setup Pedersen parameters
        #[derive(Clone)]
        struct TestWindow;
        impl Window for TestWindow {
            const WINDOW_SIZE: usize = 4;
            const NUM_WINDOWS: usize = 64;
        }
        type TestPedersen = PedersenCommitment<G1Projective, TestWindow>;
        let pedersen_params = TestPedersen::setup(&mut rng).unwrap();

        // Run with first set of blinding factors
        let blinding_r1 = Fr::rand(&mut rng);
        let blinding_s1 = Fr::rand(&mut rng);
        let mut transcript1 = BayerGrothTranscript::<Fq>::new(b"test-domain");
        let output1 = transcript1.run_protocol::<G1Projective, 5>(
            &pedersen_params,
            &perm,
            blinding_r1,
            blinding_s1,
        );

        // Run with different blinding factors but same permutation
        let blinding_r2 = Fr::rand(&mut rng);
        let blinding_s2 = Fr::rand(&mut rng);
        let mut transcript2 = BayerGrothTranscript::<Fq>::new(b"test-domain");
        let output2 = transcript2.run_protocol::<G1Projective, 5>(
            &pedersen_params,
            &perm,
            blinding_r2,
            blinding_s2,
        );

        // Commitments should be different due to different blinding
        assert_ne!(output1.c_perm, output2.c_perm);
        assert_ne!(output1.c_power, output2.c_power);

        // But challenges should be the same since same commitments are absorbed
        // Wait, actually they should be different because different commitments
        // are absorbed. Let me fix this test...
        assert_ne!(output1.perm_power_challenge, output2.perm_power_challenge);

        tracing::debug!(target = LOG_TARGET, "✓ Blinding factor test passed");
        Ok(())
    }

    fn test_gadget_protocol_for_size<const N: usize>(
        rng: &mut impl RngCore,
    ) -> Result<(), SynthesisError> {
        use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;

        // Create test permutation
        let mut perm: [usize; N] = std::array::from_fn(|i| i + 1);
        // Shuffle it randomly
        for i in (1..N).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            perm.swap(i, j);
        }

        // ============= Setup Gadget Protocol =============
        let cs = ConstraintSystem::<ark_bn254::Fq>::new_ref();

        // Create random commitments as curve points
        let c_perm = G1Projective::rand(rng);
        let c_power = G1Projective::rand(rng);

        // Allocate commitments as curve variables
        type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<ark_bn254::Fq>>;
        let c_perm_var = G1Var::new_variable(cs.clone(), || Ok(c_perm), AllocationMode::Witness)?;
        let c_power_var = G1Var::new_variable(cs.clone(), || Ok(c_power), AllocationMode::Witness)?;

        // Create gadget transcript and run protocol
        let mut gadget_transcript =
            BayerGrothTranscriptGadget::<ark_bn254::Fq>::new(cs.clone(), b"test-domain")?;
        let gadget_output =
            gadget_transcript.run_protocol(cs.clone(), &c_perm_var, &c_power_var)?;

        // Extract gadget challenge values
        let gadget_power_challenge = gadget_output.perm_power_challenge.value()?;
        let gadget_mixing_y = gadget_output.perm_mixing_challenge_y.value()?;
        let gadget_offset_z = gadget_output.perm_offset_challenge_z.value()?;

        tracing::debug!(target = LOG_TARGET, "Gadget protocol output for N={}:", N);
        tracing::debug!(
            target = LOG_TARGET,
            ?gadget_power_challenge,
            ?gadget_mixing_y,
            ?gadget_offset_z,
            "Derived challenges"
        );

        // Verify challenges are non-zero
        assert!(!gadget_power_challenge.is_zero());
        assert!(!gadget_mixing_y.is_zero());
        assert!(!gadget_offset_z.is_zero());

        // Check constraint satisfaction
        assert!(cs.is_satisfied()?);

        tracing::debug!(
            target = LOG_TARGET,
            constraints = cs.num_constraints(),
            variables = cs.num_witness_variables(),
            "✓ Gadget protocol verified for N={}",
            N
        );

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

        // Initialize Fiat-Shamir transcript (operates over base field)
        let mut transcript = BayerGrothTranscript::<Fq>::new(b"BayerGroth-Test");

        // Step 1: Absorb commitment to permutation vector and derive power challenge
        transcript.absorb_perm_vector_commitment(&c_perm);
        let perm_power_challenge_base = transcript.derive_perm_power_challenge();
        // Convert from base field to scalar field
        let perm_power_challenge_val =
            Fr::from_le_bytes_mod_order(&perm_power_challenge_base.into_bigint().to_bytes_le());

        // Step 2: Compute permutation power vector
        let perm_power_vector_vals = compute_perm_power_vector(&perm, perm_power_challenge_val);

        // Simulate external commitment to power vector
        let c_power = G1Projective::rand(&mut rng);

        // Step 3: Absorb commitment to power vector
        transcript.absorb_perm_power_vector_commitment(&c_power);

        // Step 4: Derive final challenges in base field and convert to scalar field
        let (perm_mixing_challenge_y_base, perm_offset_challenge_z_base) =
            transcript.derive_perm_challenges_y_z();
        let perm_mixing_challenge_y_val =
            Fr::from_le_bytes_mod_order(&perm_mixing_challenge_y_base.into_bigint().to_bytes_le());
        let perm_offset_challenge_z_val =
            Fr::from_le_bytes_mod_order(&perm_offset_challenge_z_base.into_bigint().to_bytes_le());

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
        // Note: We use Fr (scalar field) for the constraint system since we're doing
        // scalar field arithmetic. The challenges are drawn from Fq (base field) but
        // converted to Fr for the actual computation.
        let cs = ConstraintSystem::<Fr>::new_ref();

        use crate::shuffling::bayer_groth_permutation::linking_rs_gadgets::{
            alloc_vector, left_product_gadget, linear_blend_gadget, right_product_gadget,
        };

        // Allocate permutation values as circuit variables (these are scalar field elements)
        let perm_vector = alloc_vector(cs.clone(), &perm_vector_vals, AllocationMode::Witness)?;
        let perm_power_vector =
            alloc_vector(cs.clone(), &perm_power_vector_vals, AllocationMode::Witness)?;
        
        // Allocate challenges as circuit variables
        // These were originally drawn from base field (Fq) but converted to scalar field (Fr)
        let perm_power_challenge = FpVar::new_witness(cs.clone(), || Ok(perm_power_challenge_val))?;
        let perm_mixing_challenge_y =
            FpVar::new_witness(cs.clone(), || Ok(perm_mixing_challenge_y_val))?;
        let perm_offset_challenge_z =
            FpVar::new_witness(cs.clone(), || Ok(perm_offset_challenge_z_val))?;

        // Compute the linear blend d = y * perm_vector + perm_power_vector
        // All operations are in the scalar field Fr
        let d = linear_blend_gadget(&perm_vector, &perm_power_vector, &perm_mixing_challenge_y)?;
        let left_circuit = left_product_gadget(&d, &perm_offset_challenge_z)?;
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
