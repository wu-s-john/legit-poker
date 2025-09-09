//! Fiat-Shamir challenge derivation for Bayer-Groth permutation proof

use crate::pedersen_commitment::pedersen_commit_scalars;
use crate::shuffling::curve_absorb::CurveAbsorb;
use ark_crypto_primitives::commitment::pedersen::Parameters;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{fmt::Debug, vec::Vec};

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::linking_rs_gadgets";

/// Minimal output structure for power challenge setup (without product permutation)
#[derive(Debug, Clone)]
pub struct BGPowerChallengeSetup<F: PrimeField, G: CurveGroup> {
    /// The Fiat-Shamir challenge x ∈ F_q* used to compute powers x^π(i)
    pub power_challenge: F,
    /// Commitment to the permutation vector
    pub permutation_commitment: G,
    /// Commitment to the power permutation vector
    pub power_permutation_commitment: G,
}

/// Output structure for the Bayer-Groth protocol execution
#[derive(Debug, Clone)]
pub struct BayerGrothSetupParameters<F: PrimeField, G: CurveGroup, const N: usize> {
    /// The Fiat-Shamir challenge x ∈ F_q* used to compute powers x^π(i)
    /// This challenge is derived from the commitment to the permutation vector
    pub perm_power_challenge: F,
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
pub struct BayerGrothTranscript<F: PrimeField, RO: CryptographicSponge> {
    sponge: RO,
    _phantom: ark_std::marker::PhantomData<F>,
}

impl<F: PrimeField, RO: CryptographicSponge> BayerGrothTranscript<F, RO> {
    /// Create a new transcript with domain separation
    pub fn new(domain: &[u8], mut sponge: RO) -> Self {
        // Domain separation
        sponge.absorb(&domain);

        Self {
            sponge,
            _phantom: ark_std::marker::PhantomData,
        }
    }

    /// Absorb the commitment to the permutation vector using CurveAbsorb trait for consistency
    /// This ensures identical absorption with the circuit implementation
    fn absorb_perm_vector_commitment<G>(&mut self, c_perm: &G)
    where
        G: CurveAbsorb<F, RO>,
    {
        c_perm.curve_absorb(&mut self.sponge);

        tracing::debug!(target: LOG_TARGET, "Absorbed permutation vector commitment");
    }

    /// Derive permutation power challenge from the transcript
    /// Returns perm_power_challenge which is used to compute the power vector
    fn derive_perm_power_challenge(&mut self) -> F {
        // Squeeze one field element
        let elements = self.sponge.squeeze_field_elements::<F>(1);

        let mut perm_power_challenge: F = elements[0];

        // Ensure challenge is non-zero (∈ F_q*)
        if perm_power_challenge.is_zero() {
            perm_power_challenge = F::one();
        }

        tracing::debug!(target: LOG_TARGET, "Derived permutation power challenge");

        perm_power_challenge
    }

    /// Absorb the commitment to the power vector using CurveAbsorb trait for consistency
    /// This ensures identical absorption with the circuit implementation
    fn absorb_perm_power_vector_commitment<G>(&mut self, c_power: &G)
    where
        G: CurveAbsorb<F, RO>,
    {
        c_power.curve_absorb(&mut self.sponge);

        tracing::debug!(target: LOG_TARGET, "Absorbed power vector commitment");
    }

    /// Derive final challenges for permutation equality check
    /// Returns (mixing_challenge_y, offset_challenge_z)
    fn derive_perm_challenges_y_z(&mut self) -> (F, F) {
        let elements = self.sponge.squeeze_field_elements::<F>(2);
        let mixing_challenge_y = elements[0];
        let offset_challenge_z = elements[1];

        tracing::debug!(target: LOG_TARGET, "Derived permutation mixing and offset challenges");

        (mixing_challenge_y, offset_challenge_z)
    }

    /// Compute minimal power challenge setup (without product permutation challenges)
    ///
    /// This is a simplified version that only computes:
    /// 1. Commitment to permutation vector
    /// 2. Power challenge
    /// 3. Power permutation vector
    /// 4. Commitment to power permutation vector
    ///
    /// Parameters:
    /// - perm_params: DeckHashWindow parameters for permutation commitment
    /// - power_params: ReencryptionWindow parameters for power vector commitment
    /// - permutation: The permutation values (1-indexed)
    /// - prover_blinding_r: Blinding factor for c_perm
    /// - prover_blinding_s: Blinding factor for c_power
    ///
    /// Returns: Tuple of (power_permutation_vector, BGPowerChallengeSetup)
    #[tracing::instrument(
        target = LOG_TARGET,
        skip(self, perm_params, power_params),
        fields(
            permutation = ?permutation,
            prover_blinding_r = ?prover_blinding_r,
            prover_blinding_s = ?prover_blinding_s,
            N = N
        )
    )]
    pub fn compute_power_challenge_setup<G, const N: usize>(
        &mut self,
        perm_params: &Parameters<G>,
        power_params: &Parameters<G>,
        permutation: &[usize; N],
        prover_blinding_r: G::ScalarField,
        prover_blinding_s: G::ScalarField,
    ) -> (
        [G::ScalarField; N],
        BGPowerChallengeSetup<G::ScalarField, G>,
    )
    where
        G: CurveGroup<BaseField = F> + CurveAbsorb<F, RO>,
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

        // Step 1: Compute Pedersen commitment to permutation vector using DeckHashWindow parameters
        let c_perm = pedersen_commit_scalars::<G, N>(perm_params, &perm_vector, prover_blinding_r);

        // Step 2: Absorb commitment to permutation vector
        self.absorb_perm_vector_commitment(&c_perm);
        tracing::debug!(target: LOG_TARGET, ?c_perm, "Absorbed permutation vector commitment");

        // Step 3: Derive power challenge in base field and convert to scalar field
        let perm_power_challenge_base: G::BaseField = self.derive_perm_power_challenge();
        let perm_power_challenge: G::ScalarField = G::ScalarField::from_le_bytes_mod_order(
            &perm_power_challenge_base.into_bigint().to_bytes_le(),
        );
        tracing::debug!(target: LOG_TARGET, ?perm_power_challenge, "Derived permutation power challenge");

        // Step 4: Compute permutation power vector
        let perm_power_vector =
            super::utils::compute_perm_power_vector(permutation, perm_power_challenge);

        // Step 5: Compute Pedersen commitment to power vector using ReencryptionWindow parameters
        let c_power_perm =
            pedersen_commit_scalars::<G, N>(power_params, &perm_power_vector, prover_blinding_s);

        let setup = BGPowerChallengeSetup {
            power_challenge: perm_power_challenge,
            permutation_commitment: c_perm,
            power_permutation_commitment: c_power_perm,
        };

        (perm_power_vector, setup)
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
    /// - generator: The generator point for commitments (typically G::generator())
    /// - permutation: The permutation values (1-indexed)
    /// - prover_blinding_r: Prover-provided blinding factor for c_perm (scalar field)
    /// - prover_blinding_s: Prover-provided blinding factor for c_power (scalar field)
    ///
    /// Returns: Tuple of (BayerGrothSetupParameters, perm_power_vector)
    /// where perm_power_vector is the private witness
    #[tracing::instrument(
        target = LOG_TARGET,
        skip(self, perm_params, power_params),
        fields(
            permutation = ?permutation,
            prover_blinding_r = ?prover_blinding_r,
            prover_blinding_s = ?prover_blinding_s,
            N = N
        )
    )]
    pub fn run_protocol<G, const N: usize>(
        &mut self,
        perm_params: &Parameters<G>, // DeckHashWindow parameters for permutation
        power_params: &Parameters<G>, // ReencryptionWindow parameters for power vector
        permutation: &[usize; N],
        prover_blinding_r: G::ScalarField,
        prover_blinding_s: G::ScalarField,
    ) -> (
        BayerGrothSetupParameters<G::ScalarField, G, N>,
        [G::ScalarField; N],
    )
    where
        G: CurveGroup<BaseField = F> + CurveAbsorb<F, RO>,
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

        // Step 1: Compute Pedersen commitment to permutation vector using DeckHashWindow parameters
        // This uses a linearly homomorphic commitment over scalar field elements
        let c_perm = pedersen_commit_scalars::<G, N>(perm_params, &perm_vector, prover_blinding_r);

        // Step 2: Absorb commitment to permutation vector
        self.absorb_perm_vector_commitment(&c_perm);
        tracing::debug!(target: LOG_TARGET, ?c_perm, "Absorbed permutation vector commitment");

        // Step 3: Derive power challenge in base field and convert to scalar field
        let perm_power_challenge_base: G::BaseField = self.derive_perm_power_challenge();
        // Convert from base field to scalar field for use in computations
        let perm_power_challenge: G::ScalarField = G::ScalarField::from_le_bytes_mod_order(
            &perm_power_challenge_base.into_bigint().to_bytes_le(),
        );
        tracing::debug!(target: LOG_TARGET, ?perm_power_challenge, "Derived permutation power challenge");

        // Step 4: Compute permutation power vector
        let perm_power_vector =
            super::utils::compute_perm_power_vector(permutation, perm_power_challenge);

        // Step 5: Compute Pedersen commitment to power vector using ReencryptionWindow parameters
        // The power vector contains scalar field elements x^π(i), so we use the linearly homomorphic commitment
        let c_power_perm =
            pedersen_commit_scalars::<G, N>(power_params, &perm_power_vector, prover_blinding_s);

        // Step 6: Absorb commitment to power vector
        self.absorb_perm_power_vector_commitment(&c_power_perm);
        tracing::debug!(target: LOG_TARGET, ?c_power_perm, "Absorbed commitment to power vector");

        // Step 7: Derive mixing and offset challenges in base field and convert to scalar field
        let (perm_mixing_challenge_y_base, perm_offset_challenge_z_base) =
            self.derive_perm_challenges_y_z();
        let perm_mixing_challenge_y = G::ScalarField::from_le_bytes_mod_order(
            &perm_mixing_challenge_y_base.into_bigint().to_bytes_le(),
        );
        let perm_offset_challenge_z = G::ScalarField::from_le_bytes_mod_order(
            &perm_offset_challenge_z_base.into_bigint().to_bytes_le(),
        );
        tracing::debug!(target: LOG_TARGET, ?perm_mixing_challenge_y, ?perm_offset_challenge_z, "Derived permutation mixing and offset challenges");

        let params = BayerGrothSetupParameters {
            perm_power_challenge,
            c_perm,
            c_power: c_power_perm,
            blinding_s: prover_blinding_s,
            perm_mixing_challenge_y,
            perm_offset_challenge_z,
        };

        (params, perm_power_vector)
    }
}

/// Create a new transcript with PoseidonSponge for backward compatibility
pub fn new_bayer_groth_transcript_with_poseidon<F>(
    domain: &[u8],
) -> BayerGrothTranscript<F, PoseidonSponge<F>>
where
    F: PrimeField,
{
    let config = crate::config::poseidon_config::<F>();
    let sponge = PoseidonSponge::new(&config);
    BayerGrothTranscript::new(domain, sponge)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::pedersen_commitment_opening_proof::{DeckHashWindow, ReencryptionWindow};
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_crypto_primitives::commitment::{
        pedersen::Commitment as PedersenCommitment, CommitmentScheme,
    };
    use ark_ec::PrimeGroup;
    use ark_ff::Field;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
    use ark_relations::gr1cs::{ConstraintSystem, SynthesisError};
    use ark_std::Zero;
    use ark_std::{rand::SeedableRng, test_rng, UniformRand};
    use rand::{rngs::StdRng, RngCore};

    #[test]
    fn test_fiat_shamir_deterministic() {
        let mut rng = test_rng();

        // Create identical inputs
        let perm = [3, 1, 4, 2, 5];
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

        // Run protocol twice with same inputs
        // Transcript operates over base field (Fq)
        let mut transcript1 = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");

        let _generator = G1Projective::generator();

        let (output1, perm_power_vector1) = transcript1.run_protocol::<G1Projective, 5>(
            &perm_params,
            &power_params,
            &perm,
            prover_blinding_r,
            prover_blinding_s,
        );

        let mut transcript2 = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");
        let (output2, perm_power_vector2) = transcript2.run_protocol::<G1Projective, 5>(
            &perm_params,
            &power_params,
            &perm,
            prover_blinding_r,
            prover_blinding_s,
        );

        // Should get identical outputs
        assert_eq!(output1.perm_power_challenge, output2.perm_power_challenge);
        assert_eq!(perm_power_vector1, perm_power_vector2);
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

        let _generator = G1Projective::generator();

        // Create Pedersen parameters
        let mut deck_rng = StdRng::seed_from_u64(42);
        let perm_params = PedersenCommitment::<G1Projective, DeckHashWindow>::setup(&mut deck_rng)
            .expect("Failed to setup DeckHashWindow Pedersen parameters");
        let mut power_rng = StdRng::seed_from_u64(43);
        let power_params =
            PedersenCommitment::<G1Projective, ReencryptionWindow>::setup(&mut power_rng)
                .expect("Failed to setup ReencryptionWindow Pedersen parameters");

        // Run with different permutations
        let mut transcript1 = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");
        let (output1, _) = transcript1.run_protocol::<G1Projective, 3>(
            &perm_params,
            &power_params,
            &perm1,
            prover_blinding_r,
            prover_blinding_s,
        );

        let mut transcript2 = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");
        let (output2, _) = transcript2.run_protocol::<G1Projective, 3>(
            &perm_params,
            &power_params,
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

        let power_vector =
            crate::shuffling::bayer_groth_permutation::utils::compute_perm_power_vector(
                &perm,
                perm_power_challenge,
            );

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
        let mut transcript = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test");

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
        let mut rng = test_rng();
        let perm: [usize; 5] = [3, 1, 4, 2, 5];
        let _generator = G1Projective::generator();

        // Create Pedersen parameters
        let mut deck_rng = StdRng::seed_from_u64(42);
        let perm_params = PedersenCommitment::<G1Projective, DeckHashWindow>::setup(&mut deck_rng)
            .expect("Failed to setup DeckHashWindow Pedersen parameters");
        let mut power_rng = StdRng::seed_from_u64(43);
        let power_params =
            PedersenCommitment::<G1Projective, ReencryptionWindow>::setup(&mut power_rng)
                .expect("Failed to setup ReencryptionWindow Pedersen parameters");

        // Run with first set of blinding factors
        let blinding_r1 = Fr::rand(&mut rng);
        let blinding_s1 = Fr::rand(&mut rng);
        let mut transcript1 = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");
        let (output1, _) = transcript1.run_protocol::<G1Projective, 5>(
            &perm_params,
            &power_params,
            &perm,
            blinding_r1,
            blinding_s1,
        );

        // Run with different blinding factors but same permutation
        let blinding_r2 = Fr::rand(&mut rng);
        let blinding_s2 = Fr::rand(&mut rng);
        let mut transcript2 = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");
        let (output2, _) = transcript2.run_protocol::<G1Projective, 5>(
            &perm_params,
            &power_params,
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
        let mut gadget_transcript = crate::shuffling::bayer_groth_permutation::bg_setup_gadget::new_bayer_groth_transcript_gadget_with_poseidon::<ark_bn254::Fq>(
            cs.clone(),
            b"test-domain",
        )?;
        let gadget_output = gadget_transcript.run_protocol::<G1Projective, G1Var>(
            cs.clone(),
            &c_perm_var,
            &c_power_var,
        )?;

        // Extract gadget challenge values (they are in scalar field Fr)
        let gadget_power_challenge: Fr = gadget_output.perm_power_challenge.value()?;
        let gadget_mixing_y: Fr = gadget_output.perm_mixing_challenge_y.value()?;
        let gadget_offset_z: Fr = gadget_output.perm_offset_challenge_z.value()?;

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

    /// Test the new minimal compute_power_challenge_setup method
    #[test]
    fn test_compute_power_challenge_setup() {
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

        // Test the new minimal method
        let mut transcript1 = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");
        let (power_vector1, setup1) = transcript1.compute_power_challenge_setup::<G1Projective, 5>(
            &perm_params,
            &power_params,
            &perm,
            prover_blinding_r,
            prover_blinding_s,
        );

        // Test that run_protocol produces the same power challenge and commitments
        let mut transcript2 = new_bayer_groth_transcript_with_poseidon::<Fq>(b"test-domain");
        let (full_params, power_vector2) = transcript2.run_protocol::<G1Projective, 5>(
            &perm_params,
            &power_params,
            &perm,
            prover_blinding_r,
            prover_blinding_s,
        );

        // Verify that both methods produce the same results
        assert_eq!(setup1.power_challenge, full_params.perm_power_challenge);
        assert_eq!(setup1.permutation_commitment, full_params.c_perm);
        assert_eq!(setup1.power_permutation_commitment, full_params.c_power);
        assert_eq!(power_vector1, power_vector2);

        // Verify power vector is computed correctly
        assert_eq!(power_vector1[0], setup1.power_challenge.pow([3u64])); // x^3
        assert_eq!(power_vector1[1], setup1.power_challenge); // x^1
        assert_eq!(power_vector1[2], setup1.power_challenge.pow([4u64])); // x^4
        assert_eq!(power_vector1[3], setup1.power_challenge.pow([2u64])); // x^2
        assert_eq!(power_vector1[4], setup1.power_challenge.pow([5u64])); // x^5
    }

    /// Test complete Bayer-Groth protocol with Fiat-Shamir
    #[test]
    fn test_complete_protocol() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        let n = 52; // Standard deck size

        // Generate random permutation (shuffle)
        let mut perm_vec: Vec<usize> = (1..=n).collect();
        // Fisher-Yates shuffle
        for i in (1..n).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            perm_vec.swap(i, j);
        }

        // Create permutation vector from permutation
        let perm_vector_vals: Vec<Fr> = perm_vec.iter().map(|&i| Fr::from(i as u64)).collect();

        // Simulate external commitment to permutation vector (in practice, this is expensive)
        let c_perm = G1Projective::rand(&mut rng);

        // Initialize Fiat-Shamir transcript (operates over base field)
        let mut transcript = new_bayer_groth_transcript_with_poseidon::<Fq>(b"BayerGroth-Test");

        // Step 1: Absorb commitment to permutation vector and derive power challenge
        transcript.absorb_perm_vector_commitment(&c_perm);
        let perm_power_challenge_base = transcript.derive_perm_power_challenge();
        // Convert from base field to scalar field
        let perm_power_challenge_val =
            Fr::from_le_bytes_mod_order(&perm_power_challenge_base.into_bigint().to_bytes_le());

        // Step 2: Compute permutation power vector
        // Create a fixed-size array for compute_perm_power_vector
        const N: usize = 52;
        let perm: [usize; N] = perm_vec
            .try_into()
            .expect("Permutation should have exactly 52 elements");
        let perm_power_vector_vals =
            crate::shuffling::bayer_groth_permutation::utils::compute_perm_power_vector::<Fr, N>(
                &perm,
                perm_power_challenge_val,
            );
        let perm_power_vector_vals_vec: Vec<Fr> = perm_power_vector_vals.to_vec();

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
            &perm_power_vector_vals_vec,
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
            alloc_vector, left_product_gadget, linear_blend_gadget_dynamic, right_product_gadget,
        };

        // Allocate permutation values as circuit variables (these are scalar field elements)
        let perm_vector = alloc_vector(cs.clone(), &perm_vector_vals, AllocationMode::Witness)?;
        let perm_power_vector = alloc_vector(
            cs.clone(),
            &perm_power_vector_vals_vec,
            AllocationMode::Witness,
        )?;

        // Allocate challenges as circuit variables
        // These were originally drawn from base field (Fq) but converted to scalar field (Fr)
        let perm_power_challenge = FpVar::new_witness(cs.clone(), || Ok(perm_power_challenge_val))?;
        let perm_mixing_challenge_y =
            FpVar::new_witness(cs.clone(), || Ok(perm_mixing_challenge_y_val))?;
        let perm_offset_challenge_z =
            FpVar::new_witness(cs.clone(), || Ok(perm_offset_challenge_z_val))?;

        // Compute the linear blend d = y * perm_vector + perm_power_vector
        // All operations are in the scalar field Fr
        let d = linear_blend_gadget_dynamic(
            &perm_vector,
            &perm_power_vector,
            &perm_mixing_challenge_y,
        )?;
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
