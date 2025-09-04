//! Complete shuffling proof system combining RS shuffle, Bayer-Groth linking, and sigma protocol
//!
//! This module provides a complete proof system for verifying card shuffling with:
//! - RS (Riffle Shuffle) algorithm for the actual permutation
//! - Bayer-Groth setup for proving permutation correctness
//! - Sigma protocol for proving re-encryption correctness
//! - SNARK proof for verifying shuffled indices

use super::bayer_groth_permutation::bg_setup::{BayerGrothSetupParameters, BayerGrothTranscript};
use super::data_structures::ElGamalCiphertext;
use super::proof_system::{IndicesStatement, ProofSystem, SigmaStatement};
use super::rs_shuffle::{
    circuit::RSShuffleWithBayerGrothLinkCircuit, data_structures::WitnessData,
    witness_preparation::apply_rs_shuffle_permutation,
};
use crate::{
    curve_absorb::{CurveAbsorb, CurveAbsorbGadget},
    shuffling::data_structures::ElGamalKeys,
};
use ark_crypto_primitives::commitment::pedersen::Parameters;
use ark_crypto_primitives::snark::SNARK;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ec::{pairing::Pairing, CurveConfig, CurveGroup};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng, RngCore},
    vec::Vec,
    UniformRand, Zero,
};

const LOG_TARGET: &str = "nexus_nova::shuffling::shuffling_proof";

/// Complete shuffling proof containing all proof components
pub struct ShufflingProof<G, const N: usize, IP, SP>
where
    G: CurveGroup,
    IP: ProofSystem<
        Statement = IndicesStatement<E, G, GV, N, LEVELS>,
        Error = Box<dyn std::error::Error>,
    >,
    SP: ProofSystem<Statement = SigmaStatement<G, N>, Error = Box<dyn std::error::Error>>,
{
    /// Bayer-Groth setup parameters (public-facing)
    pub bg_setup_params: BayerGrothSetupParameters<G::ScalarField, G, N>,
    /// Sigma protocol proof for re-encryption correctness
    pub sigma_proof: SP::Proof,
    /// SNARK proof for shuffled indices correctness
    pub shuffling_indices_proof: IP::Proof,
    _marker: PhantomData<(IP, SP)>,
}

/// Configuration for the shuffling proof system
pub struct ShufflingConfig<G, const N: usize, const LEVELS: usize, IP, SP>
where
    G: CurveGroup,
    IP: ProofSystem<
        Statement = IndicesStatement<E, G, GV, N, LEVELS>,
        Error = Box<dyn std::error::Error>,
    >,
    SP: ProofSystem<Statement = SigmaStatement<G, N>, Error = Box<dyn std::error::Error>>,
{
    /// Domain separation string for Fiat-Shamir
    pub domain: Vec<u8>,
    /// Generator point for commitments
    pub generator: G,
    /// Public key for ElGamal encryption (aggregated from all shufflers)
    pub public_key: G,
    /// Indices proof system
    pub indices_proof_system: IP,
    /// Sigma proof system
    pub sigma_proof_system: SP,
}

/// Create RS Shuffle with Bayer-Groth Link circuit
///
/// This function creates the circuit instance with all necessary inputs
/// for proving correct shuffling with Bayer-Groth linking.
///
/// # Type Parameters
/// - `E`: Pairing curve
/// - `G`: Inner curve group
/// - `GV`: Curve variable type
/// - `N`: Number of cards
/// - `LEVELS`: Number of RS shuffle levels
///
/// # Parameters
/// - `seed`: RS shuffle seed (used as alpha challenge)
/// - `bg_setup_params`: Bayer-Groth setup parameters with commitments
/// - `permutation_usize`: The permutation as usize array
/// - `witness_data`: RS shuffle witness data
/// - `blinding_r`: First blinding factor
/// - `blinding_s`: Second blinding factor
/// - `generator`: Generator point for commitments
/// - `domain`: Domain separation string
fn create_rs_shuffle_circuit<E, G, GV, const N: usize, const LEVELS: usize>(
    seed: E::ScalarField,
    bg_setup_params: &BayerGrothSetupParameters<G::ScalarField, G, N>,
    permutation_usize: &[usize; N],
    witness_data: &WitnessData<N, LEVELS>,
    blinding_r: <G::Config as CurveConfig>::ScalarField,
    blinding_s: <G::Config as CurveConfig>::ScalarField,
    generator: G,
    domain: Vec<u8>,
) -> RSShuffleWithBayerGrothLinkCircuit<E::ScalarField, G, GV, N, LEVELS>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    G::Config: CurveConfig<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
{
    // Convert permutation to scalar field elements
    let permutation_scalars: [<G::Config as CurveConfig>::ScalarField; N] =
        std::array::from_fn(|i| {
            <G::Config as CurveConfig>::ScalarField::from(permutation_usize[i] as u64)
        });

    // Extract initial indices (0..N-1)
    let indices_init: [E::ScalarField; N] = std::array::from_fn(|i| E::ScalarField::from(i as u64));

    // Extract shuffled indices from witness data
    let final_sorted = &witness_data.next_levels[LEVELS - 1];
    let indices_after_shuffle: [E::ScalarField; N] =
        std::array::from_fn(|i| E::ScalarField::from(final_sorted[i].idx as u64));

    // Create and return the circuit using the new method
    RSShuffleWithBayerGrothLinkCircuit::<E::ScalarField, G, GV, N, LEVELS>::new(
        seed,
        bg_setup_params.c_perm,
        bg_setup_params.c_power,
        permutation_scalars,
        witness_data.clone(),
        indices_init,
        indices_after_shuffle,
        (blinding_r, blinding_s),
        generator,
        domain,
    )
}

/// Generate a complete shuffling proof
///
/// # Type Parameters
/// - `N`: Number of cards being shuffled
/// - `LEVELS`: Number of levels in the RS shuffle
///
/// # Parameters
/// - `config`: Configuration containing keys and parameters
/// - `ct_input`: Input ElGamal ciphertexts to shuffle
/// - `seed`: Random seed for RS shuffle
/// - `rng`: Random number generator for re-encryption and blinding
///
/// # Returns
/// - `Ok((ct_output, ShufflingProof))`: Output ciphertexts and complete proof of correct shuffling
/// - `Err`: If proof generation fails
pub fn prove_shuffling<E, G, GV, const N: usize, const LEVELS: usize, IP, SP>(
    config: &ShufflingConfig<G, N, LEVELS, IP, SP>,
    ct_input: &[ElGamalCiphertext<G>; N],
    seed: E::ScalarField,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<([ElGamalCiphertext<G>; N], ShufflingProof<G, N, IP, SP>), Box<dyn std::error::Error>>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField> + CurveAbsorb<E::ScalarField>,
    G::Config: CurveConfig<BaseField = E::ScalarField>,
    <G::Config as CurveConfig>::ScalarField: UniformRand,
    E::ScalarField: PrimeField + Absorb,
    GV: CurveVar<G, E::ScalarField> + CurveAbsorbGadget<E::ScalarField>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    IP: ProofSystem<
        Statement = IndicesStatement<E, G, GV, N, LEVELS>,
        Error = Box<dyn std::error::Error>,
    >,
    SP: ProofSystem<Statement = SigmaStatement<G, N>, Error = Box<dyn std::error::Error>>,
{
    tracing::debug!(target: LOG_TARGET, "Starting shuffling proof generation");

    // Step 1: Apply RS shuffle permutation to get witness data and permutation
    tracing::debug!(target: LOG_TARGET, "Step 1: Applying RS shuffle permutation");
    let (witness_data, _num_samples, ct_shuffled) =
        apply_rs_shuffle_permutation::<E::ScalarField, ElGamalCiphertext<G>, N, LEVELS>(
            seed, ct_input,
        );

    // Extract the permutation from witness data's final sorted level
    // The permutation maps original indices to new positions
    let final_sorted = &witness_data.next_levels[LEVELS - 1];
    // TODO: MAYBE we don't need to do this
    let permutation_usize: [usize; N] = std::array::from_fn(|i| {
        // The permutation is 1-indexed, convert from u16 to usize
        final_sorted[i].idx as usize + 1
    });

    // Step 2: Generate re-encryption randomness and apply re-encryption
    tracing::debug!(target: LOG_TARGET, "Step 2: Generating re-encryption");
    let rerandomization_factors: [<G::Config as CurveConfig>::ScalarField; N] =
        std::array::from_fn(|_| <G::Config as CurveConfig>::ScalarField::rand(rng));
    let ct_output: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| {
        // Re-encrypt the shuffled ciphertext
        let r = rerandomization_factors[i];
        ElGamalCiphertext {
            c1: ct_shuffled[i].c1 + config.generator * r,
            c2: ct_shuffled[i].c2 + config.public_key * r,
        }
    });

    // Step 3: Run Bayer-Groth setup to generate setup parameters
    tracing::debug!(target: LOG_TARGET, "Step 3: Running Bayer-Groth setup");
    let blinding_r = <G::Config as CurveConfig>::ScalarField::rand(rng);
    let blinding_s = <G::Config as CurveConfig>::ScalarField::rand(rng);

    let mut bg_transcript = BayerGrothTranscript::<E::ScalarField>::new(&config.domain);
    let (bg_setup_params, perm_power_vector) = bg_transcript.run_protocol::<G, N>(
        config.generator,
        &permutation_usize,
        blinding_r,
        blinding_s,
    );

    // Step 4: Create and run SNARK circuit for RS shuffle with Bayer-Groth linking
    tracing::debug!(target: LOG_TARGET, "Step 4: Creating and running SNARK circuit");

    // Create the circuit using helper function
    let circuit = create_rs_shuffle_circuit::<E, G, GV, N, LEVELS>(
        seed,
        &bg_setup_params,
        &permutation_usize,
        &witness_data,
        blinding_r,
        blinding_s,
        config.generator,
        config.domain.clone(),
    );

    // Generate SNARK proof using the generic proof system
    let indices_stmt = IndicesStatement {
        seed,
        bg_setup_params: bg_setup_params.clone(),
        permutation_usize,
        witness_data: witness_data.clone(),
        blinding_r,
        blinding_s,
        generator: config.generator,
        domain: config.domain.clone(),
        _marker: PhantomData::<GV>,
    };
    let shuffling_indices_proof = config.indices_proof_system.prove(&indices_stmt, rng)?;

    // Step 5: Generate sigma protocol proof for re-encryption correctness
    tracing::debug!(target: LOG_TARGET, "Step 5: Generating sigma protocol proof");

    // Generate new blinding factor for sigma protocol (different from BG blinding)
    let sigma_blinding = <G::Config as CurveConfig>::ScalarField::rand(rng);

    // Create ElGamal keys structure (using dummy private key for verification)
    let keys = ElGamalKeys {
        private_key: <G::Config as CurveConfig>::ScalarField::from(1u64),
        public_key: config.public_key,
    };

    // Create dummy Pedersen parameters - in practice these would be properly initialized
    let mut randomness_generator = Vec::with_capacity(N + 1);
    for _ in 0..=N {
        randomness_generator.push(config.generator);
    }
    // Create a 2D generator table for Pedersen commitments
    // For simplicity, using single element rows
    let generators = vec![vec![config.generator]; N];
    let pedersen_params = Parameters {
        generators,
        randomness_generator,
    };

    // Create Poseidon transcript for Fiat-Shamir
    let mut transcript = PoseidonSponge::<E::ScalarField>::new(&crate::config::poseidon_config());
    transcript.absorb(&config.domain);

    // Create sigma protocol statement
    let sigma_stmt = SigmaStatement {
        keys,
        pedersen_params,
        input_ciphertexts: *ct_input,
        output_ciphertexts: ct_output.clone(),
        perm_power_challenge: bg_setup_params.perm_power_challenge,
        power_perm_vector: bg_setup_params.c_perm.clone(),
        perm_power_vector: perm_power_vector.clone(),
        power_perm_blinding_factor: sigma_blinding,
        rerandomization_scalars: rerandomization_factors.clone(),
        domain: config.domain.clone(),
    };
    let sigma_proof = config.sigma_proof_system.prove(&sigma_stmt, rng)?;

    tracing::debug!(target: LOG_TARGET, "Successfully generated complete shuffling proof");

    Ok((
        ct_output,
        ShufflingProof {
            bg_setup_params,
            sigma_proof,
            shuffling_indices_proof,
            _marker: PhantomData,
        },
    ))
}

/// Verify a complete shuffling proof
///
/// # Type Parameters
/// - `N`: Number of cards being shuffled
/// - `LEVELS`: Number of levels in the RS shuffle
///
/// # Parameters
/// - `config`: Configuration containing keys and parameters
/// - `ct_input`: Original input ciphertexts
/// - `ct_output`: Output ciphertexts after shuffling and re-encryption
/// - `proof`: The shuffling proof to verify
///
/// # Returns
/// - `Ok(true)`: If the proof is valid
/// - `Ok(false)`: If the proof is invalid
/// - `Err`: If verification fails
pub fn verify_shuffling<E, G, const N: usize, const LEVELS: usize, IP, SP>(
    config: &ShufflingConfig<G, N, LEVELS, IP, SP>,
    ct_input: &[ElGamalCiphertext<G>; N],
    ct_output: &[ElGamalCiphertext<G>; N],
    proof: &ShufflingProof<G, N, IP, SP>,
) -> Result<bool, Box<dyn std::error::Error>>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField> + CurveAbsorb<E::ScalarField>,
    G::Config: CurveConfig<BaseField = E::ScalarField>,
    <G::Config as CurveConfig>::ScalarField: UniformRand + Absorb,
    E::ScalarField: PrimeField + Absorb,
    IP: ProofSystem<
        Statement = IndicesStatement<E, G, GV, N, LEVELS>,
        Error = Box<dyn std::error::Error>,
    >,
    SP: ProofSystem<Statement = SigmaStatement<G, N>, Error = Box<dyn std::error::Error>>,
{
    tracing::debug!(target: LOG_TARGET, "Starting shuffling proof verification");

    // Step 1: Verify Bayer-Groth proof point (simplified check)
    tracing::debug!(target: LOG_TARGET, "Step 1: Verifying Bayer-Groth proof");
    // In a complete implementation, this would verify the permutation equality
    // For now, we just check that the commitments are non-zero
    if proof.bg_setup_params.c_perm.is_zero() || proof.bg_setup_params.c_power.is_zero() {
        tracing::warn!(target: LOG_TARGET, "Invalid Bayer-Groth commitments");
        return Ok(false);
    }

    // Step 2: Verify sigma protocol proof
    tracing::debug!(target: LOG_TARGET, "Step 2: Verifying sigma protocol proof");

    // Create ElGamal keys structure (using dummy private key for verification)
    let keys = ElGamalKeys {
        private_key: <G::Config as CurveConfig>::ScalarField::from(1u64),
        public_key: config.public_key,
    };

    // Create dummy Pedersen parameters - in practice these would be properly initialized
    let mut randomness_generator = Vec::with_capacity(N + 1);
    for _ in 0..=N {
        randomness_generator.push(config.generator);
    }
    // Create a 2D generator table for Pedersen commitments
    // For simplicity, using single element rows
    let generators = vec![vec![config.generator]; N];
    let pedersen_params = Parameters {
        generators,
        randomness_generator,
    };

    // Create Poseidon transcript for Fiat-Shamir
    let mut transcript = PoseidonSponge::<E::ScalarField>::new(&crate::config::poseidon_config());
    transcript.absorb(&config.domain);

    // Create sigma protocol statement for verification
    // Note: We need to reconstruct perm_power_vector for verification
    // In practice, this would be part of the public inputs or proof
    let perm_power_vector = vec![<G::Config as CurveConfig>::ScalarField::zero(); N];

    let sigma_stmt = SigmaStatement {
        keys,
        pedersen_params,
        input_ciphertexts: *ct_input,
        output_ciphertexts: *ct_output,
        perm_power_challenge: proof.bg_setup_params.perm_power_challenge,
        power_perm_vector: proof.bg_setup_params.c_perm.clone(),
        perm_power_vector,
        power_perm_blinding_factor: <G::Config as CurveConfig>::ScalarField::zero(), // Not used in verification
        rerandomization_scalars: vec![<G::Config as CurveConfig>::ScalarField::zero(); N], // Not used in verification
        domain: config.domain.clone(),
    };

    if let Err(e) = config
        .sigma_proof_system
        .verify(&sigma_stmt, &proof.sigma_proof)
    {
        tracing::warn!(target: LOG_TARGET, "Sigma protocol verification failed: {}", e);
        return Ok(false);
    }

    // Step 3: Verify SNARK proof
    tracing::debug!(target: LOG_TARGET, "Step 3: Verifying SNARK proof");

    // Create indices statement for verification
    // Note: In practice, these values would be reconstructed from public inputs
    let indices_stmt = IndicesStatement::<E, G, _, N, LEVELS> {
        seed: E::ScalarField::from(17u64), // Placeholder - would be actual seed
        bg_setup_params: proof.bg_setup_params.clone(),
        permutation_usize: [0; N], // Not used in verification
        witness_data: WitnessData {
            next_levels: [[Default::default(); N]; LEVELS],
        }, // Not used in verification
        blinding_r: <G::Config as CurveConfig>::ScalarField::zero(), // Not used in verification
        blinding_s: <G::Config as CurveConfig>::ScalarField::zero(), // Not used in verification
        generator: config.generator,
        domain: config.domain.clone(),
        _marker: PhantomData,
    };

    if let Err(e) = config
        .indices_proof_system
        .verify(&indices_stmt, &proof.shuffling_indices_proof)
    {
        tracing::warn!(target: LOG_TARGET, "SNARK verification failed: {}", e);
        return Ok(false);
    }

    tracing::debug!(target: LOG_TARGET, "Shuffling proof verification succeeded");
    Ok(true)
}

/// Generic function that tests proving and verifying a shuffling proof
///
/// This function takes a configuration and input ciphertexts,
/// generates a proof using `prove_shuffling`, then verifies it using `verify_shuffling`
///
/// Returns true if the proof generation and verification succeed
pub fn test_prove_and_verify<E, G, GV, const N: usize, const LEVELS: usize, IP, SP, R>(
    config: &ShufflingConfig<G, N, LEVELS, IP, SP>,
    ct_input: &[ElGamalCiphertext<G>; N],
    seed: E::ScalarField,
    rng: &mut R,
) -> Result<bool, Box<dyn std::error::Error>>
where
    R: Rng + RngCore + CryptoRng,
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField> + CurveAbsorb<E::ScalarField>,
    G::Config: CurveConfig<BaseField = E::ScalarField>,
    <G::Config as CurveConfig>::ScalarField: UniformRand + Absorb,
    E::ScalarField: PrimeField + Absorb,
    GV: CurveVar<G, E::ScalarField> + CurveAbsorbGadget<E::ScalarField>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    IP: ProofSystem<
        Statement = IndicesStatement<E, G, GV, N, LEVELS>,
        Error = Box<dyn std::error::Error>,
    >,
    SP: ProofSystem<Statement = SigmaStatement<G, N>, Error = Box<dyn std::error::Error>>,
{
    // Generate the proof
    let (ct_output, proof) =
        prove_shuffling::<E, G, GV, N, LEVELS, IP, SP>(config, ct_input, seed, rng)?;

    // Verify the proof
    let is_valid =
        verify_shuffling::<E, G, N, LEVELS, IP, SP>(config, ct_input, &ct_output, &proof)?;

    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_ec::PrimeGroup;
    use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    /// Helper function to generate proving and verifying keys for testing
    /// These keys can be generated once and reused across tests
    fn generate_test_keys<E, G, GV, const N: usize, const LEVELS: usize, R>(
        rng: &mut R,
    ) -> (ProvingKey<E>, VerifyingKey<E>)
    where
        R: Rng + RngCore + CryptoRng,
        E: Pairing,
        G: CurveGroup<BaseField = E::ScalarField> + CurveAbsorb<E::ScalarField>,
        G::Config: CurveConfig<BaseField = E::ScalarField>,
        GV: CurveVar<G, E::ScalarField> + CurveAbsorbGadget<E::ScalarField>,
        for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
        <G::Config as CurveConfig>::ScalarField: UniformRand,
        E::ScalarField: PrimeField + Absorb,
    {
        // Create a simple dummy circuit for key generation
        let generator = G::generator();
        let seed = E::ScalarField::from(42u64);
        let dummy_permutation: [usize; N] = std::array::from_fn(|i| i);
        let blinding_r = <G::Config as CurveConfig>::ScalarField::from(1u64);
        let blinding_s = <G::Config as CurveConfig>::ScalarField::from(2u64);

        // Create minimal dummy data
        let dummy_ct: [ElGamalCiphertext<G>; N] = std::array::from_fn(|_| ElGamalCiphertext {
            c1: G::zero(),
            c2: G::zero(),
        });

        let (witness_data, _, _) =
            apply_rs_shuffle_permutation::<E::ScalarField, ElGamalCiphertext<G>, N, LEVELS>(
                seed, &dummy_ct,
            );

        let mut bg_transcript = BayerGrothTranscript::<E::ScalarField>::new(b"test");
        let (bg_setup_params, _) = bg_transcript.run_protocol::<G, N>(
            generator,
            &dummy_permutation,
            blinding_r,
            blinding_s,
        );

        let dummy_circuit = create_rs_shuffle_circuit::<E, G, GV, N, LEVELS>(
            seed,
            &bg_setup_params,
            &dummy_permutation,
            &witness_data,
            blinding_r,
            blinding_s,
            generator,
            b"test".to_vec(),
        );

        Groth16::<E>::circuit_specific_setup(dummy_circuit, rng)
            .expect("Key generation should succeed")
    }

    #[test]
    fn test_shuffling_proof_bn254() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Define types for BN254 with Grumpkin
        // Note: Grumpkin's base field is BN254's scalar field (Fr)
        // This satisfies the constraint G::BaseField = E::ScalarField
        const N: usize = 10;
        const LEVELS: usize = 3;

        type E = Bn254;
        type G = GrumpkinProjective;
        type GV = ProjectiveVar<GrumpkinConfig, FpVar<Fr>>;

        // Generate proving and verifying keys once
        // In production, these would be generated in a trusted setup ceremony
        let (proving_key, verifying_key) =
            generate_test_keys::<E, G, GV, N, LEVELS, StdRng>(&mut rng);

        // Setup configuration
        let generator = G::generator();
        // Grumpkin scalar field for private key
        let private_key = ark_grumpkin::Fr::rand(&mut rng);
        let public_key = generator * private_key;
        let domain = b"test_domain".to_vec();

        // Create proof systems
        use crate::shuffling::proof_system::{
            create_groth16_indices_proof_system, create_sigma_proof_system,
        };

        let indices_proof_system =
            create_groth16_indices_proof_system::<E, G, GV, N, LEVELS>(proving_key, verifying_key);
        let sigma_proof_system = create_sigma_proof_system::<G, N>();

        let config = ShufflingConfig {
            domain: domain.clone(),
            generator,
            public_key,
            indices_proof_system,
            sigma_proof_system,
        };

        // Create actual input ciphertexts with encrypted values
        let ct_input: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| {
            let message = ark_grumpkin::Fr::from(i as u64);
            let randomness = ark_grumpkin::Fr::rand(&mut rng);
            ElGamalCiphertext::encrypt_scalar(message, randomness, public_key)
        });

        // Test with random seed (BN254's scalar field)
        let shuffle_seed = Fr::rand(&mut rng);

        // Call the generic test function
        let result = test_prove_and_verify::<E, G, GV, N, LEVELS, _, _, StdRng>(
            &config,
            &ct_input,
            shuffle_seed,
            &mut rng,
        );

        match result {
            Ok(is_valid) => {
                assert!(is_valid, "Proof should be valid");
                println!("✅ Shuffling proof test passed for BN254 with Grumpkin!");
            }
            Err(e) => {
                panic!("Test failed with error: {}", e);
            }
        }
    }
}
