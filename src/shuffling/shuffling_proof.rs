//! Complete shuffling proof system combining RS shuffle, Bayer-Groth linking, and sigma protocol
//!
//! This module provides a complete proof system for verifying card shuffling with:
//! - RS (Riffle Shuffle) algorithm for the actual permutation
//! - Bayer-Groth setup for proving permutation correctness
//! - Reencryption protocol for proving re-encryption correctness
//! - SNARK proof for verifying shuffled permutation

use super::bayer_groth_permutation::bg_setup::{
    new_bayer_groth_transcript_with_poseidon, BayerGrothSetupParameters,
};
use super::bayer_groth_permutation::reencryption_protocol::prove;
use super::data_structures::ElGamalCiphertext;
use super::proof_system::{
    PermutationPublicInput, PermutationWitness, ProofSystem, ReencryptionPublicInput,
    ReencryptionWitness,
};
use super::rs_shuffle::native::run_rs_shuffle_permutation;
#[cfg(test)]
use super::rs_shuffle::{
    circuit::RSShuffleWithBayerGrothLinkCircuit, data_structures::PermutationWitnessTrace,
};
use crate::curve_absorb::{CurveAbsorb, CurveAbsorbGadget};
use crate::pedersen_commitment_opening_proof::{DeckHashWindow, ReencryptionWindow};
use ark_crypto_primitives::commitment::pedersen::Commitment as PedersenCommitment;
use ark_crypto_primitives::commitment::CommitmentScheme;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_std::{
    marker::PhantomData,
    rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng},
    vec::Vec,
    UniformRand,
};

const LOG_TARGET: &str = "nexus_nova::shuffling::shuffling_proof";

/// Type alias for Pedersen commitment with ReencryptionWindow configuration
type PedersenReenc<G> = PedersenCommitment<G, ReencryptionWindow>;

/// Type alias for Pedersen commitment with DeckHashWindow configuration
type PedersenDeck<G> = PedersenCommitment<G, DeckHashWindow>;

// ============================================================================
// New prover/verifier (v2) using PermutationGroth16 + native Σ‑protocol
// ============================================================================

use crate::shuffling::pedersen_commitment::opening_proof::{
    verify as verify_pedersen_opening, PedersenCommitmentOpeningProof, PedersenParams,
};
use crate::shuffling::permutation_proof::proof_system::PermutationGroth16;
use crate::shuffling::permutation_proof::{
    prepare_witness, PublicData as PermPublicData, WitnessData as PermWitnessData,
};
use ark_ec::pairing::Pairing;
use ark_groth16::{PreparedVerifyingKey, Proof as Groth16Proof};

/// Public configuration for the new shuffling prover/verifier
pub struct ShufflingConfigV2<G: CurveGroup> {
    /// Generator on inner curve for ElGamal and commitments
    pub generator: G,
    /// Aggregated ElGamal public key
    pub public_key: G,
}

/// Complete shuffling proof artifacts for the new prover
pub struct ShufflingProofV2<E, G, const N: usize>
where
    E: Pairing,
    G: CurveGroup,
{
    /// Groth16 proof for the permutation circuit
    pub perm_snark_proof: Groth16Proof<E>,
    /// Prepared verifying key (public)
    pub perm_snark_pvk: PreparedVerifyingKey<E>,
    /// Flattened public inputs used by the permutation circuit
    pub perm_snark_public_inputs: Vec<E::ScalarField>,
    /// Bayer–Groth minimal setup outputs used across sub-protocols
    pub power_challenge_scalar: G::ScalarField,
    pub permutation_commitment: G,
    pub power_permutation_commitment: G,
    /// Native Pedersen opening proof for c_power
    pub power_opening_proof: PedersenCommitmentOpeningProof<G>,
    /// Native Σ‑protocol proof for re-encryption correctness
    pub reencryption_proof:
        super::bayer_groth_permutation::reencryption_protocol::ReencryptionProof<G, N>,
}

/// Prove a shuffle with the new RS SNARK (with VRF) and native Σ‑protocol
pub fn prove_shuffling_v2<E, G, GG, const N: usize, const LEVELS: usize>(
    config: &ShufflingConfigV2<G>,
    ct_input: &[ElGamalCiphertext<G>; N],
    // VRF inputs
    vrf_nonce: G::BaseField,
    vrf_sk: G::ScalarField,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<([ElGamalCiphertext<G>; N], ShufflingProofV2<E, G, N>), Box<dyn std::error::Error>>
where
    E: Pairing<ScalarField = G::BaseField>,
    G: CurveGroup + CurveAbsorb<G::BaseField> + ark_ff::ToConstraintField<G::BaseField>,
    G::Config: CurveConfig,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    GG: CurveVar<G, G::BaseField>
        + crate::shuffling::curve_absorb::CurveAbsorbGadget<
            G::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
        >,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, G, GG>,
    for<'a> &'a GG: crate::shuffling::curve_absorb::CurveAbsorbGadget<
        G::BaseField,
        ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
    >,
{
    // 1) RS shuffle (native) to get permutation and permuted ciphertexts
    let rs_shuffle_trace =
        run_rs_shuffle_permutation::<G::BaseField, ElGamalCiphertext<G>, N, LEVELS>(
            vrf_nonce, ct_input,
        );

    // 2) Apply re-encryption (native) using random scalars
    let rerand: [G::ScalarField; N] =
        crate::shuffling::encryption::generate_randomization_array::<G::Config, N>(rng);
    let ct_output: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| ElGamalCiphertext {
        c1: rs_shuffle_trace.permuted_output[i].c1 + config.generator * rerand[i],
        c2: rs_shuffle_trace.permuted_output[i].c2 + config.public_key * rerand[i],
    });

    // 3) Pedersen parameters (deterministic seeds for consistency across prove/verify)
    let mut deck_rng = StdRng::seed_from_u64(42);
    let perm_params = PedersenDeck::<G>::setup(&mut deck_rng)?;
    let mut power_rng = StdRng::seed_from_u64(43);
    let power_params = PedersenReenc::<G>::setup(&mut power_rng)?;

    // 4) Prepare permutation witnesses (native), including BG setup + opening
    let mut prep_params = crate::shuffling::permutation_proof::PermutationParameters::<G, _> {
        perm_params: &perm_params,
        power_params: &power_params,
        rng,
    };
    let mut sponge =
        PoseidonSponge::<G::BaseField>::new(&crate::config::poseidon_config::<G::BaseField>());
    let prepared =
        prepare_witness::<G, _, _, N, LEVELS>(&mut prep_params, vrf_nonce, vrf_sk, &mut sponge)?;

    // 5) Groth16 permutation proof (build keys per-proof due to num_samples dependency)
    let perm_sys: PermutationGroth16<E, G, GG, N, LEVELS> =
        PermutationGroth16::setup(rng, prepared.rs_trace.num_samples)?;
    let public = PermPublicData::<G, N> {
        nonce: vrf_nonce,
        pk_public: prepared.pk,
        indices_init: prepared.indices_init,
        alpha_rs: prepared.vrf_value,
        power_challenge_public: prepared.bg_setup.power_challenge_base,
        c_perm: prepared.bg_setup.permutation_commitment,
        c_power: prepared.bg_setup.power_permutation_commitment,
        power_opening_proof: prepared.power_opening_proof.clone(),
    };
    let witness = PermWitnessData::<G, N, LEVELS> {
        sk: vrf_sk,
        rs_witness: prepared.rs_trace.witness_trace.clone(),
        power_perm_vec_wit: prepared.perm_power_vector_base,
        power_perm_vec_scalar_wit: prepared.perm_power_vector_scalar,
    };
    let (perm_proof, perm_public_inputs) =
        perm_sys.prove(rng, &public, &witness, prepared.rs_trace.num_samples)?;
    let pvk = perm_sys.prepared_vk().clone();

    // 6) Native Σ‑protocol for re-encryption correctness
    let mut tr_sig =
        PoseidonSponge::<G::BaseField>::new(&crate::config::poseidon_config::<G::BaseField>());
    let reencryption_proof = prove::<G, _, N>(
        &config.public_key,
        &power_params,
        ct_input,
        &ct_output,
        prepared.bg_setup.power_challenge_scalar,
        &prepared.bg_setup.power_permutation_commitment,
        &prepared.perm_power_vector_scalar,
        prepared.blinding_s,
        &rerand,
        &mut tr_sig,
        rng,
    );

    Ok((
        ct_output,
        ShufflingProofV2 {
            perm_snark_proof: perm_proof,
            perm_snark_pvk: pvk,
            perm_snark_public_inputs: perm_public_inputs,
            power_challenge_scalar: prepared.bg_setup.power_challenge_scalar,
            permutation_commitment: prepared.bg_setup.permutation_commitment,
            power_permutation_commitment: prepared.bg_setup.power_permutation_commitment,
            power_opening_proof: prepared.power_opening_proof,
            reencryption_proof,
        },
    ))
}

/// Verify a shuffle with the new RS SNARK and native Σ‑protocol
pub fn  <E, G, const N: usize>(
    config: &ShufflingConfigV2<G>,
    ct_input: &[ElGamalCiphertext<G>; N],
    ct_output: &[ElGamalCiphertext<G>; N],
    proof: &ShufflingProofV2<E, G, N>,
) -> Result<bool, Box<dyn std::error::Error>>
where
    E: Pairing<ScalarField = G::BaseField>,
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
{
    // 1) Verify Groth16 permutation proof
    let ok_snark = ark_groth16::Groth16::<E>::verify_proof(
        &proof.perm_snark_pvk,
        &proof.perm_snark_proof,
        &proof.perm_snark_public_inputs,
    )?;
    if !ok_snark {
        return Ok(false);
    }

    // 2) Verify Pedersen opening of c_power (natively)
    let mut power_rng = StdRng::seed_from_u64(43);
    let power_params_raw = PedersenReenc::<G>::setup(&mut power_rng)?;
    let ped_params = PedersenParams::<G>::from_arkworks::<N>(power_params_raw.clone());
    verify_pedersen_opening::<G, N>(
        &ped_params,
        &proof.power_permutation_commitment,
        &proof.power_opening_proof,
    )
    .map_err(|e| -> Box<dyn std::error::Error> {
        format!("pedersen opening verify: {e:?}").into()
    })?;

    // 3) Verify native re-encryption Σ‑protocol
    let mut tr_sig =
        PoseidonSponge::<G::BaseField>::new(&crate::config::poseidon_config::<G::BaseField>());
    let ok_sigma = super::bayer_groth_permutation::reencryption_protocol::verify::<G, _, N>(
        &config.public_key,
        &power_params_raw,
        ct_input,
        ct_output,
        proof.power_challenge_scalar,
        &proof.power_permutation_commitment,
        &proof.reencryption_proof,
        &mut tr_sig,
    );
    if !ok_sigma {
        return Ok(false);
    }

    Ok(true)
}

/// Helper function to create RS Shuffle with Bayer-Groth Link circuit
#[cfg(test)]
fn create_rs_shuffle_circuit<G, GV, const N: usize, const LEVELS: usize>(
    seed: G::BaseField,
    bg_setup_params: &BayerGrothSetupParameters<G::ScalarField, G, N>,
    permutation_usize: &[usize; N],
    witness_data: &PermutationWitnessTrace<N, LEVELS>,
    blinding_r: <G::Config as CurveConfig>::ScalarField,
    blinding_s: <G::Config as CurveConfig>::ScalarField,
    generator: G,
    domain: Vec<u8>,
) -> RSShuffleWithBayerGrothLinkCircuit<
    G::BaseField,
    G,
    GV,
    ark_crypto_primitives::sponge::poseidon::PoseidonSponge<G::BaseField>,
    ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
    N,
    LEVELS,
>
where
    G: CurveGroup,
    G::Config: CurveConfig,
    GV: CurveVar<G, G::BaseField>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    G::BaseField: PrimeField,
{
    // Convert permutation to scalar field elements
    let permutation_scalars: [<G::Config as CurveConfig>::ScalarField; N] =
        std::array::from_fn(|i| {
            <G::Config as CurveConfig>::ScalarField::from(permutation_usize[i] as u64)
        });

    // Extract initial indices (0..N-1)
    let indices_init: [G::BaseField; N] = std::array::from_fn(|i| G::BaseField::from(i as u64));

    // Extract shuffled indices from witness data
    let final_sorted = &witness_data.next_levels[LEVELS - 1];
    let indices_after_shuffle: [G::BaseField; N] =
        std::array::from_fn(|i| G::BaseField::from(final_sorted[i].idx as u64));

    // Create and return the circuit using the new method
    RSShuffleWithBayerGrothLinkCircuit::<
        G::BaseField,
        G,
        GV,
        ark_crypto_primitives::sponge::poseidon::PoseidonSponge<G::BaseField>,
        ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
        N,
        LEVELS,
    >::new(
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

/// Complete shuffling proof containing all proof components
/// Generic over IP (Permutation Proof system) and SP (Reencryption Proof system)
pub struct ShufflingProof<IP, SP, G, const N: usize>
where
    IP: ProofSystem,
    SP: ProofSystem,
    G: CurveGroup,
{
    /// Bayer-Groth setup parameters (public-facing)
    pub bg_setup_params: BayerGrothSetupParameters<G::ScalarField, G, N>,
    /// Reencryption protocol proof for re-encryption correctness
    pub reencryption_proof: SP::Proof,
    /// SNARK proof for shuffled permutation correctness
    pub shuffling_permutation_snark_proof: IP::Proof,
    _marker: PhantomData<(IP, SP)>,
}

impl<IP, SP, G, const N: usize> ShufflingProof<IP, SP, G, N>
where
    IP: ProofSystem,
    SP: ProofSystem,
    G: CurveGroup,
{
    /// Create a new ShufflingProof
    pub fn new(
        bg_setup_params: BayerGrothSetupParameters<G::ScalarField, G, N>,
        reencryption_proof: SP::Proof,
        shuffling_permutation_snark_proof: IP::Proof,
    ) -> Self {
        Self {
            bg_setup_params,
            reencryption_proof,
            shuffling_permutation_snark_proof,
            _marker: PhantomData,
        }
    }
}

/// Configuration for the shuffling proof system
/// Generic over IP (Permutation Proof system) and SP (Reencryption Proof system)
pub struct ShufflingConfig<IP, SP, G>
where
    IP: ProofSystem,
    SP: ProofSystem,
    G: CurveGroup,
{
    /// Domain separation string for Fiat-Shamir
    pub domain: Vec<u8>,
    /// Generator point for commitments
    pub generator: G,
    /// Public key for ElGamal encryption (aggregated from all shufflers)
    pub public_key: G,
    /// Permutation proof system instance
    pub permutation_proof_system: IP,
    /// Reencryption protocol proof system instance
    pub reencryption_proof_system: SP,
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
pub fn prove_shuffling<G, GV, IP, SP, const N: usize, const LEVELS: usize>(
    config: &ShufflingConfig<IP, SP, G>,
    ct_input: &[ElGamalCiphertext<G>; N],
    seed: G::BaseField,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<([ElGamalCiphertext<G>; N], ShufflingProof<IP, SP, G, N>), Box<dyn std::error::Error>>
where
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::Config: CurveConfig,
    <G::Config as CurveConfig>::ScalarField: UniformRand,
    G::BaseField: PrimeField + Absorb,
    GV: CurveVar<G, G::BaseField>
        + CurveAbsorbGadget<
            G::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
        >,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    IP: ProofSystem<
        PublicInput = PermutationPublicInput<G, GV, N, LEVELS>,
        Witness = PermutationWitness<G, GV, N, LEVELS>,
    >,
    SP: ProofSystem<
        PublicInput = ReencryptionPublicInput<G, N>,
        Witness = ReencryptionWitness<G, N>,
    >,
    IP::Error: Into<Box<dyn std::error::Error>>,
    SP::Error: Into<Box<dyn std::error::Error>>,
{
    tracing::debug!(target: LOG_TARGET, "Starting shuffling proof generation");

    // Step 1: Apply RS shuffle permutation to get witness data and permutation
    tracing::debug!(target: LOG_TARGET, "Step 1: Applying RS shuffle permutation");
    let rs_shuffle_trace =
        run_rs_shuffle_permutation::<G::BaseField, ElGamalCiphertext<G>, N, LEVELS>(seed, ct_input);

    // Create an RSShuffleTrace with the permutation as the output
    let permutation_trace = super::rs_shuffle::data_structures::RSShuffleTrace {
        witness_trace: rs_shuffle_trace.witness_trace.clone(),
        num_samples: rs_shuffle_trace.num_samples,
        permuted_output: rs_shuffle_trace.extract_permutation_array(),
    };

    // Step 2: Generate re-encryption randomness and apply re-encryption
    tracing::debug!(target: LOG_TARGET, "Step 2: Generating re-encryption");
    let rerandomization_factors: [<G::Config as CurveConfig>::ScalarField; N] =
        crate::shuffling::encryption::generate_randomization_array::<G::Config, N>(rng);
    let ct_output: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| {
        // Re-encrypt the shuffled ciphertext
        let r = rerandomization_factors[i];
        ElGamalCiphertext {
            c1: rs_shuffle_trace.permuted_output[i].c1 + config.generator * r,
            c2: rs_shuffle_trace.permuted_output[i].c2 + config.public_key * r,
        }
    });

    // Step 3: Generate Pedersen parameters for both window types
    // NOTE: Using fixed seeds to ensure consistency between prover and verifier.
    // In production, these would be shared public parameters.
    let mut deck_rng = StdRng::seed_from_u64(42);
    let perm_params =
        PedersenDeck::<G>::setup(&mut deck_rng).map_err(|e| -> Box<dyn std::error::Error> {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to setup DeckHashWindow Pedersen parameters: {:?}",
                    e
                ),
            ))
        })?;

    let mut power_rng = StdRng::seed_from_u64(43);
    let power_params =
        PedersenReenc::<G>::setup(&mut power_rng).map_err(|e| -> Box<dyn std::error::Error> {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to setup ReencryptionWindow Pedersen parameters: {:?}",
                    e
                ),
            ))
        })?;

    // Step 4: Run Bayer-Groth setup to generate setup parameters
    tracing::debug!(target: LOG_TARGET, "Step 4: Running Bayer-Groth setup");
    let blinding_r = <G::Config as CurveConfig>::ScalarField::rand(rng);
    let blinding_s = <G::Config as CurveConfig>::ScalarField::rand(rng);

    let mut bg_transcript =
        new_bayer_groth_transcript_with_poseidon::<G::BaseField>(&config.domain);
    let (bg_setup_params, perm_power_vector) = bg_transcript.run_protocol::<G, N>(
        &perm_params,
        &power_params,
        &permutation_trace.permuted_output,
        blinding_r,
        blinding_s,
    );

    // Step 5: Create and run SNARK circuit for RS shuffle with Bayer-Groth linking
    tracing::debug!(target: LOG_TARGET, "Step 5: Creating permutation proof with generic proof system");

    // Create PermutationPublicInput
    let permutation_public = PermutationPublicInput::<G, GV, N, LEVELS>::new(
        seed,
        bg_setup_params.clone(),
        config.generator,
        config.domain.clone(),
    );

    // Create PermutationWitness
    let permutation_witness =
        PermutationWitness::<G, GV, N, LEVELS>::new(permutation_trace, blinding_r, blinding_s);

    // Generate proof using the generic permutation proof system
    let shuffling_permutation_snark_proof = config
        .permutation_proof_system
        .prove(&permutation_public, &permutation_witness, rng)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Step 6: Generate reencryption protocol proof for re-encryption correctness
    tracing::debug!(target: LOG_TARGET, "Step 6: Generating reencryption protocol proof with generic proof system");

    // Create ReencryptionPublicInput
    let reencryption_public = ReencryptionPublicInput::<G, N>::new(
        config.public_key,
        power_params,
        ct_input.clone(),
        ct_output.clone(),
        bg_setup_params.perm_power_challenge,
        bg_setup_params.c_power,
        config.domain.clone(),
    );

    // Create ReencryptionWitness using the blinding factor from BG setup
    // This ensures consistency with the commitment to the power vector
    let reencryption_witness = ReencryptionWitness::<G, N>::new(
        perm_power_vector,
        bg_setup_params.blinding_s,
        rerandomization_factors,
    );

    // Generate proof using the generic reencryption proof system
    let reencryption_proof = config
        .reencryption_proof_system
        .prove(&reencryption_public, &reencryption_witness, rng)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    tracing::debug!(target: LOG_TARGET, "Successfully generated complete shuffling proof");

    Ok((
        ct_output,
        ShufflingProof::new(
            bg_setup_params,
            reencryption_proof,
            shuffling_permutation_snark_proof,
        ),
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
pub fn verify_shuffling<G, GV, IP, SP, const N: usize, const LEVELS: usize>(
    config: &ShufflingConfig<IP, SP, G>,
    ct_input: &[ElGamalCiphertext<G>; N],
    ct_output: &[ElGamalCiphertext<G>; N],
    proof: &ShufflingProof<IP, SP, G, N>,
    seed: G::BaseField,
) -> Result<bool, Box<dyn std::error::Error>>
where
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::Config: CurveConfig,
    <G::Config as CurveConfig>::ScalarField: UniformRand + Absorb,
    G::BaseField: PrimeField + Absorb,
    GV: CurveVar<G, G::BaseField>
        + CurveAbsorbGadget<
            G::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
        >,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    IP: ProofSystem<PublicInput = PermutationPublicInput<G, GV, N, LEVELS>>,
    SP: ProofSystem<PublicInput = ReencryptionPublicInput<G, N>>,
    IP::Error: Into<Box<dyn std::error::Error>>,
    SP::Error: Into<Box<dyn std::error::Error>>,
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

    // Step 2: Verify reencryption protocol proof
    tracing::debug!(target: LOG_TARGET, "Step 2: Verifying reencryption protocol proof with generic proof system");

    // Generate proper Pedersen parameters with distinct generators
    // NOTE: In production, these parameters would be shared between prover and verifier
    // and generated during a trusted setup phase. For testing, we use fixed seeds
    // to ensure consistency between prover and verifier.
    // Note: We only need the power_params for reencryption verification
    let mut power_rng = StdRng::seed_from_u64(43);
    let power_params =
        PedersenReenc::<G>::setup(&mut power_rng).map_err(|e| -> Box<dyn std::error::Error> {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to setup ReencryptionWindow Pedersen parameters: {:?}",
                    e
                ),
            ))
        })?;

    // Create ReencryptionPublicInput for verification
    let reencryption_public = ReencryptionPublicInput::<G, N>::new(
        config.public_key,
        power_params,
        ct_input.clone(),
        ct_output.clone(),
        proof.bg_setup_params.perm_power_challenge,
        proof.bg_setup_params.c_power,
        config.domain.clone(),
    );

    // Verify using the generic reencryption proof system
    config
        .reencryption_proof_system
        .verify(&reencryption_public, &proof.reencryption_proof)
        .map_err(|e| -> Box<dyn std::error::Error> {
            tracing::warn!(target: LOG_TARGET, "Reencryption protocol verification failed");
            e.into()
        })?;

    // Step 3: Verify SNARK proof
    tracing::debug!(target: LOG_TARGET, "Step 3: Verifying permutation proof with generic proof system");

    // Create PermutationPublicInput for verification
    let permutation_public = PermutationPublicInput::<G, GV, N, LEVELS>::new(
        seed,
        proof.bg_setup_params.clone(),
        config.generator,
        config.domain.clone(),
    );

    // Verify using the generic permutation proof system
    config
        .permutation_proof_system
        .verify(
            &permutation_public,
            &proof.shuffling_permutation_snark_proof,
        )
        .map_err(|e| -> Box<dyn std::error::Error> {
            tracing::warn!(target: LOG_TARGET, "Permutation proof verification failed");
            e.into()
        })?;

    tracing::debug!(target: LOG_TARGET, "Shuffling proof verification succeeded");
    Ok(true)
}

/// Generic function that tests proving and verifying a shuffling proof
///
/// This function takes a configuration and input ciphertexts,
/// generates a proof using `prove_shuffling`, then verifies it using `verify_shuffling`
///
/// Returns true if the proof generation and verification succeed
pub fn test_prove_and_verify<G, GV, IP, SP, const N: usize, const LEVELS: usize, R>(
    config: &ShufflingConfig<IP, SP, G>,
    ct_input: &[ElGamalCiphertext<G>; N],
    seed: G::BaseField,
    rng: &mut R,
) -> Result<bool, Box<dyn std::error::Error>>
where
    R: Rng + RngCore + CryptoRng,
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::Config: CurveConfig,
    <G::Config as CurveConfig>::ScalarField: UniformRand + Absorb,
    G::BaseField: PrimeField + Absorb,
    GV: CurveVar<G, G::BaseField>
        + CurveAbsorbGadget<
            G::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
        >,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    IP: ProofSystem<
        PublicInput = PermutationPublicInput<G, GV, N, LEVELS>,
        Witness = PermutationWitness<G, GV, N, LEVELS>,
    >,
    SP: ProofSystem<
        PublicInput = ReencryptionPublicInput<G, N>,
        Witness = ReencryptionWitness<G, N>,
    >,
    IP::Error: Into<Box<dyn std::error::Error>>,
    SP::Error: Into<Box<dyn std::error::Error>>,
{
    // Generate the proof
    let (ct_output, proof) =
        prove_shuffling::<G, GV, IP, SP, N, LEVELS>(config, ct_input, seed, rng)?;

    // Verify the proof
    let is_valid =
        verify_shuffling::<G, GV, IP, SP, N, LEVELS>(config, ct_input, &ct_output, &proof, seed)?;

    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::super::proof_system::{
        create_dummy_proof_system, create_groth16_permutation_proof_system,
        create_reencryption_proof_system, DummyProofSystem,
    };
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_ec::pairing::Pairing;
    use ark_ec::PrimeGroup;
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
    use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_snark::SNARK;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::Zero;
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    const TEST_TARGET: &str = "nexus_nova";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target(TEST_TARGET, tracing::Level::TRACE);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_line_number(true) // Add line numbers
                    .with_timer(tracing_subscriber::fmt::time::uptime()) // Use elapsed time instead of date
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    /// Helper function to generate proving and verifying keys for testing
    /// These keys can be generated once and reused across tests
    fn generate_permutation_proving_keys<E, G, GV, const N: usize, const LEVELS: usize, R>(
        rng: &mut R,
    ) -> (ProvingKey<E>, VerifyingKey<E>)
    where
        R: Rng + RngCore + CryptoRng,
        E: Pairing,
        G: CurveGroup<BaseField = E::ScalarField> + CurveAbsorb<G::BaseField>,
        G::Config: CurveConfig<BaseField = E::ScalarField>,
        GV: CurveVar<G, G::BaseField>
            + CurveAbsorbGadget<
                G::BaseField,
                ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<
                    G::BaseField,
                >,
            >,
        for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
        <G::Config as CurveConfig>::ScalarField: UniformRand,
        G::BaseField: PrimeField + Absorb,
    {
        // Create a simple dummy circuit for key generation
        let generator = G::generator();
        let seed = G::BaseField::from(42u64);
        let dummy_permutation: [usize; N] = std::array::from_fn(|i| i);
        let blinding_r = <G::Config as CurveConfig>::ScalarField::from(1u64);
        let blinding_s = <G::Config as CurveConfig>::ScalarField::from(2u64);

        // Create minimal dummy data
        let dummy_ct: [ElGamalCiphertext<G>; N] = std::array::from_fn(|_| ElGamalCiphertext {
            c1: G::zero(),
            c2: G::zero(),
        });

        let rs_shuffle_trace =
            run_rs_shuffle_permutation::<G::BaseField, ElGamalCiphertext<G>, N, LEVELS>(
                seed, &dummy_ct,
            );

        // Create Pedersen parameters for test key generation
        use ark_std::rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut deck_rng = StdRng::seed_from_u64(42);
        let perm_params = PedersenDeck::<G>::setup(&mut deck_rng)
            .expect("Failed to setup DeckHashWindow Pedersen parameters");
        let mut power_rng = StdRng::seed_from_u64(43);
        let power_params = PedersenReenc::<G>::setup(&mut power_rng)
            .expect("Failed to setup ReencryptionWindow Pedersen parameters");

        let mut bg_transcript = new_bayer_groth_transcript_with_poseidon::<G::BaseField>(b"test");
        let (bg_setup_params, _) = bg_transcript.run_protocol::<G, N>(
            &perm_params,
            &power_params,
            &dummy_permutation,
            blinding_r,
            blinding_s,
        );

        let dummy_circuit = create_rs_shuffle_circuit::<G, GV, N, LEVELS>(
            seed,
            &bg_setup_params,
            &dummy_permutation,
            &rs_shuffle_trace.witness_trace,
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
        let _gaurd = setup_test_tracing();
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
            generate_permutation_proving_keys::<E, G, GV, N, LEVELS, StdRng>(&mut rng);

        // Create concrete proof system instances
        let permutation_proof_system = create_groth16_permutation_proof_system::<E, G, GV, N, LEVELS>(
            proving_key,
            verifying_key,
        );
        let reencryption_proof_system = create_reencryption_proof_system::<G, N>();

        // Setup configuration
        let generator = G::generator();
        // Grumpkin scalar field for private key
        let private_key = ark_grumpkin::Fr::rand(&mut rng);
        let public_key = generator * private_key;
        // IMPORTANT: Domain must match the one used during key generation ("test").
        // Otherwise, the Groth16 keys won't match the circuit constants.
        let domain = b"test".to_vec();

        let config = ShufflingConfig {
            domain: domain.clone(),
            generator,
            public_key,
            permutation_proof_system,
            reencryption_proof_system,
        };

        // Create actual input ciphertexts with encrypted values
        let ct_input: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| {
            let message = ark_grumpkin::Fr::from(i as u64);
            let randomness = ark_grumpkin::Fr::rand(&mut rng);
            ElGamalCiphertext::encrypt_scalar(message, randomness, public_key)
        });

        // Test with random seed (Grumpkin's base field which is BN254's scalar field)
        let shuffle_seed = ark_bn254::Fr::rand(&mut rng);

        // Call the generic test function
        type IP = super::super::proof_system::Groth16PermutationProofSystem<E, G, GV, N, LEVELS>;
        type SP = super::super::proof_system::ReencryptionProofSystem<G, N>;

        let result = test_prove_and_verify::<G, GV, IP, SP, N, LEVELS, StdRng>(
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

    #[test]
    fn test_shuffling_proof_with_dummy_permutation() -> Result<(), Box<dyn std::error::Error>> {
        let _tracing_gaurd = setup_test_tracing();
        let mut rng = StdRng::seed_from_u64(12345);

        // Define types for the test
        const N: usize = 10;
        const LEVELS: usize = 3;

        type G = GrumpkinProjective;
        type GV = ProjectiveVar<GrumpkinConfig, FpVar<Fr>>;

        // Create DummyProofSystem for permutation (always succeeds)
        // The DummyProofSystem needs the correct PublicInput and Witness types
        type DummyIP = DummyProofSystem<
            PermutationPublicInput<G, GV, N, LEVELS>,
            PermutationWitness<G, GV, N, LEVELS>,
        >;
        let permutation_proof_system: DummyIP = create_dummy_proof_system();

        // Create real ReencryptionProofSystem for reencryption protocol
        type SP = super::super::proof_system::ReencryptionProofSystem<G, N>;
        let reencryption_proof_system = create_reencryption_proof_system::<G, N>();

        // Setup configuration
        let generator = G::generator();
        // Generate a valid ElGamal public key (sk * G)
        let private_key = ark_grumpkin::Fr::rand(&mut rng);
        let public_key = generator * private_key;
        let domain = b"test_dummy_domain".to_vec();

        let config = ShufflingConfig {
            domain: domain.clone(),
            generator,
            public_key,
            permutation_proof_system,
            reencryption_proof_system,
        };

        // Create actual input ciphertexts with encrypted values
        let ct_input: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| {
            let message = ark_grumpkin::Fr::from(i as u64);
            let randomness = ark_grumpkin::Fr::rand(&mut rng);
            ElGamalCiphertext::encrypt_scalar(message, randomness, public_key)
        });

        // Test with random seed (Grumpkin's base field which is BN254's scalar field)
        let shuffle_seed = ark_bn254::Fr::rand(&mut rng);

        // Test prove and verify using dummy permutation proof system
        println!("Testing shuffling proof with DummyProofSystem for permutation...");

        // Generate the proof - using ? operator for clean error handling
        let (ct_output, proof) = prove_shuffling::<G, GV, DummyIP, SP, N, LEVELS>(
            &config,
            &ct_input,
            shuffle_seed,
            &mut rng,
        )?;
        println!("✓ Proof generation succeeded with dummy permutation proof system");

        // Verify the proof - using ? operator
        let is_valid = verify_shuffling::<G, GV, DummyIP, SP, N, LEVELS>(
            &config,
            &ct_input,
            &ct_output,
            &proof,
            shuffle_seed,
        )?;

        assert!(is_valid, "Proof verification should succeed");
        println!("✓ Proof verification succeeded");

        // Verify that the proof components are as expected
        // DummyProofSystem returns unit type () as proof
        // So we can't inspect the permutation proof, but we can verify reencryption proof exists
        assert!(
            !proof.bg_setup_params.c_perm.is_zero(),
            "BG commitment should be non-zero"
        );
        assert!(
            !proof.bg_setup_params.c_power.is_zero(),
            "BG power commitment should be non-zero"
        );

        println!("✅ Shuffling proof test with dummy permutation passed!");
        Ok(())
    }
}
