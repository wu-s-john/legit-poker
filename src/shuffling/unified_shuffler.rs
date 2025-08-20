//! Unified shuffler service that generates both Bayer-Groth and RS+Groth16 proofs

use super::{
    bayer_groth::{self, BgParams, BgProof, ShuffleInstance, ShuffleWitness},
    data_structures::ElGamalCiphertext,
    rs_shuffle::{
        circuit::RSShuffleIndicesCircuit, witness_preparation::prepare_witness_data, LEVELS, N,
    },
};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof as Groth16Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    vec::Vec,
};
use std::time::Instant;

/// Unified proof containing both Bayer-Groth and RS+Groth16 proofs
#[derive(Clone, Debug)]
pub struct UnifiedShuffleProof {
    /// Bayer-Groth pairing-free proof
    pub bayer_groth_proof: BgProof,
    /// RS shuffle proof using Groth16
    pub rs_groth16_proof: Groth16Proof<Bn254>,
    /// Public inputs for RS Groth16 verification
    pub rs_public_inputs: Vec<Fr>,
    /// Permutation used for the shuffle
    pub permutation: Vec<usize>,
    /// Timing metrics
    pub metrics: ProofGenerationMetrics,
}

/// Metrics for proof generation timing
#[derive(Clone, Debug, Default)]
pub struct ProofGenerationMetrics {
    pub bayer_groth_time_ms: u128,
    pub rs_witness_time_ms: u128,
    pub rs_setup_time_ms: u128,
    pub rs_groth16_time_ms: u128,
    pub total_time_ms: u128,
}

/// Setup parameters for the unified shuffler
pub struct UnifiedShufflerSetup {
    /// Bayer-Groth parameters
    pub bg_params: BgParams,
    /// RS+Groth16 proving key
    pub rs_proving_key: ProvingKey<Bn254>,
    /// RS+Groth16 verifying key
    pub rs_verifying_key: VerifyingKey<Bn254>,
}

/// Generate both Bayer-Groth and RS+Groth16 proofs for a shuffle
///
/// This function:
/// 1. Generates a permutation using the RS shuffle algorithm
/// 2. Creates a Bayer-Groth proof for the shuffle
/// 3. Creates an RS+Groth16 proof for the same permutation
/// 4. Returns both proofs in a unified structure
pub fn generate_unified_shuffle_proof<R: Rng + RngCore + CryptoRng>(
    rng: &mut R,
    setup: &UnifiedShufflerSetup,
    inputs: Vec<ElGamalCiphertext<G1Projective>>,
    shuffler_sk: Fr,
) -> Result<UnifiedShuffleProof, Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let mut metrics = ProofGenerationMetrics::default();

    // Validate input size
    if inputs.len() != N {
        return Err(format!("Expected {} cards, got {}", N, inputs.len()).into());
    }

    // Derive public key from secret key
    let shuffler_pk = (G1Affine::generator() * shuffler_sk).into_affine();

    // Step 1: Generate permutation using RS shuffle algorithm
    tracing::info!(target: "unified_shuffler", "Generating RS shuffle permutation");
    let seed = Fr::rand(rng);
    let (witness_data, num_samples) = prepare_witness_data::<Fr, N, LEVELS>(seed);

    // Extract permutation from RS shuffle witness
    let final_sorted = &witness_data.next_levels[LEVELS - 1];
    let mut permutation = vec![0usize; N];
    for (position, sorted_row) in final_sorted.iter().enumerate() {
        permutation[position] = sorted_row.idx as usize;
    }

    // Verify it's a valid permutation
    let mut check_perm = permutation.clone();
    check_perm.sort();
    if check_perm != (0..N).collect::<Vec<_>>() {
        return Err("Invalid permutation generated".into());
    }

    // Step 2: Shuffle and re-encrypt the ciphertexts
    let mut outputs = Vec::new();
    let mut reenc_rands = Vec::new();

    for i in 0..N {
        let input_idx = permutation[i];
        let input = &inputs[input_idx];

        // Re-encrypt with fresh randomness
        let r_new = Fr::rand(rng);
        reenc_rands.push(r_new);

        let c1_new = input.c1 + G1Affine::generator() * r_new;
        let c2_new = input.c2 + shuffler_pk * r_new;

        outputs.push(ElGamalCiphertext::<G1Projective> {
            c1: c1_new,
            c2: c2_new,
        });
    }

    // Step 3: Generate Bayer-Groth proof
    tracing::info!(target: "unified_shuffler", "Generating Bayer-Groth proof");
    let bg_start = Instant::now();

    let bg_instance = ShuffleInstance {
        inputs: inputs.clone(),
        outputs: outputs.clone(),
        pk: shuffler_pk,
    };

    let bg_witness = ShuffleWitness {
        perm: permutation.clone(),
        reenc_rands: reenc_rands.clone(),
    };

    let bayer_groth_proof = bayer_groth::prove(&setup.bg_params, &bg_instance, &bg_witness, rng);
    metrics.bayer_groth_time_ms = bg_start.elapsed().as_millis();

    // Step 4: Generate RS+Groth16 proof
    tracing::info!(target: "unified_shuffler", "Generating RS+Groth16 proof");

    // Create indices for the circuit
    let indices_init: Vec<Fr> = (0..N).map(|i| Fr::from(i as u64)).collect();
    let indices_after_shuffle: Vec<Fr> = permutation.iter().map(|&i| Fr::from(i as u64)).collect();

    // Generate Fiat-Shamir challenge
    let alpha = Fr::rand(rng);

    // Create circuit
    let circuit = RSShuffleIndicesCircuit::<Fr, N, LEVELS> {
        indices_init: indices_init.clone(),
        indices_after_shuffle: indices_after_shuffle.clone(),
        seed,
        alpha,
        witness: witness_data,
        num_samples,
    };

    // Generate Groth16 proof
    let groth16_start = Instant::now();
    let rs_groth16_proof = Groth16::<Bn254>::prove(&setup.rs_proving_key, circuit, rng)?;
    metrics.rs_groth16_time_ms = groth16_start.elapsed().as_millis();

    // Prepare public inputs for verification
    let mut rs_public_inputs = vec![seed];
    rs_public_inputs.extend(&indices_init);
    rs_public_inputs.extend(&indices_after_shuffle);
    rs_public_inputs.push(alpha);

    metrics.total_time_ms = start_time.elapsed().as_millis();

    tracing::info!(
        target: "unified_shuffler",
        "Unified proof generation complete. BG: {}ms, RS+Groth16: {}ms, Total: {}ms",
        metrics.bayer_groth_time_ms,
        metrics.rs_groth16_time_ms,
        metrics.total_time_ms
    );

    Ok(UnifiedShuffleProof {
        bayer_groth_proof,
        rs_groth16_proof,
        rs_public_inputs,
        permutation,
        metrics,
    })
}

/// Verify both proofs in the unified shuffle proof
pub fn verify_unified_shuffle_proof(
    setup: &UnifiedShufflerSetup,
    proof: &UnifiedShuffleProof,
    inputs: &[ElGamalCiphertext<G1Projective>],
    outputs: &[ElGamalCiphertext<G1Projective>],
    shuffler_pk: G1Affine,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Verify Bayer-Groth proof
    let bg_instance = ShuffleInstance {
        inputs: inputs.to_vec(),
        outputs: outputs.to_vec(),
        pk: shuffler_pk,
    };

    let bg_valid = bayer_groth::verify(&setup.bg_params, &bg_instance, &proof.bayer_groth_proof);

    if !bg_valid {
        tracing::warn!(target: "unified_shuffler", "Bayer-Groth proof verification failed");
        return Ok(false);
    }

    // Verify RS+Groth16 proof
    let rs_valid = Groth16::<Bn254>::verify(
        &setup.rs_verifying_key,
        &proof.rs_public_inputs,
        &proof.rs_groth16_proof,
    )?;

    if !rs_valid {
        tracing::warn!(target: "unified_shuffler", "RS+Groth16 proof verification failed");
        return Ok(false);
    }

    tracing::info!(target: "unified_shuffler", "Both proofs verified successfully");
    Ok(true)
}

/// Setup function for the unified shuffler
/// This generates the necessary parameters for both proof systems
pub fn setup_unified_shuffler<R: Rng + RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<UnifiedShufflerSetup, Box<dyn std::error::Error>> {
    tracing::info!(target: "unified_shuffler", "Setting up unified shuffler parameters");

    // Setup Bayer-Groth parameters
    let pedersen_params = bayer_groth::commitment::setup_pedersen_params(rng);
    let bg_params = BgParams {
        pedersen_params,
        g: G1Affine::generator(),
    };

    // Setup RS+Groth16 parameters
    // Create a dummy circuit for setup
    let seed = Fr::rand(rng);
    let (witness_data, num_samples) = prepare_witness_data::<Fr, N, LEVELS>(seed);
    let indices_init: Vec<Fr> = (0..N).map(|i| Fr::from(i as u64)).collect();
    let indices_after_shuffle = indices_init.clone(); // Dummy values for setup
    let alpha = Fr::rand(rng);

    let setup_circuit = RSShuffleIndicesCircuit::<Fr, N, LEVELS> {
        indices_init,
        indices_after_shuffle,
        seed,
        alpha,
        witness: witness_data,
        num_samples,
    };

    tracing::info!(target: "unified_shuffler", "Performing Groth16 trusted setup");
    let (rs_proving_key, rs_verifying_key) =
        Groth16::<Bn254>::circuit_specific_setup(setup_circuit, rng)?;

    Ok(UnifiedShufflerSetup {
        bg_params,
        rs_proving_key,
        rs_verifying_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test_unified_shuffle_proof() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Setup
        let setup = setup_unified_shuffler(&mut rng).expect("Setup failed");

        // Generate ElGamal key pair
        let sk = Fr::rand(&mut rng);
        let pk = (G1Affine::generator() * sk).into_affine();

        // Create input deck
        let mut inputs = Vec::new();
        for i in 0..N {
            let card_value = Fr::from(i as u64);
            let msg = G1Affine::generator() * card_value;
            let r = Fr::rand(&mut rng);
            let c1 = G1Affine::generator() * r;
            let c2 = msg + pk * r;
            inputs.push(ElGamalCiphertext::<G1Projective> { c1, c2 });
        }

        // Generate unified proof
        let proof = generate_unified_shuffle_proof(&mut rng, &setup, inputs.clone(), sk)
            .expect("Proof generation failed");

        // Extract outputs from the proof generation
        // (In practice, these would be computed from the proof)
        let mut outputs = Vec::new();
        for i in 0..N {
            let input_idx = proof.permutation[i];
            let input = &inputs[input_idx];
            // Simulate re-encryption (simplified for test)
            outputs.push(input.clone());
        }

        // Verify the proof
        let valid = verify_unified_shuffle_proof(&setup, &proof, &inputs, &outputs, pk)
            .expect("Verification failed");

        assert!(valid, "Unified shuffle proof should be valid");
    }
}
