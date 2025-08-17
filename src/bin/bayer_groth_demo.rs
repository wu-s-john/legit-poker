//! Demo binary for Bayer-Groth shuffle proof

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::vec::Vec;
use ark_std::{rand::rngs::StdRng, rand::SeedableRng};

use zk_poker::shuffling::{
    bayer_groth::{
        commitment::setup_pedersen_params, prover::prove, verifier::verify, BgParams,
        ShuffleInstance, ShuffleWitness, M, N, R,
    },
    data_structures::ElGamalCiphertext,
    rs_shuffle::{circuit::RSShuffleIndicesCircuit, witness_preparation::prepare_witness_data},
};

// RS shuffle levels constant
const LEVELS: usize = 5;

fn main() {
    println!("=== Bayer-Groth Shuffle Proof Demo ===");
    println!(
        "Proving shuffle of {} cards ({}×{} matrix decomposition)\n",
        N, M, R
    );

    // Initialize RNG with seed for reproducibility
    let mut rng = StdRng::seed_from_u64(12345);

    // Setup phase
    println!("1. Setting up parameters...");
    let pedersen_params = setup_pedersen_params(&mut rng);
    let g = G1Affine::generator();
    let params = BgParams { pedersen_params, g };

    // Generate ElGamal key pair
    println!("2. Generating ElGamal key pair...");
    let sk = Fr::rand(&mut rng);
    let pk = (G1Affine::generator() * sk).into_affine();
    println!("   Public key generated");

    // Create input deck (52 cards)
    println!("\n3. Creating input deck of {} cards...", N);
    let mut inputs = Vec::new();
    for i in 0..N {
        // Each card is encrypted as a group element
        let card_value = Fr::from(i as u64);
        let msg = G1Affine::generator() * card_value;

        // ElGamal encryption
        let r = Fr::rand(&mut rng);
        let c1 = G1Affine::generator() * r;
        let c2 = msg + pk * r;

        inputs.push(ElGamalCiphertext::<G1Projective> { c1, c2 });
    }
    println!("   {} encrypted cards created", N);

    // Generate permutation using RS shuffle algorithm
    println!("\n4. Generating permutation using RS shuffle algorithm...");

    // Generate seed for deterministic RS shuffle
    let seed = Fr::rand(&mut rng);
    println!("   Seed generated for RS shuffle");

    // Generate witness data using RS shuffle algorithm
    let (witness_data, num_samples) = prepare_witness_data::<Fr, N, LEVELS>(seed);
    println!("   RS shuffle witness data generated");
    println!("   - Levels: {}", LEVELS);
    println!("   - Bit generation samples: {}", num_samples);

    // Extract permutation from the final level of RS shuffle
    let final_sorted = &witness_data.next_levels[LEVELS - 1];
    let mut perm = vec![0usize; N];
    for (position, sorted_row) in final_sorted.iter().enumerate() {
        perm[position] = sorted_row.idx as usize;
    }

    // Verify it's a valid permutation
    let mut check_perm = perm.clone();
    check_perm.sort();
    let is_valid = check_perm == (0..N).collect::<Vec<_>>();
    println!(
        "   Permutation validity check: {}",
        if is_valid { "✓" } else { "✗" }
    );

    // Display bit distribution across levels
    println!("   Bit distribution across levels:");
    for level in 0..LEVELS {
        let ones_count = witness_data.bits_mat[level].iter().filter(|&&b| b).count();
        let zeros_count = N - ones_count;
        println!(
            "     Level {}: {} zeros, {} ones",
            level, zeros_count, ones_count
        );
    }

    // Display first few permutation values
    print!("   Permutation (first 10): ");
    for i in 0..10.min(N) {
        print!("{} ", perm[i]);
    }
    println!("...");

    // Generate Groth16 proof for RS shuffle
    println!("\n5. Generating Groth16 proof for RS shuffle permutation...");

    // Create initial indices (0..N-1)
    let indices_init: Vec<Fr> = (0..N).map(|i| Fr::from(i as u64)).collect();

    // Create shuffled indices from permutation
    let indices_after_shuffle: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

    // Create Fiat-Shamir challenge
    let alpha = Fr::rand(&mut rng);

    // Create circuit instance
    let circuit = RSShuffleIndicesCircuit::<Fr, N, LEVELS> {
        indices_init: indices_init.clone(),
        indices_after_shuffle: indices_after_shuffle.clone(),
        seed,
        alpha,
        witness: witness_data,
        num_samples,
    };

    // Generate trusted setup parameters (in practice, this would be done once in a ceremony)
    println!("   Performing trusted setup...");
    let setup_start = std::time::Instant::now();
    let (groth16_pk, groth16_vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)
            .expect("Failed to generate proving and verifying keys");
    let setup_time = setup_start.elapsed();
    println!("   Setup completed in {:?}", setup_time);

    // Generate proof
    println!("   Generating Groth16 proof...");
    let proof_start = std::time::Instant::now();
    let groth16_proof = Groth16::<Bn254>::prove(&groth16_pk, circuit.clone(), &mut rng)
        .expect("Failed to generate Groth16 proof");
    let groth16_prove_time = proof_start.elapsed();
    println!("   Groth16 proof generated in {:?}", groth16_prove_time);

    // Prepare public inputs for verification
    let mut public_inputs = vec![seed];
    public_inputs.extend(&indices_init);
    public_inputs.extend(&indices_after_shuffle);
    public_inputs.push(alpha);

    // Verify proof
    println!("   Verifying Groth16 proof...");
    let verify_start = std::time::Instant::now();
    let valid_groth16 = Groth16::<Bn254>::verify(&groth16_vk, &public_inputs, &groth16_proof)
        .expect("Failed to verify Groth16 proof");
    let groth16_verify_time = verify_start.elapsed();

    if valid_groth16 {
        println!(
            "   ✓ Groth16 proof verified successfully in {:?}",
            groth16_verify_time
        );
    } else {
        println!("   ✗ Groth16 proof verification failed!");
    }

    println!(
        "   Groth16 proof size: {} bytes",
        groth16_proof.serialized_size(ark_serialize::Compress::Yes)
    );

    // Shuffle and re-encrypt
    println!("\n6. Shuffling and re-encrypting cards...");
    let mut outputs = Vec::new();
    let mut reenc_rands = Vec::new();

    for i in 0..N {
        let input_idx = perm[i];
        let input = &inputs[input_idx];

        // Re-encrypt with fresh randomness
        let r_new = Fr::rand(&mut rng);
        reenc_rands.push(r_new);

        let c1_new = input.c1 + G1Affine::generator() * r_new;
        let c2_new = input.c2 + pk * r_new;

        outputs.push(ElGamalCiphertext::<G1Projective> {
            c1: c1_new,
            c2: c2_new,
        });
    }
    println!("   Shuffle complete");

    // Create instance and witness
    let instance = ShuffleInstance {
        inputs: inputs.clone(),
        outputs: outputs.clone(),
        pk,
    };

    let witness = ShuffleWitness {
        perm: perm.clone(),
        reenc_rands,
    };

    // Generate proof
    println!("\n7. Generating Bayer-Groth proof...");
    let start = std::time::Instant::now();
    let proof = prove(&params, &instance, &witness, &mut rng);
    let prove_time = start.elapsed();

    println!("   Proof generated in {:?}", prove_time);
    println!("   - Row commitments: {}", proof.c_rows.len());
    println!("   - Column commitments: {}", proof.c_cols.len());
    println!("   - Bit commitments: {}", proof.c_bits.len());
    println!("   - Response values: {}", proof.resp_values.len());

    // Verify proof
    println!("\n8. Verifying Bayer-Groth proof...");
    let start = std::time::Instant::now();
    let valid = verify(&params, &instance, &proof);
    let verify_time = start.elapsed();

    if valid {
        println!("   ✓ Proof verified successfully in {:?}", verify_time);
    } else {
        println!("   ✗ Proof verification failed!");
    }

    // Test invalid proof
    println!("\n9. Testing invalid proof detection...");
    let mut bad_proof = proof.clone();
    bad_proof.resp_values[0] = Fr::rand(&mut rng);

    let invalid = verify(&params, &instance, &bad_proof);
    if !invalid {
        println!("   ✓ Invalid proof correctly rejected");
    } else {
        println!("   ✗ Invalid proof incorrectly accepted!");
    }

    // Verify shuffle correctness (with secret key for demo)
    println!("\n10. Verifying shuffle correctness (demo only with secret key)...");
    let mut decrypted_inputs = Vec::new();
    let mut decrypted_outputs = Vec::new();

    for input in &inputs {
        // Decrypt: m = c2 - sk * c1
        let m = (input.c2 - input.c1 * sk).into_affine();
        decrypted_inputs.push(m);
    }

    for output in &outputs {
        let m = (output.c2 - output.c1 * sk).into_affine();
        decrypted_outputs.push(m);
    }

    // Check that outputs are a permutation of inputs
    let mut sorted_inputs = decrypted_inputs.clone();
    let mut sorted_outputs = decrypted_outputs.clone();
    sorted_inputs.sort_by_key(|p| format!("{:?}", p));
    sorted_outputs.sort_by_key(|p| format!("{:?}", p));

    if sorted_inputs == sorted_outputs {
        println!("   ✓ Decrypted outputs are a permutation of inputs");
    } else {
        println!("   ✗ Shuffle verification failed!");
    }

    // Summary
    println!("\n=== Summary ===");
    println!("Deck size: {} cards", N);
    println!("Permutation generation: RS shuffle with {} levels", LEVELS);
    println!("\nGroth16 proof for RS shuffle:");
    println!("  Setup time: {:?}", setup_time);
    println!("  Proving time: {:?}", groth16_prove_time);
    println!("  Verification time: {:?}", groth16_verify_time);
    println!(
        "  Proof size: {} bytes",
        groth16_proof.serialized_size(ark_serialize::Compress::Yes)
    );
    println!("\nBayer-Groth shuffle proof:");
    println!("  Matrix decomposition: {}×{}", M, R);
    println!(
        "  Proof size: ~{} group elements",
        proof.c_rows.len() + proof.c_cols.len() + proof.c_bits.len() + 1
    );
    println!("  Proving time: {:?}", prove_time);
    println!("  Verification time: {:?}", verify_time);
    println!("\nDemo complete!");
}
