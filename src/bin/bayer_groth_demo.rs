//! Demo binary for Bayer-Groth shuffle proof

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::vec::Vec;
use ark_std::{rand::rngs::StdRng, rand::SeedableRng};

use zk_poker::shuffling::{
    bayer_groth::{
        commitment::setup_pedersen_params, decomposition::random_permutation, prover::prove,
        verifier::verify, BgParams, ShuffleInstance, ShuffleWitness, M, N, R,
    },
    data_structures::ElGamalCiphertext,
};

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

    // Generate random permutation
    println!("\n4. Generating random permutation...");
    let perm = random_permutation(N, &mut rng);

    // Display first few permutation values
    print!("   Permutation (first 10): ");
    for i in 0..10.min(N) {
        print!("{} ", perm[i]);
    }
    println!("...");

    // Shuffle and re-encrypt
    println!("\n5. Shuffling and re-encrypting cards...");
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
    println!("\n6. Generating Bayer-Groth proof...");
    let start = std::time::Instant::now();
    let proof = prove(&params, &instance, &witness, &mut rng);
    let prove_time = start.elapsed();

    println!("   Proof generated in {:?}", prove_time);
    println!("   - Row commitments: {}", proof.c_rows.len());
    println!("   - Column commitments: {}", proof.c_cols.len());
    println!("   - Bit commitments: {}", proof.c_bits.len());
    println!("   - Response values: {}", proof.resp_values.len());

    // Verify proof
    println!("\n7. Verifying proof...");
    let start = std::time::Instant::now();
    let valid = verify(&params, &instance, &proof);
    let verify_time = start.elapsed();

    if valid {
        println!("   ✓ Proof verified successfully in {:?}", verify_time);
    } else {
        println!("   ✗ Proof verification failed!");
    }

    // Test invalid proof
    println!("\n8. Testing invalid proof detection...");
    let mut bad_proof = proof.clone();
    bad_proof.resp_values[0] = Fr::rand(&mut rng);

    let invalid = verify(&params, &instance, &bad_proof);
    if !invalid {
        println!("   ✓ Invalid proof correctly rejected");
    } else {
        println!("   ✗ Invalid proof incorrectly accepted!");
    }

    // Verify shuffle correctness (with secret key for demo)
    println!("\n9. Verifying shuffle correctness (demo only with secret key)...");
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
    println!("Matrix decomposition: {}×{}", M, R);
    println!(
        "Proof size: ~{} group elements",
        proof.c_rows.len() + proof.c_cols.len() + proof.c_bits.len() + 1
    );
    println!("Proving time: {:?}", prove_time);
    println!("Verification time: {:?}", verify_time);
    println!("\nDemo complete!");
}
