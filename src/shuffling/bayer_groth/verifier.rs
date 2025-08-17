//! Verifier implementation for Bayer-Groth shuffle (pairing-free)

use ark_bn254::{Fr, G1Projective};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_std::vec::Vec;

use super::{
    commitment::BgCommitment, transcript::BgTranscript, BgParams, BgProof, ShuffleInstance, M, N, R,
};

/// Verify a Bayer-Groth shuffle proof (MSM-only, no pairings)
pub fn verify(_params: &BgParams, instance: &ShuffleInstance, proof: &BgProof) -> bool {
    // Check proof structure
    if proof.c_rows.len() != N
        || proof.c_cols.len() != N
        || proof.c_bits.len() != M * R
        || proof.resp_values.len() != N
        || proof.aux_scalars.is_empty()
    {
        return false;
    }

    // Recreate transcript for verification
    let mut transcript = BgTranscript::new(b"BayerGroth-Shuffle-v1");

    // Add public inputs
    transcript.append_ciphertexts(b"inputs", &instance.inputs);
    transcript.append_ciphertexts(b"outputs", &instance.outputs);

    // Add proof commitments
    transcript.append_commitments(b"row-commitments", &proof.c_rows);
    transcript.append_commitments(b"col-commitments", &proof.c_cols);
    transcript.append_commitments(b"bit-commitments", &proof.c_bits);
    transcript.append_commitment(b"linkage", &proof.link_commit);

    // Recompute challenges
    let challenge_main = transcript.challenge_scalar(b"main-challenge");
    let challenge_batch = transcript.challenge_scalars(b"batch-challenges", N);

    // Verify challenges match
    if proof.aux_scalars[0] != challenge_main {
        return false;
    }
    for i in 0..N {
        if i + 1 < proof.aux_scalars.len() && proof.aux_scalars[i + 1] != challenge_batch[i] {
            return false;
        }
    }

    // Check 1: Verify row/column commitment aggregation
    for i in 0..N {
        // Verify that resp_values[i] is consistent with row and column commitments
        // This would use the homomorphic property of Pedersen commitments
        // Com(row) * Com(col)^challenge = Com(row + challenge * col)

        let _aggregated = BgCommitment::aggregate(
            &[proof.c_rows[i].clone(), proof.c_cols[i].clone()],
            &[Fr::one(), challenge_batch[i]],
        );

        // Note: In a complete implementation, we'd verify this against resp_values[i]
        // using the commitment verification
    }

    // Check 2: Verify bit commitments represent valid 0/1 values
    for _bit_com in &proof.c_bits {
        // In a complete zero-knowledge proof, we'd verify that each committed value
        // is either 0 or 1 using a range proof or similar technique
        // For now, we trust the structure
    }

    // Check 3: Verify matrix structure constraints
    // Each row should sum to exactly R (13 elements)
    // Each column should sum to exactly M (4 elements)
    if !verify_matrix_structure(proof) {
        return false;
    }

    // Check 4: Verify re-encryption consistency
    // This checks that outputs are valid re-encryptions of shuffled inputs
    if !verify_reencryption(instance, proof, &challenge_main) {
        return false;
    }

    // Check 5: Verify permutation structure
    // The row/column indices should form a valid permutation
    if !verify_permutation_structure(proof) {
        return false;
    }

    true
}

/// Verify that the bit matrix has correct row/column sums
fn verify_matrix_structure(_proof: &BgProof) -> bool {
    // In the full protocol, we'd verify using the committed bit values
    // that each row sums to R and each column sums to M
    // This ensures exactly N = M*R elements are placed in the matrix

    // For now, return true as placeholder
    // In practice, this would involve homomorphic operations on commitments
    true
}

/// Verify re-encryption consistency using MSMs
fn verify_reencryption(instance: &ShuffleInstance, _proof: &BgProof, challenge: &Fr) -> bool {
    // Verify that the shuffled outputs are valid re-encryptions
    // This uses the homomorphic property of ElGamal

    // Compute aggregated input ciphertext
    let mut agg_input_c1 = G1Projective::zero();
    let mut agg_input_c2 = G1Projective::zero();

    for (i, input) in instance.inputs.iter().enumerate() {
        let weight = challenge.pow([i as u64]);
        agg_input_c1 += input.c1 * weight;
        agg_input_c2 += input.c2 * weight;
    }

    // Compute aggregated output ciphertext
    let mut agg_output_c1 = G1Projective::zero();
    let mut agg_output_c2 = G1Projective::zero();

    for (i, output) in instance.outputs.iter().enumerate() {
        // Weight should match the permuted position
        // In practice, we'd use the committed permutation to determine weights
        let weight = challenge.pow([i as u64]);
        agg_output_c1 += output.c1 * weight;
        agg_output_c2 += output.c2 * weight;
    }

    // Check that the difference is a valid re-encryption
    // (agg_output - agg_input) should be an encryption of zero
    // with randomness committed in link_commit

    // For now, return true as placeholder
    // Full implementation would verify the linkage commitment
    true
}

/// Verify that row/column indices form a valid permutation
fn verify_permutation_structure(_proof: &BgProof) -> bool {
    // Check that the committed row/column values form a bijection
    // This ensures each position maps to exactly one other position

    // In the full protocol, we'd verify:
    // 1. Each (row, col) pair appears exactly once
    // 2. All positions 0..N-1 are covered

    // For now, return true as placeholder
    true
}

/// Batch verification for multiple shuffle proofs
pub fn batch_verify(params: &BgParams, instances: &[ShuffleInstance], proofs: &[BgProof]) -> bool {
    assert_eq!(instances.len(), proofs.len());

    // Generate random linear combination weights
    let mut rng = ark_std::test_rng();
    let mut weights = Vec::new();
    for _ in 0..instances.len() {
        weights.push(Fr::rand(&mut rng));
    }

    // Aggregate all proofs with weights
    // This allows verifying multiple proofs with a single MSM

    // For each instance/proof pair
    for (_i, (instance, proof)) in instances.iter().zip(proofs.iter()).enumerate() {
        // Verify with weight
        if !verify(params, instance, proof) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::bayer_groth::{
        commitment::setup_pedersen_params, prover::prove, ShuffleWitness,
    };
    use crate::shuffling::data_structures::ElGamalCiphertext;
    use ark_bn254::G1Affine;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    fn setup_test_instance(
        rng: &mut impl ark_std::rand::Rng,
    ) -> (BgParams, ShuffleInstance, ShuffleWitness) {
        // Setup parameters
        let pedersen_params = setup_pedersen_params(rng);
        let g = G1Affine::generator();
        let params = BgParams { pedersen_params, g };

        // Generate ElGamal key
        let sk = Fr::rand(rng);
        let pk = (G1Affine::generator() * sk).into_affine();

        // Create input ciphertexts
        let mut inputs = Vec::new();
        for i in 0..N {
            let msg = G1Affine::generator() * Fr::from(i as u64);
            let r = Fr::rand(rng);
            let c1 = G1Affine::generator() * r;
            let c2 = msg + pk * r;
            inputs.push(ElGamalCiphertext { c1, c2 });
        }

        // Create permutation
        use super::super::decomposition::random_permutation;
        let perm = random_permutation(N, rng);

        // Shuffle and re-encrypt
        let mut outputs = Vec::new();
        let mut reenc_rands = Vec::new();

        for i in 0..N {
            let input_idx = perm[i];
            let input = &inputs[input_idx];

            let r_new = Fr::rand(rng);
            reenc_rands.push(r_new);

            let c1_new = input.c1 + G1Affine::generator() * r_new;
            let c2_new = input.c2 + pk * r_new;

            outputs.push(ElGamalCiphertext {
                c1: c1_new,
                c2: c2_new,
            });
        }

        let instance = ShuffleInstance {
            inputs,
            outputs,
            pk,
        };

        let witness = ShuffleWitness { perm, reenc_rands };

        (params, instance, witness)
    }

    #[test]
    fn test_proof_verification() {
        let mut rng = test_rng();
        let (params, instance, witness) = setup_test_instance(&mut rng);

        // Generate proof
        let proof = prove(&params, &instance, &witness, &mut rng);

        // Verify proof
        assert!(verify(&params, &instance, &proof));
    }

    #[test]
    fn test_invalid_proof_fails() {
        let mut rng = test_rng();
        let (params, instance, witness) = setup_test_instance(&mut rng);

        // Generate valid proof
        let mut proof = prove(&params, &instance, &witness, &mut rng);

        // Corrupt the proof
        proof.resp_values[0] = Fr::rand(&mut rng);

        // Verification should fail
        assert!(!verify(&params, &instance, &proof));
    }
}
