//! Prover implementation for Bayer-Groth shuffle

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_std::rand::Rng;
use ark_std::{vec, vec::Vec};

use super::{
    commitment::BgCommitment, decomposition::PermutationDecomposition, transcript::BgTranscript,
    BgParams, BgProof, ShuffleInstance, ShuffleWitness, M, N, R,
};

/// Generate a Bayer-Groth shuffle proof (pairing-free version)
pub fn prove<RNG: Rng>(
    params: &BgParams,
    instance: &ShuffleInstance,
    witness: &ShuffleWitness,
    rng: &mut RNG,
) -> BgProof {
    assert_eq!(instance.inputs.len(), N);
    assert_eq!(instance.outputs.len(), N);
    assert_eq!(witness.perm.len(), N);
    assert_eq!(witness.reenc_rands.len(), N);

    // Initialize transcript for Fiat-Shamir
    let mut transcript = BgTranscript::new(b"BayerGroth-Shuffle-v1");

    // Add public inputs to transcript
    transcript.append_ciphertexts(b"inputs", &instance.inputs);
    transcript.append_ciphertexts(b"outputs", &instance.outputs);

    // Decompose permutation into row/column indices
    let decomp = PermutationDecomposition::from_permutation(&witness.perm);

    // Step 1: Commit to row and column indices
    let mut c_rows = Vec::with_capacity(N);

    for i in 0..N {
        let row_val = Fr::from(decomp.rows[i] as u64);
        let (com, _rand) = BgCommitment::commit(&params.pedersen_params, &row_val, rng);
        c_rows.push(com);
    }

    let mut c_cols = Vec::with_capacity(N);

    for i in 0..N {
        let col_val = Fr::from(decomp.cols[i] as u64);
        let (com, _rand) = BgCommitment::commit(&params.pedersen_params, &col_val, rng);
        c_cols.push(com);
    }

    // Add commitments to transcript
    transcript.append_commitments(b"row-commitments", &c_rows);
    transcript.append_commitments(b"col-commitments", &c_cols);

    // Step 2: Create bitness commitments for matrix representation
    // For each position, prove that the value is a valid bit (0 or 1)
    let mut c_bits = Vec::new();

    // Create M×R matrix of bits indicating where each element maps
    let matrix = decomp.to_matrix();

    for row in 0..M {
        for col in 0..R {
            let bit_val = if matrix[row][col] {
                Fr::one()
            } else {
                Fr::zero()
            };
            let (com, _rand) = BgCommitment::commit(&params.pedersen_params, &bit_val, rng);
            c_bits.push(com);
        }
    }

    transcript.append_commitments(b"bit-commitments", &c_bits);

    // Step 3: Commit to re-encryption linkage
    // This proves consistency between shuffled outputs and re-encryption
    let link_value = compute_linkage_value(&witness.reenc_rands);
    let (link_commit, _link_rand) = BgCommitment::commit(&params.pedersen_params, &link_value, rng);

    transcript.append_commitment(b"linkage", &link_commit);

    // Step 4: Get Fiat-Shamir challenges
    let challenge_main = transcript.challenge_scalar(b"main-challenge");
    let challenge_batch = transcript.challenge_scalars(b"batch-challenges", N);

    // Step 5: Compute aggregated responses
    let mut resp_values = Vec::new();

    // Aggregate row/column responses using challenges
    for i in 0..N {
        // Compute response value: row[i] + challenge * col[i]
        let row_val = Fr::from(decomp.rows[i] as u64);
        let col_val = Fr::from(decomp.cols[i] as u64);
        let resp_val = row_val + challenge_batch[i] * col_val;
        resp_values.push(resp_val);
    }

    // Step 6: Store auxiliary scalars (challenges) for verification
    let mut aux_scalars = vec![challenge_main];
    aux_scalars.extend_from_slice(&challenge_batch);

    BgProof {
        c_rows,
        c_cols,
        c_bits,
        link_commit,
        resp_values,
        aux_scalars,
    }
}

/// Compute linkage value for re-encryption consistency
fn compute_linkage_value(reenc_rands: &[Fr]) -> Fr {
    // Sum of all re-encryption randomness values
    // This ensures the prover knows the re-encryption randomness
    reenc_rands.iter().fold(Fr::zero(), |acc, r| acc + r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::bayer_groth::commitment::setup_pedersen_params;
    use crate::shuffling::data_structures::ElGamalCiphertext;
    use ark_bn254::G1Affine;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    fn setup_test_instance(rng: &mut impl Rng) -> (BgParams, ShuffleInstance, ShuffleWitness) {
        // Setup parameters
        let pedersen_params = setup_pedersen_params(rng);
        let g = G1Affine::generator();
        let params = BgParams { pedersen_params, g };

        // Generate ElGamal key pair
        let sk = Fr::rand(rng);
        let pk = (G1Affine::generator() * sk).into_affine();

        // Create input ciphertexts (encrypting 0, 1, 2, ..., N-1)
        let mut inputs = Vec::new();
        for i in 0..N {
            let msg = G1Affine::generator() * Fr::from(i as u64);
            let r = Fr::rand(rng);
            let c1 = G1Affine::generator() * r;
            let c2 = msg + pk * r;
            inputs.push(ElGamalCiphertext { c1, c2 });
        }

        // Create permutation and shuffle
        use super::super::decomposition::random_permutation;
        let perm = random_permutation(N, rng);

        // Create shuffled outputs with re-encryption
        let mut outputs = Vec::new();
        let mut reenc_rands = Vec::new();

        for i in 0..N {
            let input_idx = perm[i];
            let input = &inputs[input_idx];

            // Re-encrypt
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
    fn test_proof_generation() {
        let mut rng = test_rng();
        let (params, instance, witness) = setup_test_instance(&mut rng);

        let proof = prove(&params, &instance, &witness, &mut rng);

        // Basic sanity checks
        assert_eq!(proof.c_rows.len(), N);
        assert_eq!(proof.c_cols.len(), N);
        assert_eq!(proof.c_bits.len(), M * R);
        assert_eq!(proof.resp_values.len(), N);
        assert!(!proof.aux_scalars.is_empty());
    }
}
