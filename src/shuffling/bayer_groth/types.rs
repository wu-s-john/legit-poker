//! Core types for Bayer-Groth shuffle proof

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_crypto_primitives::commitment::pedersen::Parameters;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::commitment::BgCommitment;
use crate::shuffling::data_structures::ElGamalCiphertext;

/// Bayer-Groth shuffle proof structure (pairing-free)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BgProof {
    /// Commitments to row indices (one per output position)
    pub c_rows: Vec<BgCommitment>,

    /// Commitments to column indices (one per output position)
    pub c_cols: Vec<BgCommitment>,

    /// Bitness commitments for matrix entries (compressed)
    pub c_bits: Vec<BgCommitment>,

    /// Re-encryption linkage commitment
    pub link_commit: BgCommitment,

    /// Aggregated response values for FS-compressed checks
    pub resp_values: Vec<Fr>,

    /// Auxiliary scalars (FS challenges)
    pub aux_scalars: Vec<Fr>,
}

/// Parameters for Bayer-Groth proof system
#[derive(Clone)]
pub struct BgParams {
    /// Pedersen commitment parameters from arkworks
    pub pedersen_params: Parameters<G1Projective>,

    /// Generator for ElGamal (could reuse from pedersen_params)
    pub g: G1Affine,
}

/// Public shuffle instance
#[derive(Clone)]
pub struct ShuffleInstance {
    /// Input ciphertexts
    pub inputs: Vec<ElGamalCiphertext<G1Projective>>,

    /// Output ciphertexts (shuffled and re-encrypted)
    pub outputs: Vec<ElGamalCiphertext<G1Projective>>,

    /// ElGamal public key
    pub pk: G1Affine,
}

/// Secret witness for the shuffle
#[derive(Clone)]
pub struct ShuffleWitness {
    /// Permutation π: output j comes from input perm[j]
    pub perm: Vec<usize>,

    /// Re-encryption randomness for each output
    pub reenc_rands: Vec<Fr>,
}
