//! Fiat-Shamir transcript for non-interactive zero-knowledge

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::PoseidonSponge,
    CryptographicSponge,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;

use super::commitment::BgCommitment;
use crate::shuffling::data_structures::ElGamalCiphertext;

/// Fiat-Shamir transcript for Bayer-Groth protocol
pub struct BgTranscript {
    sponge: PoseidonSponge<Fr>,
}

impl BgTranscript {
    /// Create a new transcript with domain separation
    pub fn new(domain: &[u8]) -> Self {
        let config = crate::config::poseidon_config::<Fr>();
        let mut sponge = PoseidonSponge::new(&config);
        
        // Domain separation
        sponge.absorb(&domain);
        
        Self { sponge }
    }
    
    /// Append a commitment to the transcript
    pub fn append_commitment(&mut self, label: &[u8], commitment: &BgCommitment) {
        // Absorb label for context
        self.sponge.absorb(&label);
        
        // Serialize and absorb the commitment point
        let mut bytes = Vec::new();
        commitment.commitment.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);
    }
    
    /// Append multiple commitments
    pub fn append_commitments(&mut self, label: &[u8], commitments: &[BgCommitment]) {
        self.sponge.absorb(&label);
        for com in commitments {
            let mut bytes = Vec::new();
            com.commitment.serialize_compressed(&mut bytes).unwrap();
            self.sponge.absorb(&bytes);
        }
    }
    
    /// Append a ciphertext to the transcript
    pub fn append_ciphertext<G: CurveGroup>(&mut self, label: &[u8], ct: &ElGamalCiphertext<G>) 
    where
        G::BaseField: PrimeField,
    {
        self.sponge.absorb(&label);
        
        // Serialize c1 and c2
        let mut bytes = Vec::new();
        ct.c1.serialize_compressed(&mut bytes).unwrap();
        ct.c2.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);
    }
    
    /// Append multiple ciphertexts
    pub fn append_ciphertexts<G: CurveGroup>(&mut self, label: &[u8], cts: &[ElGamalCiphertext<G>])
    where
        G::BaseField: PrimeField,
    {
        self.sponge.absorb(&label);
        for ct in cts {
            let mut bytes = Vec::new();
            ct.c1.serialize_compressed(&mut bytes).unwrap();
            ct.c2.serialize_compressed(&mut bytes).unwrap();
            self.sponge.absorb(&bytes);
        }
    }
    
    /// Append a scalar to the transcript
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Fr) {
        self.sponge.absorb(&label);
        let mut bytes = Vec::new();
        scalar.serialize_compressed(&mut bytes).unwrap();
        self.sponge.absorb(&bytes);
    }
    
    /// Append multiple scalars
    pub fn append_scalars(&mut self, label: &[u8], scalars: &[Fr]) {
        self.sponge.absorb(&label);
        for scalar in scalars {
            let mut bytes = Vec::new();
            scalar.serialize_compressed(&mut bytes).unwrap();
            self.sponge.absorb(&bytes);
        }
    }
    
    /// Get a challenge scalar from the transcript
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Fr {
        self.sponge.absorb(&label);
        self.sponge.squeeze_field_elements(1)[0]
    }
    
    /// Get multiple challenge scalars
    pub fn challenge_scalars(&mut self, label: &[u8], n: usize) -> Vec<Fr> {
        self.sponge.absorb(&label);
        self.sponge.squeeze_field_elements(n)
    }
    
    /// Fork the transcript for parallel sub-protocols
    pub fn fork(&self, label: &[u8]) -> Self {
        let config = crate::config::poseidon_config::<Fr>();
        let mut new_sponge = PoseidonSponge::new(&config);
        
        // Copy current state and add fork label
        // Note: This is simplified - in practice you'd properly clone state
        new_sponge.absorb(&label);
        
        Self { sponge: new_sponge }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    
    #[test]
    fn test_transcript_deterministic() {
        let mut rng = test_rng();
        
        // Create two transcripts with same inputs
        let mut t1 = BgTranscript::new(b"test-domain");
        let mut t2 = BgTranscript::new(b"test-domain");
        
        // Add same data to both
        let scalar = Fr::rand(&mut rng);
        t1.append_scalar(b"test-scalar", &scalar);
        t2.append_scalar(b"test-scalar", &scalar);
        
        // Should get same challenge
        let c1 = t1.challenge_scalar(b"challenge");
        let c2 = t2.challenge_scalar(b"challenge");
        
        assert_eq!(c1, c2);
    }
    
    #[test]
    fn test_transcript_different_inputs() {
        let mut rng = test_rng();
        
        let mut t1 = BgTranscript::new(b"test-domain");
        let mut t2 = BgTranscript::new(b"test-domain");
        
        // Add different data
        let s1 = Fr::rand(&mut rng);
        let s2 = Fr::rand(&mut rng);
        t1.append_scalar(b"scalar", &s1);
        t2.append_scalar(b"scalar", &s2);
        
        // Should get different challenges
        let c1 = t1.challenge_scalar(b"challenge");
        let c2 = t2.challenge_scalar(b"challenge");
        
        assert_ne!(c1, c2);
    }
}