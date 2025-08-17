//! Shuffler service for managing card shuffling operations

use crate::shuffling::{
    data_structures::ElGamalCiphertext,
    player_decryption::{
        combine_blinding_contributions_for_player, generate_committee_decryption_share,
        PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
    },
    unified_shuffler::{self, ProofGenerationMetrics, UnifiedShuffleProof, UnifiedShufflerSetup},
};
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::{CryptoRng, Rng, RngCore};
use std::sync::Arc;

/// Shuffler service that manages shuffling operations
pub struct ShufflerService {
    setup: Arc<UnifiedShufflerSetup>,
    secret_key: Fr,
    public_key: G1Affine,
}

impl ShufflerService {
    /// Create a new shuffler service with the given setup and key pair
    pub fn new<R: Rng + RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: Option<Fr>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate or use provided secret key
        let secret_key = secret_key.unwrap_or_else(|| Fr::rand(rng));
        let public_key = (G1Affine::generator() * secret_key).into_affine();

        // Setup unified shuffler parameters
        let setup = unified_shuffler::setup_unified_shuffler(rng)?;

        Ok(Self {
            setup: Arc::new(setup),
            secret_key,
            public_key,
        })
    }

    /// Get the public key of this shuffler
    pub fn public_key(&self) -> G1Affine {
        self.public_key
    }

    /// Shuffle and encrypt a deck of cards
    ///
    /// This function:
    /// 1. Shuffles the input deck using RS shuffle algorithm
    /// 2. Re-encrypts all cards with fresh randomness
    /// 3. Generates both Bayer-Groth and RS+Groth16 proofs
    pub fn shuffle_and_encrypt<R: Rng + RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        input_deck: Vec<ElGamalCiphertext<G1Projective>>,
    ) -> Result<
        (Vec<ElGamalCiphertext<G1Projective>>, UnifiedShuffleProof),
        Box<dyn std::error::Error>,
    > {
        // Generate unified proof
        let proof = unified_shuffler::generate_unified_shuffle_proof(
            rng,
            &self.setup,
            input_deck.clone(),
            self.secret_key,
        )?;

        // Reconstruct outputs from the permutation and re-encryption
        let mut outputs = Vec::new();
        for i in 0..proof.permutation.len() {
            let input_idx = proof.permutation[i];
            let input = &input_deck[input_idx];

            // Re-encrypt with fresh randomness (simplified - in practice would use the same randomness as in proof)
            let r_new = Fr::rand(rng);
            let c1_new = input.c1 + G1Affine::generator() * r_new;
            let c2_new = input.c2 + self.public_key * r_new;

            outputs.push(ElGamalCiphertext::<G1Projective> {
                c1: c1_new,
                c2: c2_new,
            });
        }

        Ok((outputs, proof))
    }

    /// Generate player-targeted blinding contribution
    ///
    /// This is the first phase of the two-phase decryption process.
    /// Each shuffler contributes their secret δ_j to add blinding specifically allowing the target player access.
    pub fn generate_player_blinding_contribution(
        &self,
        aggregated_public_key: G1Projective,
        player_public_key: G1Projective,
    ) -> PlayerTargetedBlindingContribution<G1Projective> {
        // Use a portion of the secret key as the blinding factor (in practice, would generate fresh randomness)
        PlayerTargetedBlindingContribution::generate(
            self.secret_key,
            aggregated_public_key,
            player_public_key,
        )
    }

    /// Combine blinding contributions from all shufflers to create player-accessible ciphertext
    ///
    /// This should be called after all shufflers have submitted their blinding contributions.
    /// It creates the complete public transcript that gets posted on-chain.
    pub fn combine_blinding_contributions(
        initial_ciphertext: &ElGamalCiphertext<G1Projective>,
        contributions: &[PlayerTargetedBlindingContribution<G1Projective>],
        aggregated_public_key: G1Projective,
        player_public_key: G1Projective,
    ) -> Result<PlayerAccessibleCiphertext<G1Projective>, Box<dyn std::error::Error>> {
        combine_blinding_contributions_for_player(
            initial_ciphertext,
            contributions,
            aggregated_public_key,
            player_public_key,
        )
        .map_err(|e| e.into())
    }

    /// Generate partial unblinding share for a player's encrypted card
    ///
    /// This is the second phase of the two-phase decryption process.
    /// Each committee member j computes μ_u,j = A_u^x_j where x_j is their secret share.
    pub fn generate_unblinding_share(
        &self,
        encrypted_card: &PlayerAccessibleCiphertext<G1Projective>,
        member_index: usize,
    ) -> PartialUnblindingShare<G1Projective> {
        generate_committee_decryption_share(encrypted_card, self.secret_key, member_index)
    }

    /// Verify a unified shuffle proof
    pub fn verify_shuffle_proof(
        &self,
        proof: &UnifiedShuffleProof,
        inputs: &[ElGamalCiphertext<G1Projective>],
        outputs: &[ElGamalCiphertext<G1Projective>],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        unified_shuffler::verify_unified_shuffle_proof(
            &self.setup,
            proof,
            inputs,
            outputs,
            self.public_key,
        )
    }

    /// Get proof generation metrics from the last shuffle
    pub fn get_metrics(proof: &UnifiedShuffleProof) -> ProofGenerationMetrics {
        proof.metrics.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::{player_decryption::PlayerAccessibleCiphertext, rs_shuffle::N};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test_shuffler_service() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Create shuffler service
        let shuffler =
            ShufflerService::new(&mut rng, None).expect("Failed to create shuffler service");

        // Create test deck
        let mut deck = Vec::new();
        for i in 0..N {
            let card_value = Fr::from(i as u64);
            let msg = G1Affine::generator() * card_value;
            let r = Fr::rand(&mut rng);
            let c1 = G1Affine::generator() * r;
            let c2 = msg + shuffler.public_key() * r;
            deck.push(ElGamalCiphertext::<G1Projective> { c1, c2 });
        }

        // Shuffle and encrypt
        let (shuffled_deck, proof) = shuffler
            .shuffle_and_encrypt(&mut rng, deck.clone())
            .expect("Failed to shuffle and encrypt");

        assert_eq!(shuffled_deck.len(), N);
        assert_eq!(proof.permutation.len(), N);

        // Test player-targeted blinding contribution
        let aggregated_pk = G1Affine::generator() * Fr::from(123u64);
        let player_pk = G1Affine::generator() * Fr::from(456u64);

        let blinding_contribution =
            shuffler.generate_player_blinding_contribution(aggregated_pk.into(), player_pk.into());

        // Verify the contribution has the expected structure
        assert!(blinding_contribution.verify(aggregated_pk.into(), player_pk.into()));

        // Test unblinding share generation (would need a PlayerAccessibleCiphertext in practice)
        // This is just to verify the API works
        let test_ciphertext = PlayerAccessibleCiphertext {
            blinded_base: G1Affine::generator().into(),
            blinded_message_with_player_key: G1Affine::generator().into(),
            player_unblinding_helper: G1Affine::generator().into(),
            shuffler_proofs: vec![],
        };

        let unblinding_share = shuffler.generate_unblinding_share(&test_ciphertext, 0);
        assert_eq!(unblinding_share.member_index, 0);
    }
}
