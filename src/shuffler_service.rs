//! Shuffler service for managing card shuffling operations

use crate::domain::{ActorType, AppendParams, RoomId};
use crate::player_service::DatabaseClient;
use crate::shuffling::{
    data_structures::ElGamalCiphertext,
    game_events::{PlayerBlindingContributionEvent, ShuffleAndEncryptEvent, UnblindingShareEvent},
    player_decryption::{
        combine_blinding_contributions_for_player, generate_committee_decryption_share,
        PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
    },
    unified_shuffler::{self, ProofGenerationMetrics, UnifiedShuffleProof, UnifiedShufflerSetup},
};
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, Rng, RngCore};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Shuffler service that manages shuffling operations
pub struct ShufflerService {
    pub id: String,
    pub game_id: Option<[u8; 32]>,
    setup: Arc<UnifiedShufflerSetup>,
    secret_key: Fr,
    public_key: G1Affine,
    pub db_client: Option<Arc<dyn DatabaseClient>>,
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
            id: format!(
                "shuffler_{}",
                hex::encode(public_key.to_string().as_bytes())
            ),
            game_id: None,
            setup: Arc::new(setup),
            secret_key,
            public_key,
            db_client: None,
        })
    }

    /// Create with database connection and shared setup
    pub fn new_with_db<R: Rng + RngCore + CryptoRng>(
        rng: &mut R,
        shuffler_id: String,
        game_id: [u8; 32],
        setup: Arc<UnifiedShufflerSetup>,
        db_client: Arc<dyn DatabaseClient>,
        secret_key: Option<Fr>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let secret_key = secret_key.unwrap_or_else(|| Fr::rand(rng));
        let public_key = (G1Affine::generator() * secret_key).into_affine();

        Ok(Self {
            id: shuffler_id,
            game_id: Some(game_id),
            setup,
            secret_key,
            public_key,
            db_client: Some(db_client),
        })
    }

    /// Create with existing setup (for GameManager)
    pub fn new_with_setup<R: Rng + RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: Option<Fr>,
        setup: Arc<UnifiedShufflerSetup>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let secret_key = secret_key.unwrap_or_else(|| Fr::rand(rng));
        let public_key = (G1Affine::generator() * secret_key).into_affine();

        Ok(Self {
            id: format!(
                "shuffler_{}",
                hex::encode(public_key.to_string().as_bytes())
            ),
            game_id: None,
            setup,
            secret_key,
            public_key,
            db_client: None,
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
        // For test compatibility, use self.public_key as aggregated key
        // In production, this should be passed as a parameter
        self.shuffle_and_encrypt_with_key(rng, input_deck, self.public_key.into())
    }

    /// Shuffle and encrypt a deck of cards with specified aggregated public key
    pub fn shuffle_and_encrypt_with_key<R: Rng + RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        input_deck: Vec<ElGamalCiphertext<G1Projective>>,
        aggregated_public_key: G1Projective,
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

            // Re-encrypt with fresh randomness using the aggregated public key
            let r_new = Fr::rand(rng);
            let c1_new = input.c1 + G1Affine::generator() * r_new;
            let c2_new = input.c2 + aggregated_public_key * r_new;

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

    /// Shuffle and encrypt with database logging
    pub async fn shuffle_and_encrypt_with_logging<R: Rng + RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        input_deck: Vec<ElGamalCiphertext<G1Projective>>,
        shuffler_index: usize,
        room_id: RoomId,
    ) -> Result<
        (Vec<ElGamalCiphertext<G1Projective>>, UnifiedShuffleProof),
        Box<dyn std::error::Error>,
    > {
        // Perform the shuffle
        let (output_deck, proof) = self.shuffle_and_encrypt(rng, input_deck.clone())?;

        // Create shuffle event if we have a database client
        if let (Some(_db_client), Some(game_id)) = (&self.db_client, self.game_id) {
            let event = ShuffleAndEncryptEvent {
                game_id,
                shuffler_index,
                shuffler_public_key: self.public_key.into(),
                output_deck: output_deck.clone(),
                shuffle_proof: Some(proof.clone()),
                input_deck_hash: hash_deck(&input_deck)?,
                timestamp: Utc::now().timestamp() as u64,
            };

            // Write to database
            self.write_to_database(room_id, "shuffle_and_encrypt", event)
                .await?;
        }

        Ok((output_deck, proof))
    }

    /// Generate blinding contribution with database logging
    pub async fn generate_blinding_with_logging(
        &self,
        aggregated_public_key: G1Projective,
        player_public_key: G1Projective,
        player_id: String,
        card_indices: Vec<usize>,
        shuffler_index: usize,
        room_id: RoomId,
    ) -> Result<PlayerTargetedBlindingContribution<G1Projective>, Box<dyn std::error::Error>> {
        // Generate contribution
        let contribution =
            self.generate_player_blinding_contribution(aggregated_public_key, player_public_key);

        // Create event if we have a database client
        if let (Some(_db_client), Some(game_id)) = (&self.db_client, self.game_id) {
            let player_id_bytes: [u8; 32] = player_id.as_bytes()[..32.min(player_id.len())]
                .try_into()
                .unwrap_or([0u8; 32]);

            let event = PlayerBlindingContributionEvent {
                game_id,
                player_id: player_id_bytes,
                card_indices,
                shuffler_index,
                blinding_contribution: contribution.clone(),
                aggregated_public_key,
                player_public_key,
                timestamp: Utc::now().timestamp() as u64,
            };

            // Write to database
            self.write_to_database(room_id, "blinding_contribution", event)
                .await?;
        }

        Ok(contribution)
    }

    /// Generate unblinding share with database logging
    pub async fn generate_unblinding_with_logging(
        &self,
        encrypted_card: &PlayerAccessibleCiphertext<G1Projective>,
        member_index: usize,
        player_id: String,
        card_indices: Vec<usize>,
        room_id: RoomId,
    ) -> Result<PartialUnblindingShare<G1Projective>, Box<dyn std::error::Error>> {
        // Generate share
        let share = self.generate_unblinding_share(encrypted_card, member_index);

        // Create event if we have a database client
        if let (Some(_db_client), Some(game_id)) = (&self.db_client, self.game_id) {
            let player_id_bytes: [u8; 32] = player_id.as_bytes()[..32.min(player_id.len())]
                .try_into()
                .unwrap_or([0u8; 32]);

            let event = UnblindingShareEvent {
                game_id,
                player_id: player_id_bytes,
                card_indices,
                unblinding_share: share.clone(),
                unblinding_proof: None,
                timestamp: Utc::now().timestamp() as u64,
            };

            // Write to database
            self.write_to_database(room_id, "unblinding_share", event)
                .await?;
        }

        Ok(share)
    }

    // Helper to write events to database
    async fn write_to_database<T: Serialize>(
        &self,
        room_id: RoomId,
        event_type: &str,
        payload: T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let (Some(db_client), Some(game_id)) = (&self.db_client, self.game_id) {
            let params = AppendParams {
                room_id,
                actor_type: ActorType::Shuffler,
                actor_id: self.id.clone(),
                kind: event_type.to_string(),
                payload: serde_json::to_value(payload)?,
                correlation_id: Some(hex::encode(game_id)),
                idempotency_key: None,
            };

            db_client.append_to_transcript(params).await?;
        }
        Ok(())
    }
}

/// Hash a deck of cards for verification
fn hash_deck(
    deck: &[ElGamalCiphertext<G1Projective>],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    for card in deck {
        let mut bytes = Vec::new();
        card.c1.serialize_compressed(&mut bytes)?;
        card.c2.serialize_compressed(&mut bytes)?;
        hasher.update(&bytes);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::{
        player_decryption::{recover_card_value, PlayerAccessibleCiphertext},
        rs_shuffle::N,
    };
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::Zero;
    use tracing::{debug, info};
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new()
            .with_default(tracing::Level::WARN)
            .with_target("game_demo", tracing::Level::DEBUG)
            .with_target("zk_poker", tracing::Level::DEBUG)
            .with_target("shuffling", tracing::Level::DEBUG)
            .with_target("nexus_nova", tracing::Level::DEBUG)
            .with_target("shuffler_service", tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

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

    #[test]
    fn test_complete_shuffle_and_decrypt_protocol() {
        let _guard = setup_test_tracing();
        let mut rng = StdRng::seed_from_u64(42);

        // ============ PHASE 1: SETUP ============
        // Create shared setup for all shufflers
        let shared_setup = Arc::new(
            unified_shuffler::setup_unified_shuffler(&mut rng)
                .expect("Failed to create unified setup"),
        );

        // Create 3 shufflers with the shared setup
        let shuffler1 = ShufflerService::new_with_setup(&mut rng, None, shared_setup.clone())
            .expect("Failed to create shuffler 1");
        let shuffler2 = ShufflerService::new_with_setup(&mut rng, None, shared_setup.clone())
            .expect("Failed to create shuffler 2");
        let shuffler3 = ShufflerService::new_with_setup(&mut rng, None, shared_setup.clone())
            .expect("Failed to create shuffler 3");

        // Compute aggregated public key (sum of all shuffler public keys)
        let pk1: G1Projective = shuffler1.public_key().into();
        let pk2: G1Projective = shuffler2.public_key().into();
        let pk3: G1Projective = shuffler3.public_key().into();
        let aggregated_public_key: G1Projective = pk1 + pk2 + pk3;

        // Create a player with their own keypair
        let player_secret = Fr::rand(&mut rng);
        let player_public_key: G1Projective = (G1Affine::generator() * player_secret).into();

        // ============ PHASE 2: CREATE INITIAL DECK ============
        // Create a full deck of 52 cards, with card 42 at index 0 for testing
        let mut deck = Vec::new();
        let test_card_value = 42u8;

        for i in 0..52 {
            let card_value = if i == 0 { test_card_value } else { i as u8 };
            let message = Fr::from(card_value as u64);
            let message_point: G1Projective = (G1Affine::generator() * message).into();

            // Start with unencrypted cards (c1 = 0, c2 = g^m)
            let card = ElGamalCiphertext::<G1Projective> {
                c1: G1Projective::zero(),
                c2: message_point,
            };
            deck.push(card);
        }

        info!(target: "shuffler_service", "Initial deck created with 52 cards, test card value {} at index 0", test_card_value);

        // ============ PHASE 3: SEQUENTIAL SHUFFLING ============
        // Each shuffler takes turns shuffling and encrypting the deck

        // Shuffler 1 shuffles and encrypts with aggregated key
        let (deck_after_s1, _proof1) = shuffler1
            .shuffle_and_encrypt_with_key(&mut rng, deck.clone(), aggregated_public_key)
            .expect("Shuffler 1 failed to shuffle");
        debug!(target: "shuffler_service", "Shuffler 1 completed shuffle");

        // Shuffler 2 shuffles and re-encrypts with aggregated key
        let (deck_after_s2, _proof2) = shuffler2
            .shuffle_and_encrypt_with_key(&mut rng, deck_after_s1.clone(), aggregated_public_key)
            .expect("Shuffler 2 failed to shuffle");
        debug!(target: "shuffler_service", "Shuffler 2 completed shuffle");

        // Shuffler 3 shuffles and re-encrypts with aggregated key
        let (final_shuffled_deck, _proof3) = shuffler3
            .shuffle_and_encrypt_with_key(&mut rng, deck_after_s2.clone(), aggregated_public_key)
            .expect("Shuffler 3 failed to shuffle");
        debug!(target: "shuffler_service", "Shuffler 3 completed shuffle");

        // We'll test with the first card after shuffling (which could be any card from the original deck)
        // For simplicity, we'll decrypt the first card position
        let shuffled_card = &final_shuffled_deck[0];

        // ============ PHASE 4: PLAYER-TARGETED BLINDING (Two-Phase Decryption - Phase 1) ============
        // Each shuffler generates a blinding contribution for the target player

        let blinding_contribution1 = shuffler1
            .generate_player_blinding_contribution(aggregated_public_key, player_public_key);
        assert!(
            blinding_contribution1.verify(aggregated_public_key, player_public_key),
            "Shuffler 1 blinding contribution invalid"
        );

        let blinding_contribution2 = shuffler2
            .generate_player_blinding_contribution(aggregated_public_key, player_public_key);
        assert!(
            blinding_contribution2.verify(aggregated_public_key, player_public_key),
            "Shuffler 2 blinding contribution invalid"
        );

        let blinding_contribution3 = shuffler3
            .generate_player_blinding_contribution(aggregated_public_key, player_public_key);
        assert!(
            blinding_contribution3.verify(aggregated_public_key, player_public_key),
            "Shuffler 3 blinding contribution invalid"
        );

        debug!(target: "shuffler_service", "All blinding contributions generated and verified");

        // Combine all blinding contributions to create player-accessible ciphertext
        let blinding_contributions = vec![
            blinding_contribution1,
            blinding_contribution2,
            blinding_contribution3,
        ];

        let player_accessible_ciphertext = ShufflerService::combine_blinding_contributions(
            shuffled_card,
            &blinding_contributions,
            aggregated_public_key,
            player_public_key,
        )
        .expect("Failed to combine blinding contributions");

        debug!(target: "shuffler_service", "Blinding contributions combined into player-accessible ciphertext");

        // ============ PHASE 5: PARTIAL UNBLINDING SHARES (Two-Phase Decryption - Phase 2) ============
        // Each shuffler provides their unblinding share

        let unblinding_share1 =
            shuffler1.generate_unblinding_share(&player_accessible_ciphertext, 0);
        let unblinding_share2 =
            shuffler2.generate_unblinding_share(&player_accessible_ciphertext, 1);
        let unblinding_share3 =
            shuffler3.generate_unblinding_share(&player_accessible_ciphertext, 2);

        debug!(target: "shuffler_service", "All unblinding shares generated");

        // ============ PHASE 6: PLAYER DECRYPTS CARD ============
        // Player uses their secret key and all unblinding shares to recover the card value

        let unblinding_shares = vec![unblinding_share1, unblinding_share2, unblinding_share3];

        let recovered_value = recover_card_value(
            &player_accessible_ciphertext,
            player_secret,
            unblinding_shares.clone(),
            3, // expected_members
        )
        .expect("Failed to recover card value");

        info!(target: "shuffler_service", "Recovered card value: {}", recovered_value);

        // ============ VERIFICATION ============
        // Since the deck was shuffled, we don't know which card ended up at position 0
        // We just verify that we recovered a valid card value (0-51)
        assert!(
            recovered_value < 52,
            "Recovered value {} is not a valid card (should be 0-51)",
            recovered_value
        );

        info!(target: "shuffler_service", "✅ Success! Valid card value {} correctly recovered through complete protocol", recovered_value);

        // ============ ADDITIONAL TESTS ============

        // Test 1: Missing an unblinding share should fail (n-of-n requirement)
        let incomplete_shares = vec![unblinding_shares[0].clone(), unblinding_shares[1].clone()];
        let result = recover_card_value(
            &player_accessible_ciphertext,
            player_secret,
            incomplete_shares,
            3, // Still expecting 3 members
        );
        assert!(
            result.is_err(),
            "Should fail with incomplete unblinding shares"
        );
        debug!(target: "shuffler_service", "✅ Correctly failed with incomplete shares");

        // Test 2: Wrong player secret should fail to decrypt correctly
        let wrong_player_secret = Fr::rand(&mut rng);
        let result = recover_card_value(
            &player_accessible_ciphertext,
            wrong_player_secret,
            unblinding_shares.clone(),
            3,
        );
        // Should either error or return an invalid card value (>= 52)
        assert!(
            result.is_err() || result.unwrap() >= 52,
            "Should fail with wrong player secret"
        );
        debug!(target: "shuffler_service", "✅ Correctly failed with wrong player secret");
    }

    #[test]
    fn test_multiple_card_values() {
        let _guard = setup_test_tracing();
        let mut rng = StdRng::seed_from_u64(99);

        // Setup
        let shared_setup = Arc::new(
            unified_shuffler::setup_unified_shuffler(&mut rng)
                .expect("Failed to create unified setup"),
        );

        let shuffler1 = ShufflerService::new_with_setup(&mut rng, None, shared_setup.clone())
            .expect("Failed to create shuffler 1");
        let shuffler2 = ShufflerService::new_with_setup(&mut rng, None, shared_setup.clone())
            .expect("Failed to create shuffler 2");

        let pk1: G1Projective = shuffler1.public_key().into();
        let pk2: G1Projective = shuffler2.public_key().into();
        let aggregated_public_key: G1Projective = pk1 + pk2;

        let player_secret = Fr::rand(&mut rng);
        let player_public_key: G1Projective = (G1Affine::generator() * player_secret).into();

        // Test different positions in the deck
        for test_position in [0usize, 1, 25, 51] {
            // Create a full deck of 52 cards
            let mut initial_deck = Vec::new();
            for i in 0..52 {
                let card_value = i as u8;
                let message = Fr::from(card_value as u64);
                let message_point: G1Projective = (G1Affine::generator() * message).into();

                let card = ElGamalCiphertext::<G1Projective> {
                    c1: G1Projective::zero(),
                    c2: message_point,
                };
                initial_deck.push(card);
            }

            // Shuffle with both shufflers using aggregated key
            let (deck_s1, _) = shuffler1
                .shuffle_and_encrypt_with_key(&mut rng, initial_deck, aggregated_public_key)
                .expect("Shuffle failed");
            let (deck_s2, _) = shuffler2
                .shuffle_and_encrypt_with_key(&mut rng, deck_s1, aggregated_public_key)
                .expect("Shuffle failed");

            // Generate blinding contributions
            let contributions = vec![
                shuffler1.generate_player_blinding_contribution(
                    aggregated_public_key,
                    player_public_key,
                ),
                shuffler2.generate_player_blinding_contribution(
                    aggregated_public_key,
                    player_public_key,
                ),
            ];

            // Test decrypting a card at the test position
            let player_ciphertext = ShufflerService::combine_blinding_contributions(
                &deck_s2[test_position],
                &contributions,
                aggregated_public_key,
                player_public_key,
            )
            .expect("Failed to combine");

            // Generate unblinding shares
            let unblinding_shares = vec![
                shuffler1.generate_unblinding_share(&player_ciphertext, 0),
                shuffler2.generate_unblinding_share(&player_ciphertext, 1),
            ];

            // Recover and verify
            let recovered =
                recover_card_value(&player_ciphertext, player_secret, unblinding_shares, 2)
                    .expect("Recovery failed");

            // Just verify we got a valid card value (0-51)
            assert!(
                recovered < 52,
                "Position {} failed to recover valid card value, got {}",
                test_position,
                recovered
            );
            debug!(target: "shuffler_service", "✅ Position {} recovered valid card value {}", test_position, recovered);
        }
    }
}
