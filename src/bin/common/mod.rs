//! Common functions shared between demo binaries
//!
//! This module contains all the shared functionality used by both
//! bayer_groth_demo.rs and game_demo.rs to avoid code duplication.

use ark_crypto_primitives::sponge::{
    poseidon::constraints::PoseidonSpongeVar,
    Absorb,
};
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_std::rand::{CryptoRng, Rng, RngCore};

use zk_poker::shuffling::{
    community_decryption::{decrypt_community_card, CommunityDecryptionShare},
    curve_absorb::{CurveAbsorb, CurveAbsorbGadget},
    data_structures::ElGamalCiphertext,
    player_decryption::{
        combine_blinding_contributions_for_player, generate_committee_decryption_share,
        recover_card_value, PlayerTargetedBlindingContribution,
    },
    proof_system::{
        create_dummy_proof_system, create_reencryption_proof_system, DummyProofSystem,
        PermutationPublicInput, PermutationWitness, ProofSystem, ReencryptionProofSystem,
        ReencryptionPublicInput, ReencryptionWitness,
    },
    shuffling_proof::{prove_shuffling, verify_shuffling, ShufflingConfig, ShufflingProof},
};

// ============================================================================
// Card Display Helpers
// ============================================================================

/// Convert a card ID (0-51) to a readable card name with rank and suit
pub fn card_id_to_string(card_id: u8) -> String {
    const SUITS: [&str; 4] = ["♣", "♦", "♥", "♠"];
    const RANKS: [&str; 13] = [
        "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A",
    ];

    if card_id >= 52 {
        return format!("Invalid({})", card_id);
    }

    let suit_idx = (card_id / 13) as usize;
    let rank_idx = (card_id % 13) as usize;

    format!("{}{}", RANKS[rank_idx], SUITS[suit_idx])
}

/// Format multiple card IDs as a readable string
pub fn format_cards(card_ids: &[u8]) -> String {
    card_ids
        .iter()
        .map(|&id| card_id_to_string(id))
        .collect::<Vec<_>>()
        .join(", ")
}

// ============================================================================
// Setup Functions
// ============================================================================

/// Setup a single shuffler with their secret and public key pair
/// Returns: (secret_key, public_key)
pub fn setup_shuffler<G, R>(rng: &mut R) -> (G::ScalarField, G)
where
    G: CurveGroup,
    G::ScalarField: UniformRand,
    R: RngCore + CryptoRng,
{
    let secret_key = G::ScalarField::rand(rng);
    let public_key = G::generator() * secret_key;
    (secret_key, public_key)
}

/// Setup a single player with their secret and public key pair
/// Returns: (secret_key, public_key)
pub fn setup_player<G, R>(rng: &mut R) -> (G::ScalarField, G)
where
    G: CurveGroup,
    G::ScalarField: UniformRand,
    R: RngCore + CryptoRng,
{
    let secret_key = G::ScalarField::rand(rng);
    let public_key = G::generator() * secret_key;
    (secret_key, public_key)
}

/// Create game configuration with aggregated shuffler public keys and proof systems
pub fn setup_game_config<G, GV, const N: usize, const LEVELS: usize>(
    shuffler_public_keys: &[G],
    domain: Vec<u8>,
) -> ShufflingConfig<
    DummyProofSystem<
        PermutationPublicInput<G, GV, N, LEVELS>,
        PermutationWitness<G, GV, N, LEVELS>,
    >,
    ReencryptionProofSystem<G, N>,
    G,
>
where
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    GV: CurveVar<G, G::BaseField>,
{
    // Aggregate all shuffler public keys
    let aggregated_public_key = shuffler_public_keys
        .iter()
        .fold(G::zero(), |acc, pk| acc + pk);

    // Create proof systems
    let permutation_proof_system = create_dummy_proof_system();
    let reencryption_proof_system = create_reencryption_proof_system::<G, N>();

    ShufflingConfig {
        domain,
        generator: G::generator(),
        public_key: aggregated_public_key,
        permutation_proof_system,
        reencryption_proof_system,
    }
}

/// Create initial encrypted deck of N cards using the aggregated public key
pub fn create_encrypted_deck<G, R, const N: usize>(
    aggregated_public_key: G,
    rng: &mut R,
) -> [ElGamalCiphertext<G>; N]
where
    G: CurveGroup,
    G::ScalarField: UniformRand,
    R: RngCore + CryptoRng,
{
    std::array::from_fn(|i| {
        let message = G::ScalarField::from(i as u64);
        let randomness = G::ScalarField::rand(rng);
        ElGamalCiphertext::encrypt_scalar(message, randomness, aggregated_public_key)
    })
}

// ============================================================================
// Shuffling and Proof Functions
// ============================================================================

/// Perform a single shuffle with complete proof generation and verification
pub fn perform_shuffle_with_proof<G, GV, IP, SP, R, const N: usize, const LEVELS: usize>(
    config: &ShufflingConfig<IP, SP, G>,
    current_deck: &[ElGamalCiphertext<G>; N],
    shuffle_seed: G::BaseField,
    rng: &mut R,
) -> Result<([ElGamalCiphertext<G>; N], ShufflingProof<IP, SP, G, N>), Box<dyn std::error::Error>>
where
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::Config: CurveConfig,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    G::BaseField: PrimeField + Absorb,
    GV: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField, PoseidonSpongeVar<G::BaseField>>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
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
    R: RngCore + CryptoRng,
{
    // Generate proof
    let (shuffled_deck, proof) =
        prove_shuffling::<G, GV, IP, SP, N, LEVELS>(config, current_deck, shuffle_seed, rng)?;

    // Verify proof
    let is_valid = verify_shuffling::<G, GV, IP, SP, N, LEVELS>(
        config,
        current_deck,
        &shuffled_deck,
        &proof,
        shuffle_seed,
    )?;

    if !is_valid {
        return Err("Shuffle proof verification failed".into());
    }

    Ok((shuffled_deck, proof))
}

// ============================================================================
// Decryption Functions
// ============================================================================

/// Decrypt a single card for a player using the two-phase protocol
pub fn decrypt_card_for_player<G, R>(
    encrypted_card: &ElGamalCiphertext<G>,
    player_secret: G::ScalarField,
    shuffler_secrets: &[G::ScalarField],
    aggregated_public_key: G,
    player_public_key: G,
    rng: &mut R,
) -> Result<u8, Box<dyn std::error::Error>>
where
    G: CurveGroup + CurveAbsorb<G::BaseField> + 'static,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    G::Affine: Absorb,
    R: Rng,
{
    // Step 1: Generate blinding contributions from all shufflers
    let blinding_contributions: Vec<PlayerTargetedBlindingContribution<G>> = shuffler_secrets
        .iter()
        .map(|&secret| {
            PlayerTargetedBlindingContribution::generate(
                secret,
                aggregated_public_key,
                player_public_key,
                rng,
            )
        })
        .collect();

    // Step 2: Combine blinding contributions
    let player_ciphertext = combine_blinding_contributions_for_player(
        encrypted_card,
        &blinding_contributions,
        aggregated_public_key,
        player_public_key,
    )
    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Step 3: Generate unblinding shares from all shufflers
    let unblinding_shares = shuffler_secrets
        .iter()
        .enumerate()
        .map(|(idx, &secret)| generate_committee_decryption_share(&player_ciphertext, secret, idx))
        .collect();

    // Step 4: Recover card value
    let card_value = recover_card_value(
        &player_ciphertext,
        player_secret,
        unblinding_shares,
        shuffler_secrets.len(),
    )
    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    Ok(card_value)
}

/// Decrypt multiple cards for a player (e.g., hole cards)
/// Returns error if ANY card fails to decrypt
pub fn decrypt_cards_for_player<G, R>(
    encrypted_cards: &[ElGamalCiphertext<G>],
    player_secret: G::ScalarField,
    shuffler_secrets: &[G::ScalarField],
    aggregated_public_key: G,
    player_public_key: G,
    rng: &mut R,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    G: CurveGroup + CurveAbsorb<G::BaseField> + 'static,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    G::Affine: Absorb,
    R: Rng,
{
    encrypted_cards
        .iter()
        .enumerate()
        .map(|(idx, card)| {
            decrypt_card_for_player(
                card,
                player_secret,
                shuffler_secrets,
                aggregated_public_key,
                player_public_key,
                rng,
            )
            .map_err(|e| format!("Failed to decrypt card {} for player: {}", idx, e).into())
        })
        .collect::<Result<Vec<u8>, Box<dyn std::error::Error>>>()
}

/// Decrypt a community card using committee protocol (no blinding needed)
/// Community cards are public, so we don't need player-specific blinding
pub fn decrypt_community_card_simple<G, R>(
    encrypted_card: &ElGamalCiphertext<G>,
    shuffler_secrets: &[G::ScalarField],
    shuffler_public_keys: &[G],
    rng: &mut R,
) -> Result<u8, Box<dyn std::error::Error>>
where
    G: CurveGroup + CurveAbsorb<G::BaseField> + 'static,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    R: Rng,
{
    // Generate decryption shares from all committee members
    let shares: Vec<CommunityDecryptionShare<G>> = shuffler_secrets
        .iter()
        .enumerate()
        .map(|(idx, &secret)| CommunityDecryptionShare::generate(encrypted_card, secret, idx, rng))
        .collect();

    // Verify shares (optional but recommended for security)
    for (share, &pk) in shares.iter().zip(shuffler_public_keys.iter()) {
        if !share.verify(encrypted_card, pk) {
            return Err("Invalid decryption share".into());
        }
    }

    // Decrypt the card value
    decrypt_community_card(encrypted_card, shares, shuffler_secrets.len()).map_err(|e| e.into())
}

/// Decrypt multiple community cards
pub fn decrypt_community_cards<G, R>(
    encrypted_cards: &[ElGamalCiphertext<G>],
    shuffler_secrets: &[G::ScalarField],
    shuffler_public_keys: &[G],
    rng: &mut R,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    G: CurveGroup + CurveAbsorb<G::BaseField> + 'static,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    R: Rng,
{
    encrypted_cards
        .iter()
        .enumerate()
        .map(|(idx, card)| {
            decrypt_community_card_simple(card, shuffler_secrets, shuffler_public_keys, rng)
                .map_err(|e| format!("Failed to decrypt community card {}: {}", idx, e).into())
        })
        .collect::<Result<Vec<u8>, Box<dyn std::error::Error>>>()
}
