//! Common functions shared between demo binaries
//!
//! This module contains all the shared functionality used by both
//! bayer_groth_demo.rs and game_demo.rs to avoid code duplication.

use anyhow::Result;
use ark_crypto_primitives::sponge::{poseidon::constraints::PoseidonSpongeVar, Absorb};
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_std::rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};

use zk_poker::shuffling::{
    community_decryption::{decrypt_community_card, CommunityDecryptionShare},
    curve_absorb::{CurveAbsorb, CurveAbsorbGadget},
    data_structures::ElGamalCiphertext,
    permutation_proof::PermutationGroth16,
    player_decryption::{
        combine_blinding_contributions_for_player, generate_committee_decryption_share,
        recover_card_value, PlayerTargetedBlindingContribution,
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
pub fn setup_game_config<E, G>(shuffler_public_keys: &[G]) -> ShufflingConfig<E, G>
where
    E: ark_ec::pairing::Pairing,
    G: CurveGroup,
{
    // Aggregate all shuffler public keys
    let aggregated_public_key = shuffler_public_keys
        .iter()
        .fold(G::zero(), |acc, pk| acc + pk);

    ShufflingConfig {
        generator: G::generator(),
        public_key: aggregated_public_key,
        perm_snark_keys: Default::default(),
    }
}

fn required_poseidon_samples<F: PrimeField>(total_bits: usize) -> usize {
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let usable_bits_per_element = field_bits.saturating_sub(2);
    (total_bits + usable_bits_per_element - 1) / usable_bits_per_element
}

/// Ensure the permutation SNARK keys needed for the demo are available.
pub fn ensure_permutation_snark_keys<E, G, GV, const N: usize, const LEVELS: usize>(
    config: &mut ShufflingConfig<E, G>,
) -> Result<(usize, bool)>
where
    E: ark_ec::pairing::Pairing<ScalarField = G::BaseField>,
    G: CurveGroup + CurveAbsorb<G::BaseField> + ark_ff::ToConstraintField<G::BaseField>,
    G::Config: CurveConfig,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    GV: CurveVar<G, G::BaseField>
        + CurveAbsorbGadget<G::BaseField, PoseidonSpongeVar<G::BaseField>>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>
        + CurveAbsorbGadget<G::BaseField, PoseidonSpongeVar<G::BaseField>>,
{
    let total_bits = N * LEVELS;
    let num_samples = required_poseidon_samples::<G::BaseField>(total_bits);

    if config.perm_snark_keys.contains_key(&num_samples) {
        return Ok((num_samples, false));
    }

    let mut rng = StdRng::seed_from_u64(123_456_789);
    let perm_sys = PermutationGroth16::<E, G, GV, N, LEVELS>::setup(&mut rng, num_samples)?;

    config.perm_snark_keys.insert(
        num_samples,
        (
            perm_sys.proving_key().clone(),
            perm_sys.prepared_vk().clone(),
        ),
    );

    Ok((num_samples, true))
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
pub fn perform_shuffle_with_proof<E, G, GV, R, const N: usize, const LEVELS: usize>(
    config: &ShufflingConfig<E, G>,
    current_deck: &[ElGamalCiphertext<G>; N],
    vrf_nonce: G::BaseField,
    rng: &mut R,
) -> Result<([ElGamalCiphertext<G>; N], ShufflingProof<E, G, N>), Box<dyn std::error::Error>>
where
    E: ark_ec::pairing::Pairing<ScalarField = G::BaseField>,
    G: CurveGroup + CurveAbsorb<G::BaseField> + ark_ff::ToConstraintField<G::BaseField>,
    G::Config: CurveConfig,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    G::BaseField: PrimeField + Absorb,
    GV: CurveVar<G, G::BaseField>
        + CurveAbsorbGadget<G::BaseField, PoseidonSpongeVar<G::BaseField>>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    for<'a> &'a GV: CurveAbsorbGadget<G::BaseField, PoseidonSpongeVar<G::BaseField>>,
    R: RngCore + CryptoRng,
{
    // Generate proof
    let (shuffled_deck, proof, bg_setup) =
        prove_shuffling::<E, G, GV, N, LEVELS>(config, current_deck, vrf_nonce, rng)?;

    // Verify proof
    let is_valid =
        verify_shuffling::<E, G, N>(config, &bg_setup, current_deck, &shuffled_deck, &proof)?;

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
