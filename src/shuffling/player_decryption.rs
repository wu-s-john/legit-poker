use super::chaum_pedersen::ChaumPedersenProof;
use super::curve_absorb::CurveAbsorb;
use super::data_structures::ElGamalCiphertext;
use crate::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{collections::HashMap, sync::Mutex};
use once_cell::sync::Lazy;
use tracing::{instrument, warn};

const LOG_TARGET: &str = "nexus_nova::shuffling::player_decryption";

/// Player-targeted blinding contribution from a single shuffler
/// Each shuffler contributes their secret δ_j to add blinding specifically allowing the target player access
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlayerTargetedBlindingContribution<C: CurveGroup> {
    /// g^δ_j - shuffler's blinding contribution to the base element
    pub blinding_base_contribution: C,
    /// (aggregated_public_key·player_public_key)^δ_j - shuffler's blinding contribution combined with player key
    pub blinding_combined_contribution: C,
    /// Proof that the same δ_j was used for both contributions
    pub proof: ChaumPedersenProof<C>,
}

impl<C> PlayerTargetedBlindingContribution<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C: CurveAbsorb<C::BaseField>,
{
    /// Generate a player-targeted blinding contribution with a Chaum-Pedersen proof
    ///
    /// # Arguments
    /// * `secret_share` - The shuffler's secret share δ_j
    /// * `aggregated_public_key` - The aggregated public key from all shufflers (pk)
    /// * `player_public_key` - The target player's public key (y_u)
    #[instrument(skip(secret_share, rng), level = "trace")]
    pub fn generate<R: Rng>(
        secret_share: C::ScalarField,
        aggregated_public_key: C,
        player_public_key: C,
        rng: &mut R,
    ) -> Self {
        let generator = C::generator();

        // Compute public values
        // Blinding base: g^secret_share_j
        let blinding_base_contribution = (generator * secret_share).into_affine().into_group();

        // H = aggregated_public_key · player_public_key (combined base)
        let h = (aggregated_public_key + player_public_key)
            .into_affine()
            .into_group();

        // Blinding combined: H^secret_share_j = (aggregated_public_key · player_public_key)^secret_share_j
        let blinding_combined_contribution = (h * secret_share).into_affine().into_group();

        // Generate the non-interactive Chaum-Pedersen proof (deterministic)
        let config = poseidon_config::<C::BaseField>();
        let mut sponge = PoseidonSponge::new(&config);
        let proof = ChaumPedersenProof::prove(&mut sponge, secret_share, generator, h, rng);

        Self {
            blinding_base_contribution,
            blinding_combined_contribution,
            proof,
        }
    }

    /// Verify a shuffler's blinding contribution Chaum-Pedersen proof
    ///
    /// # Arguments
    /// * `aggregated_public_key` - The aggregated public key from all shufflers
    /// * `player_public_key` - The target player's public key
    #[instrument(skip(self), level = "trace")]
    pub fn verify(&self, aggregated_public_key: C, player_public_key: C) -> bool {
        let generator = C::generator();
        let h = aggregated_public_key + player_public_key;

        // Verify the non-interactive proof
        let config = poseidon_config::<C::BaseField>();
        let mut sponge = PoseidonSponge::new(&config);
        let result = self.proof.verify(
            &mut sponge,
            generator,
            h,
            self.blinding_base_contribution,
            self.blinding_combined_contribution,
        );

        if !result {
            warn!(target: LOG_TARGET, "Blinding contribution proof verification failed!");
        }

        result
    }
}

/// Player-accessible ciphertext for a specific card
/// This is the complete public transcript that gets posted on-chain,
/// specifically structured so only the target player can access the card value
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlayerAccessibleCiphertext<C: CurveGroup> {
    /// g^(r+Δ) where r is initial randomness and Δ = Σδ_j - the blinded base element
    pub blinded_base: C,
    /// pk^(r+Δ) * g^m_i * y_u^Δ where m_i is the card value - includes player-specific term
    pub blinded_message_with_player_key: C,
    /// g^Δ = g^(Σδ_j) - helper element allowing player to remove their specific blinding
    pub player_unblinding_helper: C,
    /// All Chaum-Pedersen proofs from each shuffler, proving correct blinding
    pub shuffler_proofs: Vec<ChaumPedersenProof<C>>,
}

/// Partial unblinding share from a single committee member
/// Each committee member j provides their portion of unblinding: blinded_base^x_j where x_j is their secret share
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PartialUnblindingShare<C: CurveGroup> {
    /// blinded_base^x_j - the partial unblinding from committee member j
    pub share: C,
    /// Index of the committee member providing this share
    pub member_index: usize,
}

/// Pre-computed mapping between card values (0-51) and their group element representations
/// This allows O(1) lookup when recovering card values from decrypted group elements
struct CardValueMap<C: CurveGroup> {
    /// Reverse mapping from group element to card value for O(1) lookup
    element_to_value: HashMap<C, u8>,
    /// Forward mapping from card value to group element
    value_to_element: Vec<C>,
}

impl<C: CurveGroup> CardValueMap<C> {
    /// Create a new card value mapping by pre-computing g^i for i ∈ [0, 51]
    fn new() -> Self {
        let generator = C::generator();
        let mut element_to_value = HashMap::new();
        let mut value_to_element = Vec::with_capacity(52);

        // Pre-compute g^i for all valid card values
        for i in 0u8..52 {
            let element = generator * C::ScalarField::from(i);
            element_to_value.insert(element, i);
            value_to_element.push(element);
        }

        Self {
            element_to_value,
            value_to_element,
        }
    }

    /// Lookup the card value for a given group element
    /// Returns None if the element doesn't correspond to a valid card
    fn lookup(&self, element: &C) -> Option<u8> {
        self.element_to_value.get(element).copied()
    }
}

/// Lazy-initialized card value mappings for different curve types
/// Each curve type will have its mapping computed once on first use
static CARD_MAPS: Lazy<Mutex<HashMap<std::any::TypeId, Box<dyn std::any::Any + Send + Sync>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Get or create the card value mapping for a specific curve type
fn get_card_value_map<C: CurveGroup + 'static>() -> CardValueMap<C> {
    let mut maps = CARD_MAPS.lock().unwrap();
    let type_id = std::any::TypeId::of::<C>();

    maps.entry(type_id)
        .or_insert_with(|| Box::new(CardValueMap::<C>::new()))
        .downcast_ref::<CardValueMap<C>>()
        .unwrap()
        .clone()
}

impl<C: CurveGroup> Clone for CardValueMap<C> {
    fn clone(&self) -> Self {
        Self {
            element_to_value: self.element_to_value.clone(),
            value_to_element: self.value_to_element.clone(),
        }
    }
}

/// Combines blinding contributions from all shufflers to create player-accessible ciphertext
///
/// This creates the complete public transcript that gets posted on-chain.
/// All proofs are included so anyone can verify the blinding was done correctly.
///
/// # Arguments
/// * `initial_ciphertext` - The ElGamal ciphertext from the shuffled deck
/// * `blinding_contributions` - Blinding contributions from each committee member
/// * `aggregated_public_key` - The aggregated public key from all shufflers
/// * `player_public_key` - The target player's public key
#[instrument(skip(initial_ciphertext, blinding_contributions), level = "trace")]
pub fn combine_blinding_contributions_for_player<C: CurveGroup>(
    initial_ciphertext: &ElGamalCiphertext<C>,
    blinding_contributions: &[PlayerTargetedBlindingContribution<C>],
    aggregated_public_key: C,
    player_public_key: C,
) -> Result<PlayerAccessibleCiphertext<C>, &'static str>
where
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
    C: CurveAbsorb<C::BaseField>,
{
    // First verify all blinding contributions using try_for_each for early abort
    blinding_contributions
        .iter()
        .enumerate()
        .try_for_each(|(i, contribution)| {
            if !contribution.verify(aggregated_public_key, player_public_key) {
                warn!(target: LOG_TARGET, "Invalid blinding contribution at index {}", i);
                Err("Invalid blinding contribution")
            } else {
                Ok(())
            }
        })?;

    // Combine all blinding contributions using separate folds for clarity

    // Accumulate blinded base: g^r + Σg^δ_j
    let blinded_base = blinding_contributions
        .iter()
        .fold(initial_ciphertext.c1, |acc, contribution| {
            acc + contribution.blinding_base_contribution
        });

    // Accumulate blinded message with player key: pk^r * g^m_i + Σ(pk·y_u)^δ_j
    let blinded_message_with_player_key = blinding_contributions
        .iter()
        .fold(initial_ciphertext.c2, |acc, contribution| {
            acc + contribution.blinding_combined_contribution
        });

    // Accumulate player unblinding helper: Σg^δ_j
    let player_unblinding_helper = blinding_contributions
        .iter()
        .fold(C::zero(), |acc, contribution| {
            acc + contribution.blinding_base_contribution
        });

    // Collect all proofs for the transcript
    let proofs: Vec<_> = blinding_contributions
        .iter()
        .map(|contribution| contribution.proof.clone())
        .collect();

    Ok(PlayerAccessibleCiphertext {
        blinded_base,
        blinded_message_with_player_key,
        player_unblinding_helper,
        shuffler_proofs: proofs,
    })
}

/// Batch verification for multiple shuffler encryption shares
/// Note: This assumes all shares use the same aggregated_public_key
#[instrument(skip(shares, _rng), level = "trace")]
pub fn batch_verify_shuffler_shares<C, R>(
    shares: &[PlayerTargetedBlindingContribution<C>],
    aggregated_public_key: C,
    player_public_key: C,
    _rng: &mut R,
) -> bool
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
    C: CurveAbsorb<C::BaseField>,
    R: Rng,
{
    if shares.is_empty() {
        warn!(target: LOG_TARGET, "No shares to verify");
        return false;
    }

    // Verify each share individually since they use context-based proofs
    // In the future, this could be optimized with a custom batch verification
    for (i, share) in shares.iter().enumerate() {
        if !share.verify(aggregated_public_key, player_public_key) {
            warn!(target: LOG_TARGET, "Share {} failed verification", i);
            return false;
        }
    }

    true
}

/// Generate a decryption share for a specific player's encrypted card
///
/// Each committee member j computes μ_u,j = A_u^x_j where x_j is their secret share.
/// This is a single exponentiation that can be pre-computed to avoid timing attacks.
///
/// # Arguments
/// * `encrypted_card` - The player's encrypted card containing A_u
/// * `committee_secret` - The committee member's secret share x_j
/// * `member_index` - The index of this committee member
#[instrument(skip(committee_secret), level = "trace")]
pub fn generate_committee_decryption_share<C: CurveGroup>(
    encrypted_card: &PlayerAccessibleCiphertext<C>,
    committee_secret: C::ScalarField,
    member_index: usize,
) -> PartialUnblindingShare<C> {
    // Compute μ_u,j = blinded_base^x_j = g^((r+Δ) * x_j)
    let share = encrypted_card.blinded_base * committee_secret;

    PartialUnblindingShare {
        share,
        member_index,
    }
}

/// Aggregate committee decryption shares to compute μ_u = pk^(r+Δ)
///
/// IMPORTANT: This is an n-of-n scheme - ALL committee members must provide shares.
/// This is not a threshold scheme; if any member's share is missing, decryption will fail.
///
/// # Arguments
/// * `shares` - Decryption shares from ALL n committee members
/// * `expected_members` - The expected number of committee members
///
/// # Returns
/// The aggregated value μ_u = ∏(μ_u,j) = A_u^x where x = Σx_j
#[instrument(skip(shares), level = "trace")]
pub fn combine_unblinding_shares<C: CurveGroup>(
    shares: &[PartialUnblindingShare<C>],
    expected_members: usize,
) -> Result<C, &'static str> {
    // Verify we have exactly n shares (n-of-n requirement)
    if shares.len() != expected_members {
        warn!(target: LOG_TARGET,
            "Expected {} shares but got {}",
            expected_members, shares.len()
        );
        return Err(
            "Missing committee member shares - this is an n-of-n scheme requiring all members",
        );
    }

    // Verify all member indices are unique and in range
    let mut seen_indices = vec![false; expected_members];
    for share in shares {
        if share.member_index >= expected_members {
            warn!(target: LOG_TARGET,
                "Invalid member index: {} (max: {})",
                share.member_index, expected_members - 1
            );
            return Err("Invalid member index");
        }
        if seen_indices[share.member_index] {
            warn!(target: LOG_TARGET,
                "Duplicate member index: {}",
                share.member_index
            );
            return Err("Duplicate member index");
        }
        seen_indices[share.member_index] = true;
    }

    // Aggregate by multiplying all shares: μ_u = ∏(μ_u,j)
    // This gives us A_u^(Σx_j) = A_u^x = g^((r+Δ) * x) = pk^(r+Δ)
    let mut mu = C::zero();
    for share in shares {
        if mu.is_zero() {
            mu = share.share;
        } else {
            mu = mu + share.share;
        }
    }

    Ok(mu)
}

/// Decrypt a player's encrypted card using their secret and committee decryption shares
///
/// This implements the complete decryption protocol:
/// 1. Player uses their secret s_u to compute S = D^s_u (cancels committee blinding)
/// 2. Committee members provide decryption shares μ_u,j = A_u^x_j
/// 3. Shares are aggregated to get μ_u = pk^(r+Δ)
/// 4. Message is recovered: g^m = B_u / (μ_u · S)
/// 5. Card value is found by lookup in pre-computed table
///
/// # Arguments
/// * `encrypted_card` - The encrypted card for this player
/// * `player_secret` - The player's secret key s_u (only the player knows this)
/// * `committee_shares` - Decryption shares from ALL committee members (n-of-n)
/// * `expected_members` - The expected number of committee members
///
/// # Returns
/// The decrypted card value (0-51) or an error if decryption fails
#[instrument(skip(player_secret, unblinding_shares), level = "trace")]
pub fn recover_card_value<C>(
    player_ciphertext: &PlayerAccessibleCiphertext<C>,
    player_secret: C::ScalarField,
    unblinding_shares: Vec<PartialUnblindingShare<C>>,
    expected_members: usize,
) -> Result<u8, &'static str>
where
    C: CurveGroup + 'static,
    C::ScalarField: PrimeField,
{
    tracing::debug!(
        target: LOG_TARGET,
        blinded_base = ?player_ciphertext.blinded_base,
        blinded_message = ?player_ciphertext.blinded_message_with_player_key,
        helper = ?player_ciphertext.player_unblinding_helper,
        ?player_secret,
        "=== Native recover_card_value ==="
    );

    // Step 1: Compute player-specific unblinding using the helper element
    // Only the player can do this as it requires knowing s_u
    let player_unblinding = player_ciphertext.player_unblinding_helper * player_secret;
    tracing::debug!(
        target: LOG_TARGET,
        ?player_unblinding,
        "Player unblinding (helper * secret)"
    );

    // Step 2: Combine committee unblinding shares
    // This requires ALL n committee members (n-of-n scheme)
    let combined_unblinding = combine_unblinding_shares(&unblinding_shares, expected_members)?;
    tracing::debug!(
        target: LOG_TARGET,
        ?combined_unblinding,
        expected_members,
        actual_shares = unblinding_shares.len(),
        "Combined unblinding"
    );

    // Step 3: Recover the message group element by removing all blinding
    // g^m = blinded_message / (combined_unblinding · player_unblinding)
    let recovered_element =
        player_ciphertext.blinded_message_with_player_key - combined_unblinding - player_unblinding;
    tracing::debug!(
        target: LOG_TARGET,
        ?recovered_element,
        "Recovered element"
    );

    // Step 4: Map the group element back to a card value using pre-computed table
    let card_map = get_card_value_map::<C>();

    tracing::debug!(target: LOG_TARGET, "Looking up in card map...");
    // Check what the expected values should be for our test indices
    let generator = C::generator();
    for i in 48u8..52 {
        let expected = generator * C::ScalarField::from(i);
        tracing::trace!(target: LOG_TARGET, "g^{} = {:?}", i, expected);
        if expected == recovered_element {
            tracing::debug!(target: LOG_TARGET, "Found match at index {}", i);
        }
    }

    match card_map.lookup(&recovered_element) {
        Some(card_value) => {
            tracing::debug!(target: LOG_TARGET, "Successfully found card value: {}", card_value);
            Ok(card_value)
        }
        None => {
            warn!(target: LOG_TARGET,
                "Failed to find card value for recovered element"
            );
            Err("Recovered element does not correspond to a valid card value")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use ark_std::Zero;

    #[test]
    fn test_player_targeted_blinding_contribution_proof() {
        let mut rng = test_rng();

        // Setup - Generate keys for committee and player
        let committee_secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let aggregated_public_key = GrumpkinProjective::generator() * committee_secret;

        let player_secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Create a PlayerTargetedBlindingContribution with proof
        let secret_share = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let contribution = PlayerTargetedBlindingContribution::generate(
            secret_share,
            aggregated_public_key,
            player_public_key,
            &mut rng,
        );

        // Verify the proof is valid
        assert!(
            contribution.verify(aggregated_public_key, player_public_key),
            "Valid proof should verify successfully"
        );

        // Test that tampering with blinding_base_contribution makes verification fail
        let mut bad_contribution = contribution.clone();
        bad_contribution.blinding_base_contribution = GrumpkinProjective::generator()
            * <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        assert!(
            !bad_contribution.verify(aggregated_public_key, player_public_key),
            "Tampered blinding_base_contribution should fail verification"
        );

        // Test that tampering with blinding_combined_contribution makes verification fail
        let mut bad_contribution = contribution.clone();
        bad_contribution.blinding_combined_contribution = GrumpkinProjective::generator()
            * <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        assert!(
            !bad_contribution.verify(aggregated_public_key, player_public_key),
            "Tampered blinding_combined_contribution should fail verification"
        );
    }

    #[test]
    fn test_complete_blinding_and_recovery_protocol() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        // ============ SETUP PHASE ============
        // Three shufflers with their own keys
        let shuffler1_secret = ScalarField::rand(&mut rng);
        let shuffler1_pk = GrumpkinProjective::generator() * shuffler1_secret;

        let shuffler2_secret = ScalarField::rand(&mut rng);
        let shuffler2_pk = GrumpkinProjective::generator() * shuffler2_secret;

        let shuffler3_secret = ScalarField::rand(&mut rng);
        let shuffler3_pk = GrumpkinProjective::generator() * shuffler3_secret;

        // Aggregated public key for the committee
        let aggregated_pk = shuffler1_pk + shuffler2_pk + shuffler3_pk;
        let aggregated_secret = shuffler1_secret + shuffler2_secret + shuffler3_secret;

        // Target player with their own key
        let player_secret = ScalarField::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // ============ STAGE 1: SEQUENTIAL ENCRYPTION ============
        // Initial message/card
        let message = ScalarField::from(42u64); // Card value
        let message_point = GrumpkinProjective::generator() * message;

        // Start with initial ciphertext (0, M)
        let initial_ciphertext = ElGamalCiphertext::new(
            GrumpkinProjective::zero(), // c1 = 0
            message_point,              // c2 = g^m
        );
        let mut ciphertext = initial_ciphertext;

        // Shuffler 1 encrypts with randomness r1
        let r1 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r1, aggregated_pk);
        // Now: c1 = g^r1, c2 = pk^r1 * g^m

        // Shuffler 2 re-encrypts with randomness r2
        let r2 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r2, aggregated_pk);
        // Now: c1 = g^(r1+r2), c2 = pk^(r1+r2) * g^m

        // Shuffler 3 re-encrypts with randomness r3
        let r3 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r3, aggregated_pk);
        // Now: c1 = g^(r1+r2+r3), c2 = pk^(r1+r2+r3) * g^m

        let total_r = r1 + r2 + r3;

        // ============ STAGE 2: PLAYER-TARGETED BLINDING ============
        // Each shuffler creates their blinding contribution for the target player

        // Shuffler 1's contribution
        let delta1 = ScalarField::rand(&mut rng);
        let contribution1 = PlayerTargetedBlindingContribution::generate(
            delta1,
            aggregated_pk,
            player_public_key,
            &mut rng,
        );
        assert_eq!(
            contribution1.blinding_base_contribution,
            GrumpkinProjective::generator() * delta1
        );
        assert_eq!(
            contribution1.blinding_combined_contribution,
            (aggregated_pk + player_public_key) * delta1
        );

        // Shuffler 2's contribution
        let delta2 = ScalarField::rand(&mut rng);
        let contribution2 = PlayerTargetedBlindingContribution::generate(
            delta2,
            aggregated_pk,
            player_public_key,
            &mut rng,
        );

        // Shuffler 3's contribution
        let delta3 = ScalarField::rand(&mut rng);
        let contribution3 = PlayerTargetedBlindingContribution::generate(
            delta3,
            aggregated_pk,
            player_public_key,
            &mut rng,
        );

        let total_delta = delta1 + delta2 + delta3;

        // ============ STAGE 3: COMBINATION ============
        let contributions = vec![contribution1, contribution2, contribution3];
        let player_ciphertext = combine_blinding_contributions_for_player(
            &ciphertext,
            &contributions,
            aggregated_pk,
            player_public_key,
        )
        .unwrap();

        // ============ VERIFICATION ============
        // Verify blinded_base = g^(r + Δ)
        let expected_blinded_base = GrumpkinProjective::generator() * (total_r + total_delta);
        assert_eq!(
            player_ciphertext.blinded_base, expected_blinded_base,
            "blinded_base should equal g^(r + Δ)"
        );

        // Verify blinded_message_with_player_key = pk^(r + Δ) * g^m * y_u^Δ
        let expected_blinded_message = aggregated_pk * (total_r + total_delta) // pk^(r + Δ)
            + message_point // g^m
            + player_public_key * total_delta; // y_u^Δ
        assert_eq!(
            player_ciphertext.blinded_message_with_player_key, expected_blinded_message,
            "blinded_message_with_player_key should equal pk^(r+Δ) * g^m * y_u^Δ"
        );

        // Verify player_unblinding_helper = g^Δ
        let expected_helper = GrumpkinProjective::generator() * total_delta;
        assert_eq!(
            player_ciphertext.player_unblinding_helper, expected_helper,
            "player_unblinding_helper should equal g^Δ"
        );

        // Verify all proofs are included
        assert_eq!(player_ciphertext.shuffler_proofs.len(), 3);

        // ============ CARD RECOVERY ============
        // Generate partial unblinding shares from each committee member
        let unblinding1 =
            generate_committee_decryption_share(&player_ciphertext, shuffler1_secret, 0);
        let unblinding2 =
            generate_committee_decryption_share(&player_ciphertext, shuffler2_secret, 1);
        let unblinding3 =
            generate_committee_decryption_share(&player_ciphertext, shuffler3_secret, 2);

        // Verify individual shares are computed correctly
        assert_eq!(
            unblinding1.share,
            player_ciphertext.blinded_base * shuffler1_secret
        );
        assert_eq!(
            unblinding2.share,
            player_ciphertext.blinded_base * shuffler2_secret
        );
        assert_eq!(
            unblinding3.share,
            player_ciphertext.blinded_base * shuffler3_secret
        );

        // Use the recover_card_value function with all shares
        let unblinding_shares = vec![unblinding1, unblinding2, unblinding3];
        let recovered_value = recover_card_value(
            &player_ciphertext,
            player_secret,
            unblinding_shares.clone(),
            3,
        )
        .expect("Card recovery should succeed with all shares");

        // Verify the recovered value matches the original
        assert_eq!(recovered_value, 42, "Should recover original card value");

        // Test that missing a share prevents recovery (n-of-n requirement)
        let incomplete_shares = vec![unblinding_shares[0].clone(), unblinding_shares[1].clone()];
        let result = recover_card_value(&player_ciphertext, player_secret, incomplete_shares, 3);
        assert!(
            result.is_err(),
            "Card recovery should fail with missing shares"
        );

        // Test that wrong player secret fails
        let wrong_secret = ScalarField::rand(&mut rng);
        let result = recover_card_value(
            &player_ciphertext,
            wrong_secret,
            unblinding_shares.clone(),
            3,
        );
        assert!(
            result.is_err() || result.unwrap() != 42,
            "Wrong secret should not recover correctly"
        );

        // Also verify manual computation matches
        let player_unblinding = player_ciphertext.player_unblinding_helper * player_secret;
        let combined_unblinding = player_ciphertext.blinded_base * aggregated_secret;
        let recovered = player_ciphertext.blinded_message_with_player_key
            - combined_unblinding
            - player_unblinding;
        assert_eq!(
            recovered, message_point,
            "Manual computation should also recover original message"
        );
    }

    #[test]
    fn test_card_value_mapping() {
        // Test that the card value mapping works correctly
        let card_map = get_card_value_map::<GrumpkinProjective>();
        let generator = GrumpkinProjective::generator();

        // Test all valid card values
        for i in 0u8..52 {
            let element = generator * <GrumpkinProjective as PrimeGroup>::ScalarField::from(i);
            let recovered = card_map.lookup(&element);
            assert_eq!(recovered, Some(i), "Card value {} should map correctly", i);
        }

        // Test that invalid values return None
        let invalid_element =
            generator * <GrumpkinProjective as PrimeGroup>::ScalarField::from(100u64);
        assert_eq!(
            card_map.lookup(&invalid_element),
            None,
            "Invalid card values should return None"
        );
    }

    #[test]
    fn test_card_recovery_with_different_values() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        // Setup committee
        let shuffler1_secret = ScalarField::rand(&mut rng);
        let shuffler2_secret = ScalarField::rand(&mut rng);
        let aggregated_pk = GrumpkinProjective::generator() * (shuffler1_secret + shuffler2_secret);

        // Setup player
        let player_secret = ScalarField::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Test different card values
        for card_value in [0u8, 1, 25, 51] {
            // Encrypt the card
            let message = ScalarField::from(card_value);
            let message_point = GrumpkinProjective::generator() * message;

            let mut ciphertext = ElGamalCiphertext::new(GrumpkinProjective::zero(), message_point);

            let r = ScalarField::rand(&mut rng);
            ciphertext = ciphertext.add_encryption_layer(r, aggregated_pk);

            // Create player-targeted blinding
            let delta1 = ScalarField::rand(&mut rng);
            let contribution1 = PlayerTargetedBlindingContribution::generate(
                delta1,
                aggregated_pk,
                player_public_key,
                &mut rng,
            );

            let delta2 = ScalarField::rand(&mut rng);
            let contribution2 = PlayerTargetedBlindingContribution::generate(
                delta2,
                aggregated_pk,
                player_public_key,
                &mut rng,
            );

            let contributions = vec![contribution1, contribution2];
            let player_ciphertext = combine_blinding_contributions_for_player(
                &ciphertext,
                &contributions,
                aggregated_pk,
                player_public_key,
            )
            .unwrap();

            // Generate unblinding shares
            let unblinding1 =
                generate_committee_decryption_share(&player_ciphertext, shuffler1_secret, 0);
            let unblinding2 =
                generate_committee_decryption_share(&player_ciphertext, shuffler2_secret, 1);

            // Recover and verify
            let recovered = recover_card_value(
                &player_ciphertext,
                player_secret,
                vec![unblinding1, unblinding2],
                2,
            )
            .expect("Card recovery should succeed");

            assert_eq!(
                recovered, card_value,
                "Card value {} should recover correctly",
                card_value
            );
        }
    }

    #[test]
    fn test_batch_verification_of_blinding_contributions() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        // Setup multiple shufflers with a shared aggregated key
        let num_shufflers = 3;
        let mut shares = Vec::new();

        // Create individual shuffler keys and compute aggregated key
        let shuffler1_secret = ScalarField::rand(&mut rng);
        let shuffler1_pk = GrumpkinProjective::generator() * shuffler1_secret;

        let shuffler2_secret = ScalarField::rand(&mut rng);
        let shuffler2_pk = GrumpkinProjective::generator() * shuffler2_secret;

        let shuffler3_secret = ScalarField::rand(&mut rng);
        let shuffler3_pk = GrumpkinProjective::generator() * shuffler3_secret;

        // This is the aggregated public key all shufflers use
        let aggregated_public_key = shuffler1_pk + shuffler2_pk + shuffler3_pk;

        let player_secret = ScalarField::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Generate contributions from each shuffler using the same aggregated key
        for _ in 0..num_shufflers {
            let secret_share = ScalarField::rand(&mut rng);
            let contribution = PlayerTargetedBlindingContribution::generate(
                secret_share,
                aggregated_public_key,
                player_public_key,
                &mut rng,
            );
            shares.push(contribution);
        }

        // Batch verify all contributions
        assert!(
            batch_verify_shuffler_shares(
                &shares,
                aggregated_public_key,
                player_public_key,
                &mut rng
            ),
            "Batch verification of valid contributions should succeed"
        );

        // Tamper with one contribution and verify batch fails
        shares[1].blinding_base_contribution =
            GrumpkinProjective::generator() * ScalarField::rand(&mut rng);
        assert!(
            !batch_verify_shuffler_shares(
                &shares,
                aggregated_public_key,
                player_public_key,
                &mut rng
            ),
            "Batch verification with tampered contribution should fail"
        );
    }
}
