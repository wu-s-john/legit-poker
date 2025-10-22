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
use serde::{Deserialize, Serialize};
use tracing::{instrument, warn};

const LOG_TARGET: &str = "legit_poker::shuffling::community_decryption";

/// Community card decryption share from a single committee member
/// Each committee member provides c1^x_j where x_j is their secret share
#[derive(Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct CommunityDecryptionShare<C: CurveGroup> {
    /// c1^x_j - committee member j's partial decryption share
    #[serde(with = "crate::crypto_serde::curve")]
    pub share: C,
    /// Proof that log_g(pk_j) = log_c1(share_j)
    pub proof: ChaumPedersenProof<C>,
    /// Canonical key of the committee member providing this share
    pub member_key: crate::ledger::CanonicalKey<C>,
}

impl<C> CommunityDecryptionShare<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C: CurveAbsorb<C::BaseField>,
{
    /// Generate a community decryption share with a Chaum-Pedersen proof
    ///
    /// # Arguments
    /// * `ciphertext` - The ElGamal ciphertext to partially decrypt
    /// * `committee_secret` - The committee member's secret share x_j
    /// * `member_key` - Canonical key identifying this committee member
    #[instrument(skip(committee_secret, rng), level = "trace")]
    pub fn generate<R: Rng>(
        ciphertext: &ElGamalCiphertext<C>,
        committee_secret: C::ScalarField,
        member_key: crate::ledger::CanonicalKey<C>,
        rng: &mut R,
    ) -> Self
    where
        C: ark_serialize::CanonicalSerialize,
    {
        let generator = C::generator();

        // Compute the partial decryption share: share_j = c1^x_j
        let share = (ciphertext.c1 * committee_secret)
            .into_affine()
            .into_group();

        // Generate Chaum-Pedersen proof that log_g(pk_j) = log_c1(share_j)
        // This proves that the same secret x_j was used for both pk_j and share_j
        let config = poseidon_config::<C::BaseField>();
        let mut sponge = PoseidonSponge::new(&config);
        let proof =
            ChaumPedersenProof::prove(&mut sponge, committee_secret, generator, ciphertext.c1, rng);

        Self {
            share,
            proof,
            member_key,
        }
    }

    /// Verify a committee member's decryption share Chaum-Pedersen proof
    ///
    /// # Arguments
    /// * `ciphertext` - The ElGamal ciphertext being decrypted
    /// * `member_public_key` - The committee member's public key (g^x_j)
    #[instrument(skip(self), level = "trace")]
    pub fn verify(&self, ciphertext: &ElGamalCiphertext<C>, member_public_key: C) -> bool {
        let generator = C::generator();

        // Verify the Chaum-Pedersen proof
        let config = poseidon_config::<C::BaseField>();
        let mut sponge = PoseidonSponge::new(&config);
        let result = self.proof.verify(
            &mut sponge,
            generator,
            ciphertext.c1,
            member_public_key,
            self.share,
        );

        if !result {
            warn!(target: LOG_TARGET, "Decryption share proof verification failed for member {:?}!", self.member_key);
        }

        result
    }
}

/// Combine community decryption shares to compute pk^r
///
/// IMPORTANT: This is an n-of-n scheme - ALL committee members must provide shares.
/// This is not a threshold scheme; if any member's share is missing, decryption will fail.
///
/// # Arguments
/// * `shares` - Decryption shares from ALL n committee members
/// * `expected_members` - The expected number of committee members
///
/// # Returns
/// The aggregated value pk^r = ∏(share_j) = c1^(Σx_j)
#[instrument(skip(shares), level = "trace")]
pub fn combine_community_shares<C: CurveGroup>(
    shares: &[CommunityDecryptionShare<C>],
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

    // Note: With canonical keys, uniqueness is guaranteed by the map structure
    // and range checks are not applicable. We only verify the count.

    // Aggregate by adding all shares: pk^r = Σ(share_j)
    // This gives us c1^(Σx_j) = g^(r*Σx_j) = pk^r
    let aggregated = shares
        .iter()
        .fold(C::zero(), |acc, share| acc + share.share);

    Ok(aggregated)
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

/// Decrypt a community card using committee decryption shares
///
/// This implements the complete decryption protocol for community cards:
/// 1. Committee members provide decryption shares share_j = c1^x_j
/// 2. Shares are aggregated to get pk^r = c1^(Σx_j)
/// 3. Message is recovered: g^m = c2 / pk^r
/// 4. Card value is found by lookup in pre-computed table
///
/// # Arguments
/// * `ciphertext` - The encrypted community card
/// * `decryption_shares` - Decryption shares from ALL committee members (n-of-n)
/// * `expected_members` - The expected number of committee members
///
/// # Returns
/// The decrypted card value (0-51) or an error if decryption fails
#[instrument(skip(decryption_shares), level = "trace")]
pub fn decrypt_community_card<C>(
    ciphertext: &ElGamalCiphertext<C>,
    decryption_shares: Vec<CommunityDecryptionShare<C>>,
    expected_members: usize,
) -> Result<u8, &'static str>
where
    C: CurveGroup + 'static,
    C::ScalarField: PrimeField,
{
    tracing::debug!(
        target: LOG_TARGET,
        c1 = ?ciphertext.c1,
        c2 = ?ciphertext.c2,
        expected_members,
        actual_shares = decryption_shares.len(),
        "=== Community card decryption ==="
    );

    // Step 1: Combine committee decryption shares to get pk^r
    let combined_shares = combine_community_shares(&decryption_shares, expected_members)?;
    tracing::debug!(
        target: LOG_TARGET,
        ?combined_shares,
        "Combined decryption shares"
    );

    // Step 2: Recover the message group element
    // g^m = c2 / pk^r
    let recovered_element = ciphertext.c2 - combined_shares;
    tracing::debug!(
        target: LOG_TARGET,
        ?recovered_element,
        "Recovered element (g^m)"
    );

    // Step 3: Map the group element back to a card value using pre-computed table
    let card_map = get_card_value_map::<C>();

    tracing::debug!(target: LOG_TARGET, "Looking up card value in pre-computed map...");
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
    fn test_community_decryption_share_proof() {
        let mut rng = test_rng();

        // Setup - Generate committee member key
        let committee_secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let committee_public_key = GrumpkinProjective::generator() * committee_secret;

        // Create an encrypted card
        let message = <GrumpkinProjective as PrimeGroup>::ScalarField::from(42u64);
        let message_point = GrumpkinProjective::generator() * message;
        let randomness = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);

        // For community cards, we use the aggregated public key
        let aggregated_pk = committee_public_key; // In real scenario, this would be sum of all committee PKs
        let ciphertext = ElGamalCiphertext::encrypt(message_point, randomness, aggregated_pk);

        // Create a decryption share with proof
        let member_key = crate::ledger::CanonicalKey::new(committee_public_key);
        let share = CommunityDecryptionShare::generate(&ciphertext, committee_secret, member_key, &mut rng);

        // Verify the proof is valid
        assert!(
            share.verify(&ciphertext, committee_public_key),
            "Valid proof should verify successfully"
        );

        // Test that tampering with the share makes verification fail
        let mut bad_share = share.clone();
        bad_share.share = GrumpkinProjective::generator()
            * <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        assert!(
            !bad_share.verify(&ciphertext, committee_public_key),
            "Tampered share should fail verification"
        );
    }

    #[test]
    fn test_simple_community_decryption() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        // Three committee members with their own keys
        let member1_secret = ScalarField::rand(&mut rng);
        let member1_pk = GrumpkinProjective::generator() * member1_secret;

        let member2_secret = ScalarField::rand(&mut rng);
        let member2_pk = GrumpkinProjective::generator() * member2_secret;

        let member3_secret = ScalarField::rand(&mut rng);
        let member3_pk = GrumpkinProjective::generator() * member3_secret;

        // Aggregated public key for the committee
        let aggregated_pk = member1_pk + member2_pk + member3_pk;
        let aggregated_secret = member1_secret + member2_secret + member3_secret;

        // Encrypt a card value
        let card_value = 25u8;
        let message = ScalarField::from(card_value);
        let message_point = GrumpkinProjective::generator() * message;
        let randomness = ScalarField::rand(&mut rng);

        let ciphertext = ElGamalCiphertext::encrypt(message_point, randomness, aggregated_pk);

        // Generate decryption shares from each committee member
        let member_key1 = crate::ledger::CanonicalKey::new(member1_pk);
        let member_key2 = crate::ledger::CanonicalKey::new(member2_pk);
        let member_key3 = crate::ledger::CanonicalKey::new(member3_pk);
        let share1 = CommunityDecryptionShare::generate(&ciphertext, member1_secret, member_key1, &mut rng);
        let share2 = CommunityDecryptionShare::generate(&ciphertext, member2_secret, member_key2, &mut rng);
        let share3 = CommunityDecryptionShare::generate(&ciphertext, member3_secret, member_key3, &mut rng);

        // Verify all shares
        assert!(share1.verify(&ciphertext, member1_pk));
        assert!(share2.verify(&ciphertext, member2_pk));
        assert!(share3.verify(&ciphertext, member3_pk));

        // Decrypt the community card
        let decryption_shares = vec![share1, share2, share3];
        let recovered_value = decrypt_community_card(&ciphertext, decryption_shares, 3)
            .expect("Decryption should succeed");

        assert_eq!(
            recovered_value, card_value,
            "Should recover original card value"
        );

        // Also verify manual computation
        let pk_r = ciphertext.c1 * aggregated_secret;
        let recovered_manual = ciphertext.c2 - pk_r;
        assert_eq!(
            recovered_manual, message_point,
            "Manual decryption should also work"
        );
    }

    #[test]
    fn test_community_decryption_with_shuffling() {
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

        // ============ SEQUENTIAL ENCRYPTION ============
        // Initial message/card
        let card_value = 51u8; // Ace of Spades
        let message = ScalarField::from(card_value);
        let message_point = GrumpkinProjective::generator() * message;

        // Start with initial ciphertext (0, M)
        let initial_ciphertext = ElGamalCiphertext::new(GrumpkinProjective::zero(), message_point);
        let mut ciphertext = initial_ciphertext;

        // Shuffler 1 encrypts with randomness r1
        let r1 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r1, aggregated_pk);

        // Shuffler 2 re-encrypts with randomness r2
        let r2 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r2, aggregated_pk);

        // Shuffler 3 re-encrypts with randomness r3
        let r3 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r3, aggregated_pk);

        // ============ COMMUNITY DECRYPTION ============
        // Generate decryption shares from each committee member
        let shuffler_key1 = crate::ledger::CanonicalKey::new(shuffler1_pk);
        let shuffler_key2 = crate::ledger::CanonicalKey::new(shuffler2_pk);
        let shuffler_key3 = crate::ledger::CanonicalKey::new(shuffler3_pk);
        let share1 = CommunityDecryptionShare::generate(&ciphertext, shuffler1_secret, shuffler_key1, &mut rng);
        let share2 = CommunityDecryptionShare::generate(&ciphertext, shuffler2_secret, shuffler_key2, &mut rng);
        let share3 = CommunityDecryptionShare::generate(&ciphertext, shuffler3_secret, shuffler_key3, &mut rng);

        // Verify individual shares are computed correctly
        assert_eq!(share1.share, ciphertext.c1 * shuffler1_secret);
        assert_eq!(share2.share, ciphertext.c1 * shuffler2_secret);
        assert_eq!(share3.share, ciphertext.c1 * shuffler3_secret);

        // Verify all proofs
        assert!(share1.verify(&ciphertext, shuffler1_pk));
        assert!(share2.verify(&ciphertext, shuffler2_pk));
        assert!(share3.verify(&ciphertext, shuffler3_pk));

        // Decrypt the community card
        let decryption_shares = vec![share1.clone(), share2.clone(), share3.clone()];
        let recovered_value = decrypt_community_card(&ciphertext, decryption_shares, 3)
            .expect("Decryption should succeed");

        assert_eq!(
            recovered_value, card_value,
            "Should recover original card value"
        );

        // Test that missing a share prevents decryption (n-of-n requirement)
        let incomplete_shares = vec![share1.clone(), share2.clone()];
        let result = decrypt_community_card(&ciphertext, incomplete_shares, 3);
        assert!(
            result.is_err(),
            "Decryption should fail with missing shares"
        );

        // Test with wrong public key in verification
        assert!(
            !share1.verify(&ciphertext, shuffler2_pk),
            "Verification should fail with wrong public key"
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
    fn test_community_decryption_with_different_values() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        // Setup committee with two members
        let member1_secret = ScalarField::rand(&mut rng);
        let member1_pk = GrumpkinProjective::generator() * member1_secret;

        let member2_secret = ScalarField::rand(&mut rng);
        let member2_pk = GrumpkinProjective::generator() * member2_secret;

        let aggregated_pk = member1_pk + member2_pk;

        // Test different card values
        for card_value in [0u8, 1, 13, 26, 39, 51] {
            // Encrypt the card
            let message = ScalarField::from(card_value);
            let message_point = GrumpkinProjective::generator() * message;
            let randomness = ScalarField::rand(&mut rng);

            let ciphertext = ElGamalCiphertext::encrypt(message_point, randomness, aggregated_pk);

            // Generate decryption shares
            let member_key1 = crate::ledger::CanonicalKey::new(member1_pk);
            let member_key2 = crate::ledger::CanonicalKey::new(member2_pk);
            let share1 =
                CommunityDecryptionShare::generate(&ciphertext, member1_secret, member_key1.clone(), &mut rng);
            let share2 =
                CommunityDecryptionShare::generate(&ciphertext, member2_secret, member_key2.clone(), &mut rng);

            // Verify shares
            assert!(share1.verify(&ciphertext, member1_pk));
            assert!(share2.verify(&ciphertext, member2_pk));

            // Decrypt and verify
            let recovered = decrypt_community_card(&ciphertext, vec![share1, share2], 2)
                .expect("Decryption should succeed");

            assert_eq!(
                recovered, card_value,
                "Card value {} should recover correctly",
                card_value
            );
        }
    }
}
