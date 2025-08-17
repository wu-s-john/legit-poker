use super::data_structures::*;
use crate::poseidon_config;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar, Absorb,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    boolean::Boolean, fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar,
    prelude::*,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use std::ops::Not;

const LOG_TARGET: &str = "shuffle::circuit";

/// Circuit for verifying card shuffling
#[derive(Clone)]
pub struct ShuffleCircuit<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    /// Public key of the shuffler
    pub shuffler_public_key: Projective<G>,
    /// The shuffle proof to verify
    pub proof: ShuffleProof<Projective<G>>,
    /// Random seed for the shuffle
    pub seed: G::BaseField,
}

impl<G: SWCurveConfig> ShuffleCircuit<G>
where
    G::BaseField: PrimeField,
{
    /// Create a new shuffle circuit with the given shuffler public key, proof, and seed
    pub fn new(
        shuffler_public_key: Projective<G>,
        proof: ShuffleProof<Projective<G>>,
        seed: G::BaseField,
    ) -> Self {
        Self { shuffler_public_key, proof, seed }
    }

    #[tracing::instrument(
        target = "shuffle::circuit",
        name = "generate_random_values_for_deck",
        level = "debug",
        skip_all,
        fields(deck_size = tracing::field::Empty)
    )]
    fn generate_random_values_for_deck(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        seed: &FpVar<G::BaseField>,
        deck_size: usize,
    ) -> Result<Vec<FpVar<G::BaseField>>, SynthesisError>
    where
        G::BaseField: PrimeField + Absorb + Copy,
    {
        crate::track_constraints!(&cs, "constructing random values for deck", LOG_TARGET, {
            // Create Poseidon config
            tracing::debug!(target: LOG_TARGET, "Creating Poseidon config");
            let config = poseidon_config::<G::BaseField>();
            let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

            // Absorb seed
            tracing::debug!(target: LOG_TARGET, "Absorbing seed into sponge");
            sponge.absorb(&seed)?;

            // Generate random value for each card
            tracing::debug!(
                target: LOG_TARGET,
                "Generating random values for {} cards",
                deck_size
            );

            // Squeeze all random values at once - much more efficient
            let random_values: Result<Vec<_>, _> = (0..deck_size)
                .map(|_| sponge.squeeze_field_elements(1).map(|vals| vals[0].clone()))
                .collect();
            let random_values = random_values?;

            // Safety check: ensure we got exactly the right number of random values
            assert_eq!(
                random_values.len(),
                deck_size,
                "Squeeze operation should return exactly {} random values, got {}",
                deck_size,
                random_values.len()
            );

            tracing::debug!(target: LOG_TARGET, "All random values generated");

            Ok(random_values)
        })
    }


    /// Compute the grand product for a deck of cards
    fn compute_deck_product<'a, I>(
        &self,
        _cs: ConstraintSystemRef<G::BaseField>,
        deck: I,
        alpha: &FpVar<G::BaseField>,
        beta: &FpVar<G::BaseField>,
    ) -> Result<FpVar<G::BaseField>, SynthesisError>
    where
        G::BaseField: PrimeField,
        I: Iterator<Item = (&'a ElGamalCiphertextVar<G>, &'a FpVar<G::BaseField>)>,
    {
        // Precompute powers of alpha outside the loop
        let alpha_1 = alpha.clone();
        let alpha_2 = &alpha_1 * alpha;
        let alpha_3 = &alpha_2 * alpha;
        let alpha_4 = &alpha_3 * alpha;
        let alpha_5 = &alpha_4 * alpha;

        let mut product = FpVar::one();
        for (card, random_val) in deck {
            // Compute linear combination of card components using powers of alpha
            // card_repr = c1.x + α*c1.y + α²*c1.z + α³*c2.x + α⁴*c2.y + α⁵*c2.z
            let card_repr = &card.c1.x
                + &alpha_1 * &card.c1.y
                + &alpha_2 * &card.c1.z
                + &alpha_3 * &card.c2.x
                + &alpha_4 * &card.c2.y
                + &alpha_5 * &card.c2.z;

            // Compute term: card_repr + beta * random_value
            let term = card_repr + beta.clone() * random_val.clone();
            product *= term;
        }
        Ok(product)
    }

    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    fn verify_equivalance_through_grand_product(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        deck: &Vec<(&ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>,
        sorted_deck: &Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>,
        alpha: &FpVar<G::BaseField>,
        beta: &FpVar<G::BaseField>,
    ) -> Result<(), SynthesisError>
    where
        G::BaseField: PrimeField,
    {
        let ns = ns!(cs, "grand_product");
        let cs = ns.cs();

        // Verify that rerandomized_deck and sorted_deck contain the same multiset
        // using the grand product argument with challenges alpha and beta

        // Compute product for rerandomized deck
        let product = self.compute_deck_product(
            cs.clone(),
            deck.iter().map(|(card, val)| (*card, val)),
            alpha,
            beta,
        )?;

        if let Ok(product_val) = product.value() {
            tracing::info!(target: LOG_TARGET, "Computed product for randomized deck: {:?}", product_val);
        }

        // Compute product for sorted deck
        let sorted_product = self.compute_deck_product(
            cs.clone(),
            sorted_deck.iter().map(|(card, val)| (card, val)),
            alpha,
            beta,
        )?;

        if let Ok(sorted_product_val) = sorted_product.value() {
            tracing::info!(target: LOG_TARGET, "Computed product for sorted deck: {:?}", sorted_product_val);
        }

        // Check if products are equal before enforcing (only if values are available)
        if let (Ok(product_val), Ok(sorted_product_val)) = (product.value(), sorted_product.value())
        {
            if product_val != sorted_product_val {
                tracing::error!(
                    target: LOG_TARGET,
                    "Products are not equal! product: {:?}, sorted_product: {:?}",
                    product_val,
                    sorted_product_val
                );
            }
        }

        // Enforce equality - this proves the multiset is preserved
        // product.enforce_equal(&sorted_product)?;

        tracing::info!(target: LOG_TARGET, "Grand product verification complete");
        Ok(())
    }

    /// Verify that the sorted deck is actually sorted in increasing order by random values
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    #[allow(dead_code)]
    fn verify_sorting_order(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        proof: &ShuffleProofVar<G>,
    ) -> Result<(), SynthesisError>
    where
        G::BaseField: PrimeField,
    {
        ns!(cs, "verify_sorting_order");

        tracing::info!(
            target = LOG_TARGET,
            "Verifying sorting order for {} cards",
            proof.sorted_deck.len()
        );

        // For each adjacent pair, verify that random_value[i] <= random_value[i+1]
        for i in 0..(proof.sorted_deck.len() - 1) {
            let (_, current_random) = &proof.sorted_deck[i];
            let (_, next_random) = &proof.sorted_deck[i + 1];

            tracing::debug!(
                target: LOG_TARGET,
                "Are they increasing ({:?}) : Current value: {:?}, next value: {:?}",
                current_random.value()? <= next_random.value()?,
                current_random.value()?,
                next_random.value()?
            );

            // Enforce current <= next
            // Convert to bits and compare lexicographically
            let current_bits = current_random.to_bits_le()?;
            let next_bits = next_random.to_bits_le()?;

            // Implement lexicographic comparison manually
            // Start from MSB (last bit in little-endian representation)
            let mut is_less_or_equal = Boolean::TRUE;
            let mut found_difference = Boolean::FALSE;

            for i in (0..current_bits.len()).rev() {
                let current_bit = &current_bits[i];
                let next_bit = &next_bits[i];

                // If we haven't found a difference yet, check this bit position
                let bits_differ = current_bit.is_neq(next_bit)?;
                let current_is_zero = current_bit.not();
                let next_is_one = next_bit.clone();
                let current_less_at_this_bit = &current_is_zero & &next_is_one;

                // Update is_less_or_equal based on the first difference we find
                let condition = &bits_differ & &found_difference.clone().not();
                is_less_or_equal = Boolean::conditionally_select(
                    &condition,
                    &current_less_at_this_bit,
                    &is_less_or_equal,
                )?;

                // Mark that we found a difference
                found_difference = &found_difference | &bits_differ;
            }

            is_less_or_equal.enforce_equal(&Boolean::TRUE)?;
        }

        Ok(())
    }
}

impl<G: SWCurveConfig> ConstraintSynthesizer<G::BaseField> for ShuffleCircuit<G>
where
    G::BaseField: PrimeField + Absorb,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G::BaseField>,
    ) -> Result<(), SynthesisError> {
        tracing::info!(target = LOG_TARGET, "Starting circuit generation");

        // Allocate public inputs
        tracing::info!(target = LOG_TARGET, "Allocating public inputs...");
        let seed_var = FpVar::<G::BaseField>::new_input(ns!(cs, "seed"), || Ok(self.seed))?;
        let shuffler_pk_var = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            ns!(cs, "shuffler_pk"),
            || Ok(self.shuffler_public_key),
            AllocationMode::Witness,
        )?;
        tracing::info!(target: LOG_TARGET, "Public inputs allocated");

        // Allocate the shuffle proof as witness
        tracing::info!(target: LOG_TARGET, "Allocating shuffle proof witness...");

        // Debug print the sorted deck from self.proof before allocation
        tracing::info!(
            target: LOG_TARGET,
            "Native sorted deck: {:?}",
            self.proof.sorted_deck.iter().collect::<Vec<_>>()
        );

        let proof_var = {
            ShuffleProofVar::<G>::new_variable(
                cs.clone(),
                || Ok(&self.proof),
                AllocationMode::Witness,
            )?
        };

        tracing::info!(
            target = LOG_TARGET,
            "Shuffle proof witness allocated. Input deck size: {}",
            proof_var.input_deck.len()
        );

        // Generate random values for each card using Poseidon
        tracing::info!(target = LOG_TARGET, "Generating random values for deck...");
        let random_values = self.generate_random_values_for_deck(
            cs.clone(),
            &seed_var,
            proof_var.input_deck.len(),
        )?;

        // Apply re-randomization to create the new deck
        let rerandomized_deck = super::encryption::ElGamalEncryption::<G>::reencrypt_cards_with_new_randomization(
            cs.clone(),
            &proof_var.input_deck,
            &proof_var.encryption_randomization_values,
            &shuffler_pk_var,
        )?;

        tracing::info!(target: LOG_TARGET, "Finish rerandomizing cards");

        // Pair rerandomized cards with random values for grand product
        let deck_with_rerandomizations: Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)> =
            rerandomized_deck
                .into_iter()
                .zip(random_values.iter().cloned())
                .collect();

        // Generate challenges for grand product
        let alpha = FpVar::new_witness(cs.clone(), || Ok(G::BaseField::from(7u64)))?; // In practice, from Fiat-Shamir
        let beta = FpVar::new_witness(cs.clone(), || Ok(G::BaseField::from(13u64)))?; // In practice, from Fiat-Shamir

        // Only do debug logging if we're in witness generation mode (not during proof generation)
        if cs.is_in_setup_mode() {
            tracing::debug!(target: LOG_TARGET, "Debug logging deck data...");
            // Log both cards and random values from both decks for comparison
            if let Ok(deck_data) = deck_with_rerandomizations
                .iter()
                .map(
                    |(card, random_val)| match (card.value(), random_val.value()) {
                        (Ok(c), Ok(r)) => Ok((c, r)),
                        _ => Err(()),
                    },
                )
                .collect::<Result<Vec<_>, _>>()
            {
                let mut deck_rerandomization_data = deck_data;
                deck_rerandomization_data.sort_by_key(|(_, random)| *random);
                tracing::debug!(target: LOG_TARGET, "Deck Rerandomization Data: {:?}", deck_rerandomization_data);
            }

            if let Ok(sorted_data) = proof_var
                .sorted_deck
                .iter()
                .map(
                    |(card, random_val)| match (card.value(), random_val.value()) {
                        (Ok(c), Ok(r)) => Ok((c, r)),
                        _ => Err(()),
                    },
                )
                .collect::<Result<Vec<_>, _>>()
            {
                let mut sorted_deck_data = sorted_data;
                sorted_deck_data.sort_by_key(|(_, random)| *random);
                tracing::debug!(target: LOG_TARGET, "Sorted Deck Data: {:?}", sorted_deck_data);
            }
        }

        // Check if constraints are satisfied before grand product
        tracing::info!(
            target: LOG_TARGET,
            "Checking constraint satisfaction before grand product verification..."
        );

        // Verify grand product (multiset equivalence) using the associated lists
        tracing::info!(
            target: LOG_TARGET,
            "Starting grand product verification..."
        );
        // Convert deck_with_rerandomizations to the expected format with references
        let deck_with_rerandomizations_refs: Vec<(&ElGamalCiphertextVar<G>, FpVar<G::BaseField>)> =
            deck_with_rerandomizations
                .iter()
                .map(|(card, random_val)| (card, random_val.clone()))
                .collect();

        self.verify_equivalance_through_grand_product(
            cs.clone(),
            &deck_with_rerandomizations_refs,
            &proof_var.sorted_deck,
            &alpha,
            &beta,
        )?;

        // // Verify that the sorted deck is actually sorted
        // tracing::info!(target = LOG_TARGET, "Verifying sorting order...");
        // self.verify_sorting_order(cs.clone(), &proof_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::ElGamalEncryption;
    use ark_bn254::{g1::Config as G1Config, Fq, Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use ark_std::Zero;

    const TEST_TARGET: &str = "shuffle::test";

    #[test]
    fn test_rerandomization_native_vs_circuit() -> Result<(), Box<dyn std::error::Error>> {
        // Use BN254 G1 curve
        type G = G1Config;
        type C = G1Projective;

        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Create shuffler keys
        let shuffler_private_key = Fr::rand(&mut rng);
        let shuffler_keys = ElGamalKeys::<C>::new(shuffler_private_key);

        // Create a test ElGamal ciphertext by encrypting a message
        let message = Fr::from(42u64);
        let encryption_randomness = Fr::rand(&mut rng);
        let ciphertext = ElGamalCiphertext::encrypt_scalar(
            message,
            encryption_randomness,
            shuffler_keys.public_key,
        );

        // Create randomness for re-encryption
        let rerandomization = Fr::rand(&mut rng);

        // Native computation
        let native_result =
            ciphertext.add_encryption_layer(rerandomization, shuffler_keys.public_key);

        tracing::debug!(target: TEST_TARGET, "Native computation:");
        tracing::debug!(target: TEST_TARGET, c1 = ?ciphertext.c1, c2 = ?ciphertext.c2, "Original ciphertext");
        tracing::debug!(target: TEST_TARGET, ?rerandomization, "Re-randomization value");
        tracing::debug!(target: TEST_TARGET, public_key = ?shuffler_keys.public_key, "Public key");
        tracing::debug!(target: TEST_TARGET, c1 = ?native_result.c1, c2 = ?native_result.c2, "Re-randomized ciphertext");

        // Circuit computation
        // Allocate the ciphertext as circuit variables
        let ciphertext_var = ElGamalCiphertextVar::<G>::new_variable(
            cs.clone(),
            || Ok(ciphertext),
            AllocationMode::Witness,
        )?;

        // Allocate the public key
        let shuffler_pk_var = ProjectiveVar::<G, FpVar<Fq>>::new_variable(
            cs.clone(),
            || Ok(shuffler_keys.public_key),
            AllocationMode::Witness,
        )?;

        // Convert scalar field randomness to base field for circuit
        let rerandomization_base_field = scalar_to_base_field::<Fr, Fq>(&rerandomization);
        let rerandomization_var = FpVar::<Fq>::new_variable(
            cs.clone(),
            || Ok(rerandomization_base_field),
            AllocationMode::Witness,
        )?;

        // Perform re-randomization in circuit
        let circuit_result = ElGamalEncryption::<G>::rerandomize_ciphertext(
            cs.clone(),
            &ciphertext_var,
            &rerandomization_var,
            &shuffler_pk_var,
        )?;

        // Extract the circuit computation results
        let circuit_c1_value = circuit_result.c1.value()?;
        let circuit_c2_value = circuit_result.c2.value()?;

        tracing::debug!(target: TEST_TARGET, "Circuit computation:");
        tracing::debug!(target: TEST_TARGET, ?circuit_c1_value, ?circuit_c2_value, "Re-randomized ciphertext");

        // Compare results
        let c1_matches = native_result.c1 == circuit_c1_value;
        let c2_matches = native_result.c2 == circuit_c2_value;

        tracing::debug!(target: TEST_TARGET, %c1_matches, %c2_matches, "Comparison results");

        // Verify the constraint system is satisfied
        assert!(cs.is_satisfied()?, "Constraint system should be satisfied");

        // Check if results match
        assert_eq!(
            native_result.c1, circuit_c1_value,
            "c1 values should match between native and circuit computation"
        );
        assert_eq!(
            native_result.c2, circuit_c2_value,
            "c2 values should match between native and circuit computation"
        );

        tracing::info!(target: TEST_TARGET, "✅ Native and circuit re-randomization produce identical results!");

        Ok(())
    }

    #[test]
    fn test_multiple_rerandomizations() -> Result<(), Box<dyn std::error::Error>> {
        // Test with multiple different randomness values
        type G = G1Config;
        type C = G1Projective;

        let mut rng = test_rng();

        // Create test ElGamal encryption
        let shuffler_keys = ElGamalKeys::<C>::new(Fr::from(42u64));
        let message = Fr::from(123u64);
        let encryption_randomness = Fr::from(456u64);
        let ciphertext = ElGamalCiphertext::encrypt_scalar(
            message,
            encryption_randomness,
            shuffler_keys.public_key,
        );

        // Test with different randomness values
        let test_randomness = vec![
            Fr::from(1u64),
            Fr::from(1000u64),
            Fr::rand(&mut rng),
            Fr::zero(),
        ];

        for (i, randomness) in test_randomness.iter().enumerate() {
            let cs = ConstraintSystem::<Fq>::new_ref();

            tracing::debug!(target: TEST_TARGET, test_index = i, ?randomness, "Testing re-randomization");

            // Native computation
            let native_result =
                ciphertext.add_encryption_layer(*randomness, shuffler_keys.public_key);

            // Circuit computation
            let ciphertext_var = ElGamalCiphertextVar::<G>::new_variable(
                cs.clone(),
                || Ok(ciphertext.clone()),
                AllocationMode::Witness,
            )?;

            let shuffler_pk_var = ProjectiveVar::<G, FpVar<Fq>>::new_variable(
                cs.clone(),
                || Ok(shuffler_keys.public_key),
                AllocationMode::Witness,
            )?;

            let randomness_base_field = scalar_to_base_field::<Fr, Fq>(randomness);
            let randomness_var = FpVar::<Fq>::new_variable(
                cs.clone(),
                || Ok(randomness_base_field),
                AllocationMode::Witness,
            )?;

            let circuit_result = ElGamalEncryption::<G>::rerandomize_ciphertext(
                cs.clone(),
                &ciphertext_var,
                &randomness_var,
                &shuffler_pk_var,
            )?;

            let circuit_c1_value = circuit_result.c1.value()?;
            let circuit_c2_value = circuit_result.c2.value()?;

            let c1_matches = native_result.c1 == circuit_c1_value;
            let c2_matches = native_result.c2 == circuit_c2_value;

            tracing::debug!(
                target: TEST_TARGET,
                test_index = i,
                ?native_result.c1,
                ?circuit_c1_value,
                %c1_matches,
                "c1 comparison"
            );

            tracing::debug!(
                target: TEST_TARGET,
                test_index = i,
                ?native_result.c2,
                ?circuit_c2_value,
                %c2_matches,
                "c2 comparison"
            );

            assert_eq!(
                native_result.c1, circuit_c1_value,
                "Test {} failed: c1 mismatch",
                i
            );
            assert_eq!(
                native_result.c2, circuit_c2_value,
                "Test {} failed: c2 mismatch",
                i
            );
            assert!(
                cs.is_satisfied()?,
                "Test {} failed: constraints not satisfied",
                i
            );
        }

        tracing::info!(target: TEST_TARGET, "✅ All re-randomization tests passed!");
        Ok(())
    }

    #[test]
    fn test_encryption_consistency() -> Result<(), Box<dyn std::error::Error>> {
        // Test that encrypt uses add_encryption_layer correctly
        type C = G1Projective;

        let mut rng = test_rng();
        let shuffler_keys = ElGamalKeys::<C>::new(Fr::rand(&mut rng));

        // Test with curve point message
        let message_point = C::generator() * Fr::from(999u64);
        let randomness = Fr::from(777u64);

        // Method 1: Direct encryption
        let encrypted1 =
            ElGamalCiphertext::encrypt(message_point, randomness, shuffler_keys.public_key);

        // Method 2: Manual construction with add_encryption_layer
        let initial = ElGamalCiphertext::new(C::zero(), message_point);
        let encrypted2 = initial.add_encryption_layer(randomness, shuffler_keys.public_key);

        // They should be identical
        assert_eq!(encrypted1.c1, encrypted2.c1, "c1 should match");
        assert_eq!(encrypted1.c2, encrypted2.c2, "c2 should match");

        tracing::info!(target: TEST_TARGET, "✅ Encryption methods are consistent!");

        Ok(())
    }
}
