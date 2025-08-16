use super::{data_structures::*, error::ShuffleError, utils::generate_random_values};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::UniformRand;

const LOG_TARGET: &str = "shuffle::subprotocol";

#[tracing::instrument(target = LOG_TARGET, name= "prove_shuffle", skip(input_deck, shuffler_keys))]
pub fn prove_as_subprotocol<C: CurveGroup>(
    seed: C::BaseField,
    input_deck: Vec<ElGamalCiphertext<C>>,
    shuffler_keys: &ElGamalKeys<C>,
) -> Result<ShuffleProof<C>, ShuffleError>
where
    C::BaseField: Absorb + PrimeField,
{
    tracing::info!(target = LOG_TARGET, "Starting shuffle proof generation");

    // Validate deck size
    if input_deck.len() != DECK_SIZE {
        return Err(ShuffleError::InvalidDeckSize(input_deck.len()));
    }

    // 1. Generate random values for sorting using Poseidon with seed
    let random_values = generate_random_values::<C::BaseField>(seed, DECK_SIZE);
    tracing::debug!(
        target: LOG_TARGET,
        "Generated {} random sorting values",
        DECK_SIZE
    );

    tracing::debug!(
        target: LOG_TARGET,
        "First 10 random values: {:?}",
        &random_values[0..10.min(random_values.len())]
    );

    // 2. Generate rerandomization values r'_i (scalars in the scalar field)
    let mut rng = ark_std::test_rng(); // In production, use a secure RNG
    let rerandomization_values: Vec<C::ScalarField> = (0..DECK_SIZE)
        .map(|_| C::ScalarField::rand(&mut rng))
        .collect();
    tracing::debug!(
        target: LOG_TARGET,
        "Generated {} rerandomization values",
        DECK_SIZE
    );

    // 3. Add encryption layer to each card (operations on C):
    //    - New c1 = c1 + r'_i * G
    //    - New c2 = c2 + r'_i * Y (where Y is shuffler's public key)
    let rerandomized_cards: Vec<ElGamalCiphertext<C>> = input_deck
        .iter()
        .zip(&rerandomization_values)
        .map(|(card, &rerand)| card.add_encryption_layer(rerand, shuffler_keys.public_key))
        .collect();
    tracing::debug!(target = LOG_TARGET, "Re-randomized all cards");

    // 4. Create associated list: [(re_randomized_card_i, random_value_i)]
    let associated_list: Vec<(ElGamalCiphertext<C>, C::BaseField)> =
        rerandomized_cards.into_iter().zip(random_values).collect();

    // 5. Sort by random values to get the sorted deck
    let mut sorted_associated_list = associated_list;
    sorted_associated_list.sort_by(|a, b| a.1.cmp(&b.1));

    // 6. Return ShuffleProof with all components
    let proof = ShuffleProof::new(input_deck, sorted_associated_list, rerandomization_values)?;

    tracing::info!(target = LOG_TARGET, "Shuffle proof generation complete");
    Ok(proof)
}
