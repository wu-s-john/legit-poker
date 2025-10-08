use crate::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ff::PrimeField;

const _LOG_TARGET: &str = "legit_poker::shuffling::util";

pub fn generate_random_values<F: Absorb + PrimeField>(seed: F, count: usize) -> Vec<F> {
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);

    // Absorb the seed
    sponge.absorb(&seed);

    // Squeeze all values at once to ensure proper state advancement
    // This is more efficient and ensures proper randomness
    let values = sponge.squeeze_field_elements(count);

    values
}

// generate_chaum_pedersen_witness moved to crate::chaum_pedersen::generate_chaum_pedersen_witness
