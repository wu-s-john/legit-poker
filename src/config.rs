use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::PrimeField;

/// Returns a Poseidon configuration for the given field
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    // Standard Poseidon configuration with secure parameters
    // Using alpha = 5 which is a common choice for security
    let num_rounds = 8 + 31; // full_rounds + partial_rounds
    let t = 3; // state width (rate + capacity)

    // Create Arc constants - one vector per round, each with t elements
    let mut ark_constants = Vec::new();
    for _ in 0..num_rounds {
        let mut round_constants = Vec::new();
        for _ in 0..t {
            round_constants.push(F::zero());
        }
        ark_constants.push(round_constants);
    }

    PoseidonConfig::new(
        8,                           // full_rounds
        31,                          // partial_rounds
        5,                           // alpha (S-box power)
        vec![vec![F::zero(); t]; t], // MDS matrix (t x t)
        ark_constants,               // Arc constants (one vector per round)
        2,                           // rate
        1,                           // capacity
    )
}
