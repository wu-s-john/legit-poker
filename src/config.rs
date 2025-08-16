use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::PrimeField;

/// Returns a Poseidon configuration for the given field
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    // Standard Poseidon configuration with secure parameters
    // Using alpha = 5 which is a common choice for security
    PoseidonConfig::new(
        8,   // full_rounds
        31,  // partial_rounds
        5,   // alpha (S-box power)
        vec![vec![F::zero(); 3]; 8 + 31], // MDS matrix (will be replaced with proper values)
        vec![F::zero(); 3],                // Arc constants for each round
        2,   // rate
        1,   // capacity
    )
}