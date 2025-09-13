//! Bit generation for RS shuffle using Poseidon hash
//!
//! This module handles the generation of pseudorandom bits for the RS shuffle algorithm.
//! It draws exactly 2 Poseidon hashes and creates a 52×5 bit matrix from them.
//!
//! Provides both native and SNARK circuit implementations.

// N and LEVELS are now generic parameters
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

const LOG_TARGET: &str = "nexus_nova::shuffling::rs_shuffle::bit_generation";

/// Derive split bits from random seed using Poseidon hash
///
/// Dynamically determines how many field elements are needed based on the field size,
/// draws them from Poseidon, and fills a N×LEVELS matrix.
///
/// # Returns
/// - The bit matrix [[bool; N]; LEVELS]
/// - The number of field element samples that were drawn
#[tracing::instrument(
    target = LOG_TARGET,
    name = "derive_split_bits",
    fields(
    )
)]
pub fn derive_split_bits<F, const N: usize, const LEVELS: usize>(
    seed: F,
) -> ([[bool; N]; LEVELS], usize)
where
    F: Field + PrimeField + ark_crypto_primitives::sponge::Absorb,
{
    use crate::shuffling::utils::generate_random_values;
    use ark_ff::BigInteger;

    // Calculate how many field elements we need
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let usable_bits_per_element = field_bits.saturating_sub(2); // After trimming first and last
    let total_bits_needed = N * LEVELS; // 260 bits
    let num_elements_needed =
        (total_bits_needed + usable_bits_per_element - 1) / usable_bits_per_element;

    tracing::debug!(
        target: LOG_TARGET,
        seed = ?seed,
        field_bits,
        usable_bits_per_element,
        num_elements_needed,
        "Deriving split bits from seed"
    );

    // Draw the required number of field elements from Poseidon
    let random_values = generate_random_values(seed, num_elements_needed);

    tracing::debug!(
        target: LOG_TARGET,
        num_random_values = random_values.len(),
        "Random values generated"
    );

    // Debug: log the actual field values
    #[cfg(test)]
    {
        for (i, val) in random_values.iter().enumerate() {
            tracing::debug!(target: LOG_TARGET, "Random value[{}]: {:?}", i, val);
        }
    }

    // Convert field elements to bits and collect into a single stream
    let mut bit_stream = Vec::new();

    for value in random_values.iter() {
        // Get bit decomposition of the field element (LSB first)
        // This produces exactly F::MODULUS_BIT_SIZE bits
        let value_bigint = value.into_bigint();
        let mut value_bits = Vec::with_capacity(F::MODULUS_BIT_SIZE as usize);

        // Extract bits from the BigInteger representation
        for i in 0..(F::MODULUS_BIT_SIZE as usize) {
            value_bits.push(value_bigint.get_bit(i));
        }

        // Trim first and last bits
        if value_bits.len() > 2 {
            bit_stream.extend_from_slice(&value_bits[1..value_bits.len() - 1]);
        }
    }

    // Fill the N×LEVELS matrix using array::from_fn
    let bit_matrix = std::array::from_fn(|level| {
        std::array::from_fn(|i| {
            let bit_index = level * N + i;
            if bit_index < bit_stream.len() {
                bit_stream[bit_index]
            } else {
                false // Default to false if we somehow run out of bits
            }
        })
    });

    (bit_matrix, num_elements_needed)
}

/// SNARK circuit version: Derive split bits from seed using Poseidon hash
///
/// This is the constraint-generating version that creates R1CS constraints.
///
/// # Arguments
/// * `cs` - The constraint system reference
/// * `seed` - The seed as a field variable (typically a public input)
/// * `num_samples` - The number of field elements to squeeze from Poseidon
///
/// # Returns
/// A N×LEVELS matrix of Boolean circuit variables representing the derived bits
#[tracing::instrument(
    target = LOG_TARGET,
    name = "derive_split_bits::circuit",
    skip(cs),
    fields(
        seed = ?seed.value(),
        num_samples,
    )
)]
pub fn derive_split_bits_gadget<F, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<F>,
    seed: &FpVar<F>,
    num_samples: usize,
) -> Result<[[Boolean<F>; N]; LEVELS], SynthesisError>
where
    F: PrimeField + Absorb,
{
    use crate::poseidon_config;

    tracing::debug!(
        target: LOG_TARGET,
        seed = ?seed.value(),
        num_samples,
        "Deriving split bits from seed in circuit"
    );

    // Create Poseidon config and sponge
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

    // Absorb the seed
    sponge.absorb(&seed)?;

    // Squeeze the specified number of field elements
    let random_values = sponge.squeeze_field_elements(num_samples)?;

    tracing::debug!(
        target: LOG_TARGET,
        num_random_values = random_values.len(),
        "Random values generated in circuit"
    );

    // Collect bits into a single stream, trimming first and last from each
    let mut bit_stream = Vec::new();

    for value in random_values {
        let value_bits = value.to_bits_le()?;

        // Trim first and last bits
        if value_bits.len() > 2usize {
            bit_stream.extend_from_slice(&value_bits[1..value_bits.len() - 1]);
        }
    }

    // Fill the N×LEVELS matrix using the bit stream
    // If we run out of bits (shouldn't happen with field size ~255 bits × 2), use false
    let result = std::array::from_fn(|level| {
        std::array::from_fn(|i| {
            let bit_index = level * N + i;
            if bit_index < bit_stream.len() {
                bit_stream[bit_index].clone()
            } else {
                // Create a constant false boolean if we run out of bits
                Boolean::constant(false)
            }
        })
    });

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::rs_shuffle::{LEVELS, N}; // Import the constants for tests
    use ark_bn254::Fr as TestField; // BN254's scalar field = Grumpkin's base field (for SNARK circuits)
    use ark_relations::gr1cs::ConstraintSystem;
    use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        use tracing_subscriber::EnvFilter;

        // Use environment filter that allows all shuffle logs
        let filter = EnvFilter::new("rs-shuffle=debug");
        let timer = tracing_subscriber::fmt::time::uptime();

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER)
                    .with_test_writer()
                    .with_file(true)
                    .with_timer(timer)
                    .with_line_number(true), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_derive_split_bits_dimensions() {
        let _guard = setup_test_tracing();
        let seed = TestField::from(12345u64);
        let (bits_mat, num_samples) = derive_split_bits::<TestField, N, LEVELS>(seed);

        // Check dimensions
        assert_eq!(bits_mat.len(), LEVELS);
        for level in &bits_mat {
            assert_eq!(level.len(), N);
        }

        // Check that we calculated samples correctly
        assert!(num_samples > 0);
        tracing::debug!(target: LOG_TARGET, "Used {} samples for field", num_samples);
    }

    #[test]
    fn test_derive_split_bits_deterministic() {
        let _guard = setup_test_tracing();
        let seed = TestField::from(98765u64);

        // Generate bits twice with same seed
        let (bits_mat1, num_samples1) = derive_split_bits::<TestField, N, LEVELS>(seed);
        let (bits_mat2, num_samples2) = derive_split_bits::<TestField, N, LEVELS>(seed);

        // Should use same number of samples
        assert_eq!(num_samples1, num_samples2);

        // Should be identical
        for level in 0..LEVELS {
            for i in 0..N {
                assert_eq!(bits_mat1[level][i], bits_mat2[level][i]);
            }
        }
    }

    #[test]
    fn test_derive_split_bits_different_seeds() {
        let _guard = setup_test_tracing();
        let seed1 = TestField::from(111u64);
        let seed2 = TestField::from(222u64);

        tracing::debug!(target: LOG_TARGET, "Seed1: {:?}", seed1);
        tracing::debug!(target: LOG_TARGET, "Seed2: {:?}", seed2);

        let (bits_mat1, num_samples1) = derive_split_bits::<TestField, N, LEVELS>(seed1);
        let (bits_mat2, _num_samples2) = derive_split_bits::<TestField, N, LEVELS>(seed2);

        tracing::debug!(target: LOG_TARGET, "Num samples used: {}", num_samples1);

        // Debug: Log first few bits from each matrix
        tracing::debug!(target: LOG_TARGET, "First 10 bits from mat1[0]: {:?}", &bits_mat1[0][..10]);
        tracing::debug!(target: LOG_TARGET, "First 10 bits from mat2[0]: {:?}", &bits_mat2[0][..10]);

        // Should be different (with high probability)
        let mut differences = 0;
        for level in 0..LEVELS {
            for i in 0..N {
                if bits_mat1[level][i] != bits_mat2[level][i] {
                    differences += 1;
                }
            }
        }

        // Debug output
        let total_bits = N * LEVELS;
        let expected_min_diff = total_bits / 4;
        tracing::debug!(target: LOG_TARGET, "Total bits: {}, Differences found: {}, Expected minimum: {}",
                 total_bits, differences, expected_min_diff);
        tracing::debug!(target: LOG_TARGET, "Difference percentage: {:.2}%",
                 (differences as f64 / total_bits as f64) * 100.0);

        // At least 25% should be different (very conservative bound)
        assert!(
            differences > (N * LEVELS) / 4,
            "Not enough differences: {} out of {} bits (expected > {})",
            differences,
            total_bits,
            expected_min_diff
        );
    }

    #[test]
    fn test_derive_split_bits_circuit_dimensions() {
        let _guard = setup_test_tracing();
        let cs = ConstraintSystem::<TestField>::new_ref();

        // Create seed as public input
        let seed = TestField::from(12345u64);
        let seed_var = FpVar::new_input(cs.clone(), || Ok(seed)).expect("Failed to allocate seed");

        // Calculate number of samples needed
        let field_bits = TestField::MODULUS_BIT_SIZE as usize;
        let usable_bits_per_element = field_bits.saturating_sub(2);
        let total_bits_needed = N * LEVELS;
        let num_samples =
            (total_bits_needed + usable_bits_per_element - 1) / usable_bits_per_element;

        // Generate bits in circuit
        let bits_mat =
            derive_split_bits_gadget::<TestField, N, LEVELS>(cs.clone(), &seed_var, num_samples)
                .expect("Circuit execution failed");

        // Check dimensions
        assert_eq!(bits_mat.len(), LEVELS);
        for level in &bits_mat {
            assert_eq!(level.len(), N);
        }

        // Check constraint satisfaction
        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
    }

    #[test]
    fn test_derive_split_bits_circuit_native_consistency() {
        let _guard = setup_test_tracing();
        // Test that circuit and native versions produce the same bits
        let seed_field = TestField::from(7777u64);

        // Native version
        let (native_bits, num_samples) = derive_split_bits::<TestField, N, LEVELS>(seed_field);

        // Circuit version using the same number of samples
        let cs = ConstraintSystem::<TestField>::new_ref();
        let seed_var =
            FpVar::new_input(cs.clone(), || Ok(seed_field)).expect("Failed to allocate seed");
        let circuit_bits =
            derive_split_bits_gadget::<TestField, N, LEVELS>(cs.clone(), &seed_var, num_samples)
                .expect("Circuit execution failed");

        // Compare the values
        for level in 0..LEVELS {
            for i in 0..N {
                let native_bit = native_bits[level][i];
                let circuit_bit = circuit_bits[level][i]
                    .value()
                    .expect("Failed to get circuit bit value");
                assert_eq!(
                    native_bit, circuit_bit,
                    "Bit mismatch at level {}, position {}",
                    level, i
                );
            }
        }

        // Verify constraints are satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
    }

    #[test]
    fn test_derive_split_bits_circuit_deterministic() {
        let _guard = setup_test_tracing();
        // Test that the same seed produces the same bits
        let seed = TestField::from(98765u64);

        // Calculate number of samples needed
        let field_bits = TestField::MODULUS_BIT_SIZE as usize;
        let usable_bits_per_element = field_bits.saturating_sub(2);
        let total_bits_needed = N * LEVELS;
        let num_samples =
            (total_bits_needed + usable_bits_per_element - 1) / usable_bits_per_element;

        // First run
        let cs1 = ConstraintSystem::<TestField>::new_ref();
        let seed_var1 =
            FpVar::new_input(cs1.clone(), || Ok(seed)).expect("Failed to allocate seed");
        let bits1 =
            derive_split_bits_gadget::<TestField, N, LEVELS>(cs1.clone(), &seed_var1, num_samples)
                .expect("Circuit execution failed");

        // Second run
        let cs2 = ConstraintSystem::<TestField>::new_ref();
        let seed_var2 =
            FpVar::new_input(cs2.clone(), || Ok(seed)).expect("Failed to allocate seed");
        let bits2 =
            derive_split_bits_gadget::<TestField, N, LEVELS>(cs2.clone(), &seed_var2, num_samples)
                .expect("Circuit execution failed");

        // Compare values
        for level in 0..LEVELS {
            for i in 0..N {
                let bit1 = bits1[level][i].value().expect("Failed to get bit1 value");
                let bit2 = bits2[level][i].value().expect("Failed to get bit2 value");
                assert_eq!(
                    bit1, bit2,
                    "Bits should be identical at level {}, position {}",
                    level, i
                );
            }
        }

        // Both constraint systems should be satisfied
        assert!(cs1.is_satisfied().unwrap());
        assert!(cs2.is_satisfied().unwrap());
    }

    #[test]
    fn test_derive_split_bits_circuit_constraint_count() {
        let _guard = setup_test_tracing();
        let cs = ConstraintSystem::<TestField>::new_ref();

        let initial_constraints = cs.num_constraints();

        // Calculate number of samples needed
        let field_bits = TestField::MODULUS_BIT_SIZE as usize;
        let usable_bits_per_element = field_bits.saturating_sub(2);
        let total_bits_needed = N * LEVELS;
        let num_samples =
            (total_bits_needed + usable_bits_per_element - 1) / usable_bits_per_element;

        // Create seed and generate bits
        let seed = TestField::from(555u64);
        let seed_var = FpVar::new_input(cs.clone(), || Ok(seed)).expect("Failed to allocate seed");
        let _bits_mat =
            derive_split_bits_gadget::<TestField, N, LEVELS>(cs.clone(), &seed_var, num_samples)
                .expect("Circuit execution failed");

        let final_constraints = cs.num_constraints();
        let constraint_count = final_constraints - initial_constraints;

        // Log the constraint count for information
        // The circuit should generate a reasonable number of constraints
        // Mainly from Poseidon hash and bit decomposition
        assert!(constraint_count > 0, "Should generate some constraints");
        assert!(
            constraint_count < 100000,
            "Should not generate excessive constraints"
        );

        // Verify satisfaction
        assert!(cs.is_satisfied().unwrap());
    }
}
