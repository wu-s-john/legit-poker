use super::{
    circuit::ShuffleCircuit, data_structures::*, error::ShuffleError, prove::prove_as_subprotocol,
};
use ark_crypto_primitives::{snark::SNARK, sponge::Absorb};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use std::marker::PhantomData;

// Tracing target constants
const LOG_TARGET: &str = "shuffle::setup";

#[derive(Clone, Debug)]
pub enum ProofSystem {
    Groth16,
    Spartan,
    Both,
}

pub struct ShuffleSetup<E: ark_ec::pairing::Pairing, C: CurveGroup> {
    pub groth16_pk: Option<ProvingKey<E>>,
    pub groth16_vk: Option<VerifyingKey<E>>,
    pub spartan_gens: Option<Vec<u8>>, // Serialized SNARKGens
    pub spartan_comm: Option<Vec<u8>>, // Serialized commitment
    pub constraint_count: usize,
    pub public_input_count: usize,
    _phantom: PhantomData<C>,
}

/// Main proof function with setup
pub fn prove_with_setup<E, P>(
    seed: <P::BaseField as Field>::BasePrimeField,
    input_deck: Vec<ElGamalCiphertext<Projective<P>>>,
    shuffler_keys: &ElGamalKeys<Projective<P>>,
    setup: &ShuffleSetup<E, Projective<P>>,
    proof_system: ProofSystem,
) -> Result<(Vec<u8>, ProofMetrics), ShuffleError>
where
    P: SWCurveConfig,
    E: ark_ec::pairing::Pairing<ScalarField = <P::BaseField as Field>::BasePrimeField>,
    <P::BaseField as Field>::BasePrimeField: PrimeField + Absorb,
    P::BaseField: PrimeField,
{
    let mut metrics = ProofMetrics::default();
    let _total_span = tracing::info_span!(target: LOG_TARGET, "prove_total").entered();

    // 1. Call prove_as_subprotocol
    let shuffle_proof = {
        let _span = tracing::info_span!(target: LOG_TARGET, "witness_synthesis").entered();
        let start = std::time::Instant::now();
        let result = prove_as_subprotocol::<Projective<P>>(seed, input_deck, shuffler_keys)?;
        metrics.witness_synthesis_time = start.elapsed();
        result
    };

    // 2. Create constraint system with witnesses
    let _cs = {
        let _span = tracing::info_span!(target: LOG_TARGET, "constraint_generation").entered();
        let start = std::time::Instant::now();

        let cs = ConstraintSystem::<<P::BaseField as Field>::BasePrimeField>::new_ref();

        // Create and run the circuit
        let circuit = ShuffleCircuit::<Projective<P>, ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar<P, ark_r1cs_std::fields::fp::FpVar<<P::BaseField as Field>::BasePrimeField>>>::new(
            shuffler_keys.public_key,
            shuffle_proof.clone(),
            seed,
        );
        circuit
            .generate_constraints(cs.clone())
            .map_err(|e| ShuffleError::Synthesis(e))?;

        // Verify constraint count matches setup if provided
        if setup.constraint_count > 0 {
            assert_eq!(
                cs.num_constraints(),
                setup.constraint_count,
                "Circuit structure changed since setup!"
            );
        }

        metrics.constraint_generation_time = start.elapsed();
        metrics.constraint_count = cs.num_constraints();
        metrics.witness_count = cs.num_witness_variables();

        tracing::info!(
            target = LOG_TARGET,
            "Witness synthesis complete: {} constraints, {} witnesses in {:?}",
            metrics.constraint_count,
            metrics.witness_count,
            metrics.constraint_generation_time
        );

        cs
    };

    // 3. Generate proof using precomputed parameters
    let proof_bytes = {
        let _span = tracing::info_span!(target: LOG_TARGET, "proof_generation").entered();
        let start = std::time::Instant::now();

        let result = match proof_system {
            ProofSystem::Groth16 => {
                let pk = setup
                    .groth16_pk
                    .as_ref()
                    .ok_or(ShuffleError::SetupNotFound)?;

                // Create the proving circuit
                let circuit = ShuffleCircuit::<Projective<P>, ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar<P, ark_r1cs_std::fields::fp::FpVar<<P::BaseField as Field>::BasePrimeField>>>::new(
                    shuffler_keys.public_key,
                    shuffle_proof,
                    seed,
                );

                let proof = Groth16::<E>::prove(
                    pk,
                    circuit,
                    &mut ark_std::rand::rngs::StdRng::seed_from_u64(1234),
                )
                .map_err(|e| {
                    ShuffleError::Synthesis(ark_relations::r1cs::SynthesisError::from(e))
                })?;

                let mut proof_bytes = Vec::new();
                proof
                    .serialize_compressed(&mut proof_bytes)
                    .map_err(|e| ShuffleError::Serialization(e.to_string()))?;
                proof_bytes
            }
            ProofSystem::Spartan => {
                // For now, we'll skip Spartan implementation due to version conflicts
                // The Spartan library needs to be updated to use the same arkworks version
                return Err(ShuffleError::InvalidInput(
                    "Spartan proof system not yet fully implemented".to_string(),
                ));
            }
            _ => {
                return Err(ShuffleError::InvalidInput(
                    "Invalid proof system".to_string(),
                ))
            }
        };

        metrics.proof_generation_time = start.elapsed();
        metrics.proof_size_bytes = result.len();
        result
    };

    // Calculate total time
    let _total_start = std::time::Instant::now();
    metrics.total_time = metrics.constraint_generation_time
        + metrics.witness_synthesis_time
        + metrics.proof_generation_time;

    Ok((proof_bytes, metrics))
}

/// Setup function - generates proving/verifying keys
pub fn setup<E, P>(
    proof_system: ProofSystem,
) -> Result<ShuffleSetup<E, Projective<P>>, ShuffleError>
where
    P: SWCurveConfig,
    E: ark_ec::pairing::Pairing<ScalarField = <P::BaseField as Field>::BasePrimeField>,
    <P::BaseField as Field>::BasePrimeField: PrimeField + Absorb,
    P::BaseField: PrimeField,
{
    let _setup_span = tracing::info_span!(target: LOG_TARGET, "setup_total").entered();
    tracing::info!(target: LOG_TARGET, "Starting setup phase");

    // We need to run the circuit once to get the constraint count
    let (constraint_count, public_input_count, sample_proof, sample_keys, sample_seed) = {
        let _span = tracing::info_span!(target: LOG_TARGET, "circuit_analysis").entered();

        let cs = ConstraintSystem::<<P::BaseField as Field>::BasePrimeField>::new_ref();

        // Create a sample proof to determine circuit structure
        let sample_deck = generate_sample_deck::<Projective<P>>();
        let sample_keys = ElGamalKeys::new(P::ScalarField::from(1u64));
        let sample_seed = <P::BaseField as Field>::BasePrimeField::from(42u64);
        let sample_proof =
            prove_as_subprotocol::<Projective<P>>(sample_seed, sample_deck, &sample_keys)?;

        // Generate the circuit to count constraints
        let circuit = ShuffleCircuit::<Projective<P>, ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar<P, ark_r1cs_std::fields::fp::FpVar<<P::BaseField as Field>::BasePrimeField>>>::new(
            sample_keys.public_key,
            sample_proof.clone(),
            sample_seed,
        );
        circuit
            .generate_constraints(cs.clone())
            .map_err(|e| ShuffleError::Synthesis(e))?;

        let constraint_count = cs.num_constraints();
        let public_input_count = cs.num_instance_variables();

        tracing::info!(
            target = LOG_TARGET,
            "Circuit has {} constraints, {} public inputs",
            constraint_count,
            public_input_count
        );

        (
            constraint_count,
            public_input_count,
            sample_proof,
            sample_keys,
            sample_seed,
        )
    };

    // Generate proof system specific parameters
    let (groth16_pk, groth16_vk, spartan_gens, spartan_comm) = match proof_system {
        ProofSystem::Groth16 => {
            let _span = tracing::info_span!(target: LOG_TARGET, "groth16_setup").entered();
            tracing::info!(target: LOG_TARGET, "Generating Groth16 setup");

            // Use the sample circuit for setup
            let circuit = ShuffleCircuit::<Projective<P>, ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar<P, ark_r1cs_std::fields::fp::FpVar<<P::BaseField as Field>::BasePrimeField>>>::new(
                sample_keys.public_key,
                sample_proof,
                sample_seed,
            );

            let (pk, vk) = Groth16::<E>::circuit_specific_setup(
                circuit,
                &mut ark_std::rand::rngs::StdRng::seed_from_u64(1234),
            )
            .map_err(|e| ShuffleError::Synthesis(ark_relations::r1cs::SynthesisError::from(e)))?;
            (Some(pk), Some(vk), None, None)
        }
        ProofSystem::Spartan => {
            let _span = tracing::info_span!(target: LOG_TARGET, "spartan_setup").entered();
            tracing::info!(target: LOG_TARGET, "Generating Spartan setup");

            // For now, we'll skip Spartan setup due to version conflicts
            // The Spartan library needs to be updated to use the same arkworks version
            let spartan_gens_placeholder = Vec::new();
            let spartan_comm_placeholder = Vec::new();

            (
                None,
                None,
                Some(spartan_gens_placeholder),
                Some(spartan_comm_placeholder),
            )
        }
        ProofSystem::Both => {
            return Err(ShuffleError::InvalidInput(
                "Both proof systems not yet implemented".to_string(),
            ));
        }
    };

    tracing::info!(target = LOG_TARGET, "Setup completed");

    Ok(ShuffleSetup {
        groth16_pk,
        groth16_vk,
        spartan_gens,
        spartan_comm,
        constraint_count,
        public_input_count,
        _phantom: PhantomData,
    })
}

/// Convert arkworks R1CS format to Spartan format
#[allow(dead_code)]
fn convert_to_spartan_format<F>(
    _matrices: &ConstraintMatrices<F>,
    _witness: &[F],
    _inputs: &[F],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ShuffleError>
where
    F: PrimeField,
{
    // For now, return placeholder data
    // The actual Spartan conversion would require the Spartan library to use the same arkworks version
    Ok((Vec::new(), Vec::new(), Vec::new()))
}

/// Convenience function without setup (for testing/single use)
pub fn prove<E, P>(
    seed: <P::BaseField as Field>::BasePrimeField,
    input_deck: Vec<ElGamalCiphertext<Projective<P>>>,
    shuffler_keys: &ElGamalKeys<Projective<P>>,
    proof_system: ProofSystem,
) -> Result<(Vec<u8>, ProofMetrics), ShuffleError>
where
    P: SWCurveConfig,
    E: ark_ec::pairing::Pairing<ScalarField = <P::BaseField as Field>::BasePrimeField>,
    <P::BaseField as Field>::BasePrimeField: PrimeField + Absorb,
    P::BaseField: PrimeField,
{
    let setup = setup::<E, P>(proof_system.clone())?;
    prove_with_setup::<E, P>(seed, input_deck, shuffler_keys, &setup, proof_system)
}

fn generate_sample_deck<C: CurveGroup>() -> Vec<ElGamalCiphertext<C>>
where
    C::ScalarField: PrimeField,
{
    let generator = C::generator();
    (0..DECK_SIZE)
        .map(|i| {
            let scalar = C::ScalarField::from((i + 1) as u64);
            let scalar_bigint = scalar.into_bigint();
            ElGamalCiphertext {
                c1: generator.mul_bigint(scalar_bigint),
                c2: generator.mul_bigint(scalar_bigint),
            }
        })
        .collect()
}

// Test
#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{CurveConfig, PrimeGroup};
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
    use ark_std::rand;
    use std::io::BufWriter;
    use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

    const TEST_TARGET: &str = "shuffle";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        use tracing_subscriber::EnvFilter;

        // Use environment filter that allows all shuffle logs
        let filter = EnvFilter::new("shuffle=debug");
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

    fn init_tracing_with_flame() -> tracing_flame::FlushGuard<BufWriter<std::fs::File>> {
        use tracing_flame::FlameLayer;
        use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*, Registry};

        // Initialize flame graph tracing
        let (flame_layer, guard) = FlameLayer::with_file("./tracing.folded").unwrap();

        let filter = EnvFilter::new("")
            .add_directive("shuffle=debug".parse().unwrap())
            .add_directive("gr1cs=info".parse().unwrap()) // Arkworks uses gr1cs target
            .add_directive("r1cs=info".parse().unwrap()) // Keep both just in case
            .add_directive(tracing::Level::WARN.into()); // Default level for everything else

        Registry::default()
            .with(flame_layer)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_level(true)
                    .with_line_number(true)
                    .with_file(true)
                    .with_timer(fmt::time::uptime()),
            )
            .with(filter)
            .init();

        guard
    }

    #[test]
    fn test_generate_sample_deck() -> Result<(), Box<dyn std::error::Error>> {
        let _gaurd = setup_test_tracing();
        // Use BN254 G1 curve
        use ark_bn254::{g1, G1Projective};

        let input_deck = generate_sample_deck::<G1Projective>();
        assert_eq!(input_deck.len(), DECK_SIZE);

        // BN254 G1 has:
        // - BaseField = Fq (BN254's base field)
        // - ScalarField = Fr (BN254's scalar field)

        // For the seed, we need the base field (Fq)
        let seed = <G1Projective as CurveGroup>::BaseField::rand(&mut rand::thread_rng());

        // For ElGamal keys, we need the scalar field (Fr)
        let private_key = <g1::Config as CurveConfig>::ScalarField::rand(&mut rand::thread_rng());
        let public_key: G1Projective = G1Projective::generator() * private_key;
        let shuffler_keys = ElGamalKeys {
            private_key,
            public_key,
        };

        // Making a proof
        let proof = prove_as_subprotocol::<G1Projective>(seed, input_deck, &shuffler_keys)?;

        tracing::info!(target: TEST_TARGET, "Finish making proof to feed for circuit");
        // Create the circuit - g1::Config implements SWCurveConfig
        let circuit: ShuffleCircuit<G1Projective, ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar<ark_bn254::g1::Config, ark_r1cs_std::fields::fp::FpVar<ark_bn254::Fq>>> =
            ShuffleCircuit::new(shuffler_keys.public_key, proof, seed);

        let _rng = rand::thread_rng();

        // Guard for measuring constraint system generation time
        let cs = ConstraintSystemRef::new(ark_relations::r1cs::ConstraintSystem::new());
        {
            let _constraint_span =
                tracing::info_span!(target: TEST_TARGET, "constraint_system_generation").entered();

            tracing::debug!(target: TEST_TARGET, "Trying to generate constraints");

            circuit.clone().generate_constraints(cs.clone())?;

            tracing::info!(
                target: TEST_TARGET,
                num_constraints = cs.num_constraints(),
                num_instance_vars = cs.num_instance_variables(),
                num_witness_vars = cs.num_witness_variables(),
                "Constraint system generated"
            );
        }

        // Check if the constraint system is satisfied
        let is_satisfied = cs.is_satisfied()?;
        tracing::info!(
            target: TEST_TARGET,
            satisfied = is_satisfied,
            "Constraint system satisfaction check"
        );

        if !is_satisfied {
            // Find which constraint is unsatisfied - returns the constraint name
            if let Some(unsatisfied_name) = cs.which_is_unsatisfied()? {
                // Get constraint names to find the index
                let constraint_names = cs.constraint_names();

                let error_msg = if let Some(names) = constraint_names {
                    // Find the index of the unsatisfied constraint
                    let index = names.iter().position(|n| n == &unsatisfied_name);

                    if let Some(idx) = index {
                        tracing::error!(
                            target: LOG_TARGET,
                            "Unsatisfied constraint at index {}: {}",
                            idx, unsatisfied_name
                        );
                        // The constraint name includes the full namespace path
                        tracing::error!(
                            target: LOG_TARGET,
                            "Full namespace path: {}",
                            unsatisfied_name
                        );
                        format!(
                            "Constraint system is not satisfied. Failed constraint '{}' at index {} (see logs for details)",
                            unsatisfied_name, idx
                        )
                    } else {
                        tracing::error!(
                            target: LOG_TARGET,
                            "Unsatisfied constraint '{}' not found in constraint names list",
                            unsatisfied_name
                        );
                        format!(
                            "Constraint system is not satisfied. Failed constraint '{}' (index not found)",
                            unsatisfied_name
                        )
                    }
                } else {
                    tracing::error!(
                        target: LOG_TARGET,
                        "No constraint names available (compile with 'std' feature). Unsatisfied: {}",
                        unsatisfied_name
                    );
                    format!(
                        "Constraint system is not satisfied. Failed constraint '{}'",
                        unsatisfied_name
                    )
                };

                tracing::error!(
                    target: LOG_TARGET,
                    "Total constraints: {}",
                    cs.num_constraints()
                );
                tracing::error!(
                    target: LOG_TARGET,
                    "Total witness variables: {}",
                    cs.num_witness_variables()
                );
                tracing::error!(
                    target: LOG_TARGET,
                    "Total instance variables: {}",
                    cs.num_instance_variables()
                );

                return Err(Box::new(ShuffleError::UnsatisfiedConstraint(error_msg)));
            }
        }

        Ok(())
    }

    /// Generic function to test Poseidon performance over any field with configurable rounds
    #[tracing::instrument(level = "info", skip_all, fields(field = std::any::type_name::<F>(), num_rounds = num_rounds))]
    fn test_poseidon_performance_generic<F: PrimeField + Absorb>(
        num_rounds: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::poseidon_config;
        use ark_crypto_primitives::sponge::{
            constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
            poseidon::PoseidonSponge, CryptographicSponge,
        };
        use ark_r1cs_std::fields::fp::FpVar;
        use ark_r1cs_std::prelude::*;
        use std::time::Instant;

        tracing::info!(target: TEST_TARGET, "Testing Poseidon performance for field: {} with {} rounds", std::any::type_name::<F>(), num_rounds);

        // Create a timing tracker
        use std::collections::HashMap;
        let mut timings = HashMap::new();

        // First, let's run the native Poseidon operations to see expected performance
        tracing::info!(target: TEST_TARGET, "\n=== Native Poseidon Operations (no constraints) ===");

        // Profile config generation separately
        let config_start = Instant::now();
        let config = poseidon_config::<F>();
        let config_time = config_start.elapsed();
        timings.insert("poseidon_config_generation", config_time);
        tracing::info!(target: TEST_TARGET, "Config generation took: {:?}", config_time);

        let native_ops_start = Instant::now();
        let mut native_sponge = PoseidonSponge::new(&config);
        let seed_value = F::from(42u64);
        native_sponge.absorb(&seed_value);

        let mut native_random_values = Vec::new();

        for round in 0..num_rounds {
            // Absorb dummy evaluations
            let dummy_eval1 = F::from((round * 2) as u64);
            native_sponge.absorb(&vec![dummy_eval1]);

            // Squeeze random value
            let random_value: F = native_sponge.squeeze_field_elements(1)[0];
            native_sponge.absorb(&random_value);

            native_random_values.push(random_value);
        }

        let native_ops_time = native_ops_start.elapsed();
        tracing::info!(target: TEST_TARGET, "Native operations for {} rounds took: {:?}", num_rounds, native_ops_time);
        tracing::info!(target: TEST_TARGET, "Average per round: {:?}", native_ops_time / num_rounds as u32);

        // Now let's do the constraint generation version
        tracing::info!(target: TEST_TARGET, "\n=== Constraint Generation Version ===");

        // Create constraint system
        let cs = ConstraintSystemRef::new(ark_relations::r1cs::ConstraintSystem::new());

        // Create seed as public input
        let seed_var = FpVar::<F>::new_input(cs.clone(), || Ok(seed_value))?;

        // Measure constraint generation time
        let start = Instant::now();
        let initial_constraints = cs.num_constraints();

        // Profile sponge creation
        let sponge_start = Instant::now();
        tracing::debug!(target: TEST_TARGET, "Creating Poseidon sponge variable");
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);
        let sponge_creation_time = sponge_start.elapsed();
        timings.insert("sponge_var_creation", sponge_creation_time);
        tracing::info!(target: TEST_TARGET, "Sponge variable creation took: {:?}", sponge_creation_time);

        // Initial absorb of seed
        tracing::debug!(target: TEST_TARGET, "Absorbing seed into sponge");
        sponge.absorb(&seed_var)?;

        let mut all_random_values = Vec::new();
        let mut round_constraints = Vec::new();

        tracing::info!(target: TEST_TARGET, "Starting {} rounds of absorb/squeeze", num_rounds);

        let constraints_after_init = cs.num_constraints();
        tracing::info!(
            target: TEST_TARGET,
            "Constraints after Poseidon init: {} (init cost: {})",
            constraints_after_init,
            constraints_after_init - initial_constraints
        );

        for round in 0..num_rounds {
            let round_start_constraints = cs.num_constraints();

            // Create some dummy data to absorb (simulating sumcheck evaluations)
            let dummy_evals = vec![FpVar::<F>::new_witness(cs.clone(), || {
                Ok(F::from((round * 2) as u64))
            })?];

            let after_witness_alloc = cs.num_constraints();

            // Absorb evaluations (like sumcheck does)
            tracing::debug!(target: TEST_TARGET, "Round {}: Absorbing evaluations", round);
            sponge.absorb(&dummy_evals)?;

            let after_absorb = cs.num_constraints();

            // Squeeze one field element per round (like sumcheck)
            tracing::debug!(target: TEST_TARGET, "Round {}: Squeezing field element", round);
            let random_value = sponge.squeeze_field_elements(1)?;

            let after_squeeze = cs.num_constraints();

            // Absorb the squeezed value back (like sumcheck does with r_k)
            sponge.absorb(&random_value[0])?;

            let round_end_constraints = cs.num_constraints();
            let round_total = round_end_constraints - round_start_constraints;
            round_constraints.push(round_total);

            tracing::info!(
                target: TEST_TARGET,
                "Round {}: {} constraints (witness: {}, absorb1: {}, squeeze: {}, absorb2: {})",
                round,
                round_total,
                after_witness_alloc - round_start_constraints,
                after_absorb - after_witness_alloc,
                after_squeeze - after_absorb,
                round_end_constraints - after_squeeze
            );

            all_random_values.push(random_value[0].clone());
        }

        let constraint_gen_time = start.elapsed();
        let final_constraints = cs.num_constraints();
        let constraints_added = final_constraints - initial_constraints;

        // Verify we got all random values
        assert_eq!(
            all_random_values.len(),
            num_rounds,
            "Should get exactly {} random values",
            num_rounds
        );

        // Log results
        tracing::info!(
            target: TEST_TARGET,
            "Poseidon hash for {} rounds completed in {:?}",
            num_rounds,
            constraint_gen_time
        );

        // Print round-by-round summary
        tracing::info!(target: TEST_TARGET, "\n=== Round-by-round constraint summary ===");
        for (i, &count) in round_constraints.iter().enumerate() {
            tracing::info!(target: TEST_TARGET, "Round {}: {} constraints", i, count);
        }

        // Calculate statistics
        let min_round = round_constraints.iter().min().unwrap_or(&0);
        let max_round = round_constraints.iter().max().unwrap_or(&0);
        let avg_round = constraints_added / num_rounds;

        tracing::info!(target: TEST_TARGET, "\n=== Statistics ===");
        tracing::info!(target: TEST_TARGET, "Min constraints per round: {}", min_round);
        tracing::info!(target: TEST_TARGET, "Max constraints per round: {}", max_round);
        tracing::info!(target: TEST_TARGET, "Avg constraints per round: {}", avg_round);
        tracing::info!(
            target: TEST_TARGET,
            "Constraints added: {} (from {} to {})",
            constraints_added,
            initial_constraints,
            final_constraints
        );
        tracing::info!(
            target: TEST_TARGET,
            "Constraints per round: {}",
            constraints_added / num_rounds
        );
        tracing::info!(
            target: TEST_TARGET,
            "Average time per round: {:?}",
            constraint_gen_time / num_rounds as u32
        );

        // Check if the constraint system is satisfied
        let is_satisfied = cs.is_satisfied()?;
        tracing::info!(
            target: TEST_TARGET,
            satisfied = is_satisfied,
            "Constraint system satisfaction check"
        );
        assert!(is_satisfied, "Constraint system should be satisfied");

        // Compare with native execution
        tracing::info!(target: TEST_TARGET, "\n=== Comparison ===");
        tracing::info!(
            target: TEST_TARGET,
            "Native operations: {:?} total, {:?} per round",
            native_ops_time,
            native_ops_time / num_rounds as u32
        );
        tracing::info!(
            target: TEST_TARGET,
            "Constraint generation: {:?} total, {:?} per round",
            constraint_gen_time,
            constraint_gen_time / num_rounds as u32
        );
        tracing::info!(
            target: TEST_TARGET,
            "Overhead factor: {:.2}x",
            constraint_gen_time.as_secs_f64() / native_ops_time.as_secs_f64()
        );

        // Verify the random values match between native and circuit
        for (i, (native_val, circuit_val)) in native_random_values
            .iter()
            .zip(all_random_values.iter())
            .enumerate()
        {
            let circuit_value = circuit_val.value()?;
            assert_eq!(
                *native_val, circuit_value,
                "Round {} random values should match",
                i
            );
        }
        tracing::info!(target: TEST_TARGET, "✅ All random values match between native and circuit execution");

        // Print profiling summary
        tracing::info!(target: TEST_TARGET, "\n=== Profiling Summary ===");
        let mut sorted_timings: Vec<_> = timings.iter().collect();
        sorted_timings.sort_by(|a, b| b.1.cmp(a.1));

        for (name, duration) in sorted_timings {
            tracing::info!(
                target: TEST_TARGET,
                "{}: {:?} ({:.2}% of total)",
                name,
                duration,
                (duration.as_secs_f64() / constraint_gen_time.as_secs_f64()) * 100.0
            );
        }

        Ok(())
    }

    #[test]
    fn test_poseidon_hash_10_points() -> Result<(), Box<dyn std::error::Error>> {
        use ark_bn254::Fr as Bn254Fr;

        tracing::info!(target: TEST_TARGET, "Starting Poseidon hash test with BN254's base field (Fr)");

        // Test with 10 points
        tracing::info!(target: TEST_TARGET, "\n=== Testing with 10 rounds ===");
        test_poseidon_performance_generic::<Bn254Fr>(10)?;

        // Ensure the flame graph is flushed by dropping the guard

        tracing::info!(target: TEST_TARGET, "Flame graph written to ./tracing.folded");
        tracing::info!(target: TEST_TARGET, "To generate SVG: inferno-flamegraph < tracing.folded > flamegraph.svg");

        Ok(())
    }

    #[test]
    fn test_snark_generate_sample_deck() -> Result<(), Box<dyn std::error::Error>> {
        let _gaurd = setup_test_tracing();
        // Use Grumpkin curve
        use ark_bn254::Bn254;
        use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};

        // ---- build a sample shuffle circuit ---------------------------------
        let input_deck = generate_sample_deck::<GrumpkinProjective>();
        let seed = <GrumpkinProjective as CurveGroup>::BaseField::rand(&mut rand::thread_rng());
        let private_key =
            <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rand::thread_rng());
        let public_key = GrumpkinProjective::generator() * private_key;
        let shuffler_keys = ElGamalKeys {
            private_key,
            public_key,
        };

        let proof = prove_as_subprotocol::<GrumpkinProjective>(seed, input_deck, &shuffler_keys)?;
        let circuit =
            ShuffleCircuit::<GrumpkinProjective, ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar<GrumpkinConfig, ark_r1cs_std::fields::fp::FpVar<<GrumpkinConfig as ark_ec::CurveConfig>::BaseField>>>::new(shuffler_keys.public_key, proof, seed);
        let mut rng = rand::thread_rng();
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)?;
        let _snark_proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;

        Ok(())
    }
}
