//! Benchmark for RSShuffleWithReencryptionCircuit using Groth16 with BN254/Grumpkin

use ark_bn254::{Bn254, Fr as ScalarField};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_grumpkin::{Projective as GrumpkinProjective, GrumpkinConfig};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::time::{Duration, Instant};
use zk_poker::shuffling::{
    data_structures::{scalar_to_base_field, ElGamalCiphertext},
    rs_shuffle::{
        circuit::RSShuffleWithReencryptionCircuit,
        witness_preparation::apply_rs_shuffle_permutation,
        LEVELS, N,
    },
};

/// Configuration for benchmark runs
struct BenchmarkConfig {
    /// Number of iterations to run
    iterations: usize,
    /// Whether to output CSV format
    csv_output: bool,
    /// Whether to run in verbose mode
    verbose: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 1,
            csv_output: false,
            verbose: true,
        }
    }
}

/// Statistics collected during benchmark
#[derive(Clone, Debug)]
struct BenchmarkStats {
    /// Number of constraints in the circuit
    num_constraints: usize,
    /// Number of witness variables
    num_witness_variables: usize,
    /// Number of public input variables
    num_public_input_variables: usize,
    /// Time to generate trusted setup
    setup_time: Duration,
    /// Time to generate proof
    proving_time: Duration,
    /// Time to verify proof
    verification_time: Duration,
    /// Size of the proof in bytes
    proof_size: usize,
    /// Size of the verification key in bytes
    vk_size: usize,
    /// Size of the proving key in bytes (if measured)
    pk_size: Option<usize>,
}

impl BenchmarkStats {
    fn print_summary(&self) {
        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║         RS Shuffle with Re-encryption Benchmark          ║");
        println!("╠═══════════════════════════════════════════════════════════╣");
        println!("║ Circuit Statistics                                        ║");
        println!("╟───────────────────────────────────────────────────────────╢");
        println!("║ Constraints:              {:>32} ║", self.num_constraints);
        println!("║ Witness Variables:        {:>32} ║", self.num_witness_variables);
        println!("║ Public Input Variables:   {:>32} ║", self.num_public_input_variables);
        println!("║ Total Variables:          {:>32} ║", 
            self.num_witness_variables + self.num_public_input_variables);
        println!("╟───────────────────────────────────────────────────────────╢");
        println!("║ Performance Metrics                                       ║");
        println!("╟───────────────────────────────────────────────────────────╢");
        println!("║ Setup Time:               {:>30?} ║", self.setup_time);
        println!("║ Proving Time:             {:>30?} ║", self.proving_time);
        println!("║ Verification Time:        {:>30?} ║", self.verification_time);
        println!("╟───────────────────────────────────────────────────────────╢");
        println!("║ Size Metrics                                              ║");
        println!("╟───────────────────────────────────────────────────────────╢");
        println!("║ Proof Size:               {:>28} B ║", self.proof_size);
        println!("║ Verification Key Size:    {:>28} B ║", self.vk_size);
        if let Some(pk_size) = self.pk_size {
            println!("║ Proving Key Size:         {:>28} B ║", pk_size);
        }
        println!("╚═══════════════════════════════════════════════════════════╝");
    }

    fn print_csv_header() {
        println!("constraints,witness_vars,public_vars,setup_ms,proving_ms,verification_ms,proof_bytes,vk_bytes");
    }

    fn print_csv(&self) {
        println!(
            "{},{},{},{},{},{},{},{}",
            self.num_constraints,
            self.num_witness_variables,
            self.num_public_input_variables,
            self.setup_time.as_millis(),
            self.proving_time.as_millis(),
            self.verification_time.as_millis(),
            self.proof_size,
            self.vk_size
        );
    }
}

/// Generate test data for the circuit
fn generate_test_data(
    rng: &mut StdRng,
) -> (
    [ElGamalCiphertext<GrumpkinProjective>; N],
    [ElGamalCiphertext<GrumpkinProjective>; N],
    [ElGamalCiphertext<GrumpkinProjective>; N],
    ScalarField,
    GrumpkinProjective,
    [ScalarField; N],
    ScalarField,
    ScalarField,
    zk_poker::shuffling::rs_shuffle::data_structures::WitnessData<N, LEVELS>,
    usize,
) {
    // Generate shuffler's key pair
    let shuffler_sk = <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::rand(rng);
    let shuffler_pk = GrumpkinProjective::generator() * shuffler_sk;

    // Create initial encrypted deck
    println!("  Generating {} encrypted cards...", N);
    let ct_init: [ElGamalCiphertext<GrumpkinProjective>; N] = std::array::from_fn(|i| {
        let message = <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::from((i + 1) as u64);
        let randomness = <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::rand(rng);
        ElGamalCiphertext::encrypt_scalar(message, randomness, shuffler_pk)
    });

    // Generate seed for RS shuffle
    let seed = ScalarField::rand(rng);

    // Apply RS shuffle permutation
    println!("  Applying RS shuffle permutation...");
    let (witness_data, num_samples, ct_after_shuffle) =
        apply_rs_shuffle_permutation::<ScalarField, _, N, LEVELS>(seed, &ct_init);

    // Generate re-encryption randomizations (as ScalarField)
    let rerandomizations_scalar: [<GrumpkinConfig as ark_ec::CurveConfig>::ScalarField; N] =
        std::array::from_fn(|_| <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::rand(rng));
    
    // Convert ScalarField values to BN254's ScalarField for the circuit
    let rerandomizations: [ScalarField; N] = std::array::from_fn(|i| {
        scalar_to_base_field::<<GrumpkinConfig as ark_ec::CurveConfig>::ScalarField, ScalarField>(&rerandomizations_scalar[i])
    });

    // Apply re-encryption
    println!("  Applying re-encryption...");
    let ct_final: [ElGamalCiphertext<GrumpkinProjective>; N] = std::array::from_fn(|i| {
        ct_after_shuffle[i].add_encryption_layer(rerandomizations_scalar[i], shuffler_pk)
    });

    // Generate Fiat-Shamir challenges
    let alpha = ScalarField::rand(rng);
    let beta = ScalarField::rand(rng);

    (
        ct_init,
        ct_after_shuffle,
        ct_final,
        seed,
        shuffler_pk,
        rerandomizations,
        alpha,
        beta,
        witness_data,
        num_samples,
    )
}

/// Run a single benchmark iteration
fn run_benchmark_iteration(config: &BenchmarkConfig) -> BenchmarkStats {
    let mut rng = StdRng::seed_from_u64(12345);

    println!("\n🔧 Generating test data...");
    let (
        ct_init,
        ct_after_shuffle,
        ct_final_reencrypted,
        seed,
        shuffler_pk,
        encryption_randomizations,
        alpha,
        beta,
        witness,
        num_samples,
    ) = generate_test_data(&mut rng);

    // Create the circuit
    println!("\n📋 Creating circuit instance...");
    let circuit = RSShuffleWithReencryptionCircuit::<ScalarField, GrumpkinProjective, N, LEVELS> {
        ct_init_pub: ct_init.clone(),
        ct_after_shuffle: ct_after_shuffle.clone(),
        ct_final_reencrypted: ct_final_reencrypted.clone(),
        seed,
        shuffler_pk,
        encryption_randomizations,
        alpha,
        beta,
        witness,
        num_samples,
    };

    // Measure constraint system size
    if config.verbose {
        println!("\n📊 Analyzing constraint system...");
    }
    let cs = ConstraintSystem::<ScalarField>::new_ref();
    let circuit_for_analysis = RSShuffleWithReencryptionCircuit::<ScalarField, GrumpkinProjective, N, LEVELS> {
        ct_init_pub: ct_init.clone(),
        ct_after_shuffle: ct_after_shuffle.clone(),
        ct_final_reencrypted: ct_final_reencrypted.clone(),
        seed,
        shuffler_pk,
        encryption_randomizations,
        alpha,
        beta,
        witness: witness.clone(),
        num_samples,
    };
    circuit_for_analysis
        .generate_constraints(cs.clone())
        .expect("Failed to generate constraints");

    let num_constraints = cs.num_constraints();
    let num_witness_variables = cs.num_witness_variables();
    let num_public_input_variables = cs.num_instance_variables() - 1; // Subtract 1 for the "one" variable

    if config.verbose {
        println!("  ✓ Constraints: {}", num_constraints);
        println!("  ✓ Witness variables: {}", num_witness_variables);
        println!("  ✓ Public input variables: {}", num_public_input_variables);
    }

    // Generate trusted setup
    println!("\n🔐 Generating trusted setup...");
    let setup_start = Instant::now();
    let circuit_for_setup = RSShuffleWithReencryptionCircuit::<ScalarField, GrumpkinProjective, N, LEVELS> {
        ct_init_pub: ct_init.clone(),
        ct_after_shuffle: ct_after_shuffle.clone(),
        ct_final_reencrypted: ct_final_reencrypted.clone(),
        seed,
        shuffler_pk,
        encryption_randomizations,
        alpha,
        beta,
        witness: witness.clone(),
        num_samples,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng)
        .expect("Failed to generate proving and verifying keys");
    let setup_time = setup_start.elapsed();
    if config.verbose {
        println!("  ✓ Setup completed in {:?}", setup_time);
    }

    // Measure key sizes
    let vk_size = vk.serialized_size(Compress::Yes);
    let pk_size = if config.verbose {
        Some(pk.serialized_size(Compress::Yes))
    } else {
        None
    };

    // Prepare verification key for faster verification
    let pvk = prepare_verifying_key(&vk);

    // Generate proof
    println!("\n🎯 Generating proof...");
    let proving_start = Instant::now();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .expect("Failed to generate proof");
    let proving_time = proving_start.elapsed();
    if config.verbose {
        println!("  ✓ Proof generated in {:?}", proving_time);
    }

    // Measure proof size
    let proof_size = proof.serialized_size(Compress::Yes);

    // Prepare public inputs for verification
    let mut public_inputs = Vec::new();
    
    // Add seed
    public_inputs.push(seed);
    
    // Add initial ciphertexts (flattened)
    for ct in &ct_init {
        // Convert curve points to field elements for public inputs
        // Note: In practice, you might hash these instead
        let c1_affine = ct.c1.into_affine();
        let c2_affine = ct.c2.into_affine();
        let c1_bytes = c1_affine.x().unwrap().into_bigint().to_bytes_le();
        let c2_bytes = c2_affine.x().unwrap().into_bigint().to_bytes_le();
        public_inputs.push(ScalarField::from_le_bytes_mod_order(&c1_bytes));
        public_inputs.push(ScalarField::from_le_bytes_mod_order(&c2_bytes));
    }
    
    // Add final re-encrypted ciphertexts (flattened)
    for ct in &ct_final_reencrypted {
        let c1_affine = ct.c1.into_affine();
        let c2_affine = ct.c2.into_affine();
        let c1_bytes = c1_affine.x().unwrap().into_bigint().to_bytes_le();
        let c2_bytes = c2_affine.x().unwrap().into_bigint().to_bytes_le();
        public_inputs.push(ScalarField::from_le_bytes_mod_order(&c1_bytes));
        public_inputs.push(ScalarField::from_le_bytes_mod_order(&c2_bytes));
    }
    
    // Add shuffler public key
    let pk_affine = shuffler_pk.into_affine();
    let pk_bytes = pk_affine.x().unwrap().into_bigint().to_bytes_le();
    public_inputs.push(ScalarField::from_le_bytes_mod_order(&pk_bytes));
    
    // Add Fiat-Shamir challenges
    public_inputs.push(alpha);
    public_inputs.push(beta);

    // Verify proof
    println!("\n✅ Verifying proof...");
    let verification_start = Instant::now();
    let valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .expect("Failed to verify proof");
    let verification_time = verification_start.elapsed();

    if valid {
        if config.verbose {
            println!("  ✓ Proof verified successfully in {:?}", verification_time);
        }
    } else {
        panic!("  ✗ Proof verification failed!");
    }

    BenchmarkStats {
        num_constraints,
        num_witness_variables,
        num_public_input_variables,
        setup_time,
        proving_time,
        verification_time,
        proof_size,
        vk_size,
        pk_size,
    }
}

/// Aggregate statistics from multiple runs
fn aggregate_stats(stats: &[BenchmarkStats]) -> BenchmarkStats {
    let n = stats.len() as u32;
    
    BenchmarkStats {
        num_constraints: stats[0].num_constraints,
        num_witness_variables: stats[0].num_witness_variables,
        num_public_input_variables: stats[0].num_public_input_variables,
        setup_time: stats.iter().map(|s| s.setup_time).sum::<Duration>() / n,
        proving_time: stats.iter().map(|s| s.proving_time).sum::<Duration>() / n,
        verification_time: stats.iter().map(|s| s.verification_time).sum::<Duration>() / n,
        proof_size: stats[0].proof_size,
        vk_size: stats[0].vk_size,
        pk_size: stats[0].pk_size,
    }
}

fn main() {
    // Initialize tracing for better debugging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║     RS Shuffle with Re-encryption Circuit Benchmark      ║");
    println!("║                  Using Groth16 on BN254                   ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("Configuration:");
    println!("  • Pairing Curve: BN254");
    println!("  • Inner Curve: Grumpkin");
    println!("  • Deck Size: {} cards", N);
    println!("  • Shuffle Levels: {}", LEVELS);
    println!("  • Total Split Bits: {}", N * LEVELS);

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mut config = BenchmarkConfig::default();

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--csv" => config.csv_output = true,
            "--quiet" => config.verbose = false,
            s if s.starts_with("--iterations=") => {
                config.iterations = s
                    .strip_prefix("--iterations=")
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(1);
            }
            "--help" => {
                println!("\nUsage: {} [OPTIONS]", args[0]);
                println!("\nOptions:");
                println!("  --iterations=N    Run N iterations (default: 1)");
                println!("  --csv             Output results in CSV format");
                println!("  --quiet           Suppress verbose output");
                println!("  --help            Show this help message");
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                eprintln!("Use --help for usage information");
                std::process::exit(1);
            }
        }
    }

    if config.csv_output {
        BenchmarkStats::print_csv_header();
    }

    // Run benchmarks
    let mut all_stats = Vec::new();
    for i in 0..config.iterations {
        if config.verbose && config.iterations > 1 {
            println!("\n═══════════════════════════════════════════════════════════");
            println!("                    Iteration {}/{}", i + 1, config.iterations);
            println!("═══════════════════════════════════════════════════════════");
        }
        
        let stats = run_benchmark_iteration(&config);
        
        if config.csv_output {
            stats.print_csv();
        }
        
        all_stats.push(stats);
    }

    // Print summary
    if !config.csv_output {
        if config.iterations > 1 {
            println!("\n═══════════════════════════════════════════════════════════");
            println!("                    Average Results");
            println!("═══════════════════════════════════════════════════════════");
            let avg_stats = aggregate_stats(&all_stats);
            avg_stats.print_summary();
        } else {
            all_stats[0].print_summary();
        }
    }

    println!("\n✨ Benchmark completed successfully!");
}