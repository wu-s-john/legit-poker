//! Benchmark for RSShuffleWithReencryptionCircuit using Groth16 with configurable pairing curves

use ark_ec::{
    pairing::Pairing, short_weierstrass::Projective, AffineRepr, CurveConfig, CurveGroup,
};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey};
use ark_r1cs_std::{
    fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar, groups::CurveVar,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use clap::{Parser, ValueEnum};
use std::time::{Duration, Instant};
use tracing_subscriber::{
    filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};
use zk_poker::shuffling::{
    data_structures::{scalar_to_base_field, ElGamalCiphertext},
    rs_shuffle::{
        circuit::RSShuffleWithReencryptionCircuit, native::run_rs_shuffle_permutation, LEVELS, N,
    },
};

// Import specific curve implementations
use ark_bls12_381::{Bls12_381, G1Projective as Bls12_381G1};
use ark_bn254::Bn254;
use ark_crypto_primitives::sponge::Absorb;
use ark_ed_on_bls12_381;
use ark_ed_on_bn254;

/// Supported inner curve configurations (curves used for encryption)
#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum InnerCurveSelection {
    /// Grumpkin curve (short Weierstrass, uses BN254 pairing)
    #[value(name = "grumpkin")]
    Grumpkin,
    /// BabyJubJub curve (twisted Edwards, uses BN254 pairing)
    #[value(name = "babyjubjub")]
    BabyJubJub,
    /// Bandersnatch curve (twisted Edwards, uses BLS12-381 pairing)
    #[value(name = "bandersnatch")]
    Bandersnatch,
    /// Jubjub curve (twisted Edwards, uses BLS12-381 pairing)
    #[value(name = "jubjub")]
    Jubjub,
}

impl std::fmt::Display for InnerCurveSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerCurveSelection::Grumpkin => write!(f, "Grumpkin (BN254)"),
            InnerCurveSelection::BabyJubJub => write!(f, "BabyJubJub (BN254)"),
            InnerCurveSelection::Bandersnatch => write!(f, "Bandersnatch (BLS12-381)"),
            InnerCurveSelection::Jubjub => write!(f, "Jubjub (BLS12-381)"),
        }
    }
}

/// RS Shuffle with Re-encryption Circuit Benchmark
#[derive(Parser, Debug)]
#[command(name = "rs_shuffle_reencrypt_bench")]
#[command(version, about, long_about = None)]
#[command(after_help = "INNER CURVE CONFIGURATIONS:
  grumpkin:     Short Weierstrass curve, uses BN254 pairing
  babyjubjub:   Twisted Edwards curve, uses BN254 pairing
  bandersnatch: Twisted Edwards curve, uses BLS12-381 pairing
  jubjub:       Twisted Edwards curve, uses BLS12-381 pairing")]
struct Cli {
    /// Select inner curve for encryption
    #[arg(long, value_enum, default_value_t = InnerCurveSelection::Grumpkin)]
    curve: InnerCurveSelection,

    /// Number of iterations to run
    #[arg(short, long, default_value_t = 1)]
    iterations: usize,

    /// Output results in CSV format
    #[arg(long)]
    csv: bool,

    /// Suppress verbose output
    #[arg(short, long)]
    quiet: bool,

    /// Enable GPU acceleration (requires ICICLE backend)
    #[arg(long)]
    gpu: bool,
}

/// Configuration for benchmark runs (derived from CLI args)
struct BenchmarkConfig {
    /// Number of iterations to run
    iterations: usize,
    /// Whether to output CSV format
    csv_output: bool,
    /// Whether to run in verbose mode
    verbose: bool,
    /// Which inner curve to use
    curve: InnerCurveSelection,
    /// Whether to use GPU acceleration
    use_gpu: bool,
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
        println!(
            "║ Witness Variables:        {:>32} ║",
            self.num_witness_variables
        );
        println!(
            "║ Public Input Variables:   {:>32} ║",
            self.num_public_input_variables
        );
        println!(
            "║ Total Variables:          {:>32} ║",
            self.num_witness_variables + self.num_public_input_variables
        );
        println!("╟───────────────────────────────────────────────────────────╢");
        println!("║ Performance Metrics                                       ║");
        println!("╟───────────────────────────────────────────────────────────╢");
        println!("║ Setup Time:               {:>30?} ║", self.setup_time);
        println!("║ Proving Time:             {:>30?} ║", self.proving_time);
        println!(
            "║ Verification Time:        {:>30?} ║",
            self.verification_time
        );
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

/// Generate test data for the circuit (generic over curves)
fn generate_test_data<E, C, const N: usize, const LEVELS: usize>(
    rng: &mut StdRng,
) -> (
    [ElGamalCiphertext<C>; N],
    [ElGamalCiphertext<C>; N],
    [ElGamalCiphertext<C>; N],
    E::ScalarField,
    C,
    [E::ScalarField; N],
    E::ScalarField,
    E::ScalarField,
    zk_poker::shuffling::rs_shuffle::data_structures::PermutationWitnessTrace<N, LEVELS>,
    usize,
)
where
    E: Pairing,
    C: CurveGroup<BaseField = E::ScalarField>,
    C::Config: CurveConfig<BaseField = E::ScalarField>,
    <C::Config as CurveConfig>::ScalarField: UniformRand,
    E::ScalarField: PrimeField + Absorb,
{
    // Generate shuffler's key pair
    let shuffler_sk = <C::Config as CurveConfig>::ScalarField::rand(rng);
    let shuffler_pk = C::generator() * shuffler_sk;

    // Create initial encrypted deck
    println!("  Generating {} encrypted cards...", N);
    let ct_init: [ElGamalCiphertext<C>; N] = std::array::from_fn(|i| {
        let message = <C::Config as CurveConfig>::ScalarField::from((i + 1) as u64);
        let randomness = <C::Config as CurveConfig>::ScalarField::rand(rng);
        ElGamalCiphertext::encrypt_scalar(message, randomness, shuffler_pk)
    });

    // Generate seed for RS shuffle
    let seed = E::ScalarField::rand(rng);

    // Apply RS shuffle permutation
    println!("  Run RS shuffle permutation...");
    let rs_shuffle_trace =
        run_rs_shuffle_permutation::<E::ScalarField, _, N, LEVELS>(seed, &ct_init);

    // Generate re-encryption randomizations (as curve's scalar field)
    let rerandomizations_scalar: [<C::Config as CurveConfig>::ScalarField; N] =
        zk_poker::shuffling::encryption::generate_randomization_array::<C::Config, N>(rng);

    // Convert curve scalar field values to pairing's scalar field for the circuit
    let rerandomizations: [E::ScalarField; N] = std::array::from_fn(|i| {
        scalar_to_base_field::<<C::Config as CurveConfig>::ScalarField, E::ScalarField>(
            &rerandomizations_scalar[i],
        )
    });

    // Apply re-encryption
    println!("  Applying re-encryption...");
    let ct_final: [ElGamalCiphertext<C>; N] = std::array::from_fn(|i| {
        rs_shuffle_trace.permuted_output[i]
            .add_encryption_layer(rerandomizations_scalar[i], shuffler_pk)
    });

    // Generate Fiat-Shamir challenges
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);

    (
        ct_init,
        rs_shuffle_trace.permuted_output,
        ct_final,
        seed,
        shuffler_pk,
        rerandomizations,
        alpha,
        beta,
        rs_shuffle_trace.witness_trace,
        rs_shuffle_trace.num_samples,
    )
}

/// Run a single benchmark iteration (generic over curves)
fn run_benchmark_iteration<E, C1, C2, CV, const N: usize, const LEVELS: usize, F>(
    config: &BenchmarkConfig,
    prover: F,
) -> BenchmarkStats
where
    E: Pairing,
    E::ScalarField: PrimeField + Absorb,
    C1: CurveGroup<BaseField = E::BaseField>, // C1's Config must be G1
    C2: CurveGroup<BaseField = E::ScalarField>,
    CV: CurveVar<C2, E::ScalarField>,
    C1::BaseField: PrimeField,
    C2::BaseField: PrimeField,
    F: Fn(
        &ProvingKey<E>,
        RSShuffleWithReencryptionCircuit<E::ScalarField, C2, CV, N, LEVELS>,
        &mut StdRng,
    ) -> Result<Proof<E>, anyhow::Error>,
{
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
    ) = generate_test_data::<E, C2, N, LEVELS>(&mut rng);

    // Generate precomputed generator powers
    let num_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;
    let generator_powers = (0..num_bits)
        .scan(C2::generator(), |acc, _| {
            let current = *acc;
            *acc = acc.double();
            Some(current)
        })
        .collect::<Vec<_>>();

    // Create the circuit
    println!("\n📋 Creating circuit instance...");
    let circuit = RSShuffleWithReencryptionCircuit::<E::ScalarField, C2, CV, N, LEVELS>::new(
        ct_init.clone(),
        ct_after_shuffle.clone(),
        ct_final_reencrypted.clone(),
        seed,
        shuffler_pk,
        encryption_randomizations,
        alpha,
        beta,
        witness.clone(),
        num_samples,
        generator_powers.clone(),
    );

    // Measure constraint system size
    if config.verbose {
        println!("\n📊 Analyzing constraint system...");
    }
    let cs = ConstraintSystem::<E::ScalarField>::new_ref();
    let circuit_for_analysis =
        RSShuffleWithReencryptionCircuit::<E::ScalarField, C2, CV, N, LEVELS>::new(
            ct_init.clone(),
            ct_after_shuffle.clone(),
            ct_final_reencrypted.clone(),
            seed,
            shuffler_pk,
            encryption_randomizations,
            alpha,
            beta,
            witness.clone(),
            num_samples,
            generator_powers.clone(),
        );
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
    let circuit_for_setup =
        RSShuffleWithReencryptionCircuit::<E::ScalarField, C2, CV, N, LEVELS>::new(
            ct_init.clone(),
            ct_after_shuffle.clone(),
            ct_final_reencrypted.clone(),
            seed,
            shuffler_pk,
            encryption_randomizations,
            alpha,
            beta,
            witness.clone(),
            num_samples,
            generator_powers.clone(),
        );
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit_for_setup, &mut rng)
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

    // Use the provided prover function
    let proof = prover(&pk, circuit, &mut rng).expect("Failed to generate proof");

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
        public_inputs.push(E::ScalarField::from_le_bytes_mod_order(&c1_bytes));
        public_inputs.push(E::ScalarField::from_le_bytes_mod_order(&c2_bytes));
    }

    // Add final re-encrypted ciphertexts (flattened)
    for ct in &ct_final_reencrypted {
        let c1_affine = ct.c1.into_affine();
        let c2_affine = ct.c2.into_affine();
        let c1_bytes = c1_affine.x().unwrap().into_bigint().to_bytes_le();
        let c2_bytes = c2_affine.x().unwrap().into_bigint().to_bytes_le();
        public_inputs.push(E::ScalarField::from_le_bytes_mod_order(&c1_bytes));
        public_inputs.push(E::ScalarField::from_le_bytes_mod_order(&c2_bytes));
    }

    // Add shuffler public key
    let pk_affine = shuffler_pk.into_affine();
    let pk_bytes = pk_affine.x().unwrap().into_bigint().to_bytes_le();
    public_inputs.push(E::ScalarField::from_le_bytes_mod_order(&pk_bytes));

    // Add Fiat-Shamir challenges
    public_inputs.push(alpha);
    public_inputs.push(beta);

    // Verify proof
    println!("\n✅ Verifying proof...");
    let verification_start = Instant::now();
    let valid = Groth16::<E>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
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

/// Run benchmark with BN254/Grumpkin curves
fn run_grumpkin_benchmark(config: &BenchmarkConfig) -> BenchmarkStats {
    use ark_bn254::Fr as BaseField;
    use ark_grumpkin::GrumpkinConfig;

    type C1 = ark_bn254::G1Projective;
    type C2 = Projective<GrumpkinConfig>;
    type CV = ProjectiveVar<GrumpkinConfig, FpVar<BaseField>>;

    // Select prover based on configuration
    #[cfg(feature = "gpu")]
    let prover = if config.use_gpu {
        |pk: &ProvingKey<Bn254>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bn254>, anyhow::Error> {
            zk_poker::gpu::groth16_gpu::prove_with_gpu::<
                zk_poker::gpu::groth16_gpu::BN254GPUProver,
                _,
                _,
            >(&pk, circuit, rng)
        }
    } else {
        |pk: &ProvingKey<Bn254>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bn254>, anyhow::Error> {
            Ok(Groth16::<Bn254>::prove(&pk, circuit, rng)?)
        }
    };

    #[cfg(not(feature = "gpu"))]
    let prover = {
        if config.use_gpu {
            eprintln!("GPU acceleration requested but not compiled in. Use --features gpu");
            std::process::exit(1);
        }
        |pk: &ProvingKey<Bn254>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bn254>, anyhow::Error> {
            Ok(Groth16::<Bn254>::prove(&pk, circuit, rng)?)
        }
    };

    run_benchmark_iteration::<Bn254, C1, C2, CV, N, LEVELS, _>(config, prover)
}

/// Run benchmark with BN254/BabyJubJub curves
fn run_babyjubjub_benchmark(config: &BenchmarkConfig) -> BenchmarkStats {
    use ark_bn254::Fr as BaseField;
    use ark_ed_on_bn254::{EdwardsConfig, EdwardsProjective};
    use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;

    type C1 = ark_bn254::G1Projective;
    type C2 = EdwardsProjective;
    type CV = AffineVar<EdwardsConfig, FpVar<BaseField>>;

    // Select prover based on configuration
    #[cfg(feature = "gpu")]
    let prover = if config.use_gpu {
        |pk: &ProvingKey<Bn254>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bn254>, anyhow::Error> {
            zk_poker::gpu::groth16_gpu::prove_with_gpu::<
                zk_poker::gpu::groth16_gpu::BN254GPUProver,
                _,
                _,
            >(&pk, circuit, rng)
        }
    } else {
        |pk: &ProvingKey<Bn254>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bn254>, anyhow::Error> {
            Ok(Groth16::<Bn254>::prove(&pk, circuit, rng)?)
        }
    };

    #[cfg(not(feature = "gpu"))]
    let prover = {
        if config.use_gpu {
            eprintln!("GPU acceleration requested but not compiled in. Use --features gpu");
            std::process::exit(1);
        }
        |pk: &ProvingKey<Bn254>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bn254>, anyhow::Error> {
            Ok(Groth16::<Bn254>::prove(&pk, circuit, rng)?)
        }
    };

    run_benchmark_iteration::<Bn254, C1, C2, CV, N, LEVELS, _>(config, prover)
}

/// Run benchmark with BLS12-381/Bandersnatch curves
fn run_bandersnatch_benchmark(config: &BenchmarkConfig) -> BenchmarkStats {
    use ark_bls12_381::Fr as BaseField;
    use ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig;
    use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;

    type C1 = Bls12_381G1;
    type C2 = ark_ed_on_bls12_381_bandersnatch::EdwardsProjective;
    type CV = AffineVar<BandersnatchConfig, FpVar<BaseField>>;

    // Select prover based on configuration
    #[cfg(feature = "gpu")]
    let prover = if config.use_gpu {
        |pk: &ProvingKey<Bls12_381>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bls12_381>, anyhow::Error> {
            zk_poker::gpu::groth16_gpu::prove_with_gpu::<
                zk_poker::gpu::groth16_gpu::BLS12_381GPUProver,
                _,
                _,
            >(&pk, circuit, rng)
        }
    } else {
        |pk: &ProvingKey<Bls12_381>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bls12_381>, anyhow::Error> {
            Ok(Groth16::<Bls12_381>::prove(&pk, circuit, rng)?)
        }
    };

    #[cfg(not(feature = "gpu"))]
    let prover = {
        if config.use_gpu {
            eprintln!("GPU acceleration requested but not compiled in. Use --features gpu");
            std::process::exit(1);
        }
        |pk: &ProvingKey<Bls12_381>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bls12_381>, anyhow::Error> {
            Ok(Groth16::<Bls12_381>::prove(&pk, circuit, rng)?)
        }
    };

    run_benchmark_iteration::<Bls12_381, C1, C2, CV, N, LEVELS, _>(config, prover)
}

/// Run benchmark with BLS12-381/Jubjub curves
fn run_jubjub_benchmark(config: &BenchmarkConfig) -> BenchmarkStats {
    use ark_bls12_381::Fr as BaseField;
    use ark_ed_on_bls12_381::{EdwardsProjective, JubjubConfig};
    use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;

    type C1 = Bls12_381G1;
    type C2 = EdwardsProjective;
    type CV = AffineVar<JubjubConfig, FpVar<BaseField>>;

    // Select prover based on configuration
    #[cfg(feature = "gpu")]
    let prover = if config.use_gpu {
        |pk: &ProvingKey<Bls12_381>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bls12_381>, anyhow::Error> {
            zk_poker::gpu::groth16_gpu::prove_with_gpu::<
                zk_poker::gpu::groth16_gpu::BLS12_381GPUProver,
                _,
                _,
            >(&pk, circuit, rng)
        }
    } else {
        |pk: &ProvingKey<Bls12_381>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bls12_381>, anyhow::Error> {
            Ok(Groth16::<Bls12_381>::prove(&pk, circuit, rng)?)
        }
    };

    #[cfg(not(feature = "gpu"))]
    let prover = {
        if config.use_gpu {
            eprintln!("GPU acceleration requested but not compiled in. Use --features gpu");
            std::process::exit(1);
        }
        |pk: &ProvingKey<Bls12_381>,
         circuit: RSShuffleWithReencryptionCircuit<_, C2, CV, N, LEVELS>,
         rng: &mut StdRng|
         -> Result<Proof<Bls12_381>, anyhow::Error> {
            Ok(Groth16::<Bls12_381>::prove(&pk, circuit, rng)?)
        }
    };

    run_benchmark_iteration::<Bls12_381, C1, C2, CV, N, LEVELS, _>(config, prover)
}

fn main() {
    // Sanity check for ASM and parallel features
    #[cfg(target_feature = "sse2")]
    eprintln!(
        "asm enabled; bmi2={}, adx={}",
        std::is_x86_feature_detected!("bmi2"),
        std::is_x86_feature_detected!("adx")
    );

    // Initialize tracing for better debugging
    let _gaurd = setup_test_tracing();

    // Parse command line arguments using Clap
    let cli = Cli::parse();

    // Initialize GPU if requested
    #[cfg(feature = "gpu")]
    if cli.gpu {
        match zk_poker::gpu::init_gpu_device() {
            Ok(_) => eprintln!("✅ GPU device initialized successfully"),
            Err(e) => {
                eprintln!("❌ Failed to initialize GPU: {}", e);
                eprintln!("   Cannot continue with GPU acceleration");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(feature = "gpu"))]
    if cli.gpu {
        eprintln!("❌ GPU acceleration requested but not compiled in.");
        eprintln!("   Please rebuild with: cargo build --features gpu");
        std::process::exit(1);
    }

    // Convert CLI args to BenchmarkConfig
    let config = BenchmarkConfig {
        iterations: cli.iterations,
        csv_output: cli.csv,
        verbose: !cli.quiet,
        curve: cli.curve,
        use_gpu: cli.gpu,
    };

    // Display configuration based on selected curve
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║     RS Shuffle with Re-encryption Circuit Benchmark      ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("Configuration:");
    match config.curve {
        InnerCurveSelection::Grumpkin => {
            println!("  • Inner Curve: Grumpkin (Short Weierstrass)");
            println!("  • Pairing: BN254");
        }
        InnerCurveSelection::BabyJubJub => {
            println!("  • Inner Curve: BabyJubJub (Twisted Edwards)");
            println!("  • Pairing: BN254");
        }
        InnerCurveSelection::Bandersnatch => {
            println!("  • Inner Curve: Bandersnatch (Twisted Edwards)");
            println!("  • Pairing: BLS12-381");
        }
        InnerCurveSelection::Jubjub => {
            println!("  • Inner Curve: Jubjub (Twisted Edwards)");
            println!("  • Pairing: BLS12-381");
        }
    }
    println!("  • Deck Size: {} cards", N);
    println!("  • Shuffle Levels: {}", LEVELS);
    println!("  • Total Split Bits: {}", N * LEVELS);

    if config.use_gpu {
        println!("  • GPU Acceleration: ENABLED");
    } else {
        println!("  • GPU Acceleration: DISABLED");
    }

    if config.csv_output {
        BenchmarkStats::print_csv_header();
    }

    // Run benchmarks
    let mut all_stats = Vec::new();
    for i in 0..config.iterations {
        if config.verbose && config.iterations > 1 {
            println!("\n═══════════════════════════════════════════════════════════");
            println!(
                "                    Iteration {}/{}",
                i + 1,
                config.iterations
            );
            println!("═══════════════════════════════════════════════════════════");
        }

        // Run benchmark with selected curve
        let stats = match config.curve {
            InnerCurveSelection::Grumpkin => run_grumpkin_benchmark(&config),
            InnerCurveSelection::BabyJubJub => run_babyjubjub_benchmark(&config),
            InnerCurveSelection::Bandersnatch => run_bandersnatch_benchmark(&config),
            InnerCurveSelection::Jubjub => run_jubjub_benchmark(&config),
        };

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

fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
    let filter = filter::Targets::new()
        .with_default(tracing::Level::WARN)
        .with_target("game_demo", tracing::Level::DEBUG)
        .with_target("zk_poker", tracing::Level::DEBUG)
        .with_target("legit_poker", tracing::Level::DEBUG);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                .with_test_writer(), // This ensures output goes to test stdout
        )
        .with(filter)
        .set_default()
}
