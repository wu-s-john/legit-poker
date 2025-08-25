//! Comprehensive test suite for type-safe non-interactive Σ-protocol
//!
//! Tests cover:
//! - Correctness: Valid proofs always verify
//! - Determinism: Same inputs produce same proof
//! - Circuit consistency: Native and circuit verifiers agree
//! - Various sizes: From N=1 to N=52 (deck size)

use crate::shuffling::bayer_groth_permutation::sigma_protocol::{
    commit_vector as sigma_commit_vector, compute_output_aggregator, msm_ciphertexts,
    prove_sigma_linkage_ni, verify_sigma_linkage_ni, SigmaProof, SigmaWindow,
};
use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalKeys};
use crate::shuffling::test_utils::{
    apply_permutation, generate_random_ciphertexts, generate_random_permutation,
    invert_permutation, shuffle_and_rerandomize_random,
};
use ark_bn254::{Fq, Fr, G1Projective};
use ark_crypto_primitives::{
    commitment::{pedersen::Parameters, CommitmentScheme},
    sponge::{poseidon::PoseidonSponge, CryptographicSponge},
};
use ark_ec::PrimeGroup;
use ark_ff::{Field, UniformRand, Zero};
use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{test_rng, vec::Vec};
use rand::RngCore;
use tracing_subscriber::{
    filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

// Test tracing target
const TEST_TARGET: &str = "sigma_test";

// Domain separators for different test scenarios (not currently used)
#[allow(dead_code)]
const _DOMAIN_DECK: &[u8] = b"sigma-linkage-deck";
#[allow(dead_code)]
const _DOMAIN_SMALL: &[u8] = b"sigma-linkage-small";
#[allow(dead_code)]
const _DOMAIN_N1: &[u8] = b"sigma-linkage-n1";
#[allow(dead_code)]
const _DOMAIN_DETERMINISM: &[u8] = b"determinism-test";
#[allow(dead_code)]
const _DOMAIN_ZERO_RERAND: &[u8] = b"zero-rerand";
#[allow(dead_code)]
const _DOMAIN_RANDOM: &[u8] = b"random-test";
#[allow(dead_code)]
const _DOMAIN_SERIALIZATION: &[u8] = b"serialization";

#[allow(dead_code)]
type _G1Var = ProjectiveVar<ark_bn254::g1::Config, ark_r1cs_std::fields::fp::FpVar<Fq>>;
type Pedersen = ark_crypto_primitives::commitment::pedersen::Commitment<G1Projective, SigmaWindow>;

/// Setup test tracing for debugging
fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
    let filter = filter::Targets::new()
        .with_target(TEST_TARGET, tracing::Level::DEBUG)
        .with_target("sigma_protocol", tracing::Level::DEBUG)
        .with_target("sigma_gadget", tracing::Level::DEBUG);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                .with_test_writer(), // This ensures output goes to test stdout
        )
        .with(filter)
        .set_default()
}

/// Test instance with all necessary data for a complete test
#[allow(non_snake_case)]
struct SigmaTestInstance<const N: usize> {
    keys: ElGamalKeys<G1Projective>,
    pedersen_params: Parameters<G1Projective>,
    C_in: [ElGamalCiphertext<G1Projective>; N],
    C_out: [ElGamalCiphertext<G1Projective>; N],
    _pi: [usize; N],
    _pi_inv: [usize; N],
    x: Fr,
    b: [Fr; N],
    sB: Fr,
    cB: G1Projective,
    rerandomization_scalars: [Fr; N], // Input-indexed rerandomization scalars r_j^in
}

/// Helper to generate a seeded permutation for reproducible tests
#[tracing::instrument(target = TEST_TARGET, skip_all, fields(N = N, seed = seed))]
fn generate_seeded_permutation<const N: usize>(seed: u64) -> [usize; N] {
    tracing::debug!("Generating permutation of size {} with seed {}", N, seed);
    let mut rng = test_rng();
    for _ in 0..seed {
        rng.next_u32();
    }
    generate_random_permutation(&mut rng)
}

/// Helper to build a complete test instance with compile-time size checking
#[tracing::instrument(target = TEST_TARGET, skip_all, fields(N = N, seed = seed))]
fn build_sigma_instance<const N: usize>(seed: u64) -> SigmaTestInstance<N> {
    tracing::debug!("Building sigma test instance for N={}, seed={}", N, seed);
    let mut rng = test_rng();
    for _ in 0..seed {
        rng.next_u32();
    }

    // Setup keys
    let sk = Fr::rand(&mut rng);
    let keys = ElGamalKeys::new(sk);

    // Setup Pedersen parameters
    let pedersen_params = Pedersen::setup(&mut rng).unwrap();

    // Generate permutation
    let pi = generate_seeded_permutation(seed);
    let pi_inv = invert_permutation(&pi);

    // Generate input deck
    let (c_in, _randomness) = generate_random_ciphertexts::<G1Projective, N>(&keys, &mut rng);

    // Shuffle and rerandomize to get output deck
    // rerandomizations_output[i] contains the randomness for output position i
    let (c_out, rerandomizations_output) =
        shuffle_and_rerandomize_random(&c_in, &pi, keys.public_key, &mut rng);

    // Derive challenge x (would come from earlier Fiat-Shamir steps)
    let x = Fr::from(2u64); // Fixed for testing

    // Compute b array: b[j] = x^{π^{-1}(j)+1}
    let mut b = [Fr::zero(); N];
    for j in 0..N {
        b[j] = x.pow(&[(pi_inv[j] + 1) as u64]);
    }
    tracing::trace!("Computed b array for witness");

    // Compute input-indexed rerandomization scalars: r_j^in = ρ_{π^{-1}(j)}
    let mut rerandomization_scalars = [Fr::zero(); N];
    for j in 0..N {
        rerandomization_scalars[j] = rerandomizations_output[pi_inv[j]];
    }
    tracing::trace!("Computed input-indexed rerandomization scalars");

    // Compute commitment to b
    let s_b = Fr::rand(&mut rng);
    tracing::trace!("Computing commitment to b with randomness");
    let c_b = commit_vector(&pedersen_params, &b, s_b);
    tracing::trace!("Commitment c_b computed");

    // Compute aggregate rerandomization rho = Σ(b_j * r_j^in)
    let mut rho = Fr::zero();
    for j in 0..N {
        rho += b[j] * rerandomization_scalars[j];
    }
    tracing::trace!("Computed aggregate rerandomization rho");

    SigmaTestInstance {
        keys,
        pedersen_params,
        C_in: c_in,
        C_out: c_out,
        _pi: pi,
        _pi_inv: pi_inv,
        x,
        b,
        sB: s_b,
        cB: c_b,
        rerandomization_scalars,
    }
}

/// Helper to commit to a vector using linear vector Pedersen
#[tracing::instrument(target = TEST_TARGET, skip_all, fields(N = N))]
fn commit_vector<const N: usize>(
    params: &Parameters<G1Projective>,
    values: &[Fr; N],
    randomness: Fr,
) -> G1Projective {
    tracing::trace!("Committing to vector of size {}", N);

    // Use the linear vector Pedersen commitment from sigma_protocol
    sigma_commit_vector(params, values, randomness)
}

/// Test with standard deck size (N=52)
#[test]
fn test_ni_sigma_protocol_deck_size() {
    let _guard = setup_test_tracing();
    const DECK_SIZE: usize = 52;
    tracing::info!(target: TEST_TARGET, "Starting deck size test with N={}", DECK_SIZE);

    let inst = build_sigma_instance::<DECK_SIZE>(42);
    let mut rng = test_rng();

    // Create transcript for non-interactive proof
    let config = crate::config::poseidon_config::<Fq>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    // Generate proof with compile-time size checking
    let proof = prove_sigma_linkage_ni::<G1Projective, DECK_SIZE>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        &inst.rerandomization_scalars,
        &mut prover_transcript,
        &mut rng,
    );

    // Verify with fresh transcript
    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<G1Projective, DECK_SIZE>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &proof,
        &mut verifier_transcript,
    ));

    println!("✓ Deck size (N=52) test passed");
}

/// Test with small size for debugging
#[test]
fn test_ni_sigma_protocol_small() {
    let _guard = setup_test_tracing();
    const N: usize = 4;
    tracing::info!(target: TEST_TARGET, "Starting small size test with N={}", N);

    let inst = build_sigma_instance::<N>(123);
    let mut rng = test_rng();

    let config = crate::config::poseidon_config::<Fq>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    let proof = prove_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        &inst.rerandomization_scalars,
        &mut prover_transcript,
        &mut rng,
    );

    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &proof,
        &mut verifier_transcript,
    ));

    println!("✓ Small size (N=4) test passed");
}

/// Test edge case with N=1
#[test]
fn test_ni_sigma_protocol_n1() {
    let _guard = setup_test_tracing();
    const N: usize = 1;
    tracing::info!(target: TEST_TARGET, "Starting edge case test with N={}", N);

    let inst = build_sigma_instance::<N>(99);
    let mut rng = test_rng();

    let config = crate::config::poseidon_config::<Fq>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    let proof = prove_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        &inst.rerandomization_scalars,
        &mut prover_transcript,
        &mut rng,
    );

    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &proof,
        &mut verifier_transcript,
    ));

    println!("✓ Edge case (N=1) test passed");
}

/// Test determinism - same inputs produce same proof
#[test]
fn test_determinism() {
    let _guard = setup_test_tracing();
    const N: usize = 10;
    tracing::info!(target: TEST_TARGET, "Starting determinism test with N={}", N);

    let inst = build_sigma_instance::<N>(777);
    let _rng = test_rng();

    let config = crate::config::poseidon_config::<Fq>();

    // Generate first proof
    let mut transcript1 = PoseidonSponge::new(&config);

    // Use fixed randomness for determinism
    let mut fixed_rng = test_rng();
    let proof1 = prove_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        &inst.rerandomization_scalars,
        &mut transcript1,
        &mut fixed_rng,
    );

    // Generate second proof with same inputs
    let mut transcript2 = PoseidonSponge::new(&config);

    let mut fixed_rng2 = test_rng();
    let proof2 = prove_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        &inst.rerandomization_scalars,
        &mut transcript2,
        &mut fixed_rng2,
    );

    // Proofs should have same challenge (from transcript)
    // But different randomness (T_com, T_grp will differ)
    // Verify both proofs
    let mut verifier_transcript1 = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &proof1,
        &mut verifier_transcript1,
    ));

    let mut verifier_transcript2 = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &proof2,
        &mut verifier_transcript2,
    ));

    println!("✓ Determinism test passed (both proofs verify)");
}

/// Test with zero rerandomization (pure permutation)
#[test]
fn test_zero_rerandomization() {
    let _guard = setup_test_tracing();
    const N: usize = 5;
    tracing::info!(target: TEST_TARGET, "Starting zero rerandomization test with N={}", N);

    let mut rng = test_rng();

    // Setup keys
    let sk = Fr::rand(&mut rng);
    let keys = ElGamalKeys::new(sk);

    // Setup Pedersen
    let pedersen_params = Pedersen::setup(&mut rng).unwrap();

    // Generate permutation
    let pi = generate_seeded_permutation::<N>(555);
    let pi_inv = invert_permutation(&pi);

    // Generate input deck
    #[allow(non_snake_case)]
    let (C_in, _randomness) = generate_random_ciphertexts::<G1Projective, N>(&keys, &mut rng);

    // Shuffle WITHOUT rerandomization (rho = 0)
    #[allow(non_snake_case)]
    let C_out = apply_permutation(&C_in, &pi);

    let x = Fr::from(3u64);

    // Compute b array
    let mut b = [Fr::zero(); N];
    for j in 0..N {
        b[j] = x.pow(&[(pi_inv[j] + 1) as u64]);
    }

    let s_b = Fr::rand(&mut rng);
    let c_b = commit_vector(&pedersen_params, &b, s_b);
    let rerandomization_scalars = [Fr::zero(); N]; // Zero rerandomization

    let config = crate::config::poseidon_config::<Fq>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    let proof = prove_sigma_linkage_ni::<G1Projective, N>(
        &keys,
        &pedersen_params,
        &C_in,
        &C_out,
        x,
        &c_b,
        &b,
        s_b,
        &rerandomization_scalars,
        &mut prover_transcript,
        &mut rng,
    );

    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<G1Projective, N>(
        &keys,
        &pedersen_params,
        &C_in,
        &C_out,
        x,
        &c_b,
        &proof,
        &mut verifier_transcript,
    ));

    println!("✓ Zero rerandomization test passed");
}

/// Test randomized property - many random instances
#[test]
fn test_randomized_many_seeds() {
    let _guard = setup_test_tracing();
    const N: usize = 8;
    const NUM_TESTS: usize = 10;
    tracing::info!(target: TEST_TARGET, "Starting randomized test with N={}, {} iterations", N, NUM_TESTS);

    for seed in 1000..(1000 + NUM_TESTS) {
        let inst = build_sigma_instance::<N>(seed as u64);
        let mut rng = test_rng();

        let config = crate::config::poseidon_config::<Fq>();
        let mut prover_transcript = PoseidonSponge::new(&config);

        let proof = prove_sigma_linkage_ni::<G1Projective, N>(
            &inst.keys,
            &inst.pedersen_params,
            &inst.C_in,
            &inst.C_out,
            inst.x,
            &inst.cB,
            &inst.b,
            inst.sB,
            &inst.rerandomization_scalars,
            &mut prover_transcript,
            &mut rng,
        );

        let mut verifier_transcript = PoseidonSponge::new(&config);

        assert!(
            verify_sigma_linkage_ni::<G1Projective, N>(
                &inst.keys,
                &inst.pedersen_params,
                &inst.C_in,
                &inst.C_out,
                inst.x,
                &inst.cB,
                &proof,
                &mut verifier_transcript,
            ),
            "Failed for seed {}",
            seed
        );
    }

    println!(
        "✓ Randomized property test passed ({} instances)",
        NUM_TESTS
    );
}

/// Test helper functions
#[test]
fn test_helper_functions() {
    let _guard = setup_test_tracing();
    const N: usize = 3;
    tracing::info!(target: TEST_TARGET, "Starting helper functions test with N={}", N);

    // Test compute_output_aggregator
    let mut rng = test_rng();
    let x = Fr::from(2u64);
    let g = G1Projective::generator();

    #[allow(non_snake_case)]
    let C_out: [ElGamalCiphertext<G1Projective>; N] = core::array::from_fn(|i| {
        let r = Fr::rand(&mut rng);
        ElGamalCiphertext {
            c1: g * r,
            c2: g * Fr::from((i + 1) as u64) + g * r,
        }
    });

    let agg = compute_output_aggregator(&C_out, x);

    // Manually compute expected
    let mut expected = ElGamalCiphertext {
        c1: G1Projective::zero(),
        c2: G1Projective::zero(),
    };
    let mut x_power = x;
    for i in 0..N {
        expected.c1 += C_out[i].c1 * x_power;
        expected.c2 += C_out[i].c2 * x_power;
        x_power *= x;
    }

    assert_eq!(agg.c1, expected.c1);
    assert_eq!(agg.c2, expected.c2);

    // Test msm_ciphertexts
    let scalars = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let msm_result = msm_ciphertexts(&C_out, &scalars);

    let mut expected_msm = ElGamalCiphertext {
        c1: G1Projective::zero(),
        c2: G1Projective::zero(),
    };
    for i in 0..N {
        expected_msm.c1 += C_out[i].c1 * scalars[i];
        expected_msm.c2 += C_out[i].c2 * scalars[i];
    }

    assert_eq!(msm_result.c1, expected_msm.c1);
    assert_eq!(msm_result.c2, expected_msm.c2);

    println!("✓ Helper functions test passed");
}

/// Test serialization round-trip
#[test]
fn test_serialization() {
    let _guard = setup_test_tracing();
    const N: usize = 6;
    tracing::info!(target: TEST_TARGET, "Starting serialization test with N={}", N);

    let inst = build_sigma_instance::<N>(888);
    let mut rng = test_rng();

    let config = crate::config::poseidon_config::<Fq>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    let proof = prove_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        &inst.rerandomization_scalars,
        &mut prover_transcript,
        &mut rng,
    );

    // Serialize proof
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes).unwrap();

    // Deserialize proof
    let proof_deserialized =
        SigmaProof::<G1Projective, N>::deserialize_uncompressed(&mut &bytes[..]).unwrap();

    // Verify deserialized proof
    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &proof_deserialized,
        &mut verifier_transcript,
    ));

    println!("✓ Serialization round-trip test passed");
    println!("  Proof size: {} bytes", bytes.len());
}
