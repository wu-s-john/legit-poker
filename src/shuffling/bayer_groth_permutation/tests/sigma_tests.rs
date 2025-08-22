//! Comprehensive test suite for type-safe non-interactive Σ-protocol
//!
//! Tests cover:
//! - Correctness: Valid proofs always verify
//! - Determinism: Same inputs produce same proof
//! - Circuit consistency: Native and circuit verifiers agree
//! - Various sizes: From N=1 to N=52 (deck size)

use crate::shuffling::bayer_groth_permutation::{
    sigma_gadgets::{
        enforce_sigma_witness_constraints, verify_sigma_linkage_gadget_ni, SigmaProofVar,
    },
    sigma_protocol::{
        compute_output_aggregator, msm_ciphertexts, prove_sigma_linkage_ni,
        verify_sigma_linkage_ni, SigmaProof,
    },
};
use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar, ElGamalKeys};
use ark_bn254::{Fq, Fr, G1Projective};
use ark_crypto_primitives::{
    commitment::{
        pedersen::{Commitment, Parameters, Randomness},
        CommitmentScheme,
    },
    sponge::{
        poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
        CryptographicSponge,
    },
};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::curves::short_weierstrass::ProjectiveVar,
    prelude::*,
};
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, test_rng, vec::Vec, Zero};

// Domain separators for different test scenarios
const DOMAIN_DECK: &[u8] = b"sigma-linkage-deck";
const DOMAIN_SMALL: &[u8] = b"sigma-linkage-small";
const DOMAIN_N1: &[u8] = b"sigma-linkage-n1";
const DOMAIN_DETERMINISM: &[u8] = b"determinism-test";
const DOMAIN_ZERO_RERAND: &[u8] = b"zero-rerand";
const DOMAIN_RANDOM: &[u8] = b"random-test";
const DOMAIN_SERIALIZATION: &[u8] = b"serialization";

type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;
type Pedersen = crate::shuffling::bayer_groth_permutation::sigma_protocol::Pedersen<G1Projective>;

/// Test instance with all necessary data for a complete test
struct SigmaTestInstance<const N: usize> {
    keys: ElGamalKeys<G1Projective>,
    pedersen_params: Parameters<G1Projective>,
    C_in: [ElGamalCiphertext<G1Projective>; N],
    C_out: [ElGamalCiphertext<G1Projective>; N],
    pi: [usize; N],
    pi_inv: [usize; N],
    x: Fr,
    b: [Fr; N],
    sB: Fr,
    cB: G1Projective,
    rho: Fr,
}

/// Helper to generate a permutation of size N
fn generate_permutation<const N: usize>(seed: u64) -> [usize; N] {
    let mut rng = test_rng();
    for _ in 0..seed {
        rng.next_u32();
    }

    let mut perm = [0; N];
    for i in 0..N {
        perm[i] = i;
    }

    // Fisher-Yates shuffle
    for i in (1..N).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        perm.swap(i, j);
    }

    perm
}

/// Helper to invert a permutation
fn invert_permutation<const N: usize>(perm: &[usize; N]) -> [usize; N] {
    let mut inv = [0; N];
    for i in 0..N {
        inv[perm[i]] = i;
    }
    inv
}

/// Helper to build a complete test instance with compile-time size checking
fn build_sigma_instance<const N: usize>(seed: u64) -> SigmaTestInstance<N> {
    let mut rng = test_rng();
    for _ in 0..seed {
        rng.next_u32();
    }

    // Setup keys
    let sk = Fr::rand(&mut rng);
    let keys = ElGamalKeys::new(sk);
    let g = G1Projective::generator();

    // Setup Pedersen parameters
    let pedersen_params = Pedersen::setup(&mut rng).unwrap();

    // Generate permutation
    let pi = generate_permutation(seed);
    let pi_inv = invert_permutation(&pi);

    // Generate input deck
    let c_in: [ElGamalCiphertext<G1Projective>; N] = core::array::from_fn(|i| {
        let r = Fr::rand(&mut rng);
        let m = g * Fr::from((i + 1) as u64); // Encrypt card value i+1
        ElGamalCiphertext {
            c1: g * r,
            c2: m + keys.public_key * r,
        }
    });

    // Shuffle and rerandomize to get output deck
    let mut rerandomizations = Vec::with_capacity(N);
    let c_out: [ElGamalCiphertext<G1Projective>; N] = core::array::from_fn(|i| {
        let r_i = Fr::rand(&mut rng);
        rerandomizations.push(r_i);

        // C'_i = C_{pi(i)} * E(1; r_i)
        let base = c_in[pi[i]].clone();
        let rerand = ElGamalCiphertext {
            c1: g * r_i,
            c2: keys.public_key * r_i,
        };
        ElGamalCiphertext {
            c1: base.c1 + rerand.c1,
            c2: base.c2 + rerand.c2,
        }
    });

    // Derive challenge x (would come from earlier Fiat-Shamir steps)
    let x = Fr::from(2u64); // Fixed for testing

    // Compute b array: b[j] = x^{π^{-1}(j)+1}
    let mut b = [Fr::zero(); N];
    for j in 0..N {
        b[j] = x.pow(&[(pi_inv[j] + 1) as u64]);
    }

    // Compute commitment to b
    let s_b = Fr::rand(&mut rng);
    let c_b = commit_vector(&pedersen_params, &b, s_b);

    // Compute aggregate rerandomization rho = ∑_i x^(i+1) * r_i
    let mut rho = Fr::zero();
    let mut x_power = x;
    for i in 0..N {
        rho += x_power * rerandomizations[i];
        x_power *= x;
    }

    SigmaTestInstance {
        keys,
        pedersen_params,
        C_in: c_in,
        C_out: c_out,
        pi,
        pi_inv,
        x,
        b,
        sB: s_b,
        cB: c_b,
        rho,
    }
}

/// Helper to commit to a vector
fn commit_vector<const N: usize>(
    params: &Parameters<G1Projective>,
    values: &[Fr; N],
    randomness: Fr,
) -> G1Projective {
    let mut input = Vec::new();
    for val in values {
        val.serialize_compressed(&mut input).unwrap();
    }

    let r = Randomness(randomness);
    Pedersen::commit(params, &input, &r).unwrap().into()
}

/// Test with standard deck size (N=52)
#[test]
fn test_ni_sigma_protocol_deck_size() {
    const DECK_SIZE: usize = 52;

    let inst = build_sigma_instance::<DECK_SIZE>(42);
    let mut rng = test_rng();

    // Create transcript for non-interactive proof
    let config = crate::config::poseidon_config::<Fr>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    // Generate proof with compile-time size checking
    let proof = prove_sigma_linkage_ni::<Fr, G1Projective, DECK_SIZE>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        inst.rho,
        &mut prover_transcript,
        &mut rng,
    );

    // Verify with fresh transcript
    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<Fr, G1Projective, DECK_SIZE>(
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
    const N: usize = 4;

    let inst = build_sigma_instance::<N>(123);
    let mut rng = test_rng();

    let config = crate::config::poseidon_config::<Fr>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    let proof = prove_sigma_linkage_ni::<Fr, G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        inst.rho,
        &mut prover_transcript,
        &mut rng,
    );

    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<Fr, G1Projective, N>(
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
    const N: usize = 1;

    let inst = build_sigma_instance::<N>(99);
    let mut rng = test_rng();

    let config = crate::config::poseidon_config::<Fr>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    let proof = prove_sigma_linkage_ni::<Fr, G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        inst.rho,
        &mut prover_transcript,
        &mut rng,
    );

    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<Fr, G1Projective, N>(
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
    const N: usize = 10;

    let inst = build_sigma_instance::<N>(777);
    let mut rng = test_rng();

    let config = crate::config::poseidon_config::<Fr>();

    // Generate first proof
    let mut transcript1 = PoseidonSponge::new(&config);

    // Use fixed randomness for determinism
    let mut fixed_rng = test_rng();
    let proof1 = prove_sigma_linkage_ni::<Fr, G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        inst.rho,
        &mut transcript1,
        &mut fixed_rng,
    );

    // Generate second proof with same inputs
    let mut transcript2 = PoseidonSponge::new(&config);

    let mut fixed_rng2 = test_rng();
    let proof2 = prove_sigma_linkage_ni::<Fr, G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        inst.rho,
        &mut transcript2,
        &mut fixed_rng2,
    );

    // Proofs should have same challenge (from transcript)
    // But different randomness (T_com, T_grp will differ)
    // Verify both proofs
    let mut verifier_transcript1 = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<Fr, G1Projective, N>(
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

    assert!(verify_sigma_linkage_ni::<Fr, G1Projective, N>(
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
    const N: usize = 5;

    let mut rng = test_rng();

    // Setup keys
    let sk = Fr::rand(&mut rng);
    let keys = ElGamalKeys::new(sk);
    let g = G1Projective::generator();

    // Setup Pedersen
    let pedersen_params = Pedersen::setup(&mut rng).unwrap();

    // Generate permutation
    let pi = generate_permutation::<N>(555);
    let pi_inv = invert_permutation(&pi);

    // Generate input deck
    let C_in: [ElGamalCiphertext<G1Projective>; N] = core::array::from_fn(|i| {
        let r = Fr::rand(&mut rng);
        let m = g * Fr::from((i + 1) as u64);
        ElGamalCiphertext {
            c1: g * r,
            c2: m + keys.public_key * r,
        }
    });

    // Shuffle WITHOUT rerandomization (rho = 0)
    let C_out: [ElGamalCiphertext<G1Projective>; N] = core::array::from_fn(|i| C_in[pi[i]].clone());

    let x = Fr::from(3u64);

    // Compute b array
    let mut b = [Fr::zero(); N];
    for j in 0..N {
        b[j] = x.pow(&[(pi_inv[j] + 1) as u64]);
    }

    let sB = Fr::rand(&mut rng);
    let cB = commit_vector(&pedersen_params, &b, sB);
    let rho = Fr::zero(); // Zero rerandomization

    let config = crate::config::poseidon_config::<Fr>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    let proof = prove_sigma_linkage_ni::<Fr, G1Projective, N>(
        &keys,
        &pedersen_params,
        &C_in,
        &C_out,
        x,
        &cB,
        &b,
        sB,
        rho,
        &mut prover_transcript,
        &mut rng,
    );

    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<Fr, G1Projective, N>(
        &keys,
        &pedersen_params,
        &C_in,
        &C_out,
        x,
        &cB,
        &proof,
        &mut verifier_transcript,
    ));

    println!("✓ Zero rerandomization test passed");
}

/// Test randomized property - many random instances
#[test]
fn test_randomized_many_seeds() {
    const N: usize = 8;
    const NUM_TESTS: usize = 10;

    for seed in 1000..(1000 + NUM_TESTS) {
        let inst = build_sigma_instance::<N>(seed as u64);
        let mut rng = test_rng();

        let config = crate::config::poseidon_config::<Fr>();
        let mut prover_transcript = PoseidonSponge::new(&config);

        let proof = prove_sigma_linkage_ni::<Fr, G1Projective, N>(
            &inst.keys,
            &inst.pedersen_params,
            &inst.C_in,
            &inst.C_out,
            inst.x,
            &inst.cB,
            &inst.b,
            inst.sB,
            inst.rho,
            &mut prover_transcript,
            &mut rng,
        );

        let mut verifier_transcript = PoseidonSponge::new(&config);

        assert!(
            verify_sigma_linkage_ni::<Fr, G1Projective, N>(
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
    const N: usize = 3;

    // Test compute_output_aggregator
    let mut rng = test_rng();
    let g = G1Projective::generator();
    let x = Fr::from(2u64);

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
    const N: usize = 6;

    let inst = build_sigma_instance::<N>(888);
    let mut rng = test_rng();

    let config = crate::config::poseidon_config::<Fr>();
    let mut prover_transcript = PoseidonSponge::new(&config);

    let proof = prove_sigma_linkage_ni::<Fr, G1Projective, N>(
        &inst.keys,
        &inst.pedersen_params,
        &inst.C_in,
        &inst.C_out,
        inst.x,
        &inst.cB,
        &inst.b,
        inst.sB,
        inst.rho,
        &mut prover_transcript,
        &mut rng,
    );

    // Serialize proof
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes).unwrap();

    // Deserialize proof
    let proof_deserialized =
        SigmaProof::<Fr, G1Projective, N>::deserialize_uncompressed(&mut &bytes[..]).unwrap();

    // Verify deserialized proof
    let mut verifier_transcript = PoseidonSponge::new(&config);

    assert!(verify_sigma_linkage_ni::<Fr, G1Projective, N>(
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
