//! Complete shuffling proof system combining RS shuffle, Bayer-Groth linking, and sigma protocol
//!
//! This module provides a complete proof system for verifying card shuffling with:
//! - RS (Riffle Shuffle) algorithm for the actual permutation
//! - Bayer-Groth setup for proving permutation correctness
//! - Reencryption protocol for proving re-encryption correctness
//! - SNARK proof for verifying shuffled permutation

use super::bayer_groth_permutation::reencryption_protocol::{prove, ReencryptionProof};
use super::data_structures::ElGamalCiphertext;
use crate::shuffling::bayer_groth_permutation::bg_setup::BGPowerChallengeSetup;

use crate::curve_absorb::CurveAbsorb;
use crate::pedersen_commitment_opening_proof::{DeckHashWindow, ReencryptionWindow};
use crate::shuffling::permutation_proof::circuit::PermutationProofCircuit;
use ark_crypto_primitives::commitment::pedersen::Commitment as PedersenCommitment;
use ark_crypto_primitives::commitment::CommitmentScheme;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::groups::CurveVar;
use ark_std::{
    rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng},
    vec::Vec,
    UniformRand,
};

const LOG_TARGET: &str = "nexus_nova::shuffling::shuffling_proof";

/// Type alias for Pedersen commitment with ReencryptionWindow configuration
type PedersenReenc<G> = PedersenCommitment<G, ReencryptionWindow>;

/// Type alias for Pedersen commitment with DeckHashWindow configuration
type PedersenDeck<G> = PedersenCommitment<G, DeckHashWindow>;

// ============================================================================
// New prover/verifier (v2) using PermutationGroth16 + native Σ‑protocol
// ============================================================================

use crate::shuffling::pedersen_commitment::opening_proof::{
    verify as verify_pedersen_opening, PedersenCommitmentOpeningProof, PedersenParams,
};
use crate::shuffling::permutation_proof::{
    prepare_witness, PublicData as PermPublicData, WitnessData as PermWitnessData,
};
use ark_ec::pairing::Pairing;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof as Groth16Proof, ProvingKey};
use ark_snark::SNARK;
use std::collections::BTreeMap;

/// Public configuration for the shuffling prover/verifier
pub struct ShufflingConfig<E, G>
where
    E: Pairing,
    G: CurveGroup,
{
    /// Generator on inner curve for ElGamal and commitments
    pub generator: G,
    /// Aggregated ElGamal public key
    pub public_key: G,
    /// Cached Groth16 permutation SNARK keys keyed by `num_samples`
    pub perm_snark_keys: BTreeMap<usize, (ProvingKey<E>, PreparedVerifyingKey<E>)>,
}

/// Complete shuffling proof artifacts
pub struct ShufflingProof<E, G, const N: usize>
where
    E: Pairing,
    G: CurveGroup,
{
    /// Groth16 proof for the permutation circuit
    pub perm_snark_proof: Groth16Proof<E>,
    /// Flattened public inputs used by the permutation circuit
    pub perm_snark_public_inputs: Vec<E::ScalarField>,
    /// Native Pedersen opening proof for c_power
    pub power_opening_proof: PedersenCommitmentOpeningProof<G>,
    /// Native Σ‑protocol proof for re-encryption correctness
    pub reencryption_proof: ReencryptionProof<G, N>,
}

/// Prove a shuffle with the new RS SNARK (with VRF) and native Σ‑protocol
#[tracing::instrument(skip(config, ct_input, rng), target = LOG_TARGET)]
pub fn prove_shuffling<E, G, GG, const N: usize, const LEVELS: usize>(
    config: &ShufflingConfig<E, G>,
    ct_input: &[ElGamalCiphertext<G>; N],
    // VRF input (public nonce). VRF secret key is sampled internally.
    vrf_nonce: G::BaseField,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<
    (
        [ElGamalCiphertext<G>; N],
        ShufflingProof<E, G, N>,
        BGPowerChallengeSetup<G::BaseField, G::ScalarField, G>,
    ),
    Box<dyn std::error::Error>,
>
where
    E: Pairing<ScalarField = G::BaseField>,
    G: CurveGroup + CurveAbsorb<G::BaseField> + ark_ff::ToConstraintField<G::BaseField>,
    G::Config: CurveConfig,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb + UniformRand,
    GG: CurveVar<G, G::BaseField>
        + crate::shuffling::curve_absorb::CurveAbsorbGadget<
            G::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
        >,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, G, GG>,
    for<'a> &'a GG: crate::shuffling::curve_absorb::CurveAbsorbGadget<
        G::BaseField,
        ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
    >,
{
    tracing::info!(
        target = LOG_TARGET,
        "prove_shuffling: start; deck_size={}",
        ct_input.len()
    );
    // 1) Pedersen parameters (deterministic seeds for consistency across prove/verify)
    let mut deck_rng = StdRng::seed_from_u64(42);
    let perm_params = PedersenDeck::<G>::setup(&mut deck_rng)?;
    let mut power_rng = StdRng::seed_from_u64(43);
    let power_params = PedersenReenc::<G>::setup(&mut power_rng)?;
    tracing::info!(
        target = LOG_TARGET,
        "prove_shuffling: Pedersen params prepared"
    );

    // 2) Prepare permutation witnesses (native), including BG setup + opening
    // Sample a fresh VRF secret key locally; only pk goes public via the SNARK inputs
    let vrf_sk = G::ScalarField::rand(rng);
    let mut prep_params = crate::shuffling::permutation_proof::PermutationParameters::<G, _> {
        perm_params: &perm_params,
        power_params: &power_params,
        rng,
    };
    let mut sponge =
        PoseidonSponge::<G::BaseField>::new(&crate::config::poseidon_config::<G::BaseField>());
    let prepared =
        prepare_witness::<G, _, _, N, LEVELS>(&mut prep_params, vrf_nonce, vrf_sk, &mut sponge)?;
    tracing::info!(
        target = LOG_TARGET,
        "prove_shuffling: witness prepared; indices_init_len={}",
        prepared.indices_init.len()
    );

    // 3) Apply the exact prepared permutation to the input deck and re-encrypt
    // Use the RS permutation extracted from the prepared witness to guarantee
    // consistency between BG setup (b, commitments) and the output deck.
    let pi_1idx: [usize; N] = prepared.rs_trace.extract_permutation_array();
    let pi_0idx: [usize; N] = core::array::from_fn(|i| pi_1idx[i] - 1);
    // Fresh rerandomization scalars
    let rerand: [G::ScalarField; N] =
        crate::shuffling::encryption::generate_randomization_array::<G::Config, N>(rng);
    let ct_output: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| {
        ct_input[pi_0idx[i]].add_encryption_layer(rerand[i], config.public_key.clone())
    });
    tracing::info!(
        target = LOG_TARGET,
        "prove_shuffling: output deck constructed via prepared RS permutation"
    );

    // 4) Groth16 permutation proof using preloaded keys from config
    let num_samples = prepared.rs_trace.num_samples;
    let (pk, _pvk) = config
        .perm_snark_keys
        .get(&num_samples)
        .ok_or("missing permutation SNARK keys for num_samples in config")?;
    let public = PermPublicData::<G, N> {
        nonce: vrf_nonce,
        pk_public: prepared.pk,
        indices_init: prepared.indices_init.map(|x| x.into()),
        alpha_rs: prepared.vrf_value.into(),
        power_challenge_public: prepared.bg_setup.power_challenge_base.into(),
        c_perm: prepared.bg_setup.permutation_commitment,
        c_power: prepared.bg_setup.power_permutation_commitment,
        power_opening_proof: prepared.power_opening_proof.clone(),
    };
    let witness = PermWitnessData::<G, N, LEVELS> {
        sk: vrf_sk,
        rs_witness: prepared.rs_trace.witness_trace.clone(),
        power_perm_vec_wit: prepared.perm_power_vector_base.map(|x| x.into()),
        power_perm_vec_scalar_wit: prepared.perm_power_vector_scalar,
    };
    // Build circuit and prove
    let circ = PermutationProofCircuit::<G, GG, N, LEVELS> {
        num_samples,
        nonce: Some(public.nonce),
        pk_public: Some(public.pk_public),
        indices_init: Some(public.indices_init),
        alpha_rs: Some(public.alpha_rs),
        power_challenge_public: Some(public.power_challenge_public),
        c_perm: Some(public.c_perm),
        c_power: Some(public.c_power),
        power_opening_proof: Some(public.power_opening_proof.clone()),
        sk: Some(witness.sk),
        rs_witness: Some(witness.rs_witness.clone()),
        power_perm_vec_wit: Some(witness.power_perm_vec_wit),
        power_perm_vec_scalar_wit: Some(witness.power_perm_vec_scalar_wit),
        _pd: core::marker::PhantomData,
    };
    let perm_proof = Groth16::<E>::prove(pk, circ.clone(), rng)?;
    // Derive public inputs from circuit
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
    let cs = ConstraintSystem::<G::BaseField>::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: true,
    });
    circ.generate_constraints(cs.clone())?;
    cs.finalize();
    let cs_borrowed = cs.borrow().unwrap();
    let inst = cs_borrowed.instance_assignment().unwrap();
    let perm_public_inputs = inst[1..].to_vec();
    tracing::info!(
        target = LOG_TARGET,
        "prove_shuffling: Groth16 done; public_inputs_len={}",
        perm_public_inputs.len()
    );

    // 5) Native Σ‑protocol for re-encryption correctness
    let mut tr_sig =
        PoseidonSponge::<G::BaseField>::new(&crate::config::poseidon_config::<G::BaseField>());
    let reencryption_proof = prove::<G, _, N>(
        &config.public_key,
        &power_params,
        ct_input,
        &ct_output,
        prepared.bg_setup.power_challenge_scalar,
        &prepared.bg_setup.power_permutation_commitment,
        &prepared.perm_power_vector_scalar,
        prepared.blinding_s,
        &rerand,
        &mut tr_sig,
        rng,
    );
    // Normalize T_grp inside the proof to affine-backed projective to avoid
    // representation mismatches during equality checks downstream.
    let mut reencryption_proof = reencryption_proof;
    reencryption_proof.blinding_rerandomization_commitment.c1 = reencryption_proof
        .blinding_rerandomization_commitment
        .c1
        .into_affine()
        .into();
    reencryption_proof.blinding_rerandomization_commitment.c2 = reencryption_proof
        .blinding_rerandomization_commitment
        .c2
        .into_affine()
        .into();
    tracing::info!(
        target = LOG_TARGET,
        "prove_shuffling: reencryption Σ‑protocol complete"
    );

    // Sanity-check the Σ‑protocol relation inline (mirrors native verifier)
    {
        use crate::shuffling::bayer_groth_permutation::utils::compute_powers_sequence_with_index_1;
        use crate::shuffling::pedersen_commitment::msm_ciphertexts;
        let powers: [G::ScalarField; N] =
            compute_powers_sequence_with_index_1(prepared.bg_setup.power_challenge_scalar);
        let input_ciphertext_aggregator = msm_ciphertexts(ct_input, &powers);
        let lhs = super::bayer_groth_permutation::reencryption_protocol::encrypt_one_and_combine(
            &config.public_key,
            reencryption_proof.sigma_response_rerand,
            &ct_output,
            &reencryption_proof.sigma_response_power_permutation_vector,
        );
        let rhs = crate::shuffling::data_structures::ElGamalCiphertext {
            c1: reencryption_proof.blinding_rerandomization_commitment.c1
                + input_ciphertext_aggregator.c1 * prepared.bg_setup.power_challenge_scalar,
            c2: reencryption_proof.blinding_rerandomization_commitment.c2
                + input_ciphertext_aggregator.c2 * prepared.bg_setup.power_challenge_scalar,
        };
        if lhs.c1 != rhs.c1 || lhs.c2 != rhs.c2 {
            tracing::warn!(
                target = LOG_TARGET,
                ?lhs,
                ?rhs,
                "prove_shuffling: inline Σ‑protocol sanity check FAILED (lhs != rhs)"
            );
        } else {
            tracing::debug!(
                target = LOG_TARGET,
                "prove_shuffling: inline Σ‑protocol sanity check passed"
            );
        }
    }

    Ok((
        ct_output,
        ShufflingProof {
            perm_snark_proof: perm_proof,
            perm_snark_public_inputs: perm_public_inputs,
            power_opening_proof: prepared.power_opening_proof,
            reencryption_proof,
        },
        prepared.bg_setup.clone(),
    ))
}

/// Verify a shuffle with the Groth16 permutation SNARK and native Σ‑protocol
#[tracing::instrument(skip(config, ct_input, ct_output, proof), target = LOG_TARGET)]
pub fn verify_shuffling<E, G, const N: usize>(
    config: &ShufflingConfig<E, G>,
    bg_setup: &BGPowerChallengeSetup<G::BaseField, G::ScalarField, G>,
    ct_input: &[ElGamalCiphertext<G>; N],
    ct_output: &[ElGamalCiphertext<G>; N],
    proof: &ShufflingProof<E, G, N>,
) -> Result<bool, Box<dyn std::error::Error>>
where
    E: Pairing<ScalarField = G::BaseField>,
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
{
    tracing::info!(
        target = LOG_TARGET,
        "verify_shuffling: start; deck_size={}",
        ct_input.len()
    );
    // 1) Verify Groth16 permutation proof
    // We no longer carry the prepared VK in the proof. Verify against any prepared VK
    // present in the config (in practice, there is typically just one entry).
    let mut ok_snark = false;
    for (_ns, (_pk, pvk)) in &config.perm_snark_keys {
        if Groth16::<E>::verify_proof(
            pvk,
            &proof.perm_snark_proof,
            &proof.perm_snark_public_inputs,
        )? {
            ok_snark = true;
            break;
        }
    }
    if !ok_snark {
        tracing::info!(
            target = LOG_TARGET,
            "verify_shuffling: SNARK verification failed"
        );
        return Ok(false);
    }
    tracing::info!(
        target = LOG_TARGET,
        "verify_shuffling: SNARK verification passed"
    );

    // 2) Verify Pedersen opening of c_power (natively)
    let mut power_rng = StdRng::seed_from_u64(43);
    let power_params_raw = PedersenReenc::<G>::setup(&mut power_rng)?;
    let ped_params = PedersenParams::<G>::from_arkworks::<N>(power_params_raw.clone());
    verify_pedersen_opening::<G, N>(
        &ped_params,
        &bg_setup.power_permutation_commitment,
        &proof.power_opening_proof,
    )
    .map_err(|e| -> Box<dyn std::error::Error> {
        format!("pedersen opening verify: {e:?}").into()
    })?;
    tracing::info!(
        target = LOG_TARGET,
        "verify_shuffling: Pedersen opening verified"
    );

    // 3) Verify native re-encryption Σ‑protocol
    let mut tr_sig =
        PoseidonSponge::<G::BaseField>::new(&crate::config::poseidon_config::<G::BaseField>());
    // Normalize ciphertexts to affine-backed representations to avoid
    // representation-induced equality mismatches inside the group checks.
    let normalized_input: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| ElGamalCiphertext {
        c1: ct_input[i].c1.into_affine().into(),
        c2: ct_input[i].c2.into_affine().into(),
    });
    let normalized_output: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| ElGamalCiphertext {
        c1: ct_output[i].c1.into_affine().into(),
        c2: ct_output[i].c2.into_affine().into(),
    });
    let ok_sigma = super::bayer_groth_permutation::reencryption_protocol::verify::<G, _, N>(
        &config.public_key,
        &power_params_raw,
        &normalized_input,
        &normalized_output,
        bg_setup.power_challenge_scalar,
        &bg_setup.power_permutation_commitment,
        &proof.reencryption_proof,
        &mut tr_sig,
    );
    if !ok_sigma {
        tracing::info!(
            target = LOG_TARGET,
            "verify_shuffling: Σ‑protocol verification failed"
        );
        return Ok(false);
    }
    tracing::info!(target = LOG_TARGET, "verify_shuffling: all checks passed");
    Ok(true)
}

// Legacy generic proof system and tests have been removed in favor of the
// unified Groth16 permutation SNARK + native Σ‑protocol flow.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rs_shuffle::native::run_rs_shuffle_permutation,
        shuffling::data_structures::ElGamalCiphertext,
    };
    use ark_bn254::{Bn254, Fr as BaseField};
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_grumpkin::{Fr as ScalarField, GrumpkinConfig, Projective as G};
    use ark_r1cs_std::{
        fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar as SWVar,
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    type GVar = SWVar<GrumpkinConfig, FpVar<BaseField>>;

    const TEST_TARGET: &str = "nexus_nova";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        // Enable our module target plus a reasonable default for others.
        let filter = filter::Targets::new()
            .with_target(LOG_TARGET, tracing::Level::DEBUG)
            .with_target(TEST_TARGET, tracing::Level::DEBUG);

        let timer = tracing_subscriber::fmt::time::uptime();
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER)
                    .with_file(true)
                    .with_timer(timer)
                    .with_line_number(true) // This ensures output goes to test stdout
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_prove_and_verify_shuffling_bn254() {
        // Keep the guard alive for the whole test so logs are emitted
        let _guard = setup_test_tracing();
        tracing::info!(
            target = TEST_TARGET,
            "test: starting prove_and_verify_shuffling_bn254"
        );
        // Pairing curve E = BN254; inner curve G = Grumpkin
        const N: usize = 8;
        const LEVELS: usize = 3;

        let mut rng = StdRng::seed_from_u64(123456789);

        // Public config
        let generator = G::generator();
        let sk = ScalarField::rand(&mut rng);
        let pk = generator * sk;
        let mut config: ShufflingConfig<Bn254, G> = ShufflingConfig {
            generator,
            public_key: pk,
            perm_snark_keys: Default::default(),
        };

        // Input deck (encrypt messages 0..N-1)
        let ct_input: [ElGamalCiphertext<G>; N] = std::array::from_fn(|i| {
            let m = ScalarField::from(i as u64);
            let r = ScalarField::rand(&mut rng);
            ElGamalCiphertext::encrypt_scalar(m, r, pk)
        });

        // VRF nonce in BN254 Fr (which equals G::BaseField)
        let nonce: BaseField = BaseField::rand(&mut rng);

        // Preload Groth16 keys in config for this num_samples
        let rs_for_keys = run_rs_shuffle_permutation::<BaseField, ElGamalCiphertext<G>, N, LEVELS>(
            nonce, &ct_input,
        );
        let ns = rs_for_keys.num_samples;
        let perm_sys = crate::shuffling::permutation_proof::proof_system::PermutationGroth16::<
            Bn254,
            G,
            GVar,
            N,
            LEVELS,
        >::setup(&mut rng, ns)
        .expect("perm setup");
        config.perm_snark_keys.insert(
            ns,
            (
                perm_sys.proving_key().clone(),
                perm_sys.prepared_vk().clone(),
            ),
        );

        // Prove and verify using the unified API
        let (ct_output, proof, bg_setup) =
            prove_shuffling::<Bn254, G, GVar, N, LEVELS>(&config, &ct_input, nonce, &mut rng)
                .expect("prove_shuffling");

        let ok = verify_shuffling::<Bn254, G, N>(&config, &bg_setup, &ct_input, &ct_output, &proof)
            .expect("verify_shuffling call");
        assert!(ok, "shuffling proof should verify");
        tracing::info!(
            target = LOG_TARGET,
            "test: shuffling proof verified successfully"
        );
    }
}
