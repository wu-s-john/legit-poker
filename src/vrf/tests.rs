//! VRF unit tests

use super::*;
use crate::vrf::gadgets::{beta_from_gamma_var, prove_vrf_gadget};
use crate::vrf::native::{prove_vrf, verify_vrf};
use ark_bn254::Fr as BaseField; // BN254's scalar field = Grumpkin's base field
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};
use ark_r1cs_std::GR1CSVar;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
    groups::curves::short_weierstrass::ProjectiveVar,
    uint8::UInt8,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::test_rng;
use tracing_subscriber::filter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

type TestCurve = GrumpkinProjective;
type TestCurveConfig = GrumpkinConfig;
type ScalarField = ark_grumpkin::Fr; // Grumpkin's scalar field
type TestCurveVar = ProjectiveVar<TestCurveConfig, FpVar<BaseField>>;

const TEST_TARGET: &str = "vrf";

/// Test circuit for prove_vrf_gadget
#[derive(Clone)]
struct VrfProveCircuit {
    // Public inputs
    pub msg: Vec<u8>,

    // Witness
    pub sk: ScalarField,

    // Expected outputs (for testing)
    pub expected_gamma: TestCurve,
    pub expected_c: ScalarField,
    pub expected_s: ScalarField,
    pub expected_beta: BaseField,

    // Parameters
    pub params: VrfParams<TestCurve>,
}

impl ConstraintSynthesizer<BaseField> for VrfProveCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BaseField>,
    ) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let msg_var = UInt8::<BaseField>::new_input_vec(cs.clone(), &self.msg)?;

        // Allocate witness
        let sk_var =
            EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(self.sk))?;

        // Run prove_vrf_gadget with Poseidon sponge
        let (proof_var, _nonce_k, beta_var) = prove_vrf_gadget::<
            TestCurve,
            TestCurveVar,
            PoseidonSponge<BaseField>,
            PoseidonSpongeVar<BaseField>,
        >(
            cs.clone(),
            &self.params,
            &self.params.sponge_params,
            &msg_var,
            sk_var,
        )?;

        // For testing: allocate expected values as inputs and enforce equality
        let expected_gamma_var = TestCurveVar::new_input(cs.clone(), || Ok(self.expected_gamma))?;
        let expected_c_var =
            EmulatedFpVar::<ScalarField, BaseField>::new_input(cs.clone(), || Ok(self.expected_c))?;
        let expected_s_var =
            EmulatedFpVar::<ScalarField, BaseField>::new_input(cs.clone(), || Ok(self.expected_s))?;
        let expected_beta_var =
            FpVar::<BaseField>::new_input(cs.clone(), || Ok(self.expected_beta))?;

        // Enforce equality - now accessing through proof_var
        proof_var.gamma.enforce_equal(&expected_gamma_var)?;
        proof_var.c.enforce_equal(&expected_c_var)?;
        proof_var.s.enforce_equal(&expected_s_var)?;
        beta_var.enforce_equal(&expected_beta_var)?;

        Ok(())
    }
}

fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
    let filter = filter::Targets::new().with_target(TEST_TARGET, tracing::Level::TRACE);

    let timer = tracing_subscriber::fmt::time::uptime();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_timer(timer)
                .with_writer(tracing_subscriber::fmt::TestWriter::default()), // This ensures output goes to test stdout
        )
        .with(filter)
        .set_default()
}

#[test]
fn test_native_vrf_roundtrip() {
    let _guard = setup_test_tracing();
    let mut rng = test_rng();

    // Setup parameters
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Generate keypair
    let sk = ScalarField::rand(&mut rng);
    let pk = TestCurve::generator() * sk;

    // Test message
    let msg = b"VRF-test-message-12345";

    // Prove
    let (proof, beta) = prove_vrf(&params, &pk, sk, msg);

    // Verify - should succeed
    let beta_verified = verify_vrf(&params, &pk, msg, &proof);
    assert_eq!(Some(beta), beta_verified, "VRF verification should succeed");

    // Verify with wrong message - should fail
    let wrong_msg = b"wrong-message";
    let beta_wrong = verify_vrf(&params, &pk, wrong_msg, &proof);
    assert_eq!(
        None, beta_wrong,
        "VRF verification should fail with wrong message"
    );

    // Verify with wrong public key - should fail
    let wrong_pk = TestCurve::generator() * ScalarField::rand(&mut rng);
    let beta_wrong_pk = verify_vrf(&params, &wrong_pk, msg, &proof);
    assert_eq!(
        None, beta_wrong_pk,
        "VRF verification should fail with wrong public key"
    );
}

#[test]
fn test_native_vs_snark_parity() {
    let _guard = setup_test_tracing();
    let mut rng = test_rng();

    // Setup parameters
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Generate keypair
    let sk = ScalarField::rand(&mut rng);
    let pk = TestCurve::generator() * sk;

    // Test message
    let msg = b"VRF-parity-test-42";

    // Native proof generation
    let (proof_native, beta_native) = prove_vrf(&params, &pk, sk, msg);

    // Create circuit
    let circuit = VrfProveCircuit {
        msg: msg.to_vec(),
        sk,
        expected_gamma: proof_native.gamma,
        expected_c: proof_native.c,
        expected_s: proof_native.s,
        expected_beta: beta_native,
        params: params.clone(),
    };

    // Generate constraints and check satisfiability
    let cs = ConstraintSystem::<BaseField>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .expect("Circuit generation should succeed");
    assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");

    // Log constraint count
    tracing::debug!(
        target: TEST_TARGET,
        "VRF prove_gadget constraint count: {}",
        cs.num_constraints()
    );
}

#[test]
fn test_deterministic_vrf_output() {
    let _guard = setup_test_tracing();
    let mut rng = test_rng();

    // Setup parameters
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Generate keypair
    let sk = ScalarField::rand(&mut rng);
    let pk = TestCurve::generator() * sk;

    // Test message
    let msg = b"deterministic-test";

    // Generate proof multiple times
    let (proof1, beta1) = prove_vrf(&params, &pk, sk, msg);
    let (proof2, beta2) = prove_vrf(&params, &pk, sk, msg);

    // Should produce identical outputs
    assert_eq!(beta1, beta2, "VRF output should be deterministic");
    assert_eq!(proof1.gamma, proof2.gamma, "Gamma should be deterministic");
    assert_eq!(proof1.c, proof2.c, "Challenge should be deterministic");
    assert_eq!(proof1.s, proof2.s, "Response should be deterministic");
}

#[test]
fn test_different_messages_different_outputs() {
    let _guard = setup_test_tracing();
    let mut rng = test_rng();

    // Setup parameters
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Generate keypair
    let sk = ScalarField::rand(&mut rng);
    let pk = TestCurve::generator() * sk;

    // Different messages
    let msg1 = b"message-1";
    let msg2 = b"message-2";

    // Generate proofs
    let (_, beta1) = prove_vrf(&params, &pk, sk, msg1);
    let (_, beta2) = prove_vrf(&params, &pk, sk, msg2);

    // Should produce different outputs
    assert_ne!(
        beta1, beta2,
        "Different messages should produce different VRF outputs"
    );
}

#[test]
fn test_different_keys_different_outputs() {
    let _guard = setup_test_tracing();
    let mut rng = test_rng();

    // Setup parameters
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Generate two different keypairs
    let sk1 = ScalarField::rand(&mut rng);
    let pk1 = TestCurve::generator() * sk1;
    let sk2 = ScalarField::rand(&mut rng);
    let pk2 = TestCurve::generator() * sk2;

    // Same message
    let msg = b"same-message";

    // Generate proofs
    let (_, beta1) = prove_vrf(&params, &pk1, sk1, msg);
    let (_, beta2) = prove_vrf(&params, &pk2, sk2, msg);

    // Should produce different outputs
    assert_ne!(
        beta1, beta2,
        "Different keys should produce different VRF outputs"
    );
}

#[test]
fn test_beta_computation_consistency() {
    let _guard = setup_test_tracing();
    let mut rng = test_rng();

    // Setup parameters
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Generate keypair
    let sk = ScalarField::rand(&mut rng);
    let pk = TestCurve::generator() * sk;

    // Test message
    let msg = b"beta-test";

    // Generate proof
    let (proof, beta_native) = prove_vrf(&params, &pk, sk, msg);

    // Compute beta directly from gamma
    let beta_computed = super::native::beta_from_gamma::<TestCurve>(&proof.gamma);

    assert_eq!(
        beta_native, beta_computed,
        "Beta computation should be consistent"
    );

    // Test in circuit
    let cs = ConstraintSystem::<BaseField>::new_ref();
    let gamma_var =
        TestCurveVar::new_witness(cs.clone(), || Ok(proof.gamma)).expect("Should allocate gamma");
    let sponge_config = crate::poseidon_config::<BaseField>();
    let beta_var = beta_from_gamma_var::<
        TestCurve,
        TestCurveVar,
        PoseidonSponge<BaseField>,
        PoseidonSpongeVar<BaseField>,
    >(cs.clone(), &sponge_config, &gamma_var)
    .expect("Should compute beta in circuit");

    assert_eq!(
        beta_var.value().unwrap(),
        beta_native,
        "Circuit beta should match native beta"
    );
}

#[test]
fn test_hash_to_curve_consistency() {
    use crate::vrf::gadgets::hash_to_curve_var;
    use crate::vrf::native::hash_to_curve;
    use ark_crypto_primitives::crh::pedersen::constraints::CRHParametersVar as PedersenCRHParamsVar;

    let _guard = setup_test_tracing();

    let mut rng = test_rng();
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Test multiple different messages
    let test_messages = vec![
        b"test1".to_vec(),
        b"longer test message".to_vec(),
        b"".to_vec(),   // empty message
        vec![0xff; 32], // all 1s
        b"VRF-test-12345-with-special-chars!@#$%".to_vec(),
    ];

    for msg in test_messages {
        tracing::debug!(
            target: TEST_TARGET,
            "Testing hash_to_curve for message of length: {}",
            msg.len()
        );

        // Native computation
        let h_native = hash_to_curve::<TestCurve>(&params, &msg);
        tracing::debug!(target: TEST_TARGET, "Native hash_to_curve result: {:?}", h_native);

        // Circuit computation
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Allocate Pedersen parameters
        let pedersen_params_var = PedersenCRHParamsVar::<TestCurve, TestCurveVar>::new_constant(
            cs.clone(),
            params.pedersen_crh_params.clone(),
        )
        .expect("Should allocate Pedersen params");

        // Allocate message bytes
        let msg_var =
            UInt8::<BaseField>::new_witness_vec(cs.clone(), &msg).expect("Should allocate message");

        // Compute hash in circuit
        let h_circuit_var =
            hash_to_curve_var::<TestCurve, TestCurveVar>(&pedersen_params_var, &msg_var)
                .expect("Should compute hash_to_curve in circuit");

        let h_circuit = h_circuit_var.value().expect("Should get value");
        tracing::debug!(target: TEST_TARGET, "Circuit hash_to_curve result: {:?}", h_circuit);

        // Verify they match
        assert_eq!(
            h_native, h_circuit,
            "Native and circuit hash_to_curve should match for message {:?}",
            msg
        );

        // Verify constraints are satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "Circuit constraints should be satisfied"
        );
    }

    tracing::debug!(target: TEST_TARGET, "✅ All hash_to_curve consistency tests passed!");
}

#[test]
fn test_generate_nonce_consistency() {
    let _guard = setup_test_tracing();
    use crate::vrf::gadgets::{generate_nonce_var, hash_to_curve_var};
    use crate::vrf::native::{generate_nonce, hash_to_curve};
    use ark_crypto_primitives::crh::pedersen::constraints::CRHParametersVar as PedersenCRHParamsVar;

    let mut rng = test_rng();
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Test with multiple secret keys and messages
    let test_cases = vec![
        (ScalarField::rand(&mut rng), b"test1".to_vec()),
        (ScalarField::rand(&mut rng), b"longer message".to_vec()),
        (ScalarField::from(12345u64), b"fixed sk test".to_vec()),
        (ScalarField::rand(&mut rng), vec![0xaa; 100]), // long message
    ];

    for (sk, msg) in test_cases {
        tracing::debug!(
            target: TEST_TARGET,
            "Testing nonce generation for message length: {}",
            msg.len()
        );

        // Compute H = hash_to_curve(msg) natively
        let h_native = hash_to_curve::<TestCurve>(&params, &msg);

        // Native nonce generation
        let nonce_native = generate_nonce::<TestCurve>(&sk, &h_native, &msg);
        tracing::debug!(target: TEST_TARGET, "Native nonce: {:?}", nonce_native);

        // Circuit nonce generation
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Allocate secret key
        let sk_var = EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(sk))
            .expect("Should allocate sk");

        // Compute H in circuit
        let pedersen_params_var = PedersenCRHParamsVar::<TestCurve, TestCurveVar>::new_constant(
            cs.clone(),
            params.pedersen_crh_params.clone(),
        )
        .expect("Should allocate Pedersen params");

        let msg_var =
            UInt8::<BaseField>::new_witness_vec(cs.clone(), &msg).expect("Should allocate message");

        let h_circuit_var =
            hash_to_curve_var::<TestCurve, TestCurveVar>(&pedersen_params_var, &msg_var)
                .expect("Should compute hash_to_curve");

        // Now directly test generate_nonce_var
        let sponge_config = crate::poseidon_config::<BaseField>();
        let (nonce_circuit_var, _nonce_bits) = generate_nonce_var::<
            TestCurve,
            TestCurveVar,
            PoseidonSponge<BaseField>,
            PoseidonSpongeVar<BaseField>,
        >(
            cs.clone(),
            &sponge_config,
            &sk_var,
            &h_circuit_var,
            &msg_var,
        )
        .expect("Should generate nonce in circuit");

        let nonce_circuit = nonce_circuit_var.value().expect("Should get nonce value");
        tracing::debug!(target: TEST_TARGET, "Circuit nonce: {:?}", nonce_circuit);

        // Verify they match
        assert_eq!(
            nonce_native, nonce_circuit,
            "Native and circuit nonce should match"
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "Circuit constraints should be satisfied"
        );
    }

    tracing::debug!(target: TEST_TARGET, "✅ Nonce generation consistency tests completed!");
}

#[test]
fn test_challenge_generation_consistency() {
    let _guard = setup_test_tracing();
    use crate::vrf::gadgets::generate_challenge_var;
    use crate::vrf::native::{generate_challenge, generate_nonce, hash_to_curve};

    let mut rng = test_rng();
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Generate test data
    let sk = ScalarField::rand(&mut rng);
    let pk = TestCurve::generator() * sk;
    let msg = b"test message for challenge";

    // Compute intermediate values natively
    let h = hash_to_curve::<TestCurve>(&params, msg);
    let gamma = h * sk;
    let k = generate_nonce::<TestCurve>(&sk, &h, msg);
    let u = TestCurve::generator() * k;
    let v = h * k;

    // Generate challenge natively
    let c_native = generate_challenge::<TestCurve>(&pk, &h, &gamma, &u, &v);
    tracing::debug!(target: TEST_TARGET, "Native challenge: {:?}", c_native);

    // Circuit version
    let cs = ConstraintSystem::<BaseField>::new_ref();

    // Allocate all the curve points
    let pk_var = TestCurveVar::new_witness(cs.clone(), || Ok(pk)).expect("Should allocate pk");
    let h_var = TestCurveVar::new_witness(cs.clone(), || Ok(h)).expect("Should allocate h");
    let gamma_var =
        TestCurveVar::new_witness(cs.clone(), || Ok(gamma)).expect("Should allocate gamma");
    let u_var = TestCurveVar::new_witness(cs.clone(), || Ok(u)).expect("Should allocate u");
    let v_var = TestCurveVar::new_witness(cs.clone(), || Ok(v)).expect("Should allocate v");

    // Generate challenge in circuit
    let sponge_config = crate::poseidon_config::<BaseField>();
    let (c_circuit_var, _c_bits) = generate_challenge_var::<
        TestCurve,
        TestCurveVar,
        PoseidonSponge<BaseField>,
        PoseidonSpongeVar<BaseField>,
    >(
        cs.clone(),
        &sponge_config,
        &pk_var,
        &h_var,
        &gamma_var,
        &u_var,
        &v_var,
    )
    .expect("Should generate challenge in circuit");

    let c_circuit = c_circuit_var.value().expect("Should get challenge value");
    tracing::debug!(target: TEST_TARGET, "Circuit challenge: {:?}", c_circuit);

    // Verify they match
    assert_eq!(
        c_native, c_circuit,
        "Native and circuit challenge should match"
    );

    assert!(
        cs.is_satisfied().unwrap(),
        "Circuit constraints should be satisfied"
    );

    tracing::debug!(target: TEST_TARGET, "✅ Challenge generation consistency test completed!");
}

#[test]
fn test_vrf_proof_var_allocation() {
    let _guard = setup_test_tracing();
    let mut rng = test_rng();

    // Setup parameters
    let params = VrfParams::<TestCurve>::setup(&mut rng);

    // Generate keypair and proof
    let sk = ScalarField::rand(&mut rng);
    let pk = TestCurve::generator() * sk;
    let msg = b"test-message";

    // Generate native proof
    let (proof_native, _beta) = prove_vrf(&params, &pk, sk, msg);

    // Test allocation in circuit
    let cs = ConstraintSystem::<BaseField>::new_ref();

    // Allocate VrfProofVar from native proof
    use crate::vrf::gadgets::VrfProofVar;
    let proof_var =
        VrfProofVar::<TestCurve, TestCurveVar>::new_witness(
            cs.clone(),
            || Ok(proof_native.clone()),
        )
        .unwrap();

    // Verify values match
    assert_eq!(
        proof_var.gamma.value().unwrap(),
        proof_native.gamma,
        "Gamma should match"
    );
    assert_eq!(
        proof_var.c.value().unwrap(),
        proof_native.c,
        "Challenge c should match"
    );
    assert_eq!(
        proof_var.s.value().unwrap(),
        proof_native.s,
        "Response s should match"
    );

    assert!(cs.is_satisfied().unwrap());
    tracing::info!(target: TEST_TARGET, "✅ VrfProofVar allocation works correctly");
}
