//! Prove/verify a correct opening to a Pedersen commitment inside a Groth16 circuit.
//!
//! This module provides zero-knowledge proof functionality for proving knowledge
//! of a Pedersen commitment opening without revealing the committed message or randomness.

use ark_crypto_primitives::commitment::pedersen::{
    constraints::CommGadget as PedersenCommGadget, Commitment as PedersenCommitment,
    Parameters as PedersenParameters, Randomness as PedersenRandomness, Window as PedersenWindow,
};
use ark_crypto_primitives::commitment::{CommitmentGadget, CommitmentScheme};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use rand::{CryptoRng, RngCore};

// ---------------------------
// Window configuration
// ---------------------------

/// Window configuration for Pedersen commitments
/// Supports 8 * 32 = 256 bits => 32-byte messages
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PedersenWin;

impl PedersenWindow for PedersenWin {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 32;
}

/// Window configuration for hashing a deck of 52 cards
/// Each card is represented by a byte (values 1-52), requiring 52 windows
/// This allows hashing a complete deck in a single operation
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DeckHashWindow;

impl PedersenWindow for DeckHashWindow {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 52; // For 52 cards in a deck
}

// ---------------------------
// Gadget functions
// ---------------------------

/// Gadget function for computing a Pedersen commitment in-circuit
///
/// This function allocates the parameters, message, and randomness as circuit variables,
/// then computes the commitment using the Pedersen commitment gadget.
///
/// # Type Parameters
/// * `G` - The curve group to use for commitments
/// * `GG` - The curve variable type for the circuit
/// * `W` - The window configuration for the Pedersen commitment
///
/// # Arguments
/// * `cs` - The constraint system
/// * `params` - The Pedersen parameters (generators)
/// * `message` - The message bytes to commit
/// * `randomness` - The randomness for the commitment
///
/// # Returns
/// The commitment as a circuit variable
pub fn pedersen_commitment_gadget<G, GG, W>(
    cs: ConstraintSystemRef<G::BaseField>,
    params: &PedersenParameters<G>,
    message: &[u8],
    randomness: &PedersenRandomness<G>,
) -> Result<GG, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    W: PedersenWindow,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, G, GG>,
{
    let _span = tracing::debug_span!(
        target: "pedersen::gadget",
        "pedersen_commitment_gadget"
    )
    .entered();

    type CommGadget<G, GG, W> = PedersenCommGadget<G, GG, W>;
    type Comm<G, W> = PedersenCommitment<G, W>;

    // Validate message length
    let msg_len_bits = message.len() * 8;
    if msg_len_bits > W::WINDOW_SIZE * W::NUM_WINDOWS {
        return Err(SynthesisError::Unsatisfiable);
    }

    // Allocate Pedersen parameters as constants
    let params_var = <CommGadget<G, GG, W> as CommitmentGadget<Comm<G, W>, G::BaseField>>::ParametersVar::new_constant(
        ark_relations::ns!(cs, "params"),
        params,
    )?;

    // Allocate the committed message as witness bytes
    let mut message_var = Vec::<UInt8<G::BaseField>>::with_capacity(message.len());
    for b in message.iter().copied() {
        message_var.push(UInt8::new_witness(cs.clone(), || Ok(b))?);
    }

    // Allocate randomness as witness
    let rand_var = <CommGadget<G, GG, W> as CommitmentGadget<Comm<G, W>, G::BaseField>>::RandomnessVar::new_witness(
        ark_relations::ns!(cs, "rand"),
        || Ok(randomness),
    )?;

    // Compute and return commitment
    CommGadget::<G, GG, W>::commit(&params_var, &message_var, &rand_var)
}

/// Gadget function that verifies a Pedersen commitment opening
///
/// This computes the commitment from the opening and enforces equality with the expected commitment.
///
/// # Type Parameters
/// * `G` - The curve group to use for commitments
/// * `GG` - The curve variable type for the circuit
/// * `W` - The window configuration for the Pedersen commitment
///
/// # Arguments
/// * `cs` - The constraint system
/// * `params` - The Pedersen parameters
/// * `message` - The message bytes
/// * `randomness` - The randomness
/// * `expected_commitment` - The expected commitment to verify against
///
/// # Returns
/// Ok(()) if the commitment is valid, error otherwise
pub fn verify_pedersen_commitment_gadget<G, GG, W>(
    cs: ConstraintSystemRef<G::BaseField>,
    params: &PedersenParameters<G>,
    message: &[u8],
    randomness: &PedersenRandomness<G>,
    expected_commitment: &G::Affine,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    W: PedersenWindow,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, G, GG>,
{
    // Compute the commitment
    let computed_var =
        pedersen_commitment_gadget::<G, GG, W>(cs.clone(), params, message, randomness)?;

    // Allocate the expected commitment as PUBLIC INPUT
    let expected_var = GG::new_input(ark_relations::ns!(cs, "commitment_input"), || {
        Ok(*expected_commitment)
    })?;

    // Mathematical equation: Commit(params, message, randomness) = commitment
    computed_var.enforce_equal(&expected_var)?;

    Ok(())
}

// ---------------------------
// Prover + Verifier helpers
// ---------------------------

/// Setup Pedersen parameters for the commitment scheme
///
/// This generates the necessary group elements and tables for efficient
/// commitment computation both natively and in-circuit.
pub fn pedersen_setup<G, W, R>(rng: &mut R) -> PedersenParameters<G>
where
    G: CurveGroup,
    W: PedersenWindow,
    R: RngCore + CryptoRng,
{
    PedersenCommitment::<G, W>::setup(rng).expect("pedersen parameter generation should not fail")
}

/// Compute a native Pedersen commitment
///
/// This computes the commitment outside the circuit for comparison
/// with the in-circuit computation.
pub fn pedersen_commit<G, W>(
    params: &PedersenParameters<G>,
    message: &[u8],
    randomness: &PedersenRandomness<G>,
) -> G::Affine
where
    G: CurveGroup,
    W: PedersenWindow,
{
    PedersenCommitment::<G, W>::commit(params, message, randomness)
        .expect("native pedersen commit should not fail")
}

// ---------------------------
// Tests
// ---------------------------

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::commitment::pedersen::Randomness as PedersenRandomness;
    use ark_ed_on_bn254::{
        constraints::EdwardsVar as JubjubVar, EdwardsAffine as JubjubAffine,
        EdwardsProjective as JubjubProjective, Fr as JubjubScalar,
    };
    use ark_ff::{ToConstraintField, UniformRand};
    use ark_groth16::Groth16;
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_serialize::CanonicalDeserialize;
    use ark_snark::SNARK;
    use rand::{rngs::StdRng, SeedableRng};
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    /// Simple circuit wrapper for Groth16 proof generation
    /// This is only used internally for proof generation
    #[derive(Clone)]
    struct PedersenCircuit<G, GG, W>
    where
        G: CurveGroup,
        W: PedersenWindow,
    {
        params: PedersenParameters<G>,
        commitment: G::Affine,
        message: Vec<u8>,
        randomness: PedersenRandomness<G>,
        _phantom: PhantomData<(GG, W)>,
    }

    impl<G, GG, W> ConstraintSynthesizer<G::BaseField> for PedersenCircuit<G, GG, W>
    where
        G: CurveGroup,
        G::BaseField: PrimeField,
        GG: CurveVar<G, G::BaseField>,
        W: PedersenWindow,
        for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, G, GG>,
    {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<G::BaseField>,
        ) -> Result<(), SynthesisError> {
            verify_pedersen_commitment_gadget::<G, GG, W>(
                cs,
                &self.params,
                &self.message,
                &self.randomness,
                &self.commitment,
            )
        }
    }

    const TEST_TARGET: &str = "nexus_nova";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target(TEST_TARGET, tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    fn prove_opening_groth16<W: PedersenWindow, R: RngCore + CryptoRng>(
        rng: &mut R,
        params: PedersenParameters<JubjubProjective>,
        message: Vec<u8>,
        randomness: PedersenRandomness<JubjubProjective>,
    ) -> Result<
        (
            ark_groth16::Proof<Bn254>,
            ark_groth16::PreparedVerifyingKey<Bn254>,
            ark_groth16::VerifyingKey<Bn254>,
            Vec<Fr>,
        ),
        SynthesisError,
    > {
        // Compute the commitment natively
        let commitment = pedersen_commit::<JubjubProjective, W>(&params, &message, &randomness);

        // Build the circuit using our gadget
        let circuit = PedersenCircuit::<JubjubProjective, JubjubVar, W> {
            params: params.clone(),
            commitment,
            message,
            randomness,
            _phantom: PhantomData,
        };

        // SNARK setup and prove
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng)?;
        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng)?;
        let pvk = Groth16::<Bn254>::process_vk(&vk)?;

        // Public input is the commitment point flattened into field elements
        let public_inputs: Vec<Fr> = commitment
            .to_field_elements()
            .expect("affine point should serialize to field elements");

        Ok((proof, pvk, vk, public_inputs))
    }

    // Test-specific verify function
    fn verify_opening_groth16(
        pvk: &ark_groth16::PreparedVerifyingKey<Bn254>,
        proof: &ark_groth16::Proof<Bn254>,
        public_inputs: &[Fr],
    ) -> Result<bool, SynthesisError> {
        Groth16::<Bn254>::verify_with_processed_vk(pvk, public_inputs, proof)
    }

    #[test]
    fn test_pedersen_opening_prove_and_verify() {
        let _gaurd = setup_test_tracing();
        let mut rng = StdRng::seed_from_u64(0);

        // 1) Setup Pedersen parameters for our window (constants in-circuit)
        let params = pedersen_setup::<JubjubProjective, PedersenWin, _>(&mut rng);

        // 2) Create a message & randomness that fit the window (32 bytes)
        let message = vec![42u8; 32];
        let randomness = PedersenRandomness::<JubjubProjective>(JubjubScalar::rand(&mut rng));

        // 3) Prove an opening to the commitment inside Groth16
        let (proof, pvk, _vk, public_inputs) = prove_opening_groth16::<PedersenWin, _>(
            &mut rng,
            params.clone(),
            message.clone(),
            randomness.clone(),
        )
        .expect("proof generation should succeed");

        // 4) Verify with the correct public input (commitment serialized to field elements)
        let ok = verify_opening_groth16(&pvk, &proof, &public_inputs)
            .expect("verification should not error");
        assert!(ok, "verifier should accept the correct opening");

        // 5) Negative test: change the public commitment, keep the same proof
        // Build a *different* commitment (flip one message byte) and derive wrong inputs
        let mut tampered = message.clone();
        tampered[0] ^= 1;
        let wrong_c =
            pedersen_commit::<JubjubProjective, PedersenWin>(&params, &tampered, &randomness);
        let wrong_inputs: Vec<Fr> = wrong_c.to_field_elements().unwrap();

        let bad = verify_opening_groth16(&pvk, &proof, &wrong_inputs)
            .expect("verification should not error");
        assert!(
            !bad,
            "verifier must reject if the public commitment doesn't match"
        );
    }

    #[test]
    fn test_different_randomness_different_commitment() {
        let _gaurd = setup_test_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let params = pedersen_setup::<JubjubProjective, PedersenWin, _>(&mut rng);
        let message = vec![1u8; 32];

        // Same message, different randomness should yield different commitments
        let r1 = PedersenRandomness::<JubjubProjective>(JubjubScalar::rand(&mut rng));
        let r2 = PedersenRandomness::<JubjubProjective>(JubjubScalar::rand(&mut rng));

        let c1 = pedersen_commit::<JubjubProjective, PedersenWin>(&params, &message, &r1);
        let c2 = pedersen_commit::<JubjubProjective, PedersenWin>(&params, &message, &r2);

        assert_ne!(
            c1, c2,
            "Different randomness should produce different commitments"
        );
    }

    #[test]
    fn test_different_messages_different_commitment() {
        let _gaurd = setup_test_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let params = pedersen_setup::<JubjubProjective, PedersenWin, _>(&mut rng);
        let randomness = PedersenRandomness::<JubjubProjective>(JubjubScalar::rand(&mut rng));

        // Different messages, same randomness should yield different commitments
        let m1 = vec![1u8; 32];
        let m2 = vec![2u8; 32];

        let c1 = pedersen_commit::<JubjubProjective, PedersenWin>(&params, &m1, &randomness);
        let c2 = pedersen_commit::<JubjubProjective, PedersenWin>(&params, &m2, &randomness);

        assert_ne!(
            c1, c2,
            "Different messages should produce different commitments"
        );
    }

    #[test]
    fn test_message_length_validation() {
        let _gaurd = setup_test_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let params = pedersen_setup::<JubjubProjective, PedersenWin, _>(&mut rng);

        // Test with valid message lengths
        for len in [1, 16, 32] {
            let message = vec![0u8; len];
            let randomness = PedersenRandomness::<JubjubProjective>(JubjubScalar::rand(&mut rng));
            let commitment =
                pedersen_commit::<JubjubProjective, PedersenWin>(&params, &message, &randomness);

            // Should be able to verify using the gadget
            let cs = ConstraintSystem::<Fr>::new_ref();
            verify_pedersen_commitment_gadget::<JubjubProjective, JubjubVar, PedersenWin>(
                cs.clone(),
                &params,
                &message,
                &randomness,
                &commitment,
            )
            .expect("Valid message length should work");

            assert!(
                cs.is_satisfied().unwrap(),
                "Circuit should be satisfied for valid message length {}",
                len
            );
        }

        // Test with invalid message length (too long)
        let too_long_message = vec![0u8; 33]; // Exceeds 32-byte window
        let randomness = PedersenRandomness::<JubjubProjective>(JubjubScalar::rand(&mut rng));
        let dummy_commitment = JubjubAffine::default();

        // Should fail when message exceeds window size
        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = verify_pedersen_commitment_gadget::<JubjubProjective, JubjubVar, PedersenWin>(
            cs,
            &params,
            &too_long_message,
            &randomness,
            &dummy_commitment,
        );

        assert!(
            result.is_err(),
            "Should fail for message exceeding window size"
        );
    }

    #[test]
    fn test_circuit_constraint_counts() {
        let _gaurd = setup_test_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let params = pedersen_setup::<JubjubProjective, PedersenWin, _>(&mut rng);
        let message = vec![0xAAu8; 32];
        let randomness = PedersenRandomness::<JubjubProjective>(JubjubScalar::rand(&mut rng));
        let commitment =
            pedersen_commit::<JubjubProjective, PedersenWin>(&params, &message, &randomness);

        let cs = ConstraintSystem::<Fr>::new_ref();

        verify_pedersen_commitment_gadget::<JubjubProjective, JubjubVar, PedersenWin>(
            cs.clone(),
            &params,
            &message,
            &randomness,
            &commitment,
        )
        .expect("Should generate constraints");

        // Log constraint counts for performance tracking
        tracing::info!(
            target: TEST_TARGET,
            constraints = cs.num_constraints(),
            witness_variables = cs.num_witness_variables(),
            instance_variables = cs.num_instance_variables(),
            "Circuit constraint counts"
        );

        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");

        // Sanity check that we have a reasonable number of constraints
        // Pedersen commitments with window-based scalar multiplication should be efficient
        assert!(
            cs.num_constraints() < 100000,
            "Too many constraints for a simple Pedersen commitment"
        );
    }

    #[test]
    fn test_zero_message_and_randomness() {
        let _gaurd = setup_test_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let params = pedersen_setup::<JubjubProjective, PedersenWin, _>(&mut rng);

        // Test with zero message and zero randomness
        let message = vec![0u8; 32];
        let randomness = PedersenRandomness::<JubjubProjective>(JubjubScalar::from(0u64));

        // Should still produce a valid commitment and proof
        let (proof, pvk, _vk, public_inputs) = prove_opening_groth16::<PedersenWin, _>(
            &mut rng,
            params.clone(),
            message.clone(),
            randomness.clone(),
        )
        .expect("Should handle zero inputs");

        let ok = verify_opening_groth16(&pvk, &proof, &public_inputs)
            .expect("Verification should not error");
        assert!(ok, "Should verify zero inputs correctly");

        // The commitment should be deterministic for zero inputs
        let c1 = pedersen_commit::<JubjubProjective, PedersenWin>(&params, &message, &randomness);
        let c2 = pedersen_commit::<JubjubProjective, PedersenWin>(&params, &message, &randomness);
        assert_eq!(
            c1, c2,
            "Zero inputs should produce deterministic commitment"
        );
    }

    #[test]
    fn test_proof_serialization() {
        let _gaurd = setup_test_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let params = pedersen_setup::<JubjubProjective, PedersenWin, _>(&mut rng);
        let message = vec![0x11u8; 32];
        let randomness = PedersenRandomness::<JubjubProjective>(JubjubScalar::rand(&mut rng));

        let (proof, pvk, vk, public_inputs) =
            prove_opening_groth16::<PedersenWin, _>(&mut rng, params, message, randomness)
                .expect("Proof generation should succeed");

        // Test that proof can be serialized and deserialized
        use ark_groth16::Proof;
        use ark_serialize::CanonicalSerialize;

        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .expect("Proof serialization should work");

        let proof_deserialized = Proof::<Bn254>::deserialize_compressed(&proof_bytes[..])
            .expect("Proof deserialization should work");

        // Verify with deserialized proof
        let ok = verify_opening_groth16(&pvk, &proof_deserialized, &public_inputs)
            .expect("Verification should not error");
        assert!(ok, "Deserialized proof should verify");

        tracing::info!(
            target: TEST_TARGET,
            proof_size_bytes = proof_bytes.len(),
            "Proof serialized"
        );

        // Also test VK serialization
        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes)
            .expect("VK serialization should work");
        tracing::info!(
            target: TEST_TARGET,
            vk_size_bytes = vk_bytes.len(),
            "Verifying key serialized"
        );
    }

    #[test]
    fn test_pedersen_hash_52_elements_with_constraint_tracking() {
        let _gaurd = setup_test_tracing();

        use crate::track_constraints;
        use ark_crypto_primitives::crh::pedersen::{
            constraints::CRHGadget as PedersenCRHGadget, Window as CRHWindow, CRH as PedersenCRH,
        };
        use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};

        let mut rng = StdRng::seed_from_u64(42);

        // Setup CRH parameters
        let crh_params = PedersenCRH::<JubjubProjective, DeckHashWindow>::setup(&mut rng)
            .expect("CRH setup should succeed");

        // Create 52 elements (like a deck of cards)
        let deck: Vec<u8> = (0u8..52u8).collect();

        // Native hash computation
        let native_hash =
            PedersenCRH::<JubjubProjective, DeckHashWindow>::evaluate(&crh_params, deck.as_slice())
                .expect("Native CRH evaluation should succeed");

        tracing::info!(
            target: TEST_TARGET,
            "Native Pedersen hash of 52 elements computed"
        );

        // Now create a circuit that computes the same hash
        #[derive(Clone)]
        struct HashCircuit<W: CRHWindow> {
            params: <PedersenCRH<JubjubProjective, W> as CRHScheme>::Parameters,
            input: Vec<u8>,
            expected_hash: JubjubAffine,
        }

        impl<W: CRHWindow> ConstraintSynthesizer<Fr> for HashCircuit<W> {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<Fr>,
            ) -> Result<(), SynthesisError> {
                // Allocate CRH parameters as constants
                type CRHGadget<W> = PedersenCRHGadget<JubjubProjective, JubjubVar, W>;
                type CRH<W> = PedersenCRH<JubjubProjective, W>;

                // Track parameter allocation
                let params_var =
                    <CRHGadget<W> as CRHSchemeGadget<CRH<W>, Fr>>::ParametersVar::new_constant(
                        ark_relations::ns!(cs, "crh_params"),
                        &self.params,
                    )?;

                // Track input allocation
                let mut input_var = Vec::new();
                for byte in self.input.iter() {
                    input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte))?);
                }

                // Track hash computation, expected hash allocation, and equality enforcement
                track_constraints!(cs.clone(), "pedersen_crh_verification", TEST_TARGET, {
                    let computed_hash = CRHGadget::<W>::evaluate(&params_var, &input_var)?;

                    let expected_var =
                        JubjubVar::new_input(ark_relations::ns!(cs, "expected_hash"), || {
                            Ok(self.expected_hash)
                        })?;

                    computed_hash.enforce_equal(&expected_var)?;
                    Ok::<(), SynthesisError>(())
                })?;

                Ok(())
            }
        }

        // Create the circuit
        let circuit = HashCircuit::<DeckHashWindow> {
            params: crh_params.clone(),
            input: deck.clone(),
            expected_hash: native_hash.into(),
        };

        // Track constraints for the entire circuit
        let cs = ConstraintSystem::<Fr>::new_ref();

        tracing::info!(
            target: TEST_TARGET,
            "=== Constraint Tracking for Pedersen Hash of 52 Elements ==="
        );

        track_constraints!(
            cs.clone(),
            "total_circuit_generation",
            TEST_TARGET,
            circuit
                .generate_constraints(cs.clone())
                .expect("Circuit generation should succeed")
        );

        // Verify the circuit is satisfied
        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");

        tracing::info!(
            target: TEST_TARGET,
            total_constraints = cs.num_constraints(),
            total_witness_variables = cs.num_witness_variables(),
            total_instance_variables = cs.num_instance_variables(),
            constraints_per_element = format!("{:.2}", cs.num_constraints() as f64 / 52.0),
            "Performance metrics for Pedersen hash of 52 elements"
        );

        // Now generate a real proof
        tracing::info!(
            target: TEST_TARGET,
            "Generating Groth16 Proof"
        );

        let circuit_for_proof = HashCircuit::<DeckHashWindow> {
            params: crh_params.clone(),
            input: deck,
            expected_hash: native_hash.into(),
        };

        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(circuit_for_proof.clone(), &mut rng)
                .expect("Setup should succeed");

        let proof = Groth16::<Bn254>::prove(&pk, circuit_for_proof, &mut rng)
            .expect("Proof generation should succeed");

        // Prepare public inputs
        let public_inputs: Vec<Fr> = native_hash.to_field_elements().unwrap();

        // Verify the proof
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
        let valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
            .expect("Verification should not error");

        assert!(valid, "Proof should verify");
        tracing::info!(
            target: TEST_TARGET,
            "✅ Proof verified successfully!"
        );

        // Test with different input should fail
        let wrong_deck: Vec<u8> = (1u8..53u8).collect();
        let wrong_hash = PedersenCRH::<JubjubProjective, DeckHashWindow>::evaluate(
            &crh_params,
            wrong_deck.as_slice(),
        )
        .expect("Wrong CRH evaluation should succeed");

        let wrong_public_inputs: Vec<Fr> = wrong_hash.to_field_elements().unwrap();

        let invalid =
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &wrong_public_inputs, &proof)
                .expect("Verification should not error");

        assert!(!invalid, "Proof should not verify with wrong public input");
        tracing::info!(
            target: TEST_TARGET,
            "✅ Correctly rejected proof with wrong public input"
        );
    }
}
