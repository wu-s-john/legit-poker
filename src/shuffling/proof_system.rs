//! Generic proof system trait and implementations for shuffling proofs
//!
//! ## Public Input Structure for RS Shuffle with Bayer-Groth Linkage
//!
//! The `RSShuffleWithBayerGrothLinkCircuit` allocates exactly 7 public input field elements:
//!
//! 1. **alpha** (1 element): The RS shuffle challenge scalar
//! 2. **c_perm** (3 elements): Commitment to permutation vector, flattened as (x, y, infinity)
//! 3. **c_power** (3 elements): Commitment to power vector, flattened as (x, y, infinity)
//!
//! ### Important Notes:
//! - Arkworks internally adds an implicit leading 1 to the public inputs
//! - Short Weierstrass curves (like BN254) serialize to 3 field elements via `ToConstraintField`
//! - The order of public inputs must exactly match the circuit's `AllocationMode::Input` order
//! - We use prepared verifying keys for efficient verification
//!
//! ### Verification Constraint:
//! ```text
//! assert_eq!(public_inputs.len() + 1, vk.gamma_abc_g1.len())
//! ```

use super::bayer_groth_permutation::{
    bg_setup::{new_bayer_groth_transcript_with_poseidon, BayerGrothSetupParameters},
    reencryption_protocol::{prove, verify},
};

// Re-export ReencryptionProof for convenience
pub use super::bayer_groth_permutation::reencryption_protocol::ReencryptionProof;
use super::data_structures::ElGamalCiphertext;
use super::rs_shuffle::{
    circuit::RSShuffleWithBayerGrothLinkCircuit, data_structures::PermutationWitnessTrace,
    native::run_rs_shuffle_permutation,
};
use crate::curve_absorb::{CurveAbsorb, CurveAbsorbGadget};
use crate::pedersen_commitment::bytes_opening::{DeckHashWindow, ReencryptionWindow};
use ark_crypto_primitives::{
    commitment::{
        pedersen::{Commitment as PedersenCommitment, Parameters},
        CommitmentScheme,
    },
    snark::SNARK,
    sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge},
};
use ark_ec::{pairing::Pairing, CurveConfig, CurveGroup};
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof as Groth16Proof, ProvingKey,
    VerifyingKey,
};
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_std::One;
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng, RngCore},
    vec::Vec,
    UniformRand,
};

/// Generic proof system trait for modular proof generation and verification
pub trait ProofSystem {
    /// The public input for the proof (visible to both prover and verifier)
    type PublicInput;
    /// The witness for the proof (private to the prover)
    type Witness;
    /// The proof object
    type Proof;
    /// Error type for proof operations
    type Error;

    /// Generate a proof for the given public input and witness
    fn prove<R: RngCore + CryptoRng>(
        &self,
        public_input: &Self::PublicInput,
        witness: &Self::Witness,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>;

    /// Verify a proof against the given public input
    fn verify(
        &self,
        public_input: &Self::PublicInput,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error>;
}

// ============================================================================
// Helper Functions for Public Input Construction
// ============================================================================

/// Helper function to flatten a curve point into field elements for use as public inputs
///
/// For Short Weierstrass curves (like BN254), this returns 3 field elements:
/// - x coordinate
/// - y coordinate
/// - infinity bit (0 for normal points, 1 for point at infinity)
pub fn flatten_curve_point<G, F>(point: &G) -> Result<Vec<F>, String>
where
    G: CurveGroup + ToConstraintField<F>,
    F: PrimeField,
{
    point
        .to_field_elements()
        .ok_or_else(|| "Failed to convert curve point to field elements".to_string())
}

/// Build public inputs for the RS shuffle circuit with Bayer-Groth linkage
///
/// The RSShuffleWithBayerGrothLinkCircuit expects exactly these public inputs in order:
/// 1. alpha (the RS shuffle challenge) - 1 field element
/// 2. c_perm (commitment to permutation vector) - 3 field elements (x, y, infinity)
/// 3. c_power (commitment to power vector) - 3 field elements (x, y, infinity)
///
/// Total: 7 field elements (plus the implicit leading 1 that arkworks adds internally)
pub fn build_public_inputs_for_rs_shuffle<G, E>(
    alpha: E::ScalarField,
    c_perm: &G,
    c_power: &G,
) -> Result<Vec<E::ScalarField>, String>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    G::Affine: ToConstraintField<E::ScalarField>,
{
    let mut public_inputs = Vec::with_capacity(7);

    // 1. Add alpha challenge
    public_inputs.push(alpha);

    // 2. Add c_perm as (x, y, 1)
    // Affine ToConstraintField may return either [x, y] or [x, y, is_infinity].
    // Normalize to [x, y, 1] to match circuit input allocation.
    let mut c_perm_fields = c_perm
        .into_affine()
        .to_field_elements()
        .ok_or_else(|| "Failed to convert c_perm to affine field elements".to_string())?;
    match c_perm_fields.len() {
        2 => {
            c_perm_fields.push(E::ScalarField::one());
        }
        3 => {
            // Overwrite the third element with 1
            c_perm_fields[2] = E::ScalarField::one();
        }
        other => {
            return Err(format!(
                "Unexpected number of affine elements for c_perm: {}",
                other
            ));
        }
    }
    public_inputs.extend(c_perm_fields);

    // 3. Add c_power as (x, y, 1)
    let mut c_power_fields = c_power
        .into_affine()
        .to_field_elements()
        .ok_or_else(|| "Failed to convert c_power to affine field elements".to_string())?;
    match c_power_fields.len() {
        2 => {
            c_power_fields.push(E::ScalarField::one());
        }
        3 => {
            c_power_fields[2] = E::ScalarField::one();
        }
        other => {
            return Err(format!(
                "Unexpected number of affine elements for c_power: {}",
                other
            ));
        }
    }
    public_inputs.extend(c_power_fields);

    // Sanity check: we should have exactly 7 elements
    debug_assert_eq!(
        public_inputs.len(),
        7,
        "RS shuffle circuit expects exactly 7 public input elements"
    );

    Ok(public_inputs)
}

// ============================================================================
// Permutation Proof System (Groth16-based SNARK)
// ============================================================================

/// Public input for the permutation proof system
pub struct PermutationPublicInput<G, GV, const N: usize, const LEVELS: usize>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GV: CurveVar<G, G::BaseField>,
{
    pub seed: G::BaseField,
    pub bg_setup_params: BayerGrothSetupParameters<G::ScalarField, G, N>,
    pub generator: G,
    pub domain: Vec<u8>,
    _marker: PhantomData<GV>,
}

impl<G, GV, const N: usize, const LEVELS: usize> PermutationPublicInput<G, GV, N, LEVELS>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GV: CurveVar<G, G::BaseField>,
{
    /// Create a new PermutationPublicInput
    pub fn new(
        seed: G::BaseField,
        bg_setup_params: BayerGrothSetupParameters<G::ScalarField, G, N>,
        generator: G,
        domain: Vec<u8>,
    ) -> Self {
        Self {
            seed,
            bg_setup_params,
            generator,
            domain,
            _marker: PhantomData,
        }
    }
}

/// Witness for the permutation proof system
pub struct PermutationWitness<G, GV, const N: usize, const LEVELS: usize>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GV: CurveVar<G, G::BaseField>,
{
    pub rs_shuffle_trace: super::rs_shuffle::data_structures::RSShuffleTrace<usize, N, LEVELS>,
    pub blinding_r: <G::Config as CurveConfig>::ScalarField,
    pub blinding_s: <G::Config as CurveConfig>::ScalarField,
    _marker: PhantomData<GV>,
}

impl<G, GV, const N: usize, const LEVELS: usize> PermutationWitness<G, GV, N, LEVELS>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GV: CurveVar<G, G::BaseField>,
{
    /// Create a new PermutationWitness
    pub fn new(
        rs_shuffle_trace: super::rs_shuffle::data_structures::RSShuffleTrace<usize, N, LEVELS>,
        blinding_r: <G::Config as CurveConfig>::ScalarField,
        blinding_s: <G::Config as CurveConfig>::ScalarField,
    ) -> Self {
        Self {
            rs_shuffle_trace,
            blinding_r,
            blinding_s,
            _marker: PhantomData,
        }
    }
}

/// Groth16-based proof system for permutation
///
/// This proof system proves correct RS shuffle with Bayer-Groth permutation linkage.
/// It maintains both the raw and prepared verifying keys for efficiency.
pub struct Groth16PermutationProofSystem<E, G, GV, const N: usize, const LEVELS: usize>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField>,
{
    pub proving_key: ProvingKey<E>,
    pub verifying_key: VerifyingKey<E>,
    pub prepared_verifying_key: PreparedVerifyingKey<E>,
    _marker: PhantomData<(G, GV)>,
}

impl<E, G, GV, const N: usize, const LEVELS: usize> ProofSystem
    for Groth16PermutationProofSystem<E, G, GV, N, LEVELS>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField> + CurveAbsorb<E::ScalarField>,
    G::Affine: ToConstraintField<E::ScalarField>,
    G::Config: CurveConfig<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField>
        + CurveAbsorbGadget<
            E::ScalarField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<E::ScalarField>,
        >,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    <G::Config as CurveConfig>::ScalarField: UniformRand,
    E::ScalarField: PrimeField + Absorb,
{
    type PublicInput = PermutationPublicInput<G, GV, N, LEVELS>;
    type Witness = PermutationWitness<G, GV, N, LEVELS>;
    type Proof = Groth16Proof<E>;
    type Error = Box<dyn std::error::Error>;

    fn prove<R: RngCore + CryptoRng>(
        &self,
        public_input: &Self::PublicInput,
        witness: &Self::Witness,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        // Convert permutation to scalar field elements
        let permutation_scalars: [<G::Config as CurveConfig>::ScalarField; N] =
            std::array::from_fn(|i| {
                <G::Config as CurveConfig>::ScalarField::from(
                    witness.rs_shuffle_trace.permuted_output[i] as u64,
                )
            });

        // Extract initial indices (0..N-1)
        let indices_init: [E::ScalarField; N] =
            std::array::from_fn(|i| E::ScalarField::from(i as u64));

        // Extract shuffled indices from witness data
        let final_sorted = &witness.rs_shuffle_trace.witness_trace.next_levels[LEVELS - 1];
        let indices_after_shuffle: [E::ScalarField; N] =
            std::array::from_fn(|i| E::ScalarField::from(final_sorted[i].idx as u64));

        // Create the circuit
        let circuit = RSShuffleWithBayerGrothLinkCircuit::<
            E::ScalarField,
            G,
            GV,
            ark_crypto_primitives::sponge::poseidon::PoseidonSponge<E::ScalarField>,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<E::ScalarField>,
            N,
            LEVELS,
        >::new(
            public_input.seed,
            public_input.bg_setup_params.c_perm,
            public_input.bg_setup_params.c_power,
            permutation_scalars,
            witness.rs_shuffle_trace.witness_trace.clone(),
            indices_init,
            indices_after_shuffle,
            (witness.blinding_r, witness.blinding_s),
            public_input.generator,
            public_input.domain.clone(),
        );

        // Generate the proof with RNG
        let proof = Groth16::<E>::prove(&self.proving_key, circuit, rng)?;
        Ok(proof)
    }

    fn verify(
        &self,
        public_input: &Self::PublicInput,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        // Build the public inputs using the helper function
        // Note: We use `seed` as `alpha` here. In production, alpha should ideally
        // be derived from a transcript to ensure proper Fiat-Shamir challenge generation.
        let public_inputs = build_public_inputs_for_rs_shuffle::<G, E>(
            public_input.seed,
            &public_input.bg_setup_params.c_perm,
            &public_input.bg_setup_params.c_power,
        )?;

        // Debug lengths to help diagnose mismatches
        tracing::debug!(
            target: "legit_poker::shuffling::proof_system",
            "public_inputs len = {}, vk.gamma_abc_g1 len = {}",
            public_inputs.len(),
            self.verifying_key.gamma_abc_g1.len()
        );
        // Debug first few elements for sanity (alpha and first coords)
        if public_inputs.len() >= 7 {
            tracing::debug!(
                target: "legit_poker::shuffling::proof_system",
                "alpha={}, c_perm_x={}, c_perm_y={}, c_perm_inf={}, c_power_x={}, c_power_y={}, c_power_inf={}",
                public_inputs[0],
                public_inputs[1],
                public_inputs[2],
                public_inputs[3],
                public_inputs[4],
                public_inputs[5],
                public_inputs[6]
            );
        }

        // Use the prepared verifying key for more efficient verification
        let valid = Groth16::<E>::verify_with_processed_vk(
            &self.prepared_verifying_key,
            &public_inputs,
            proof,
        )?;

        if !valid {
            return Err("SNARK verification failed".into());
        }
        Ok(())
    }
}

impl<E, G, GV, const N: usize, const LEVELS: usize>
    Groth16PermutationProofSystem<E, G, GV, N, LEVELS>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    G::Affine: ToConstraintField<E::ScalarField>,
    G::BaseField: PrimeField,
    GV: CurveVar<G, E::ScalarField>
        + CurveAbsorbGadget<
            E::ScalarField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<E::ScalarField>,
        >,
    for<'a> &'a GV: GroupOpsBounds<'a, G, E::ScalarField>,
{
    /// Verify a proof using the raw (unprepared) verifying key
    ///
    /// This method is less efficient than the standard `verify` method,
    /// but can be useful when you need to use the raw verifying key directly.
    pub fn verify_with_raw_vk(
        &self,
        public_input: &PermutationPublicInput<G, GV, N, LEVELS>,
        proof: &Groth16Proof<E>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Build the public inputs using the helper function
        let public_inputs = build_public_inputs_for_rs_shuffle::<G, E>(
            public_input.seed,
            &public_input.bg_setup_params.c_perm,
            &public_input.bg_setup_params.c_power,
        )?;

        // Use the raw verifying key (less efficient than prepared)
        let valid = Groth16::<E>::verify(&self.verifying_key, &public_inputs, proof)?;

        if !valid {
            return Err("SNARK verification failed".into());
        }
        Ok(())
    }
}

// ============================================================================
// Reencryption Protocol Proof System
// ============================================================================

/// Public input for the reencryption protocol proof system
pub struct ReencryptionPublicInput<G, const N: usize>
where
    G: CurveGroup,
{
    pub public_key: G,
    pub pedersen_params: Parameters<G>,
    pub input_ciphertexts: [ElGamalCiphertext<G>; N],
    pub output_ciphertexts: [ElGamalCiphertext<G>; N],
    pub perm_power_challenge: G::ScalarField,
    pub power_perm_vector: G,
    pub domain: Vec<u8>,
}

impl<G, const N: usize> ReencryptionPublicInput<G, N>
where
    G: CurveGroup,
{
    /// Create a new ReencryptionPublicInput
    pub fn new(
        public_key: G,
        pedersen_params: Parameters<G>,
        input_ciphertexts: [ElGamalCiphertext<G>; N],
        output_ciphertexts: [ElGamalCiphertext<G>; N],
        perm_power_challenge: G::ScalarField,
        power_perm_vector: G,
        domain: Vec<u8>,
    ) -> Self {
        Self {
            public_key,
            pedersen_params,
            input_ciphertexts,
            output_ciphertexts,
            perm_power_challenge,
            power_perm_vector,
            domain,
        }
    }
}

/// Witness for the reencryption protocol proof system
pub struct ReencryptionWitness<G, const N: usize>
where
    G: CurveGroup,
{
    pub perm_power_vector: [G::ScalarField; N],
    pub power_perm_blinding_factor: G::ScalarField,
    pub rerandomization_scalars: [G::ScalarField; N],
}

impl<G, const N: usize> ReencryptionWitness<G, N>
where
    G: CurveGroup,
{
    /// Create a new ReencryptionWitness
    pub fn new(
        perm_power_vector: [G::ScalarField; N],
        power_perm_blinding_factor: G::ScalarField,
        rerandomization_scalars: [G::ScalarField; N],
    ) -> Self {
        Self {
            perm_power_vector,
            power_perm_blinding_factor,
            rerandomization_scalars,
        }
    }
}

/// Reencryption protocol proof system
pub struct ReencryptionProofSystem<G, const N: usize>
where
    G: CurveGroup,
{
    _marker: PhantomData<G>,
}

impl<G, const N: usize> Default for ReencryptionProofSystem<G, N>
where
    G: CurveGroup,
{
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<G, const N: usize> ProofSystem for ReencryptionProofSystem<G, N>
where
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb + UniformRand,
{
    type PublicInput = ReencryptionPublicInput<G, N>;
    type Witness = ReencryptionWitness<G, N>;
    type Proof = ReencryptionProof<G, N>;
    type Error = Box<dyn std::error::Error>;

    fn prove<R: RngCore + CryptoRng>(
        &self,
        public_input: &Self::PublicInput,
        witness: &Self::Witness,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        // Create a fresh transcript for proving
        let mut transcript = PoseidonSponge::<G::BaseField>::new(&crate::config::poseidon_config());
        transcript.absorb(&public_input.domain);

        let proof = prove(
            &public_input.public_key,
            &public_input.pedersen_params,
            &public_input.input_ciphertexts,
            &public_input.output_ciphertexts,
            public_input.perm_power_challenge,
            &public_input.power_perm_vector,
            &witness.perm_power_vector,
            witness.power_perm_blinding_factor,
            &witness.rerandomization_scalars,
            &mut transcript,
            rng,
        );
        Ok(proof)
    }

    fn verify(
        &self,
        public_input: &Self::PublicInput,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        // Create a fresh transcript for verification
        let mut transcript = PoseidonSponge::<G::BaseField>::new(&crate::config::poseidon_config());
        transcript.absorb(&public_input.domain);

        let valid = verify(
            &public_input.public_key,
            &public_input.pedersen_params,
            &public_input.input_ciphertexts,
            &public_input.output_ciphertexts,
            public_input.perm_power_challenge,
            &public_input.power_perm_vector,
            proof,
            &mut transcript,
        );

        if !valid {
            return Err("Reencryption protocol verification failed".into());
        }
        Ok(())
    }
}

// ============================================================================
// Dummy Proof System (for testing)
// ============================================================================

/// Dummy proof system that always succeeds
pub struct DummyProofSystem<P, W> {
    _marker: PhantomData<(P, W)>,
}

impl<P, W> Default for DummyProofSystem<P, W> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<P, W> ProofSystem for DummyProofSystem<P, W> {
    type PublicInput = P;
    type Witness = W;
    type Proof = (); // Unit type as proof
    type Error = Box<dyn std::error::Error>;

    fn prove<R: RngCore + CryptoRng>(
        &self,
        _public_input: &Self::PublicInput,
        _witness: &Self::Witness,
        _rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        // Always return unit proof
        Ok(())
    }

    fn verify(
        &self,
        _public_input: &Self::PublicInput,
        _proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        // Always succeed
        Ok(())
    }
}

// ============================================================================
// Helper functions for creating proof systems
// ============================================================================

/// Helper function to create RS Shuffle with Bayer-Groth Link circuit
fn create_rs_shuffle_circuit<G, GV, const N: usize, const LEVELS: usize>(
    seed: G::BaseField,
    bg_setup_params: &BayerGrothSetupParameters<G::ScalarField, G, N>,
    permutation_usize: &[usize; N],
    witness_data: &PermutationWitnessTrace<N, LEVELS>,
    blinding_r: <G::Config as CurveConfig>::ScalarField,
    blinding_s: <G::Config as CurveConfig>::ScalarField,
    generator: G,
    domain: Vec<u8>,
) -> RSShuffleWithBayerGrothLinkCircuit<
    G::BaseField,
    G,
    GV,
    ark_crypto_primitives::sponge::poseidon::PoseidonSponge<G::BaseField>,
    ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
    N,
    LEVELS,
>
where
    G: CurveGroup,
    G::Config: CurveConfig,
    GV: CurveVar<G, G::BaseField>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    G::BaseField: PrimeField,
{
    // Convert permutation to scalar field elements
    let permutation_scalars: [<G::Config as CurveConfig>::ScalarField; N] =
        std::array::from_fn(|i| {
            <G::Config as CurveConfig>::ScalarField::from(permutation_usize[i] as u64)
        });

    // Extract initial indices (0..N-1)
    let indices_init: [G::BaseField; N] = std::array::from_fn(|i| G::BaseField::from(i as u64));

    // Extract shuffled indices from witness data
    let final_sorted = &witness_data.next_levels[LEVELS - 1];
    let indices_after_shuffle: [G::BaseField; N] =
        std::array::from_fn(|i| G::BaseField::from(final_sorted[i].idx as u64));

    // Create and return the circuit using the new method
    RSShuffleWithBayerGrothLinkCircuit::<
        G::BaseField,
        G,
        GV,
        ark_crypto_primitives::sponge::poseidon::PoseidonSponge<G::BaseField>,
        ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
        N,
        LEVELS,
    >::new(
        seed,
        bg_setup_params.c_perm,
        bg_setup_params.c_power,
        permutation_scalars,
        witness_data.clone(),
        indices_init,
        indices_after_shuffle,
        (blinding_r, blinding_s),
        generator,
        domain,
    )
}

/// Generate test keys for Groth16 proof system
pub fn generate_test_keys<E, G, GV, const N: usize, const LEVELS: usize, R>(
    rng: &mut R,
) -> (ProvingKey<E>, VerifyingKey<E>)
where
    R: Rng + RngCore + CryptoRng,
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField> + CurveAbsorb<G::BaseField>,
    G::Config: CurveConfig<BaseField = E::ScalarField>,
    GV: CurveVar<G, G::BaseField>
        + CurveAbsorbGadget<
            G::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<G::BaseField>,
        >,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    <G::Config as CurveConfig>::ScalarField: UniformRand,
    G::BaseField: PrimeField + Absorb,
{
    // Create a simple dummy circuit for key generation
    let generator = G::generator();
    let seed = G::BaseField::from(42u64);
    let dummy_permutation: [usize; N] = std::array::from_fn(|i| i);
    let blinding_r = <G::Config as CurveConfig>::ScalarField::from(1u64);
    let blinding_s = <G::Config as CurveConfig>::ScalarField::from(2u64);

    // Create minimal dummy data
    let dummy_ct: [ElGamalCiphertext<G>; N] = std::array::from_fn(|_| ElGamalCiphertext {
        c1: G::zero(),
        c2: G::zero(),
    });

    let rs_shuffle_trace =
        run_rs_shuffle_permutation::<G::BaseField, ElGamalCiphertext<G>, N, LEVELS>(
            seed, &dummy_ct,
        );

    // Create dummy Pedersen parameters for test key generation
    use ark_std::rand::SeedableRng;
    use rand::rngs::StdRng;

    let mut deck_rng = StdRng::seed_from_u64(42);
    let perm_params = PedersenCommitment::<G, DeckHashWindow>::setup(&mut deck_rng)
        .expect("Failed to setup DeckHashWindow Pedersen parameters");

    let mut power_rng = StdRng::seed_from_u64(43);
    let power_params = PedersenCommitment::<G, ReencryptionWindow>::setup(&mut power_rng)
        .expect("Failed to setup ReencryptionWindow Pedersen parameters");

    let mut bg_transcript = new_bayer_groth_transcript_with_poseidon::<G::BaseField>(b"test");
    let (bg_setup_params, _) = bg_transcript.run_protocol::<G, N>(
        &perm_params,
        &power_params,
        &dummy_permutation,
        blinding_r,
        blinding_s,
    );

    let dummy_circuit = create_rs_shuffle_circuit::<G, GV, N, LEVELS>(
        seed,
        &bg_setup_params,
        &dummy_permutation,
        &rs_shuffle_trace.witness_trace,
        blinding_r,
        blinding_s,
        generator,
        b"test".to_vec(),
    );

    Groth16::<E>::circuit_specific_setup(dummy_circuit, rng).expect("Key generation should succeed")
}

/// Create a Groth16-based permutation proof system
pub fn create_groth16_permutation_proof_system<E, G, GV, const N: usize, const LEVELS: usize>(
    proving_key: ProvingKey<E>,
    verifying_key: VerifyingKey<E>,
) -> Groth16PermutationProofSystem<E, G, GV, N, LEVELS>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField>,
{
    // Pre-process the verifying key for more efficient verification
    let prepared_verifying_key = prepare_verifying_key(&verifying_key);

    Groth16PermutationProofSystem {
        proving_key,
        verifying_key,
        prepared_verifying_key,
        _marker: PhantomData,
    }
}

/// Create a reencryption proof system
pub fn create_reencryption_proof_system<G, const N: usize>() -> ReencryptionProofSystem<G, N>
where
    G: CurveGroup,
{
    ReencryptionProofSystem::default()
}

/// Create a dummy proof system for testing
pub fn create_dummy_proof_system<P, W>() -> DummyProofSystem<P, W> {
    DummyProofSystem::default()
}
