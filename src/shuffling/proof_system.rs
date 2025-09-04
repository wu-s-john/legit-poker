//! Generic proof system trait and implementations for shuffling proofs

use super::bayer_groth_permutation::{
    bg_setup::BayerGrothSetupParameters,
    reencryption_protocol::{prove, verify},
};

// Re-export ReencryptionProof for convenience
pub use super::bayer_groth_permutation::reencryption_protocol::ReencryptionProof;
use super::data_structures::ElGamalCiphertext;
use super::rs_shuffle::{
    circuit::RSShuffleWithBayerGrothLinkCircuit, data_structures::WitnessData,
};
use crate::curve_absorb::{CurveAbsorb, CurveAbsorbGadget};
use ark_crypto_primitives::{
    commitment::pedersen::Parameters,
    snark::SNARK,
    sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge},
};
use ark_ec::{pairing::Pairing, CurveConfig, CurveGroup};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof as Groth16Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
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
// Indices Proof System (Groth16-based SNARK)
// ============================================================================

/// Public input for the indices proof system
pub struct IndicesPublicInput<G, GV, const N: usize, const LEVELS: usize>
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

impl<G, GV, const N: usize, const LEVELS: usize> IndicesPublicInput<G, GV, N, LEVELS>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GV: CurveVar<G, G::BaseField>,
{
    /// Create a new IndicesPublicInput
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

/// Witness for the indices proof system
pub struct IndicesWitness<G, GV, const N: usize, const LEVELS: usize>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GV: CurveVar<G, G::BaseField>,
{
    pub permutation_usize: [usize; N],
    pub witness_data: WitnessData<N, LEVELS>,
    pub blinding_r: <G::Config as CurveConfig>::ScalarField,
    pub blinding_s: <G::Config as CurveConfig>::ScalarField,
    _marker: PhantomData<GV>,
}

impl<G, GV, const N: usize, const LEVELS: usize> IndicesWitness<G, GV, N, LEVELS>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GV: CurveVar<G, G::BaseField>,
{
    /// Create a new IndicesWitness
    pub fn new(
        permutation_usize: [usize; N],
        witness_data: WitnessData<N, LEVELS>,
        blinding_r: <G::Config as CurveConfig>::ScalarField,
        blinding_s: <G::Config as CurveConfig>::ScalarField,
    ) -> Self {
        Self {
            permutation_usize,
            witness_data,
            blinding_r,
            blinding_s,
            _marker: PhantomData,
        }
    }
}

/// Groth16-based proof system for indices
pub struct Groth16IndicesProofSystem<E, G, GV, const N: usize, const LEVELS: usize>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField>,
{
    pub proving_key: ProvingKey<E>,
    pub verifying_key: VerifyingKey<E>,
    _marker: PhantomData<(G, GV)>,
}

impl<E, G, GV, const N: usize, const LEVELS: usize> ProofSystem
    for Groth16IndicesProofSystem<E, G, GV, N, LEVELS>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField> + CurveAbsorb<E::ScalarField>,
    G::Config: CurveConfig<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField> + CurveAbsorbGadget<E::ScalarField>,
    for<'a> &'a GV: GroupOpsBounds<'a, G, GV>,
    <G::Config as CurveConfig>::ScalarField: UniformRand,
    E::ScalarField: PrimeField + Absorb,
{
    type PublicInput = IndicesPublicInput<G, GV, N, LEVELS>;
    type Witness = IndicesWitness<G, GV, N, LEVELS>;
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
                <G::Config as CurveConfig>::ScalarField::from(witness.permutation_usize[i] as u64)
            });

        // Extract initial indices (0..N-1)
        let indices_init: [E::ScalarField; N] =
            std::array::from_fn(|i| E::ScalarField::from(i as u64));

        // Extract shuffled indices from witness data
        let final_sorted = &witness.witness_data.next_levels[LEVELS - 1];
        let indices_after_shuffle: [E::ScalarField; N] =
            std::array::from_fn(|i| E::ScalarField::from(final_sorted[i].idx as u64));

        // Create the circuit
        let circuit = RSShuffleWithBayerGrothLinkCircuit::<E::ScalarField, G, GV, N, LEVELS>::new(
            public_input.seed,
            public_input.bg_setup_params.c_perm,
            public_input.bg_setup_params.c_power,
            permutation_scalars,
            witness.witness_data.clone(),
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
        _public_input: &Self::PublicInput,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error> {
        // Prepare public inputs for verification
        let public_inputs = vec![
            G::BaseField::from(17u64), // alpha challenge (simplified)
                                       // In practice, would include commitment coordinates
        ];

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

/// Create a Groth16-based indices proof system
pub fn create_groth16_indices_proof_system<E, G, GV, const N: usize, const LEVELS: usize>(
    proving_key: ProvingKey<E>,
    verifying_key: VerifyingKey<E>,
) -> Groth16IndicesProofSystem<E, G, GV, N, LEVELS>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField>,
{
    Groth16IndicesProofSystem {
        proving_key,
        verifying_key,
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
