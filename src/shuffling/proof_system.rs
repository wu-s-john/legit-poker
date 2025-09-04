//! Generic proof system trait and implementations for shuffling proofs

use super::bayer_groth_permutation::{
    bg_setup::BayerGrothSetupParameters,
    sigma_protocol::{prove_sigma_linkage_ni, verify_sigma_linkage_ni},
};

// Re-export SigmaProof for convenience
pub use super::bayer_groth_permutation::sigma_protocol::SigmaProof;
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
pub struct IndicesPublicInput<E, G, GV, const N: usize, const LEVELS: usize>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField>,
{
    pub seed: E::ScalarField,
    pub bg_setup_params: BayerGrothSetupParameters<G::ScalarField, G, N>,
    pub generator: G,
    pub domain: Vec<u8>,
    pub _marker: PhantomData<GV>,
}

/// Witness for the indices proof system
pub struct IndicesWitness<E, G, GV, const N: usize, const LEVELS: usize>
where
    E: Pairing,
    G: CurveGroup<BaseField = E::ScalarField>,
    GV: CurveVar<G, E::ScalarField>,
{
    pub permutation_usize: [usize; N],
    pub witness_data: WitnessData<N, LEVELS>,
    pub blinding_r: <G::Config as CurveConfig>::ScalarField,
    pub blinding_s: <G::Config as CurveConfig>::ScalarField,
    pub _marker: PhantomData<(GV, E)>,
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
    type PublicInput = IndicesPublicInput<E, G, GV, N, LEVELS>;
    type Witness = IndicesWitness<E, G, GV, N, LEVELS>;
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
            E::ScalarField::from(17u64), // alpha challenge (simplified)
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
// Sigma Protocol Proof System
// ============================================================================

/// Public input for the sigma protocol proof system
pub struct SigmaPublicInput<G, const N: usize>
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

/// Witness for the sigma protocol proof system
pub struct SigmaWitness<G, const N: usize>
where
    G: CurveGroup,
{
    pub perm_power_vector: [G::ScalarField; N],
    pub power_perm_blinding_factor: G::ScalarField,
    pub rerandomization_scalars: [G::ScalarField; N],
}

/// Sigma protocol proof system
pub struct SigmaProofSystem<G, const N: usize>
where
    G: CurveGroup,
{
    _marker: PhantomData<G>,
}

impl<G, const N: usize> Default for SigmaProofSystem<G, N>
where
    G: CurveGroup,
{
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<G, const N: usize> ProofSystem for SigmaProofSystem<G, N>
where
    G: CurveGroup + CurveAbsorb<G::BaseField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb + UniformRand,
{
    type PublicInput = SigmaPublicInput<G, N>;
    type Witness = SigmaWitness<G, N>;
    type Proof = SigmaProof<G, N>;
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

        let proof = prove_sigma_linkage_ni(
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

        let valid = verify_sigma_linkage_ni(
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
            return Err("Sigma protocol verification failed".into());
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

/// Create a sigma proof system
pub fn create_sigma_proof_system<G, const N: usize>() -> SigmaProofSystem<G, N>
where
    G: CurveGroup,
{
    SigmaProofSystem::default()
}

/// Create a dummy proof system for testing
pub fn create_dummy_proof_system<P, W>() -> DummyProofSystem<P, W> {
    DummyProofSystem::default()
}
