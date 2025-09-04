//! Example usage of the generic proof system for shuffling proofs
//! 
//! This module demonstrates how to use the modular proof system architecture
//! with different proof backends (Groth16, Sigma, Dummy).

use super::proof_system::{
    create_dummy_proof_system,
    DummyProofSystem, Groth16IndicesProofSystem, ProofSystem, SigmaProofSystem,
    IndicesPublicInput, IndicesWitness, SigmaPublicInput, SigmaWitness,
};
use crate::shuffling::shuffling_proof::ShufflingProof;
use ark_bn254::{Bn254, Fr};
use ark_grumpkin::Projective as GrumpkinProjective;
use ark_r1cs_std::{fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar};
use ark_std::rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};

/// Example configuration using concrete proof systems
pub struct ConcreteShufflingConfig {
    pub domain: Vec<u8>,
    pub generator: GrumpkinProjective,
    pub public_key: GrumpkinProjective,
    pub indices_proof_system: Groth16IndicesProofSystem<
        Bn254,
        GrumpkinProjective,
        ProjectiveVar<ark_grumpkin::GrumpkinConfig, FpVar<Fr>>,
        52,
        3,
    >,
    pub sigma_proof_system: SigmaProofSystem<GrumpkinProjective, 52>,
}

/// Example configuration using dummy proof systems for testing
pub struct DummyShufflingConfig {
    pub domain: Vec<u8>,
    pub generator: GrumpkinProjective,
    pub public_key: GrumpkinProjective,
    pub indices_proof_system: DummyProofSystem<
        IndicesPublicInput<
            Bn254,
            GrumpkinProjective,
            ProjectiveVar<ark_grumpkin::GrumpkinConfig, FpVar<Fr>>,
            52,
            3,
        >,
        IndicesWitness<
            Bn254,
            GrumpkinProjective,
            ProjectiveVar<ark_grumpkin::GrumpkinConfig, FpVar<Fr>>,
            52,
            3,
        >,
    >,
    pub sigma_proof_system: DummyProofSystem<
        SigmaPublicInput<GrumpkinProjective, 52>,
        SigmaWitness<GrumpkinProjective, 52>
    >,
}

/// Example function showing how to create a shuffling proof with generic proof systems
/// 
/// Note: This is a simplified example that doesn't actually create valid proofs.
/// In a real implementation, you would need to:
/// 1. Generate proper public inputs and witnesses
/// 2. Ensure the proof types match what ShufflingProof expects
pub fn example_prove_shuffling<IP, SP, R>(
    indices_proof_system: &IP,
    sigma_proof_system: &SP,
    rng: &mut R,
) -> Result<(), Box<dyn std::error::Error>>
where
    IP: ProofSystem,
    SP: ProofSystem,
    R: RngCore + CryptoRng,
    IP::PublicInput: Default,
    IP::Witness: Default,
    SP::PublicInput: Default,
    SP::Witness: Default,
    IP::Error: std::error::Error + 'static,
    SP::Error: std::error::Error + 'static,
{
    // Create dummy public inputs and witnesses for demonstration
    let indices_public = Default::default();
    let indices_witness = Default::default();
    let sigma_public = Default::default();
    let sigma_witness = Default::default();

    // Generate proofs using the generic proof systems
    let _indices_proof = indices_proof_system.prove(&indices_public, &indices_witness, rng)?;
    let _sigma_proof = sigma_proof_system.prove(&sigma_public, &sigma_witness, rng)?;

    // In a real implementation, you would construct a ShufflingProof here
    // but we can't do that generically without knowing the concrete proof types
    println!("Proofs generated successfully (example only)");
    
    Ok(())
}

/// Example showing how to switch between different proof backends
pub fn demonstrate_proof_backend_switching() {
    let mut _rng = StdRng::seed_from_u64(12345);

    // Example 1: Using dummy proof systems for testing
    println!("Using dummy proof systems...");
    let _dummy_indices: DummyProofSystem<(), ()> = create_dummy_proof_system();
    let _dummy_sigma: DummyProofSystem<(), ()> = create_dummy_proof_system();
    
    // This would work with the dummy systems - proofs are just ()
    // let proof = example_prove_shuffling(&_dummy_indices, &_dummy_sigma, &mut _rng);

    // Example 2: Using real proof systems
    println!("Using real proof systems...");
    // In practice, you'd get these from a trusted setup
    // let (proving_key, verifying_key) = generate_keys(&mut rng);
    // let groth16_indices = create_groth16_indices_proof_system(proving_key, verifying_key);
    // let sigma_system = create_sigma_proof_system();
    
    // This would work with real systems - proofs are Groth16Proof and SigmaProof
    // let proof = example_prove_shuffling(&groth16_indices, &sigma_system, &mut rng);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_proof_system() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        // Create dummy proof systems
        let dummy_indices: DummyProofSystem<(), ()> = create_dummy_proof_system();
        let dummy_sigma: DummyProofSystem<(), ()> = create_dummy_proof_system();
        
        // Test proving with dummy public input and witness
        let unit_public = ();
        let unit_witness = ();
        let indices_proof = dummy_indices.prove(&unit_public, &unit_witness, &mut rng).unwrap();
        let sigma_proof = dummy_sigma.prove(&unit_public, &unit_witness, &mut rng).unwrap();
        
        // Verify the dummy proofs (always succeeds)
        dummy_indices.verify(&unit_public, &indices_proof).unwrap();
        dummy_sigma.verify(&unit_public, &sigma_proof).unwrap();
        
        // Both proofs should be unit type
        assert_eq!(indices_proof, ());
        assert_eq!(sigma_proof, ());
        
        println!("✅ Dummy proof system test passed!");
    }
}