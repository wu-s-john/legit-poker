use thiserror::Error;
use ark_relations::r1cs::SynthesisError;

#[derive(Error, Debug)]
pub enum ShuffleError {
    #[error("Synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
    
    #[error("Invalid deck size: expected 52, got {0}")]
    InvalidDeckSize(usize),
    
    #[error("Setup not found for proof system")]
    SetupNotFound,
    
    #[error("Constraint count mismatch: expected {expected}, got {actual}")]
    ConstraintMismatch { expected: usize, actual: usize },
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Setup failed")]
    SetupFailed,
    
    #[error("Unsatisfied constraint: {0}")]
    UnsatisfiedConstraint(String),
}