use thiserror::Error;

#[derive(Error, Debug)]
pub enum PedersenCommitmentOpeningError {
    #[error("Length mismatch in parameters")]
    LengthMismatch,

    #[error("Vector length must be a power of two")]
    NotPowerOfTwo,

    #[error("Proof verification failed")]
    BadProof,
}
