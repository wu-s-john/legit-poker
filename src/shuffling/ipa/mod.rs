pub mod error;
pub mod proof;

pub use error::IpaError;
pub use proof::{commit, commit_unblinded, prove, verify, IpaProof, PedersenParams};
