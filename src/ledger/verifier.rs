use ark_ec::CurveGroup;
use thiserror::Error;

use super::messages::{ActionEnvelope, VerifiedEnvelope};
use super::types::HandId;

pub trait Verifier<C>
where
    C: CurveGroup,
{
    fn verify(
        &self,
        hand_id: HandId,
        envelope: ActionEnvelope<C>,
    ) -> Result<VerifiedEnvelope<C>, VerifyError>;
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("unauthorized actor")]
    Unauthorized,
    #[error("invalid signature")]
    BadSignature,
    #[error("phase mismatch")]
    PhaseMismatch,
    #[error("nonce conflict")]
    NonceConflict,
    #[error("invalid message")]
    InvalidMessage,
}

#[derive(Debug, Default)]
pub struct LedgerVerifier;

impl<C> Verifier<C> for LedgerVerifier
where
    C: CurveGroup,
{
    fn verify(
        &self,
        _hand_id: HandId,
        _envelope: ActionEnvelope<C>,
    ) -> Result<VerifiedEnvelope<C>, VerifyError> {
        todo!("verifier not implemented")
    }
}
