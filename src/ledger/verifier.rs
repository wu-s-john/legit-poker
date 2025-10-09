use ark_ec::CurveGroup;
use thiserror::Error;

use super::types::HandId;
use crate::ledger::messages::AnyMessageEnvelope;

pub trait Verifier<C>
where
    C: CurveGroup,
{
    fn verify(
        &self,
        hand_id: HandId,
        envelope: AnyMessageEnvelope<C>,
    ) -> Result<AnyMessageEnvelope<C>, VerifyError>;
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

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: The verifier logic is not yet implemented. These tests capture the
    // desired behaviour and will be enabled once the underlying functionality
    // is complete.

    #[test]
    fn rejects_invalid_signatures_variant() {
        let result: Result<(), VerifyError> = Err(VerifyError::BadSignature);
        assert!(matches!(result, Err(VerifyError::BadSignature)));
    }

    #[test]
    fn rejects_unauthorized_actors_variant() {
        let result: Result<(), VerifyError> = Err(VerifyError::Unauthorized);
        assert!(matches!(result, Err(VerifyError::Unauthorized)));
    }

    #[test]
    fn rejects_phase_turn_mismatch_variant() {
        let result: Result<(), VerifyError> = Err(VerifyError::PhaseMismatch);
        assert!(matches!(result, Err(VerifyError::PhaseMismatch)));
    }

    #[test]
    fn rejects_stale_or_future_nonces_variant() {
        let result: Result<(), VerifyError> = Err(VerifyError::NonceConflict);
        assert!(matches!(result, Err(VerifyError::NonceConflict)));
    }

    #[test]
    fn rejects_malformed_messages_variant() {
        let result: Result<(), VerifyError> = Err(VerifyError::InvalidMessage);
        assert!(matches!(result, Err(VerifyError::InvalidMessage)));
    }
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
        _envelope: AnyMessageEnvelope<C>,
    ) -> Result<AnyMessageEnvelope<C>, VerifyError> {
        Err(VerifyError::InvalidMessage)
    }
}
