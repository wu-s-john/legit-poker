use serde::{Deserialize, Serialize};

/// A signed envelope carrying a serde-serializable value, its signature, and the
/// exact transcript bytes that were signed (domain-separated and canonicalized).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithSignature<Sig, T>
where
    T: Serialize,
{
    pub value: T,
    pub signature: Sig,
    /// Canonical bytes used for signing/verification (domain tag || serialized value)
    pub transcript: Vec<u8>,
}

impl<Sig, T> WithSignature<Sig, T>
where
    T: Serialize,
{
    /// Build a signed envelope using a provided SignatureScheme.
    ///
    /// The transcript is constructed as: domain_tag || serde_json(value).
    /// This function signs the transcript and returns the envelope.
    pub fn new<S, R>(
        value: T,
        domain_tag: &[u8],
        params: &<S as ark_crypto_primitives::signature::SignatureScheme>::Parameters,
        sk: &<S as ark_crypto_primitives::signature::SignatureScheme>::SecretKey,
        rng: &mut R,
    ) -> anyhow::Result<
        WithSignature<<S as ark_crypto_primitives::signature::SignatureScheme>::Signature, T>,
    >
    where
        S: ark_crypto_primitives::signature::SignatureScheme,
        R: rand::Rng,
    {
        // Serialize payload deterministically
        let mut transcript = Vec::with_capacity(domain_tag.len() + 128);
        transcript.extend_from_slice(domain_tag);
        let payload = serde_json::to_vec(&value)?;
        transcript.extend_from_slice(&payload);

        // Sign transcript using the provided scheme
        let sig = <S as ark_crypto_primitives::signature::SignatureScheme>::sign(
            params,
            sk,
            &transcript,
            rng,
        )
        .map_err(|e| anyhow::anyhow!("signature error: {e}"))?;

        Ok(WithSignature {
            value,
            signature: sig,
            transcript,
        })
    }
}

/// Minimal payload for betting action attestation.
/// Extend as needed with table/hand identifiers, nonces, etc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlayerActionBet {
    pub seat: crate::engine::nl::types::SeatId,
    pub action: crate::engine::nl::actions::PlayerBetAction,
    /// Optional anti-replay field (caller managed). 0 if unused.
    pub nonce: u64,
}
