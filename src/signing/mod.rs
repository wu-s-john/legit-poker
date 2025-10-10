use anyhow::Result;
use ark_crypto_primitives::signature::SignatureScheme;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const DOMAIN_TAG: &[u8] = b"zkpoker/action/v1";

/// Builder for canonical action transcripts.
pub struct TranscriptBuilder {
    buffer: Vec<u8>,
}

impl TranscriptBuilder {
    pub fn new(kind: &'static str) -> Self {
        let mut buffer = Vec::with_capacity(128);
        buffer.extend_from_slice(DOMAIN_TAG);
        buffer.extend_from_slice(&(kind.len() as u16).to_be_bytes());
        buffer.extend_from_slice(kind.as_bytes());
        Self { buffer }
    }

    pub fn append_u8(&mut self, value: u8) {
        self.buffer.push(value);
    }

    pub fn append_u64(&mut self, value: u64) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    pub fn append_i64(&mut self, value: i64) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    pub fn append_bytes(&mut self, bytes: &[u8]) {
        self.buffer
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buffer.extend_from_slice(bytes);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

/// Values that can be signed into a canonical transcript.
pub trait Signable {
    /// Logical kind string used for domain separation.
    fn domain_kind(&self) -> &'static str;

    /// Append this value's canonical representation into the transcript builder.
    fn write_transcript(&self, builder: &mut TranscriptBuilder);

    /// Obtain canonical signing bytes.
    fn to_signing_bytes(&self) -> Vec<u8> {
        let mut builder = TranscriptBuilder::new(self.domain_kind());
        self.write_transcript(&mut builder);
        builder.finish()
    }
}

/// A signed envelope carrying a signable value, its signature, and the exact
/// transcript bytes that were signed (domain-separated and canonicalized).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithSignature<Sig, T>
where
    T: Signable,
{
    pub value: T,
    pub signature: Sig,
    /// Canonical bytes used for signing/verification.
    pub transcript: Vec<u8>,
}

impl<Sig, T> WithSignature<Sig, T>
where
    T: Signable,
{
    /// Build a signed envelope using a provided SignatureScheme.
    ///
    /// The transcript is constructed from the value's `to_signing_bytes`.
    pub fn new<S, R>(
        value: T,
        params: &S::Parameters,
        sk: &S::SecretKey,
        rng: &mut R,
    ) -> Result<Self>
    where
        S: SignatureScheme<Signature = Sig>,
        R: rand::Rng,
    {
        let transcript = value.to_signing_bytes();

        // Sign transcript using the provided scheme
        let signature = S::sign(params, sk, &transcript, rng)
            .map_err(|e| anyhow::anyhow!("signature error: {e}"))?;

        Ok(WithSignature {
            value,
            signature,
            transcript,
        })
    }

    /// Verify this signature against the provided public parameters and key.
    pub fn verify<S>(&self, params: &S::Parameters, pk: &S::PublicKey) -> Result<bool>
    where
        S: SignatureScheme<Signature = Sig>,
    {
        S::verify(params, pk, &self.transcript, &self.signature)
            .map_err(|e| anyhow::anyhow!("signature error: {e}"))
    }
}

impl Signable for u8 {
    fn domain_kind(&self) -> &'static str {
        "primitive/u8_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(*self);
    }
}

impl Signable for u64 {
    fn domain_kind(&self) -> &'static str {
        "primitive/u64_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u64(*self);
    }
}

impl Signable for i64 {
    fn domain_kind(&self) -> &'static str {
        "primitive/i64_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_i64(*self);
    }
}

impl Signable for bool {
    fn domain_kind(&self) -> &'static str {
        "primitive/bool_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(*self as u8);
    }
}

impl<T> Signable for Option<T>
where
    T: Signable,
{
    fn domain_kind(&self) -> &'static str {
        "option/v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        match self {
            Some(value) => {
                builder.append_u8(1);
                value.write_transcript(builder);
            }
            None => builder.append_u8(0),
        }
    }
}

impl<K, V> Signable for BTreeMap<K, V>
where
    K: Ord + Signable,
    V: Signable,
{
    fn domain_kind(&self) -> &'static str {
        "collection/btree_map_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u64(self.len() as u64);
        for (key, value) in self.iter() {
            key.write_transcript(builder);
            value.write_transcript(builder);
        }
    }
}
