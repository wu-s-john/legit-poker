use anyhow::Result;
use ark_crypto_primitives::signature::SignatureScheme;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const DOMAIN_TAG: &[u8] = b"legit-poker/action/v1";

/// Trait for signature types that can be converted to/from bytes for hex serialization.
pub trait SignatureBytes: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

// Implement for Vec<u8> (identity conversion)
impl SignatureBytes for Vec<u8> {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bytes.to_vec())
    }
}

// Implement for Schnorr signatures
impl<C> SignatureBytes for ark_crypto_primitives::signature::schnorr::Signature<C>
where
    C: CurveGroup,
    C::ScalarField: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.prover_response
            .serialize_compressed(&mut bytes)
            .expect("scalar field serialization should not fail");
        self.verifier_challenge
            .serialize_compressed(&mut bytes)
            .expect("scalar field serialization should not fail");
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = &bytes[..];
        let prover_response = C::ScalarField::deserialize_compressed(&mut cursor)?;
        let verifier_challenge = C::ScalarField::deserialize_compressed(&mut cursor)?;

        Ok(Self {
            prover_response,
            verifier_challenge,
        })
    }
}

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
#[derive(Clone, Debug)]
pub struct WithSignature<Sig, T>
where
    Sig: SignatureBytes,
    T: Signable,
{
    pub value: T,
    pub signature: Sig,
    /// Canonical bytes used for signing/verification.
    /// This field is recomputed during deserialization and not serialized.
    pub transcript: Vec<u8>,
}

impl<Sig, T> Serialize for WithSignature<Sig, T>
where
    Sig: SignatureBytes,
    T: Signable + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("WithSignature", 2)?;
        state.serialize_field("value", &self.value)?;
        // Serialize signature as hex string with 0x prefix
        let hex_sig = format!("0x{}", hex::encode(self.signature.to_bytes()));
        state.serialize_field("signature", &hex_sig)?;
        state.end()
    }
}

impl<'de, Sig, T> Deserialize<'de> for WithSignature<Sig, T>
where
    Sig: SignatureBytes,
    T: Signable + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct WithSignatureVisitor<Sig, T>(std::marker::PhantomData<(Sig, T)>);

        impl<'de, Sig, T> Visitor<'de> for WithSignatureVisitor<Sig, T>
        where
            Sig: SignatureBytes,
            T: Signable + Deserialize<'de>,
        {
            type Value = WithSignature<Sig, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct WithSignature")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut value: Option<T> = None;
                let mut signature_hex: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "value" => {
                            if value.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value = Some(map.next_value()?);
                        }
                        "signature" => {
                            if signature_hex.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            signature_hex = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let value = value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                let sig_hex = signature_hex.ok_or_else(|| serde::de::Error::missing_field("signature"))?;

                // Strip 0x prefix if present
                let hex_str = sig_hex.strip_prefix("0x").unwrap_or(&sig_hex);

                // Decode hex to bytes
                let sig_bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;

                // Convert bytes to signature type
                let signature = Sig::from_bytes(&sig_bytes).map_err(serde::de::Error::custom)?;

                // Recompute transcript from the deserialized value
                let transcript = value.to_signing_bytes();

                Ok(WithSignature {
                    value,
                    signature,
                    transcript,
                })
            }
        }

        deserializer.deserialize_struct(
            "WithSignature",
            &["value", "signature"],
            WithSignatureVisitor(std::marker::PhantomData),
        )
    }
}

impl<Sig, T> WithSignature<Sig, T>
where
    Sig: SignatureBytes,
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
