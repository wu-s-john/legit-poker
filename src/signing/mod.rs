use anyhow::Result;
use ark_crypto_primitives::signature::{schnorr::Signature, SignatureScheme};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// Trait for types that can be signed with domain separation.
///
/// This trait provides a domain string for cryptographic domain separation
/// when computing signing bytes via canonical serialization.
pub trait DomainSeparated {
    /// Returns the domain separation string for this type.
    /// Must be unique across all signable types in the application.
    fn domain_string() -> &'static str;
}

/// Compute canonical signing bytes for a value.
///
/// This function serializes a value using arkworks' `CanonicalSerialize`
/// trait, which provides deterministic byte encoding suitable for
/// cryptographic signatures.
///
/// # Arguments
/// * `value` - The value to serialize
///
/// # Returns
/// A vector of compressed canonical bytes suitable for signing
pub fn signing_bytes<T>(value: &T) -> Result<Vec<u8>>
where
    T: CanonicalSerialize + DomainSeparated,
{
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|e| anyhow::anyhow!("canonical serialization failed: {}", e))?;
    Ok(bytes)
}

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
impl<C> SignatureBytes for Signature<C>
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

/// A signed envelope carrying a value and its cryptographic signature.
///
/// The signing bytes are computed on-demand via canonical serialization,
/// eliminating the need to store redundant transcript data.
#[derive(Clone, Debug)]
pub struct WithSignature<Sig, T>
where
    Sig: SignatureBytes,
    T: CanonicalSerialize + DomainSeparated,
{
    pub value: T,
    pub signature: Sig,
}

impl<Sig, T> Serialize for WithSignature<Sig, T>
where
    Sig: SignatureBytes,
    T: CanonicalSerialize + DomainSeparated + Serialize,
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
    T: CanonicalSerialize + DomainSeparated + Deserialize<'de>,
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
            T: CanonicalSerialize + DomainSeparated + Deserialize<'de>,
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
                let sig_hex =
                    signature_hex.ok_or_else(|| serde::de::Error::missing_field("signature"))?;

                // Strip 0x prefix if present
                let hex_str = sig_hex.strip_prefix("0x").unwrap_or(&sig_hex);

                // Decode hex to bytes
                let sig_bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;

                // Convert bytes to signature type
                let signature = Sig::from_bytes(&sig_bytes).map_err(serde::de::Error::custom)?;

                // No need to precompute transcript - computed on-demand in verify()

                Ok(WithSignature { value, signature })
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
    T: CanonicalSerialize + DomainSeparated,
{
    /// Build a signed envelope using a provided SignatureScheme.
    ///
    /// The signing bytes are computed from the value's canonical serialization,
    /// signed, and then discarded (recomputed on-demand for verification).
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
        // Compute signing bytes transiently for signing
        let signing_bytes = signing_bytes(&value)?;

        // Sign the canonical bytes
        let signature = S::sign(params, sk, &signing_bytes, rng)
            .map_err(|e| anyhow::anyhow!("signature error: {e}"))?;

        Ok(WithSignature { value, signature })
    }

    /// Verify this signature against the provided public parameters and key.
    ///
    /// Recomputes the signing bytes on-demand from the stored value.
    pub fn verify<S>(&self, params: &S::Parameters, pk: &S::PublicKey) -> Result<bool>
    where
        S: SignatureScheme<Signature = Sig>,
    {
        // Recompute signing bytes on-demand
        let signing_bytes = signing_bytes(&self.value)?;

        S::verify(params, pk, &signing_bytes, &self.signature)
            .map_err(|e| anyhow::anyhow!("signature error: {e}"))
    }
}
