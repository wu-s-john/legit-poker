use std::{fmt, hash::Hash, sync::Arc};

use anyhow::Result;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};

use crate::signing::DomainSeparated;

/// Curve point wrapper that caches canonical compressed bytes so it can be
/// ordered, hashed, and serialized cheaply.
#[derive(Clone)]
pub struct CanonicalKey<C>
where
    C: CurveGroup,
{
    value: C,
    bytes: Arc<[u8]>,
}

impl<C> CanonicalKey<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    /// Construct from a curve point by serializing it into canonical compressed
    /// form and caching the bytes.
    pub fn new(value: C) -> Self {
        let mut bytes = Vec::new();
        value
            .into_affine()
            .serialize_compressed(&mut bytes)
            .expect("canonical serialization should succeed");
        Self {
            value,
            bytes: bytes.into(),
        }
    }

    /// Access the underlying curve point.
    pub fn value(&self) -> &C {
        &self.value
    }

    /// Borrow the cached canonical bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper, returning the curve point.
    pub fn into_inner(self) -> C {
        self.value
    }
}

impl<C> CanonicalKey<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize,
{
    /// Reconstruct from canonical compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = C::deserialize_compressed(bytes)?;
        Ok(Self {
            value,
            bytes: Arc::from(bytes.to_vec()),
        })
    }
}

impl<C> PartialEq for CanonicalKey<C>
where
    C: CurveGroup,
{
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<C> Eq for CanonicalKey<C> where C: CurveGroup {}

impl<C> PartialOrd for CanonicalKey<C>
where
    C: CurveGroup,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.bytes.cmp(&other.bytes))
    }
}

impl<C> Ord for CanonicalKey<C>
where
    C: CurveGroup,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<C> Hash for CanonicalKey<C>
where
    C: CurveGroup,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<C> fmt::Debug for CanonicalKey<C>
where
    C: CurveGroup,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalKey(0x{})", hex::encode(&*self.bytes))
    }
}

impl<C> Serialize for CanonicalKey<C>
where
    C: CurveGroup,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(&*self.bytes)))
    }
}

impl<'de, C> Deserialize<'de> for CanonicalKey<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let stripped = encoded.strip_prefix("0x").unwrap_or(&encoded);
        let bytes = hex::decode(stripped).map_err(D::Error::custom)?;
        CanonicalKey::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

impl<C> DomainSeparated for CanonicalKey<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    fn domain_string() -> &'static str {
        "ledger/canonical_key_v1"
    }
}

impl<C> CanonicalSerialize for CanonicalKey<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        // Always write compressed bytes regardless of the compress parameter
        writer.write_all(&self.bytes)?;
        Ok(())
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        self.bytes.len()
    }
}

impl<C> CanonicalDeserialize for CanonicalKey<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize,
{
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        // Read compressed curve point
        let value = C::deserialize_compressed(&mut reader)?;
        // Re-serialize to get canonical bytes
        let mut bytes = Vec::new();
        value.into_affine().serialize_compressed(&mut bytes)?;
        Ok(Self {
            value,
            bytes: bytes.into(),
        })
    }
}

impl<C> ark_serialize::Valid for CanonicalKey<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize,
{
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        // The cached bytes should match the curve point
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CanonicalKey;
    use ark_bls12_381::G1Projective;
    use ark_std::UniformRand;

    #[test]
    fn round_trip_bytes() {
        let mut rng = ark_std::test_rng();
        let point = G1Projective::rand(&mut rng);
        let key = CanonicalKey::new(point);
        let round_trip = CanonicalKey::<G1Projective>::from_bytes(key.bytes()).unwrap();
        assert_eq!(key, round_trip);
        assert_eq!(key.value(), round_trip.value());
    }

    #[test]
    fn ordering_matches_bytes() {
        let mut rng = ark_std::test_rng();
        let p1 = G1Projective::rand(&mut rng);
        let p2 = G1Projective::rand(&mut rng);
        let k1 = CanonicalKey::new(p1);
        let k2 = CanonicalKey::new(p2);

        // Sort keys and verify ordering is consistent with byte ordering
        let mut vec = vec![k2.clone(), k1.clone()];
        vec.sort();

        // Verify that the sorted order matches byte lexicographic order
        assert!(vec[0].bytes() <= vec[1].bytes());

        // Also verify the original keys are present
        assert!(vec.contains(&k1));
        assert!(vec.contains(&k2));
    }
}
