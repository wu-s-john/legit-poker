use anyhow::{anyhow, Result};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::ledger::types::StateHash;

/// Encodes a [`StateHash`] into a lowercase hex string without a leading prefix.
pub fn encode_state_hash(hash: StateHash) -> String {
    hex::encode(hash.into_bytes())
}

/// Canonically serializes any arkworks type into a compressed byte vector.
pub fn canonical_serialize_bytes<T>(value: &T) -> Result<Vec<u8>>
where
    T: CanonicalSerialize,
{
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .map_err(|err| anyhow!("canonical serialize failed: {err}"))?;
    Ok(buf)
}

/// Canonically serializes any arkworks type into a lowercase hex string without a prefix.
pub fn canonical_serialize_hex<T>(value: &T) -> Result<String>
where
    T: CanonicalSerialize,
{
    let buf = canonical_serialize_bytes(value)?;
    Ok(hex::encode(buf))
}

/// Canonically serializes any arkworks type into a lowercase hex string with a `0x` prefix.
pub fn canonical_serialize_hex_prefixed<T>(value: &T) -> Result<String>
where
    T: CanonicalSerialize,
{
    canonical_serialize_hex(value).map(|hex| format!("0x{hex}"))
}

/// Canonically serializes a curve point and returns it as lowercase hex.
pub fn serialize_curve_hex<C>(value: &C) -> Result<String>
where
    C: CurveGroup + CanonicalSerialize,
{
    canonical_serialize_hex(value).map_err(|err| anyhow!("failed to serialize curve point: {err}"))
}

/// Canonically serializes a curve point and returns the compressed bytes.
pub fn serialize_curve_bytes<C>(value: &C) -> Result<Vec<u8>>
where
    C: CurveGroup + CanonicalSerialize,
{
    canonical_serialize_bytes(value)
        .map_err(|err| anyhow!("failed to serialize curve point: {err}"))
}

/// Canonically deserializes a value from a hex string (accepts optional 0x prefix).
pub fn canonical_deserialize_hex<T>(value: &str) -> Result<T>
where
    T: CanonicalDeserialize,
{
    let bytes = decode_hex_bytes(value)?;
    canonical_deserialize_bytes(&bytes)
}

/// Canonically deserializes a value from compressed bytes.
pub fn canonical_deserialize_bytes<T>(bytes: &[u8]) -> Result<T>
where
    T: CanonicalDeserialize,
{
    T::deserialize_compressed(&mut &bytes[..])
        .map_err(|err| anyhow!("canonical deserialize failed: {err}"))
}

/// Canonically deserializes a curve point from a hex string, normalizing SW flags if needed.
pub fn deserialize_curve_hex<C>(value: &str) -> Result<C>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let bytes = decode_hex_bytes(value)?;
    deserialize_curve_bytes(&bytes)
}

/// Canonically deserializes a curve point from compressed bytes, normalizing SW flags if needed.
pub fn deserialize_curve_bytes<C>(bytes: &[u8]) -> Result<C>
where
    C: CurveGroup + CanonicalDeserialize,
{
    match C::deserialize_compressed(&mut &bytes[..]) {
        Ok(point) => Ok(point),
        Err(ark_serialize::SerializationError::UnexpectedFlags) => {
            if let Some(normalized) = normalize_sw_compressed(bytes) {
                C::deserialize_compressed(&mut &normalized[..]).map_err(|err| {
                    anyhow!("curve deserialization failed after normalization: {err}")
                })
            } else {
                Err(anyhow!(
                    "curve deserialization failed: unexpected compression flags"
                ))
            }
        }
        Err(err) => Err(anyhow!("curve deserialization failed: {err}")),
    }
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("hex string is empty"));
    }
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return Err(anyhow!("hex string is empty"));
    }
    let mut owned = String::new();
    let input = if without_prefix.len() % 2 == 1 {
        owned.reserve(without_prefix.len() + 1);
        owned.push('0');
        owned.push_str(without_prefix);
        owned.as_str()
    } else {
        without_prefix
    };
    hex::decode(input).map_err(|err| anyhow!("failed to decode hex: {err}"))
}

fn normalize_sw_compressed(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut normalized = bytes.to_vec();
    let last = normalized.last_mut()?;
    const SW_NEGATIVE: u8 = 1 << 7;
    const SW_INFINITY: u8 = 1 << 6;
    if (*last & (SW_NEGATIVE | SW_INFINITY)) == (SW_NEGATIVE | SW_INFINITY) {
        *last &= !SW_INFINITY;
        return Some(normalized);
    }
    None
}
