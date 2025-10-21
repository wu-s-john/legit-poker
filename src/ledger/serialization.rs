use anyhow::{anyhow, Result};
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;

use crate::ledger::types::StateHash;

/// Encodes a [`StateHash`] into a lowercase hex string without a leading prefix.
pub fn encode_state_hash(hash: StateHash) -> String {
    hex::encode(hash.into_bytes())
}

/// Canonically serializes any arkworks type into a lowercase hex string without a prefix.
pub fn canonical_serialize_hex<T>(value: &T) -> Result<String>
where
    T: CanonicalSerialize,
{
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .map_err(|err| anyhow!("canonical serialize failed: {err}"))?;
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
