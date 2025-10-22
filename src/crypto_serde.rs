use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::de::Error as DeError;
use serde::ser::Error as SerError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ledger::serialization::{
    canonical_deserialize_hex, canonical_serialize_hex, deserialize_curve_hex, serialize_curve_hex,
};

/// Serde helpers for encoding curve points as 0x-prefixed hex strings.
pub mod curve {
    use super::*;

    pub fn serialize<C, S>(value: &C, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        C: CurveGroup + CanonicalSerialize,
        S: Serializer,
    {
        let hex = serialize_curve_hex(value).map_err(SerError::custom)?;
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, C, D>(deserializer: D) -> std::result::Result<C, D::Error>
    where
        C: CurveGroup + CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        deserialize_curve_hex(&s).map_err(DeError::custom)
    }
}

/// Serde helpers for BTreeMap<_, Curve> values encoded as hex strings.
pub mod curve_map {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Serialize, Deserialize)]
    struct Entry<K> {
        key: K,
        value: String,
    }

    pub fn serialize<K, C, S>(
        value: &BTreeMap<K, C>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        K: Serialize + Clone + Ord,
        C: CurveGroup + CanonicalSerialize,
        S: Serializer,
    {
        let entries: Vec<Entry<K>> = value
            .iter()
            .map(|(key, point)| {
                let hex = serialize_curve_hex(point).map_err(SerError::custom)?;
                Ok(Entry {
                    key: key.clone(),
                    value: hex,
                })
            })
            .collect::<std::result::Result<_, _>>()?;
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, K, C, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<K, C>, D::Error>
    where
        K: Deserialize<'de> + Ord,
        C: CurveGroup + CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let entries = Vec::<Entry<K>>::deserialize(deserializer)?;
        entries
            .into_iter()
            .map(|entry| {
                let point = deserialize_curve_hex(&entry.value).map_err(DeError::custom)?;
                Ok((entry.key, point))
            })
            .collect()
    }
}

/// Serde helpers for maps serialized as sorted arrays of `[key, value]` pairs.
pub mod array_map {
    use super::*;
    use std::collections::BTreeMap;

    pub fn serialize<K, V, S>(
        value: &BTreeMap<K, V>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        K: Serialize + Clone + Ord,
        V: Serialize,
        S: Serializer,
    {
        let entries: Vec<(K, &V)> = value.iter().map(|(key, v)| (key.clone(), v)).collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, K, V, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<K, V>, D::Error>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let entries = Vec::<(K, V)>::deserialize(deserializer)?;
        Ok(entries.into_iter().collect())
    }
}

/// Serde helpers for maps keyed by 2-tuples.
pub mod tuple_map2 {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Serialize, Deserialize)]
    struct Entry<K1, K2, V> {
        k1: K1,
        k2: K2,
        value: V,
    }

    pub fn serialize<K1, K2, V, S>(
        value: &BTreeMap<(K1, K2), V>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        K1: Serialize + Clone + Ord,
        K2: Serialize + Clone + Ord,
        V: Serialize,
        S: Serializer,
    {
        let entries: Vec<Entry<K1, K2, &V>> = value
            .iter()
            .map(|((k1, k2), v)| Entry {
                k1: k1.clone(),
                k2: k2.clone(),
                value: v,
            })
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, K1, K2, V, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<(K1, K2), V>, D::Error>
    where
        K1: Deserialize<'de> + Ord,
        K2: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let entries = Vec::<Entry<K1, K2, V>>::deserialize(deserializer)?;
        entries
            .into_iter()
            .map(|entry| Ok(((entry.k1, entry.k2), entry.value)))
            .collect()
    }
}

/// Serde helpers for maps keyed by 3-tuples.
pub mod tuple_map3 {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Serialize, Deserialize)]
    struct Entry<K1, K2, K3, V> {
        k1: K1,
        k2: K2,
        k3: K3,
        value: V,
    }

    pub fn serialize<K1, K2, K3, V, S>(
        value: &BTreeMap<(K1, K2, K3), V>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        K1: Serialize + Clone + Ord,
        K2: Serialize + Clone + Ord,
        K3: Serialize + Clone + Ord,
        V: Serialize,
        S: Serializer,
    {
        let entries: Vec<Entry<K1, K2, K3, &V>> = value
            .iter()
            .map(|((k1, k2, k3), v)| Entry {
                k1: k1.clone(),
                k2: k2.clone(),
                k3: k3.clone(),
                value: v,
            })
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, K1, K2, K3, V, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<(K1, K2, K3), V>, D::Error>
    where
        K1: Deserialize<'de> + Ord,
        K2: Deserialize<'de> + Ord,
        K3: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let entries = Vec::<Entry<K1, K2, K3, V>>::deserialize(deserializer)?;
        entries
            .into_iter()
            .map(|entry| Ok(((entry.k1, entry.k2, entry.k3), entry.value)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct TupleMap2Wrapper {
        #[serde(
            serialize_with = "tuple_map2::serialize",
            deserialize_with = "tuple_map2::deserialize"
        )]
        map: std::collections::BTreeMap<(u8, u8), u64>,
    }

    #[test]
    fn tuple_map2_round_trip() {
        let mut map = std::collections::BTreeMap::new();
        map.insert((1, 2), 3);
        let wrapper = TupleMap2Wrapper { map };
        let json = serde_json::to_string(&wrapper).expect("serialize");
        let restored: TupleMap2Wrapper = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.map.get(&(1, 2)), Some(&3));
    }
}

/// Serde helpers for scalar/base-field elements as 0x-prefixed hex strings.
pub mod field {
    use super::*;

    pub fn serialize<F, S>(value: &F, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        F: CanonicalSerialize,
        S: Serializer,
    {
        let hex = canonical_serialize_hex(value).map_err(SerError::custom)?;
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, F, D>(deserializer: D) -> std::result::Result<F, D::Error>
    where
        F: CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        canonical_deserialize_hex(&s).map_err(DeError::custom)
    }
}

/// Serde helpers for ElGamal ciphertexts.
pub mod elgamal {
    use super::*;
    use crate::shuffling::data_structures::ElGamalCiphertext;

    #[derive(Serialize, Deserialize)]
    struct Helper<C: CurveGroup> {
        #[serde(with = "super::curve")]
        c1: C,
        #[serde(with = "super::curve")]
        c2: C,
    }

    pub fn serialize<C, S>(
        value: &ElGamalCiphertext<C>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        C: CurveGroup + CanonicalSerialize,
        S: Serializer,
    {
        Helper {
            c1: value.c1.clone(),
            c2: value.c2.clone(),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, C, D>(
        deserializer: D,
    ) -> std::result::Result<ElGamalCiphertext<C>, D::Error>
    where
        C: CurveGroup + CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let helper = Helper::<C>::deserialize(deserializer)?;
        Ok(ElGamalCiphertext::new(helper.c1, helper.c2))
    }
}

/// Serde helpers for Chaum-Pedersen proofs.
pub mod chaum_pedersen {
    use super::*;
    use crate::chaum_pedersen::ChaumPedersenProof;

    pub fn serialize<C, S>(
        value: &ChaumPedersenProof<C>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        C: CurveGroup + CanonicalSerialize,
        C::ScalarField: CanonicalSerialize,
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Helper<C: CurveGroup> {
            #[serde(with = "super::curve")]
            t_g: C,
            #[serde(with = "super::curve")]
            t_h: C,
            #[serde(with = "super::field")]
            z: C::ScalarField,
        }

        Helper {
            t_g: value.t_g.clone(),
            t_h: value.t_h.clone(),
            z: value.z.clone(),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, C, D>(
        deserializer: D,
    ) -> std::result::Result<ChaumPedersenProof<C>, D::Error>
    where
        C: CurveGroup + CanonicalDeserialize,
        C::ScalarField: CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<C: CurveGroup> {
            #[serde(with = "super::curve")]
            t_g: C,
            #[serde(with = "super::curve")]
            t_h: C,
            #[serde(with = "super::field")]
            z: C::ScalarField,
        }

        let helper = Helper::<C>::deserialize(deserializer)?;
        Ok(ChaumPedersenProof {
            t_g: helper.t_g,
            t_h: helper.t_h,
            z: helper.z,
        })
    }
}

/// Serde helpers for vectors of scalar/base field elements encoded as hex strings.
pub mod field_vec {
    use super::*;

    pub fn serialize<F, S>(value: &[F], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        F: CanonicalSerialize,
        S: Serializer,
    {
        let hexes: Vec<String> = value
            .iter()
            .map(|item| canonical_serialize_hex(item).map_err(SerError::custom))
            .collect::<std::result::Result<_, _>>()?;
        hexes.serialize(serializer)
    }

    pub fn deserialize<'de, F, D>(deserializer: D) -> std::result::Result<Vec<F>, D::Error>
    where
        F: CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let hexes = Vec::<String>::deserialize(deserializer)?;
        hexes
            .into_iter()
            .map(|value| canonical_deserialize_hex(&value).map_err(DeError::custom))
            .collect()
    }
}

/// Serde helpers for the sorted deck entries within a shuffle proof.
pub mod shuffle_sorted_deck {
    use super::*;
    use crate::shuffling::data_structures::ElGamalCiphertext;

    #[derive(Serialize, Deserialize)]
    struct Entry<C: CurveGroup> {
        #[serde(with = "super::elgamal")]
        ciphertext: ElGamalCiphertext<C>,
        #[serde(with = "super::field")]
        randomizer: C::BaseField,
    }

    pub fn serialize<C, S>(
        value: &[(ElGamalCiphertext<C>, C::BaseField)],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        C: CurveGroup + CanonicalSerialize,
        C::BaseField: CanonicalSerialize,
        S: Serializer,
    {
        let entries: Vec<Entry<C>> = value
            .iter()
            .map(|(cipher, randomizer)| Entry {
                ciphertext: cipher.clone(),
                randomizer: randomizer.clone(),
            })
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, C, D>(
        deserializer: D,
    ) -> std::result::Result<Vec<(ElGamalCiphertext<C>, C::BaseField)>, D::Error>
    where
        C: CurveGroup + CanonicalDeserialize,
        C::BaseField: CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let entries = Vec::<Entry<C>>::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .map(|entry| (entry.ciphertext, entry.randomizer))
            .collect())
    }
}

/// Serde helpers for fixed-size arrays of ElGamal ciphertexts.
pub mod elgamal_array {
    use super::*;
    use crate::shuffling::data_structures::ElGamalCiphertext;
    use std::convert::TryInto;

    pub fn serialize<C, S>(
        value: &[ElGamalCiphertext<C>; crate::shuffling::data_structures::DECK_SIZE],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        C: CurveGroup + CanonicalSerialize,
        S: Serializer,
    {
        let vec: Vec<&ElGamalCiphertext<C>> = value.iter().collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, C, D>(
        deserializer: D,
    ) -> std::result::Result<
        [ElGamalCiphertext<C>; crate::shuffling::data_structures::DECK_SIZE],
        D::Error,
    >
    where
        C: CurveGroup + CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let vec = Vec::<ElGamalCiphertext<C>>::deserialize(deserializer)?;
        vec.into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| DeError::custom("expected deck-sized array of ciphertexts"))
    }
}

/// Serde helpers for shared `Arc<T>` wrappers.
pub mod arc {
    use super::*;
    use std::sync::Arc;

    pub fn serialize<T, S>(value: &Arc<T>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        (**value).serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> std::result::Result<Arc<T>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Arc::new)
    }
}
