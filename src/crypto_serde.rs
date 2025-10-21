use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as DeError;
use serde::ser::Error as SerError;

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

    pub fn serialize<C, S>(value: &ElGamalCiphertext<C>, serializer: S) -> std::result::Result<S::Ok, S::Error>
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

    pub fn deserialize<'de, C, D>(deserializer: D) -> std::result::Result<ElGamalCiphertext<C>, D::Error>
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

    pub fn serialize<C, S>(value: &ChaumPedersenProof<C>, serializer: S) -> std::result::Result<S::Ok, S::Error>
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

    pub fn deserialize<'de, C, D>(deserializer: D) -> std::result::Result<ChaumPedersenProof<C>, D::Error>
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

    pub fn serialize<C, S>(value: &[(ElGamalCiphertext<C>, C::BaseField)], serializer: S) -> std::result::Result<S::Ok, S::Error>
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

    pub fn deserialize<'de, C, D>(deserializer: D) -> std::result::Result<Vec<(ElGamalCiphertext<C>, C::BaseField)>, D::Error>
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

    pub fn serialize<C, S>(value: &[ElGamalCiphertext<C>; crate::shuffling::data_structures::DECK_SIZE], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        C: CurveGroup + CanonicalSerialize,
        S: Serializer,
    {
        let vec: Vec<&ElGamalCiphertext<C>> = value.iter().collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, C, D>(deserializer: D) -> std::result::Result<[ElGamalCiphertext<C>; crate::shuffling::data_structures::DECK_SIZE], D::Error>
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
