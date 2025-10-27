use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::engine::nl::types::SeatId;
use crate::shuffling::ElGamalCiphertext;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct PlayerHoleCard<C: CurveGroup> {
    pub seat: SeatId,
    pub hole_index: u8,
    pub cipher: ElGamalCiphertext<C>,
}
