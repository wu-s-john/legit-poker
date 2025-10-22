use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    engine::nl::{PlayerId, SeatId},
    ledger::{CanonicalKey, ShufflerId},
    signing::{Signable, TranscriptBuilder},
};

pub trait GameActor {}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct PlayerActor<C: CurveGroup> {
    pub seat_id: SeatId,
    pub player_id: PlayerId,
    pub player_key: CanonicalKey<C>,
}

impl<C: CurveGroup> GameActor for PlayerActor<C> {}

impl<C: CurveGroup> Signable for PlayerActor<C> {
    fn domain_kind(&self) -> &'static str {
        "ledger/player_actor_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(1);
        builder.append_u8(self.seat_id);
        builder.append_u64(self.player_id);
        self.player_key.write_transcript(builder);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct ShufflerActor<C: CurveGroup> {
    pub shuffler_id: ShufflerId,
    pub shuffler_key: CanonicalKey<C>,
}

impl<C: CurveGroup> GameActor for ShufflerActor<C> {}

impl<C: CurveGroup> Signable for ShufflerActor<C> {
    fn domain_kind(&self) -> &'static str {
        "ledger/shuffler_actor_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(2);
        builder.append_i64(self.shuffler_id);
        self.shuffler_key.write_transcript(builder);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub enum AnyActor<C: CurveGroup> {
    None,
    Player {
        seat_id: SeatId,
        player_id: PlayerId,
        player_key: CanonicalKey<C>,
    },
    Shuffler {
        shuffler_id: ShufflerId,
        shuffler_key: CanonicalKey<C>,
    },
}

impl<C: CurveGroup> Default for AnyActor<C> {
    fn default() -> Self {
        AnyActor::None
    }
}

impl<C: CurveGroup> GameActor for AnyActor<C> {}

impl<C: CurveGroup> Signable for AnyActor<C> {
    fn domain_kind(&self) -> &'static str {
        "ledger/any_actor_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        match self {
            AnyActor::None => builder.append_u8(0),
            AnyActor::Player {
                seat_id,
                player_id,
                player_key,
            } => {
                builder.append_u8(1);
                builder.append_u8(*seat_id);
                builder.append_u64(*player_id);
                player_key.write_transcript(builder);
            }
            AnyActor::Shuffler {
                shuffler_id,
                shuffler_key,
            } => {
                builder.append_u8(2);
                builder.append_i64(*shuffler_id);
                shuffler_key.write_transcript(builder);
            }
        }
    }
}
