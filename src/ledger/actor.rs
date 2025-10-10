use crate::{
    engine::nl::{PlayerId, SeatId},
    ledger::ShufflerId,
};
use serde::{Deserialize, Serialize};

use crate::signing::{Signable, TranscriptBuilder};

pub trait GameActor {}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct PlayerActor {
    pub seat_id: SeatId,
    pub player_id: PlayerId,
}

impl GameActor for PlayerActor {}

impl Signable for PlayerActor {
    fn domain_kind(&self) -> &'static str {
        "ledger/player_actor_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(1);
        builder.append_u8(self.seat_id);
        builder.append_u64(self.player_id);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ShufflerActor {
    pub shuffler_id: ShufflerId,
}

impl GameActor for ShufflerActor {}

impl Signable for ShufflerActor {
    fn domain_kind(&self) -> &'static str {
        "ledger/shuffler_actor_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(2);
        builder.append_i64(self.shuffler_id);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum AnyActor {
    None,
    Player {
        seat_id: SeatId,
        player_id: PlayerId,
    },
    Shuffler {
        shuffler_id: ShufflerId,
    },
}

impl Default for AnyActor {
    fn default() -> Self {
        AnyActor::None
    }
}

impl GameActor for AnyActor {}

impl Signable for AnyActor {
    fn domain_kind(&self) -> &'static str {
        "ledger/any_actor_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        match self {
            AnyActor::None => builder.append_u8(0),
            AnyActor::Player { seat_id, player_id } => {
                builder.append_u8(1);
                builder.append_u8(*seat_id);
                builder.append_u64(*player_id);
            }
            AnyActor::Shuffler { shuffler_id } => {
                builder.append_u8(2);
                builder.append_i64(*shuffler_id);
            }
        }
    }
}
