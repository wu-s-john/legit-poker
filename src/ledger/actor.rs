use crate::{
    engine::nl::{PlayerId, SeatId},
    ledger::ShufflerId,
};

use serde::{Deserialize, Serialize};

pub trait GameActor {}

pub trait ActorEncode {
    fn encode(&self, out: &mut Vec<u8>);
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct PlayerActor {
    pub seat_id: SeatId,
    pub player_id: PlayerId,
}

impl GameActor for PlayerActor {}

impl ActorEncode for PlayerActor {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(1);
        out.push(self.seat_id);
        out.extend_from_slice(&self.player_id.to_be_bytes());
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ShufflerActor {
    pub shuffler_id: ShufflerId,
}

impl GameActor for ShufflerActor {}

impl ActorEncode for ShufflerActor {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(2);
        out.extend_from_slice(&self.shuffler_id.to_be_bytes());
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy)]
pub struct AnyActor;

impl GameActor for AnyActor {}

impl ActorEncode for AnyActor {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(0);
    }
}
