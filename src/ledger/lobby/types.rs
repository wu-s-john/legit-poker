use crate::engine::nl::types::{Chips, HandConfig, PlayerId, SeatId, TableStakes};
use crate::ledger::snapshot::TableAtShuffling;
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::typestate::{DbRowStatus, MaybeSaved, NotSaved, Saved};
use ark_ec::CurveGroup;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct PlayerRecord<State: DbRowStatus> {
    pub display_name: String,
    pub public_key: Vec<u8>,
    pub seat_preference: Option<SeatId>,
    pub state: State,
}

impl PlayerRecord<NotSaved> {
    pub fn new(
        display_name: impl Into<String>,
        public_key: Vec<u8>,
        seat_preference: Option<SeatId>,
    ) -> Self {
        Self {
            display_name: display_name.into(),
            public_key,
            seat_preference,
            state: NotSaved,
        }
    }
}

impl PlayerRecord<MaybeSaved<PlayerId>> {
    pub fn existing(id: PlayerId) -> Self {
        Self {
            display_name: String::new(),
            public_key: Vec::new(),
            seat_preference: None,
            state: MaybeSaved { id: Some(id) },
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShufflerRecord<State: DbRowStatus> {
    pub display_name: String,
    pub public_key: Vec<u8>,
    pub state: State,
}

impl ShufflerRecord<NotSaved> {
    pub fn new(display_name: impl Into<String>, public_key: Vec<u8>) -> Self {
        Self {
            display_name: display_name.into(),
            public_key,
            state: NotSaved,
        }
    }
}

impl ShufflerRecord<MaybeSaved<ShufflerId>> {
    pub fn existing(id: ShufflerId) -> Self {
        Self {
            display_name: String::new(),
            public_key: Vec::new(),
            state: MaybeSaved { id: Some(id) },
        }
    }
}

#[derive(Clone, Debug)]
pub struct GameRecord<State: DbRowStatus> {
    pub name: String,
    pub currency: String,
    pub stakes: TableStakes,
    pub max_players: i16,
    pub rake_bps: i16,
    pub host: PlayerId,
    pub state: State,
}

impl GameRecord<NotSaved> {
    pub fn new(
        name: impl Into<String>,
        currency: impl Into<String>,
        stakes: TableStakes,
        max_players: i16,
        rake_bps: i16,
        host: PlayerId,
    ) -> Self {
        Self {
            name: name.into(),
            currency: currency.into(),
            stakes,
            max_players,
            rake_bps,
            host,
            state: NotSaved,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HandRecord<State: DbRowStatus> {
    pub game_id: GameId,
    pub hand_no: i64,
    pub status: crate::db::entity::sea_orm_active_enums::HandStatus,
    pub state: State,
}

impl HandRecord<NotSaved> {
    pub fn new(
        game_id: GameId,
        hand_no: i64,
        status: crate::db::entity::sea_orm_active_enums::HandStatus,
    ) -> Self {
        Self {
            game_id,
            hand_no,
            status,
            state: NotSaved,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlayerSeatSnapshot<C> {
    pub player: PlayerRecord<Saved<PlayerId>>,
    pub seat_id: SeatId,
    pub starting_stack: Chips,
    pub public_key: Vec<u8>,
    pub _marker: PhantomData<C>,
}

impl<C> PlayerSeatSnapshot<C> {
    pub fn new(
        player: PlayerRecord<Saved<PlayerId>>,
        seat_id: SeatId,
        starting_stack: Chips,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            player,
            seat_id,
            starting_stack,
            public_key,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShufflerAssignment<C> {
    pub shuffler: ShufflerRecord<Saved<ShufflerId>>,
    pub sequence: u16,
    pub public_key: Vec<u8>,
    pub aggregated_public_key: Vec<u8>,
    pub _marker: PhantomData<C>,
}

impl<C> ShufflerAssignment<C> {
    pub fn new(
        shuffler: ShufflerRecord<Saved<ShufflerId>>,
        sequence: u16,
        public_key: Vec<u8>,
        aggregated_public_key: Vec<u8>,
    ) -> Self {
        Self {
            shuffler,
            sequence,
            public_key,
            aggregated_public_key,
            _marker: PhantomData,
        }
    }
}

pub type DeckCommitmentBytes = Vec<u8>;

#[derive(Clone, Debug)]
pub struct GameLobbyConfig {
    pub stakes: TableStakes,
    pub max_players: i16,
    pub rake_bps: i16,
    pub name: String,
    pub currency: String,
    pub buy_in: Chips,
    pub min_players_to_start: i16,
    pub check_raise_allowed: bool,
    pub action_time_limit: std::time::Duration,
}

#[derive(Clone)]
pub struct GameMetadata {
    pub record: GameRecord<Saved<GameId>>,
    pub host: PlayerRecord<Saved<PlayerId>>,
}

#[derive(Clone, Debug)]
pub struct JoinGameOutput {
    pub player: PlayerRecord<Saved<PlayerId>>,
    pub game_player_row_id: (GameId, PlayerId),
}

#[derive(Clone, Debug)]
pub struct ShufflerRegistrationConfig {
    pub sequence: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct RegisterShufflerOutput {
    pub shuffler: ShufflerRecord<Saved<ShufflerId>>,
    pub game_shuffler_row_id: (GameId, ShufflerId),
    pub assigned_sequence: u16,
}

#[derive(Clone)]
pub struct CommenceGameParams<C> {
    pub game: GameRecord<Saved<GameId>>,
    pub hand_no: i64,
    pub hand_config: HandConfig,
    pub players: Vec<PlayerSeatSnapshot<C>>,
    pub shufflers: Vec<ShufflerAssignment<C>>,
    pub deck_commitment: Option<DeckCommitmentBytes>,
    pub buy_in: Chips,
    pub min_players: i16,
}

#[derive(Debug)]
pub struct CommenceGameOutcome<C: CurveGroup> {
    pub hand: HandRecord<Saved<HandId>>,
    pub nonce_seed: u64,
    pub initial_snapshot: TableAtShuffling<C>,
}
