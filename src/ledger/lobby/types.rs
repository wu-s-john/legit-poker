use crate::engine::nl::types::{Chips, PlayerId, SeatId, TableStakes};
use crate::ledger::snapshot::TableAtShuffling;
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::typestate::{DbRowStatus, MaybeSaved, NotSaved, Saved};
use ark_ec::CurveGroup;

#[derive(Clone, Debug)]
pub struct PlayerRecord<C, State>
where
    C: CurveGroup,
    State: DbRowStatus,
{
    pub display_name: String,
    pub public_key: C,
    pub seat_preference: Option<SeatId>,
    pub state: State,
}

impl<C: CurveGroup> PlayerRecord<C, NotSaved> {
    pub fn new(
        display_name: impl Into<String>,
        public_key: C,
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

impl<C: CurveGroup> PlayerRecord<C, MaybeSaved<PlayerId>> {
    pub fn existing(id: PlayerId) -> Self {
        Self {
            display_name: String::new(),
            public_key: C::zero(),
            seat_preference: None,
            state: MaybeSaved { id: Some(id) },
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShufflerRecord<C, State>
where
    C: CurveGroup,
    State: DbRowStatus,
{
    pub display_name: String,
    pub public_key: C,
    pub state: State,
}

impl<C: CurveGroup> ShufflerRecord<C, NotSaved> {
    pub fn new(display_name: impl Into<String>, public_key: C) -> Self {
        Self {
            display_name: display_name.into(),
            public_key,
            state: NotSaved,
        }
    }
}

impl<C: CurveGroup> ShufflerRecord<C, MaybeSaved<ShufflerId>> {
    pub fn existing(id: ShufflerId) -> Self {
        Self {
            display_name: String::new(),
            public_key: C::zero(),
            state: MaybeSaved { id: Some(id) },
        }
    }
}

#[derive(Clone, Debug)]
pub struct GameRecord<State>
where
    State: DbRowStatus,
{
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
pub struct PlayerSeatSnapshot<C>
where
    C: CurveGroup,
{
    pub player: PlayerRecord<C, Saved<PlayerId>>,
    pub seat_id: SeatId,
    pub starting_stack: Chips,
    pub public_key: C,
}

impl<C> PlayerSeatSnapshot<C>
where
    C: CurveGroup,
{
    pub fn new(
        player: PlayerRecord<C, Saved<PlayerId>>,
        seat_id: SeatId,
        starting_stack: Chips,
        public_key: C,
    ) -> Self {
        Self {
            player,
            seat_id,
            starting_stack,
            public_key,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShufflerAssignment<C: CurveGroup> {
    pub shuffler: ShufflerRecord<C, Saved<ShufflerId>>,
    pub sequence: u16,
    pub public_key: C,
    pub aggregated_public_key: C,
}

impl<C: CurveGroup> ShufflerAssignment<C> {
    pub fn new(
        shuffler: ShufflerRecord<C, Saved<ShufflerId>>,
        sequence: u16,
        public_key: C,
        aggregated_public_key: C,
    ) -> Self {
        Self {
            shuffler,
            sequence,
            public_key,
            aggregated_public_key,
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
pub struct GameMetadata<C: CurveGroup> {
    pub record: GameRecord<Saved<GameId>>,
    pub host: PlayerRecord<C, Saved<PlayerId>>,
}

#[derive(Clone, Debug)]
pub struct JoinGameOutput<C: CurveGroup> {
    pub player: PlayerRecord<C, Saved<PlayerId>>,
    pub game_player_row_id: (GameId, PlayerId),
}

#[derive(Clone, Debug)]
pub struct ShufflerRegistrationConfig {
    pub sequence: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct RegisterShufflerOutput<C: CurveGroup> {
    pub shuffler: ShufflerRecord<C, Saved<ShufflerId>>,
    pub game_shuffler_row_id: (GameId, ShufflerId),
    pub assigned_sequence: u16,
}

#[derive(Clone)]
pub struct CommenceGameParams {
    pub game_id: GameId,
    pub hand_no: i64,
    pub button_seat: SeatId,
    pub small_blind_seat: SeatId,
    pub big_blind_seat: SeatId,
    pub deck_commitment: Option<DeckCommitmentBytes>,
}

#[derive(Debug)]
pub struct CommenceGameOutcome<C: CurveGroup> {
    pub hand: HandRecord<Saved<HandId>>,
    pub nonce_seed: u64,
    pub initial_snapshot: TableAtShuffling<C>,
}
