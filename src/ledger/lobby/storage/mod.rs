use async_trait::async_trait;

use crate::engine::nl::types::{HandConfig, PlayerId, SeatId};
use crate::ledger::store::snapshot::PreparedSnapshot;
use crate::ledger::types::{GameId, HandId, ShufflerId};

use crate::ledger::lobby::error::GameSetupError;
use crate::ledger::lobby::types::GameLobbyConfig;

#[async_trait]
pub trait LobbyStorage: Send + Sync {
    async fn begin(&self) -> Result<Box<dyn LobbyStorageTxn>, GameSetupError>;
}

#[async_trait]
pub trait LobbyStorageTxn: Send {
    async fn load_player(&mut self, id: PlayerId) -> Result<Option<StoredPlayer>, GameSetupError>;

    async fn insert_player(&mut self, player: NewPlayer) -> Result<PlayerId, GameSetupError>;

    async fn load_shuffler(
        &mut self,
        id: ShufflerId,
    ) -> Result<Option<StoredShuffler>, GameSetupError>;

    async fn insert_shuffler(
        &mut self,
        shuffler: NewShuffler,
    ) -> Result<ShufflerId, GameSetupError>;

    async fn insert_game(&mut self, game: NewGame) -> Result<GameId, GameSetupError>;

    async fn insert_game_player(&mut self, row: NewGamePlayer) -> Result<(), GameSetupError>;

    async fn count_game_shufflers(&mut self, game_id: GameId) -> Result<u16, GameSetupError>;

    async fn insert_game_shuffler(&mut self, row: NewGameShuffler) -> Result<(), GameSetupError>;

    async fn insert_hand_config(
        &mut self,
        game_id: GameId,
        cfg: &HandConfig,
    ) -> Result<i64, GameSetupError>;

    async fn insert_hand(&mut self, hand: NewHand) -> Result<HandId, GameSetupError>;

    async fn insert_hand_player(&mut self, row: NewHandPlayer) -> Result<(), GameSetupError>;

    async fn insert_hand_shuffler(&mut self, row: NewHandShuffler) -> Result<(), GameSetupError>;

    async fn persist_snapshot(&mut self, prepared: PreparedSnapshot) -> Result<(), GameSetupError>;

    async fn commit(self: Box<Self>) -> Result<(), GameSetupError>;
    async fn rollback(self: Box<Self>);
}

#[derive(Clone, Debug)]
pub struct StoredPlayer {
    pub display_name: String,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NewPlayer {
    pub display_name: String,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct StoredShuffler {
    pub display_name: String,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NewShuffler {
    pub display_name: String,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NewGame {
    pub host_player_id: PlayerId,
    pub config: GameLobbyConfig,
}

#[derive(Clone, Debug)]
pub struct NewGamePlayer {
    pub game_id: GameId,
    pub player_id: PlayerId,
    pub seat_preference: Option<SeatId>,
}

#[derive(Clone, Debug)]
pub struct NewGameShuffler {
    pub game_id: GameId,
    pub shuffler_id: ShufflerId,
    pub sequence: u16,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NewHand {
    pub game_id: GameId,
    pub hand_no: i64,
    pub config_id: i64,
    pub config: HandConfig,
    pub deck_commitment: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct NewHandPlayer {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub player_id: PlayerId,
    pub seat: SeatId,
}

#[derive(Clone, Debug)]
pub struct NewHandShuffler {
    pub hand_id: HandId,
    pub shuffler_id: ShufflerId,
    pub sequence: u16,
}

pub mod in_memory;
pub mod sea_orm;

pub use in_memory::InMemoryLobbyStorage;
pub use sea_orm::SeaOrmLobbyStorage;
