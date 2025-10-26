use ark_ec::CurveGroup;
use async_trait::async_trait;

use crate::engine::nl::types::{HandConfig, PlayerId, SeatId};
use crate::ledger::store::snapshot::PreparedSnapshot;
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::CanonicalKey;

use crate::ledger::lobby::error::GameSetupError;
use crate::ledger::lobby::types::GameLobbyConfig;

#[async_trait]
pub trait LobbyStorage<C>: Send + Sync
where
    C: CurveGroup + Send + Sync + 'static,
{
    async fn begin(&self) -> Result<Box<dyn LobbyStorageTxn<C> + Send>, GameSetupError>;
}

#[async_trait]
pub trait LobbyStorageTxn<C>: Send
where
    C: CurveGroup + Send + Sync + 'static,
{
    async fn load_player(
        &mut self,
        key: &CanonicalKey<C>,
    ) -> Result<Option<StoredPlayer<C>>, GameSetupError>;

    async fn load_player_by_id(
        &mut self,
        id: PlayerId,
    ) -> Result<Option<StoredPlayer<C>>, GameSetupError>;

    async fn insert_player(
        &mut self,
        player: NewPlayer<C>,
    ) -> Result<(PlayerId, CanonicalKey<C>), GameSetupError>;

    async fn load_shuffler(
        &mut self,
        key: &CanonicalKey<C>,
    ) -> Result<Option<StoredShuffler<C>>, GameSetupError>;

    async fn load_shuffler_by_id(
        &mut self,
        id: ShufflerId,
    ) -> Result<Option<StoredShuffler<C>>, GameSetupError>;

    async fn insert_shuffler(
        &mut self,
        shuffler: NewShuffler<C>,
    ) -> Result<(ShufflerId, CanonicalKey<C>), GameSetupError>;

    async fn insert_game(&mut self, game: NewGame) -> Result<GameId, GameSetupError>;

    async fn insert_game_player(&mut self, row: NewGamePlayer) -> Result<(), GameSetupError>;

    async fn count_game_shufflers(&mut self, game_id: GameId) -> Result<u16, GameSetupError>;

    async fn insert_game_shuffler(&mut self, row: NewGameShuffler<C>)
        -> Result<(), GameSetupError>;

    async fn insert_hand_config(
        &mut self,
        game_id: GameId,
        cfg: &HandConfig,
    ) -> Result<i64, GameSetupError>;

    async fn insert_hand(&mut self, hand: NewHand) -> Result<HandId, GameSetupError>;

    async fn insert_hand_player(&mut self, row: NewHandPlayer) -> Result<(), GameSetupError>;

    async fn insert_hand_shuffler(&mut self, row: NewHandShuffler) -> Result<(), GameSetupError>;

    async fn persist_snapshot(&mut self, prepared: PreparedSnapshot) -> Result<(), GameSetupError>;

    // Query methods for game state recovery
    async fn load_game(
        &mut self,
        game_id: GameId,
    ) -> Result<crate::ledger::lobby::types::GameRecord<crate::ledger::typestate::Saved<GameId>>, GameSetupError>;

    async fn load_game_config(
        &mut self,
        game_id: GameId,
    ) -> Result<GameLobbyConfig, GameSetupError>;

    async fn load_game_players(
        &mut self,
        game_id: GameId,
    ) -> Result<Vec<(PlayerId, Option<SeatId>, C)>, GameSetupError>;

    async fn load_game_shufflers(
        &mut self,
        game_id: GameId,
    ) -> Result<Vec<(ShufflerId, u16, C)>, GameSetupError>;

    async fn commit(self: Box<Self>) -> Result<(), GameSetupError>;
    async fn rollback(self: Box<Self>);
}

#[derive(Clone, Debug)]
pub struct StoredPlayer<C: CurveGroup> {
    pub display_name: String,
    pub public_key: C,
}

#[derive(Clone, Debug)]
pub struct NewPlayer<C: CurveGroup> {
    pub display_name: String,
    pub public_key: C,
}

#[derive(Clone, Debug)]
pub struct StoredShuffler<C: CurveGroup> {
    pub display_name: String,
    pub public_key: C,
}

#[derive(Clone, Debug)]
pub struct NewShuffler<C: CurveGroup> {
    pub display_name: String,
    pub public_key: C,
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
pub struct NewGameShuffler<C: CurveGroup> {
    pub game_id: GameId,
    pub shuffler_id: ShufflerId,
    pub sequence: u16,
    pub public_key: C,
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
    pub starting_stack: crate::engine::nl::types::Chips,
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
