use super::types::{
    CommenceGameOutcome, CommenceGameParams, GameLobbyConfig, GameMetadata, JoinGameOutput,
    PlayerRecord, ShufflerRecord, ShufflerRegistrationConfig,
};
use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::{PlayerId, SeatId};
use crate::ledger::types::{GameId, ShufflerId};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::LedgerOperator;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use async_trait::async_trait;
use sea_orm::DbErr;

#[derive(Debug, thiserror::Error)]
pub enum GameSetupError {
    #[error("database error: {0}")]
    Database(#[from] DbErr),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("{0} not found")]
    NotFound(&'static str),
}

impl GameSetupError {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }
}

#[async_trait]
pub trait LedgerLobby<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    async fn host_game(
        &self,
        host: PlayerRecord<MaybeSaved<PlayerId>>,
        lobby: GameLobbyConfig,
    ) -> Result<GameMetadata, GameSetupError>;

    async fn join_game(
        &self,
        game: &super::types::GameRecord<Saved<GameId>>,
        player: PlayerRecord<MaybeSaved<PlayerId>>,
        seat_preference: Option<SeatId>,
    ) -> Result<JoinGameOutput, GameSetupError>;

    async fn register_shuffler(
        &self,
        game: &super::types::GameRecord<Saved<GameId>>,
        shuffler: ShufflerRecord<MaybeSaved<ShufflerId>>,
        cfg: ShufflerRegistrationConfig,
    ) -> Result<super::types::RegisterShufflerOutput, GameSetupError>;

    async fn commence_game(
        &self,
        operator: &LedgerOperator<C>,
        params: CommenceGameParams<C>,
    ) -> Result<CommenceGameOutcome, GameSetupError>;
}
