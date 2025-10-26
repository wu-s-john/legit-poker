use async_trait::async_trait;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, DbErr, EntityTrait,
    PaginatorTrait, QueryFilter, Set, TransactionTrait,
};

use crate::db::entity::sea_orm_active_enums::{
    GameStatus as DbGameStatus, HandStatus as DbHandStatus,
};
use crate::db::entity::{
    game_players, game_shufflers, games, hand_configs, hand_player, hand_shufflers, hands, players,
    shufflers,
};
use crate::engine::nl::types::Chips;
use crate::ledger::serialization::{deserialize_curve_bytes, serialize_curve_bytes};
use crate::ledger::store::snapshot::{persist_prepared_snapshot, PreparedSnapshot};
use crate::ledger::types::{GameId, HandId};
use crate::ledger::CanonicalKey;

use crate::ledger::lobby::error::GameSetupError;

use super::{
    LobbyStorage, LobbyStorageTxn, NewGame, NewGamePlayer, NewGameShuffler, NewHand, NewHandPlayer,
    NewHandShuffler, NewPlayer, NewShuffler, StoredPlayer, StoredShuffler,
};

pub struct SeaOrmLobbyStorage<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    connection: DatabaseConnection,
    _phantom: std::marker::PhantomData<C>,
}

impl<C> SeaOrmLobbyStorage<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    pub fn new(connection: DatabaseConnection) -> Self {
        Self {
            connection,
            _phantom: std::marker::PhantomData,
        }
    }
}

pub struct SeaOrmLobbyTxn<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    txn: DatabaseTransaction,
    _phantom: std::marker::PhantomData<C>,
}

#[async_trait]
impl<C> LobbyStorage<C> for SeaOrmLobbyStorage<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    async fn begin(&self) -> Result<Box<dyn LobbyStorageTxn<C> + Send>, GameSetupError> {
        let txn = self.connection.begin().await?;
        Ok(Box::new(SeaOrmLobbyTxn {
            txn,
            _phantom: std::marker::PhantomData,
        }))
    }
}

#[async_trait]
impl<C> LobbyStorageTxn<C> for SeaOrmLobbyTxn<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    async fn load_player(
        &mut self,
        key: &CanonicalKey<C>,
    ) -> Result<Option<StoredPlayer<C>>, GameSetupError> {
        let public_key_bytes = serialize_curve_bytes(key.value())
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;

        let record = players::Entity::find()
            .filter(players::Column::PublicKey.eq(public_key_bytes))
            .one(&self.txn)
            .await?;

        match record {
            Some(model) => {
                let public_key = deserialize_curve_bytes::<C>(&model.public_key)
                    .map_err(|e| GameSetupError::validation(format!("failed to deserialize public key: {}", e)))?;
                Ok(Some(StoredPlayer {
                    display_name: model.display_name,
                    public_key,
                }))
            }
            None => Ok(None),
        }
    }

    async fn load_player_by_id(
        &mut self,
        id: crate::engine::nl::types::PlayerId,
    ) -> Result<Option<StoredPlayer<C>>, GameSetupError> {
        let db_id = i64::try_from(id)
            .map_err(|_| GameSetupError::validation(format!("player id {} out of range", id)))?;
        let record = players::Entity::find_by_id(db_id).one(&self.txn).await?;

        match record {
            Some(model) => {
                let public_key = deserialize_curve_bytes::<C>(&model.public_key).map_err(|e| {
                    GameSetupError::validation(format!("failed to deserialize public key: {}", e))
                })?;
                Ok(Some(StoredPlayer {
                    display_name: model.display_name,
                    public_key,
                }))
            }
            None => Ok(None),
        }
    }

    async fn insert_player(&mut self, player: NewPlayer<C>) -> Result<(crate::engine::nl::types::PlayerId, CanonicalKey<C>), GameSetupError> {
        let public_key_bytes = serialize_curve_bytes(&player.public_key)
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;

        let model = players::ActiveModel {
            display_name: Set(player.display_name),
            public_key: Set(public_key_bytes),
            ..Default::default()
        };
        let inserted = model.insert(&self.txn).await?;
        let player_id = u64::try_from(inserted.id)
            .map_err(|_| GameSetupError::validation(format!("player id {} out of range", inserted.id)))?;
        Ok((player_id, CanonicalKey::new(player.public_key)))
    }

    async fn load_shuffler(
        &mut self,
        key: &CanonicalKey<C>,
    ) -> Result<Option<StoredShuffler<C>>, GameSetupError> {
        let public_key_bytes = serialize_curve_bytes(key.value())
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;

        let record = shufflers::Entity::find()
            .filter(shufflers::Column::PublicKey.eq(public_key_bytes))
            .one(&self.txn)
            .await?;

        match record {
            Some(model) => {
                let public_key = deserialize_curve_bytes::<C>(&model.public_key)
                    .map_err(|e| GameSetupError::validation(format!("failed to deserialize public key: {}", e)))?;
                Ok(Some(StoredShuffler {
                    display_name: model.display_name,
                    public_key,
                }))
            }
            None => Ok(None),
        }
    }

    async fn load_shuffler_by_id(
        &mut self,
        id: crate::ledger::types::ShufflerId,
    ) -> Result<Option<StoredShuffler<C>>, GameSetupError> {
        let record = shufflers::Entity::find_by_id(id).one(&self.txn).await?;

        match record {
            Some(model) => {
                let public_key = deserialize_curve_bytes::<C>(&model.public_key).map_err(|e| {
                    GameSetupError::validation(format!("failed to deserialize public key: {}", e))
                })?;
                Ok(Some(StoredShuffler {
                    display_name: model.display_name,
                    public_key,
                }))
            }
            None => Ok(None),
        }
    }

    async fn insert_shuffler(
        &mut self,
        shuffler: NewShuffler<C>,
    ) -> Result<(crate::ledger::types::ShufflerId, CanonicalKey<C>), GameSetupError> {
        let public_key_bytes = serialize_curve_bytes(&shuffler.public_key)
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;

        let model = shufflers::ActiveModel {
            display_name: Set(shuffler.display_name),
            public_key: Set(public_key_bytes),
            ..Default::default()
        };
        let inserted = model.insert(&self.txn).await?;
        Ok((inserted.id, CanonicalKey::new(shuffler.public_key)))
    }

    async fn insert_game(&mut self, game: NewGame) -> Result<GameId, GameSetupError> {
        let stakes = game.config.stakes;
        let small_blind = chips_to_i64(stakes.small_blind)?;
        let big_blind = chips_to_i64(stakes.big_blind)?;
        let ante = chips_to_i64(stakes.ante)?;
        let host_player_id = i64::try_from(game.host_player_id)
            .map_err(|_| GameSetupError::validation(format!("host player id {} out of range", game.host_player_id)))?;

        let active = games::ActiveModel {
            host_player_id: Set(host_player_id),
            name: Set(game.config.name.clone()),
            currency: Set(game.config.currency.clone()),
            max_players: Set(game.config.max_players),
            small_blind: Set(small_blind),
            big_blind: Set(big_blind),
            ante: Set(ante),
            rake_bps: Set(game.config.rake_bps),
            status: Set(DbGameStatus::Onboarding),
            ..Default::default()
        };
        let inserted = active.insert(&self.txn).await?;
        Ok(inserted.id)
    }

    async fn insert_game_player(&mut self, row: NewGamePlayer) -> Result<(), GameSetupError> {
        let player_id = i64::try_from(row.player_id)
            .map_err(|_| GameSetupError::validation(format!("player id {} out of range", row.player_id)))?;
        let model = game_players::ActiveModel {
            game_id: Set(row.game_id),
            player_id: Set(player_id),
            seat_preference: Set(row.seat_preference.map(|seat| seat as i16)),
            ..Default::default()
        };
        model.insert(&self.txn).await?;
        Ok(())
    }

    async fn count_game_shufflers(&mut self, game_id: GameId) -> Result<u16, GameSetupError> {
        let count = game_shufflers::Entity::find()
            .filter(game_shufflers::Column::GameId.eq(game_id))
            .count(&self.txn)
            .await?;
        u16::try_from(count)
            .map_err(|_| GameSetupError::validation("shuffler sequence exceeds supported range"))
    }

    async fn insert_game_shuffler(&mut self, row: NewGameShuffler<C>) -> Result<(), GameSetupError> {
        // Serialize the public_key field
        let public_key_bytes = serialize_curve_bytes(&row.public_key)
            .map_err(|e| GameSetupError::validation(format!("failed to serialize public key: {}", e)))?;

        let model = game_shufflers::ActiveModel {
            game_id: Set(row.game_id),
            shuffler_id: Set(row.shuffler_id),
            sequence: Set(row.sequence as i16),
            public_key: Set(public_key_bytes),
            ..Default::default()
        };
        model.insert(&self.txn).await?;
        Ok(())
    }

    async fn insert_hand_config(
        &mut self,
        game_id: GameId,
        cfg: &crate::engine::nl::types::HandConfig,
    ) -> Result<i64, GameSetupError> {
        let small_blind = chips_to_i64(cfg.stakes.small_blind)?;
        let big_blind = chips_to_i64(cfg.stakes.big_blind)?;
        let ante = chips_to_i64(cfg.stakes.ante)?;

        let model = hand_configs::ActiveModel {
            game_id: Set(game_id),
            small_blind: Set(small_blind),
            big_blind: Set(big_blind),
            ante: Set(ante),
            button_seat: Set(i16::from(cfg.button)),
            small_blind_seat: Set(i16::from(cfg.small_blind_seat)),
            big_blind_seat: Set(i16::from(cfg.big_blind_seat)),
            check_raise_allowed: Set(cfg.check_raise_allowed),
            ..Default::default()
        };

        let inserted = model.insert(&self.txn).await?;
        Ok(inserted.id)
    }

    async fn insert_hand(&mut self, hand: NewHand) -> Result<HandId, GameSetupError> {
        let model = hands::ActiveModel {
            game_id: Set(hand.game_id),
            hand_no: Set(hand.hand_no),
            button_seat: Set(hand.config.button as i16),
            small_blind_seat: Set(hand.config.small_blind_seat as i16),
            big_blind_seat: Set(hand.config.big_blind_seat as i16),
            deck_commitment: Set(hand.deck_commitment),
            status: Set(DbHandStatus::Pending),
            hand_config_id: Set(hand.config_id),
            ..Default::default()
        };
        let inserted = model.insert(&self.txn).await?;
        Ok(inserted.id)
    }

    async fn insert_hand_player(&mut self, row: NewHandPlayer) -> Result<(), GameSetupError> {
        let player_id = i64::try_from(row.player_id)
            .map_err(|_| GameSetupError::validation(format!("player id {} out of range", row.player_id)))?;
        let model = hand_player::ActiveModel {
            game_id: Set(row.game_id),
            hand_id: Set(row.hand_id),
            player_id: Set(player_id),
            seat: Set(row.seat as i16),
            nonce: Set(0),
            ..Default::default()
        };
        model.insert(&self.txn).await?;
        Ok(())
    }

    async fn insert_hand_shuffler(&mut self, row: NewHandShuffler) -> Result<(), GameSetupError> {
        let model = hand_shufflers::ActiveModel {
            hand_id: Set(row.hand_id),
            shuffler_id: Set(row.shuffler_id),
            sequence: Set(row.sequence as i16),
        };
        model.insert(&self.txn).await?;
        Ok(())
    }

    async fn persist_snapshot(&mut self, prepared: PreparedSnapshot) -> Result<(), GameSetupError> {
        persist_prepared_snapshot(&self.txn, &prepared)
            .await
            .map_err(|err| GameSetupError::Database(DbErr::Custom(err.to_string())))
    }

    async fn commit(mut self: Box<Self>) -> Result<(), GameSetupError> {
        self.txn.commit().await?;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) {
        let _ = self.txn.rollback().await;
    }
}

fn chips_to_i64(value: Chips) -> Result<i64, GameSetupError> {
    value
        .try_into()
        .map_err(|_| GameSetupError::validation("chip count exceeds database range"))
}
