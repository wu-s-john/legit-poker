use super::{
    ensure_buy_in, ensure_min_players, ensure_shuffler_sequence, ensure_unique_seats,
    validate_lobby_config, CommenceGameOutcome, CommenceGameParams, GameLobbyConfig, GameMetadata,
    GameRecord, GameSetupError, HandRecord, JoinGameOutput, LedgerLobby, PlayerRecord,
    RegisterShufflerOutput, ShufflerRecord, ShufflerRegistrationConfig,
};
use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::sea_orm_active_enums::{
    GameStatus as DbGameStatus, HandStatus as DbHandStatus,
};
use crate::db::entity::{
    game_players, game_shufflers, games, hand_seating, hand_shufflers, hands, players, shufflers,
};
use crate::engine::nl::types::{Chips, PlayerId, SeatId};
use crate::ledger::types::{GameId, ShufflerId};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::LedgerOperator;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use async_trait::async_trait;
use sea_orm::DbErr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    PaginatorTrait, QueryFilter, Set, TransactionTrait,
};
use std::convert::{TryFrom, TryInto};

pub struct SeaOrmLobby {
    connection: DatabaseConnection,
}

impl SeaOrmLobby {
    pub fn new(connection: DatabaseConnection) -> Self {
        Self { connection }
    }

    async fn begin(&self) -> Result<DatabaseTransaction, DbErr> {
        self.connection.begin().await
    }

    async fn ensure_player_saved(
        &self,
        txn: &DatabaseTransaction,
        mut player: PlayerRecord<MaybeSaved<PlayerId>>,
    ) -> Result<PlayerRecord<Saved<PlayerId>>, GameSetupError> {
        if let Some(existing_id) = player.state.id {
            let db_id = i64::try_from(existing_id)
                .map_err(|_| GameSetupError::validation("player id overflow"))?;
            let model = players::Entity::find_by_id(db_id)
                .one(txn)
                .await?
                .ok_or(GameSetupError::NotFound("player"))?;
            if player.display_name.is_empty() {
                player.display_name = model.display_name;
            }
            if player.public_key.is_empty() {
                player.public_key = model.public_key;
            }
            return Ok(PlayerRecord {
                display_name: player.display_name,
                public_key: player.public_key,
                seat_preference: player.seat_preference,
                state: Saved { id: existing_id },
            });
        }

        if player.display_name.is_empty() {
            return Err(GameSetupError::validation(
                "display_name is required for new players",
            ));
        }
        if player.public_key.is_empty() {
            return Err(GameSetupError::validation(
                "public_key is required for new players",
            ));
        }

        let active = players::ActiveModel {
            display_name: Set(player.display_name.clone()),
            public_key: Set(player.public_key.clone()),
            ..Default::default()
        };
        let inserted = active.insert(txn).await?;
        let id = PlayerId::try_from(inserted.id)
            .map_err(|_| GameSetupError::validation("player id overflow"))?;
        Ok(PlayerRecord {
            display_name: player.display_name,
            public_key: player.public_key,
            seat_preference: player.seat_preference,
            state: Saved { id },
        })
    }

    async fn ensure_shuffler_saved(
        &self,
        txn: &DatabaseTransaction,
        mut shuffler: ShufflerRecord<MaybeSaved<ShufflerId>>,
    ) -> Result<ShufflerRecord<Saved<ShufflerId>>, GameSetupError> {
        if let Some(existing_id) = shuffler.state.id {
            let model = shufflers::Entity::find_by_id(existing_id)
                .one(txn)
                .await?
                .ok_or(GameSetupError::NotFound("shuffler"))?;
            if shuffler.display_name.is_empty() {
                shuffler.display_name = model.display_name;
            }
            if shuffler.public_key.is_empty() {
                shuffler.public_key = model.public_key;
            }
            return Ok(ShufflerRecord {
                display_name: shuffler.display_name,
                public_key: shuffler.public_key,
                state: Saved { id: existing_id },
            });
        }

        if shuffler.display_name.is_empty() {
            return Err(GameSetupError::validation(
                "display_name is required for new shufflers",
            ));
        }
        if shuffler.public_key.is_empty() {
            return Err(GameSetupError::validation(
                "public_key is required for new shufflers",
            ));
        }

        let active = shufflers::ActiveModel {
            display_name: Set(shuffler.display_name.clone()),
            public_key: Set(shuffler.public_key.clone()),
            ..Default::default()
        };
        let inserted = active.insert(txn).await?;
        Ok(ShufflerRecord {
            display_name: shuffler.display_name,
            public_key: shuffler.public_key,
            state: Saved { id: inserted.id },
        })
    }
}

#[async_trait]
impl<C> LedgerLobby<C> for SeaOrmLobby
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    async fn host_game(
        &self,
        host: PlayerRecord<MaybeSaved<PlayerId>>,
        lobby: GameLobbyConfig,
    ) -> Result<GameMetadata, GameSetupError> {
        validate_lobby_config(&lobby)?;
        let txn = self.begin().await?;
        let host_saved = self.ensure_player_saved(&txn, host).await?;

        let host_db_id = i64::try_from(host_saved.state.id)
            .map_err(|_| GameSetupError::validation("host player id overflow"))?;
        let stakes = lobby.stakes;
        let small_blind = chips_to_i64(stakes.small_blind)?;
        let big_blind = chips_to_i64(stakes.big_blind)?;
        let ante = chips_to_i64(stakes.ante)?;

        let game_active = games::ActiveModel {
            host_player_id: Set(host_db_id),
            name: Set(lobby.name.clone()),
            currency: Set(lobby.currency.clone()),
            max_players: Set(lobby.max_players),
            small_blind: Set(small_blind),
            big_blind: Set(big_blind),
            ante: Set(ante),
            rake_bps: Set(lobby.rake_bps),
            status: Set(DbGameStatus::Open),
            ..Default::default()
        };
        let inserted = game_active.insert(&txn).await?;
        txn.commit().await?;

        let record = GameRecord {
            name: lobby.name,
            currency: lobby.currency,
            stakes,
            max_players: lobby.max_players,
            rake_bps: lobby.rake_bps,
            host: host_saved.state.id,
            state: Saved { id: inserted.id },
        };

        Ok(GameMetadata {
            record,
            host: host_saved,
        })
    }

    async fn join_game(
        &self,
        game: &GameRecord<Saved<GameId>>,
        player: PlayerRecord<MaybeSaved<PlayerId>>,
        seat_preference: Option<SeatId>,
    ) -> Result<JoinGameOutput, GameSetupError> {
        let txn = self.begin().await?;
        let player_saved = self.ensure_player_saved(&txn, player).await?;
        let player_id = player_saved.state.id;
        let player_db_id = i64::try_from(player_id)
            .map_err(|_| GameSetupError::validation("player id overflow"))?;

        let game_player = game_players::ActiveModel {
            game_id: Set(game.state.id),
            player_id: Set(player_db_id),
            seat_preference: Set(seat_preference.map(|seat| seat as i16)),
            ..Default::default()
        };
        game_player.insert(&txn).await?;
        txn.commit().await?;

        Ok(JoinGameOutput {
            player: player_saved,
            game_player_row_id: (game.state.id, player_id),
        })
    }

    async fn register_shuffler(
        &self,
        game: &GameRecord<Saved<GameId>>,
        shuffler: ShufflerRecord<MaybeSaved<ShufflerId>>,
        cfg: ShufflerRegistrationConfig,
    ) -> Result<RegisterShufflerOutput, GameSetupError> {
        let txn = self.begin().await?;
        let shuffler_saved = self.ensure_shuffler_saved(&txn, shuffler).await?;
        let shuffler_id = shuffler_saved.state.id;
        let sequence = if let Some(seq) = cfg.sequence {
            seq
        } else {
            let count = game_shufflers::Entity::find()
                .filter(game_shufflers::Column::GameId.eq(game.state.id))
                .count(&txn)
                .await?;
            u16::try_from(count).map_err(|_| {
                GameSetupError::validation("shuffler sequence exceeds supported range")
            })?
        };

        let model = game_shufflers::ActiveModel {
            game_id: Set(game.state.id),
            shuffler_id: Set(shuffler_saved.state.id),
            sequence: Set(sequence as i16),
            public_key: Set(shuffler_saved.public_key.clone()),
            ..Default::default()
        };
        model.insert(&txn).await?;
        txn.commit().await?;

        Ok(RegisterShufflerOutput {
            shuffler: shuffler_saved,
            game_shuffler_row_id: (game.state.id, shuffler_id),
            assigned_sequence: sequence,
        })
    }

    async fn commence_game(
        &self,
        operator: &LedgerOperator<C>,
        params: CommenceGameParams<C>,
    ) -> Result<CommenceGameOutcome, GameSetupError> {
        ensure_unique_seats(&params.players)?;
        ensure_min_players(params.min_players, &params.players)?;
        ensure_shuffler_sequence(&params.shufflers)?;
        ensure_buy_in(params.buy_in, &params.players)?;

        let txn = self.begin().await?;

        let hand_model = hands::ActiveModel {
            game_id: Set(params.game.state.id),
            hand_no: Set(params.hand_no),
            button_seat: Set(params.hand_config.button as i16),
            small_blind_seat: Set(params.hand_config.small_blind_seat as i16),
            big_blind_seat: Set(params.hand_config.big_blind_seat as i16),
            deck_commitment: Set(params.deck_commitment.clone()),
            status: Set(DbHandStatus::Pending),
            ..Default::default()
        };
        let hand_inserted = hand_model.insert(&txn).await?;
        let hand_id = hand_inserted.id;

        for seat in &params.players {
            let player_db_id = i64::try_from(seat.player.state.id)
                .map_err(|_| GameSetupError::validation("player id overflow"))?;
            let starting_stack = chips_to_i64(seat.starting_stack)?;
            let model = hand_seating::ActiveModel {
                hand_id: Set(hand_id),
                game_id: Set(params.game.state.id),
                seat: Set(seat.seat_id as i16),
                player_id: Set(player_db_id),
                player_public_key: Set(seat.public_key.clone()),
                starting_stack: Set(starting_stack),
            };
            model.insert(&txn).await?;
        }

        for assignment in &params.shufflers {
            let model = hand_shufflers::ActiveModel {
                hand_id: Set(hand_id),
                shuffler_id: Set(assignment.shuffler.state.id),
                sequence: Set(assignment.sequence as i16),
            };
            model.insert(&txn).await?;
        }

        txn.commit().await?;
        let _ = operator.state();

        let hand_record = HandRecord {
            game_id: params.game.state.id,
            hand_no: params.hand_no,
            status: DbHandStatus::Pending,
            state: Saved { id: hand_id },
        };

        Ok(CommenceGameOutcome {
            hand: hand_record,
            nonce_seed: 0,
        })
    }
}

fn chips_to_i64(value: Chips) -> Result<i64, GameSetupError> {
    value
        .try_into()
        .map_err(|_| GameSetupError::validation("chip count exceeds database range"))
}
