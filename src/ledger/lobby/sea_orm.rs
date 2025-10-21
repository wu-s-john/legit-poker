use super::{
    ensure_buy_in, ensure_min_players, ensure_shuffler_sequence, ensure_unique_seats,
    validate_lobby_config, CommenceGameOutcome, CommenceGameParams, GameLobbyConfig, GameMetadata,
    GameRecord, GameSetupError, HandRecord, JoinGameOutput, LedgerLobby, PlayerRecord,
    PlayerSeatSnapshot, RegisterShufflerOutput, ShufflerAssignment, ShufflerRecord,
    ShufflerRegistrationConfig,
};
use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::sea_orm_active_enums::{
    GameStatus as DbGameStatus, HandStatus as DbHandStatus,
};
use crate::db::entity::{
    game_players, game_shufflers, games, hand_configs, hand_player, hand_shufflers, hands, players,
    shufflers,
};
use crate::engine::nl::types::{Chips, PlayerId, PlayerStatus, SeatId};
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::{
    AnyTableSnapshot, PhaseShuffling, PlayerIdentity, PlayerRoster, PlayerStackInfo, PlayerStacks,
    SeatingMap, ShufflerIdentity, ShufflerRoster, ShufflingSnapshot, SnapshotStatus,
    TableAtShuffling, TableSnapshot,
};
use crate::ledger::store::snapshot::{prepare_snapshot, SeaOrmSnapshotStore, SnapshotStore};
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::LedgerOperator;
use crate::shuffling::data_structures::{ElGamalCiphertext, DECK_SIZE};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalDeserialize;
use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};
use sea_orm::DbErr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    PaginatorTrait, QueryFilter, Set, TransactionTrait,
};
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

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
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
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
            status: Set(DbGameStatus::Onboarding),
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
    ) -> Result<CommenceGameOutcome<C>, GameSetupError> {
        ensure_unique_seats(&params.players)?;
        ensure_min_players(params.min_players, &params.players)?;
        ensure_shuffler_sequence(&params.shufflers)?;
        ensure_buy_in(params.buy_in, &params.players)?;
        let prepared_players = prepare_players::<C>(&params.players)?;
        let prepared_shufflers = prepare_shufflers::<C>(&params.shufflers)?;

        let txn = self.begin().await?;

        let hand_config_db_id =
            insert_hand_config(&txn, params.game.state.id, &params.hand_config).await?;

        let hand_model = hands::ActiveModel {
            game_id: Set(params.game.state.id),
            hand_no: Set(params.hand_no),
            button_seat: Set(params.hand_config.button as i16),
            small_blind_seat: Set(params.hand_config.small_blind_seat as i16),
            big_blind_seat: Set(params.hand_config.big_blind_seat as i16),
            deck_commitment: Set(params.deck_commitment.clone()),
            status: Set(DbHandStatus::Pending),
            hand_config_id: Set(hand_config_db_id),
            ..Default::default()
        };
        let hand_inserted = hand_model.insert(&txn).await?;
        let hand_id = hand_inserted.id;

        for seat in &params.players {
            let player_db_id = i64::try_from(seat.player.state.id)
                .map_err(|_| GameSetupError::validation("player id overflow"))?;

            let model = hand_player::ActiveModel {
                game_id: Set(params.game.state.id),
                hand_id: Set(hand_id),
                player_id: Set(player_db_id),
                seat: Set(seat.seat_id as i16),
                nonce: Set(0),
                ..Default::default()
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

        let state = operator.state();
        let hasher = state.hasher();
        let snapshot = build_initial_shuffling_snapshot(
            &params,
            hand_id,
            &prepared_players,
            &prepared_shufflers,
            hasher.as_ref(),
        )?;
        let initial_snapshot = AnyTableSnapshot::Shuffling(snapshot.clone());
        let prepared = prepare_snapshot(&initial_snapshot, hasher.as_ref())
            .map_err(|err| GameSetupError::Database(DbErr::Custom(err.to_string())))?;
        let snapshot_store = SeaOrmSnapshotStore::<C>::new(self.connection.clone());
        snapshot_store
            .persist_snapshot_in_txn(&txn, &prepared)
            .await
            .map_err(|err| GameSetupError::Database(DbErr::Custom(err.to_string())))?;

        txn.commit().await?;

        state.upsert_snapshot(hand_id, initial_snapshot.clone(), true);

        let hand_record = HandRecord {
            game_id: params.game.state.id,
            hand_no: params.hand_no,
            status: DbHandStatus::Pending,
            state: Saved { id: hand_id },
        };

        Ok(CommenceGameOutcome {
            hand: hand_record,
            nonce_seed: 0,
            initial_snapshot: snapshot,
        })
    }
}

fn chips_to_i64(value: Chips) -> Result<i64, GameSetupError> {
    value
        .try_into()
        .map_err(|_| GameSetupError::validation("chip count exceeds database range"))
}

#[derive(Clone)]
struct PreparedPlayer<C: CurveGroup> {
    player_id: PlayerId,
    seat: SeatId,
    starting_stack: Chips,
    public_key: C,
}

#[derive(Clone)]
struct PreparedShuffler<C: CurveGroup> {
    shuffler_id: ShufflerId,
    sequence: u16,
    public_key: C,
    aggregated_public_key: C,
}

fn prepare_players<C>(
    players: &[PlayerSeatSnapshot<C>],
) -> Result<Vec<PreparedPlayer<C>>, GameSetupError>
where
    C: CurveGroup + CanonicalDeserialize,
{
    players
        .iter()
        .map(|seat| {
            let message = format!("invalid public key for player in seat {}", seat.seat_id);
            let public_key = deserialize_curve_point::<C>(&seat.public_key, message)?;
            Ok(PreparedPlayer {
                player_id: seat.player.state.id,
                seat: seat.seat_id,
                starting_stack: seat.starting_stack,
                public_key,
            })
        })
        .collect()
}

fn prepare_shufflers<C>(
    shufflers: &[ShufflerAssignment<C>],
) -> Result<Vec<PreparedShuffler<C>>, GameSetupError>
where
    C: CurveGroup + CanonicalDeserialize,
{
    shufflers
        .iter()
        .map(|assignment| {
            let pk_msg = format!(
                "invalid shuffler public key for shuffler {}",
                assignment.shuffler.state.id
            );
            let public_key = deserialize_curve_point::<C>(&assignment.public_key, pk_msg)?;
            let agg_msg = format!(
                "invalid aggregated shuffler key for shuffler {}",
                assignment.shuffler.state.id
            );
            let aggregated_public_key =
                deserialize_curve_point::<C>(&assignment.aggregated_public_key, agg_msg)?;
            Ok(PreparedShuffler {
                shuffler_id: assignment.shuffler.state.id,
                sequence: assignment.sequence,
                public_key,
                aggregated_public_key,
            })
        })
        .collect()
}

fn deserialize_curve_point<C>(bytes: &[u8], context: impl Into<String>) -> Result<C, GameSetupError>
where
    C: CurveGroup + CanonicalDeserialize,
{
    C::deserialize_compressed(&mut &bytes[..])
        .map_err(|_| GameSetupError::validation(context.into()))
}

fn build_initial_shuffling_snapshot<C>(
    params: &CommenceGameParams<C>,
    hand_id: HandId,
    players: &[PreparedPlayer<C>],
    shufflers: &[PreparedShuffler<C>],
    hasher: &dyn LedgerHasher,
) -> Result<TableAtShuffling<C>, GameSetupError>
where
    C: CurveGroup,
    C::ScalarField: UniformRand,
{
    let mut player_roster: PlayerRoster<C> = BTreeMap::new();
    let mut seating: SeatingMap = BTreeMap::new();
    let mut stacks: PlayerStacks = BTreeMap::new();

    for player in players {
        player_roster.insert(
            player.player_id,
            PlayerIdentity {
                public_key: player.public_key.clone(),
                nonce: 0,
                seat: player.seat,
            },
        );
        seating.insert(player.seat, Some(player.player_id));
        let committed =
            compute_initial_commitment(&params.hand_config, player.seat).min(player.starting_stack);
        stacks.insert(
            player.seat,
            PlayerStackInfo {
                seat: player.seat,
                player_id: Some(player.player_id),
                starting_stack: player.starting_stack,
                committed_blind: committed,
                status: PlayerStatus::Active,
            },
        );
    }

    let mut shuffler_roster: ShufflerRoster<C> = BTreeMap::new();
    let mut expected: Vec<(u16, ShufflerId)> = Vec::with_capacity(shufflers.len());
    for shuffler in shufflers {
        shuffler_roster.insert(
            shuffler.shuffler_id,
            ShufflerIdentity {
                public_key: shuffler.public_key.clone(),
                aggregated_public_key: shuffler.aggregated_public_key.clone(),
            },
        );
        expected.push((shuffler.sequence, shuffler.shuffler_id));
    }
    expected.sort_by_key(|(sequence, _)| *sequence);
    let expected_order: Vec<ShufflerId> = expected.into_iter().map(|(_, id)| id).collect();

    if expected_order.is_empty() {
        return Err(GameSetupError::validation(
            "initial snapshot requires at least one shuffler",
        ));
    }

    let aggregated_public_key = shufflers
        .first()
        .map(|shuffler| shuffler.aggregated_public_key.clone())
        .ok_or_else(|| {
            GameSetupError::validation("initial snapshot requires at least one shuffler")
        })?;
    let mut rng = StdRng::from_entropy();
    let initial_deck = std::array::from_fn::<_, DECK_SIZE, _>(|i| {
        let message = C::ScalarField::from(i as u64);
        let randomness = C::ScalarField::rand(&mut rng);
        ElGamalCiphertext::encrypt_scalar(message, randomness, aggregated_public_key.clone())
    });
    let final_deck = initial_deck.clone();

    let mut snapshot: TableSnapshot<PhaseShuffling, C> = TableSnapshot {
        game_id: params.game.state.id,
        hand_id: Some(hand_id),
        sequence: 0,
        cfg: Arc::new(params.hand_config.clone()),
        shufflers: Arc::new(shuffler_roster),
        players: Arc::new(player_roster),
        seating: Arc::new(seating),
        stacks: Arc::new(stacks),
        previous_hash: None,
        state_hash: Default::default(),
        status: SnapshotStatus::Success,
        shuffling: ShufflingSnapshot {
            initial_deck,
            steps: Vec::new(),
            final_deck,
            expected_order,
        },
        dealing: (),
        betting: (),
        reveals: (),
    };
    snapshot.initialize_hash(hasher);
    Ok(snapshot)
}

async fn insert_hand_config(
    txn: &DatabaseTransaction,
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

    let inserted = model.insert(txn).await.map_err(GameSetupError::Database)?;
    Ok(inserted.id)
}

fn compute_initial_commitment(cfg: &crate::engine::nl::types::HandConfig, seat: SeatId) -> Chips {
    let stakes = &cfg.stakes;
    let mut committed = stakes.ante;
    if seat == cfg.small_blind_seat {
        committed = committed.saturating_add(stakes.small_blind);
    }
    if seat == cfg.big_blind_seat {
        committed = committed.saturating_add(stakes.big_blind);
    }
    committed
}
