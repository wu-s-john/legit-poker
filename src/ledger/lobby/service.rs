use std::collections::BTreeMap;
use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalDeserialize;
use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};
use sea_orm::{DatabaseConnection, DbErr};

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::{Chips, HandConfig, PlayerId, PlayerStatus, SeatId, TableStakes};
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::{
    AnyTableSnapshot, PhaseShuffling, PlayerIdentity, PlayerRoster, PlayerStackInfo, PlayerStacks,
    SeatingMap, ShufflerIdentity, ShufflerRoster, ShufflingSnapshot, SnapshotStatus,
    TableAtShuffling, TableSnapshot,
};
use crate::ledger::store::snapshot::prepare_snapshot;
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::CanonicalKey;
use crate::shuffling::data_structures::{ElGamalCiphertext, DECK_SIZE};

use super::error::GameSetupError;
use super::storage::InMemoryLobbyStorage;
use super::storage::SeaOrmLobbyStorage;
use super::storage::{
    LobbyStorage, LobbyStorageTxn, NewGame, NewGamePlayer, NewGameShuffler, NewHand, NewHandPlayer,
    NewHandShuffler, NewPlayer, NewShuffler,
};
use super::types::{
    CommenceGameOutcome, CommenceGameParams, GameLobbyConfig, GameMetadata, GameRecord, HandRecord,
    JoinGameOutput, PlayerRecord, PlayerSeatSnapshot, RegisterShufflerOutput, ShufflerAssignment,
    ShufflerRecord, ShufflerRegistrationConfig,
};
use super::validation::{
    ensure_buy_in, ensure_min_players, ensure_shuffler_sequence, ensure_unique_seats,
    validate_blind_positions, validate_lobby_config,
};

#[async_trait]
pub trait LobbyService<C>: Send + Sync
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + UniformRand + Absorb,
    C::Affine: Absorb,
{
    async fn host_game(
        &self,
        host: PlayerRecord<C, MaybeSaved<PlayerId>>,
        lobby: GameLobbyConfig,
    ) -> Result<GameMetadata<C>, GameSetupError>;

    async fn join_game(
        &self,
        game: &GameRecord<Saved<GameId>>,
        player: PlayerRecord<C, MaybeSaved<PlayerId>>,
        seat_preference: Option<SeatId>,
    ) -> Result<JoinGameOutput<C>, GameSetupError>;

    async fn register_shuffler(
        &self,
        game: &GameRecord<Saved<GameId>>,
        shuffler: ShufflerRecord<C, MaybeSaved<ShufflerId>>,
        cfg: ShufflerRegistrationConfig,
    ) -> Result<RegisterShufflerOutput<C>, GameSetupError>;

    async fn commence_game(
        &self,
        hasher: &dyn LedgerHasher,
        params: CommenceGameParams,
    ) -> Result<CommenceGameOutcome<C>, GameSetupError>;
}

#[derive(Clone)]
pub struct LobbyServiceFactory<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + UniformRand + Absorb,
    C::Affine: Absorb,
{
    storage: Arc<dyn LobbyStorage<C>>,
}

impl<C> LobbyServiceFactory<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + UniformRand + Absorb,
    C::Affine: Absorb,
{
    pub fn new(storage: Arc<dyn LobbyStorage<C>>) -> Self {
        Self { storage }
    }

    pub fn from_sea_orm(connection: DatabaseConnection) -> Self {
        let storage =
            Arc::new(SeaOrmLobbyStorage::<C>::new(connection)) as Arc<dyn LobbyStorage<C>>;
        Self::new(storage)
    }

    pub fn in_memory() -> Self {
        let storage = Arc::new(InMemoryLobbyStorage::<C>::new()) as Arc<dyn LobbyStorage<C>>;
        Self::new(storage)
    }
}

pub async fn ensure_player_saved<C>(
    txn: &mut dyn LobbyStorageTxn<C>,
    mut player: PlayerRecord<C, MaybeSaved<PlayerId>>,
) -> Result<PlayerRecord<C, Saved<PlayerId>>, GameSetupError>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + UniformRand + Absorb,
    C::Affine: Absorb,
{
    if let Some(id) = player.state.id {
        if let Some(existing) = txn.load_player_by_id(id).await? {
            if player.display_name.is_empty() {
                player.display_name = existing.display_name;
            }
            // Use stored public key if caller didn't provide one (C::zero() is the default)
            let public_key = if player.public_key == C::zero() {
                existing.public_key
            } else {
                player.public_key
            };
            return Ok(PlayerRecord {
                display_name: player.display_name,
                public_key,
                seat_preference: player.seat_preference,
                state: Saved { id },
            });
        }
        return Err(GameSetupError::NotFound("player"));
    }

    if player.display_name.is_empty() {
        return Err(GameSetupError::validation(
            "display_name is required for new players",
        ));
    }

    let (id, _key) = txn
        .insert_player(NewPlayer {
            display_name: player.display_name.clone(),
            public_key: player.public_key.clone(),
        })
        .await?;

    Ok(PlayerRecord {
        display_name: player.display_name,
        public_key: player.public_key,
        seat_preference: player.seat_preference,
        state: Saved { id },
    })
}

pub async fn ensure_shuffler_saved<C>(
    txn: &mut dyn LobbyStorageTxn<C>,
    mut shuffler: ShufflerRecord<C, MaybeSaved<ShufflerId>>,
) -> Result<ShufflerRecord<C, Saved<ShufflerId>>, GameSetupError>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + UniformRand + Absorb,
    C::Affine: Absorb,
{
    if let Some(id) = shuffler.state.id {
        if let Some(existing) = txn.load_shuffler_by_id(id).await? {
            if shuffler.display_name.is_empty() {
                shuffler.display_name = existing.display_name;
            }
            // Use stored public key if caller didn't provide one (C::zero() is the default)
            let public_key = if shuffler.public_key == C::zero() {
                existing.public_key
            } else {
                shuffler.public_key
            };
            return Ok(ShufflerRecord {
                display_name: shuffler.display_name,
                public_key,
                state: Saved { id },
            });
        }
        return Err(GameSetupError::NotFound("shuffler"));
    }

    if shuffler.display_name.is_empty() {
        return Err(GameSetupError::validation(
            "display_name is required for new shufflers",
        ));
    }

    let (id, _key) = txn
        .insert_shuffler(NewShuffler {
            display_name: shuffler.display_name.clone(),
            public_key: shuffler.public_key.clone(),
        })
        .await?;

    Ok(ShufflerRecord {
        display_name: shuffler.display_name,
        public_key: shuffler.public_key,
        state: Saved { id },
    })
}

#[async_trait]
impl<C> LobbyService<C> for LobbyServiceFactory<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + UniformRand + Absorb,
    C::Affine: Absorb,
{
    async fn host_game(
        &self,
        host: PlayerRecord<C, MaybeSaved<PlayerId>>,
        lobby: GameLobbyConfig,
    ) -> Result<GameMetadata<C>, GameSetupError> {
        validate_lobby_config(&lobby)?;

        let mut txn = self.storage.begin().await?;
        let result = async {
            let host_saved = ensure_player_saved(txn.as_mut(), host).await?;

            let game_id = txn
                .insert_game(NewGame {
                    host_player_id: host_saved.state.id.clone(),
                    config: lobby.clone(),
                })
                .await?;

            Ok(GameMetadata {
                record: GameRecord {
                    name: lobby.name,
                    currency: lobby.currency,
                    stakes: lobby.stakes,
                    max_players: lobby.max_players,
                    rake_bps: lobby.rake_bps,
                    host: host_saved.state.id.clone(),
                    state: Saved { id: game_id },
                },
                host: host_saved,
            })
        }
        .await;

        match result {
            Ok(metadata) => {
                txn.commit().await?;
                Ok(metadata)
            }
            Err(err) => {
                txn.rollback().await;
                Err(err)
            }
        }
    }

    async fn join_game(
        &self,
        game: &GameRecord<Saved<GameId>>,
        player: PlayerRecord<C, MaybeSaved<PlayerId>>,
        seat_preference: Option<SeatId>,
    ) -> Result<JoinGameOutput<C>, GameSetupError> {
        let mut txn = self.storage.begin().await?;
        let result = async {
            let player_saved = ensure_player_saved(txn.as_mut(), player).await?;
            txn.insert_game_player(NewGamePlayer {
                game_id: game.state.id,
                player_id: player_saved.state.id.clone(),
                seat_preference,
            })
            .await?;

            let player_saved_clone = player_saved.clone();
            Ok(JoinGameOutput {
                player: player_saved,
                game_player_row_id: (game.state.id, player_saved_clone.state.id),
            })
        }
        .await;

        match result {
            Ok(output) => {
                txn.commit().await?;
                Ok(output)
            }
            Err(err) => {
                txn.rollback().await;
                Err(err)
            }
        }
    }

    async fn register_shuffler(
        &self,
        game: &GameRecord<Saved<GameId>>,
        shuffler: ShufflerRecord<C, MaybeSaved<ShufflerId>>,
        cfg: ShufflerRegistrationConfig,
    ) -> Result<RegisterShufflerOutput<C>, GameSetupError> {
        let mut txn = self.storage.begin().await?;
        let result = async {
            let shuffler_saved = ensure_shuffler_saved(txn.as_mut(), shuffler).await?;
            let sequence = match cfg.sequence {
                Some(seq) => seq,
                None => txn.count_game_shufflers(game.state.id).await?,
            };

            let shuffler_saved_clone = shuffler_saved.clone();
            txn.insert_game_shuffler(NewGameShuffler {
                game_id: game.state.id,
                shuffler_id: shuffler_saved_clone.state.id.clone(),
                sequence,
                public_key: shuffler_saved_clone.public_key.clone(),
            })
            .await?;

            Ok(RegisterShufflerOutput {
                shuffler: shuffler_saved,
                game_shuffler_row_id: (game.state.id, shuffler_saved_clone.state.id),
                assigned_sequence: sequence,
            })
        }
        .await;

        match result {
            Ok(output) => {
                txn.commit().await?;
                Ok(output)
            }
            Err(err) => {
                txn.rollback().await;
                Err(err)
            }
        }
    }

    async fn commence_game(
        &self,
        hasher: &dyn LedgerHasher,
        params: CommenceGameParams,
    ) -> Result<CommenceGameOutcome<C>, GameSetupError> {
        let mut txn = self.storage.begin().await?;

        // Query game state from storage
        let game = txn.load_game(params.game_id).await?;
        let game_config = txn.load_game_config(params.game_id).await?;
        let joined_players = txn.load_game_players(params.game_id).await?;
        let registered_shufflers = txn.load_game_shufflers(params.game_id).await?;

        // Reconstruct HandConfig from stored game config + hand-specific seat positions
        let hand_config = HandConfig {
            stakes: game.stakes.clone(),
            button: params.button_seat,
            small_blind_seat: params.small_blind_seat,
            big_blind_seat: params.big_blind_seat,
            check_raise_allowed: game_config.check_raise_allowed,
        };

        // Build stack map from params if provided
        let stack_map: std::collections::HashMap<PlayerId, Chips> = params
            .player_stacks
            .as_ref()
            .map(|stacks| stacks.iter().copied().collect())
            .unwrap_or_default();

        // Reconstruct PlayerSeatSnapshot from queried data
        let player_snapshots: Vec<PlayerSeatSnapshot<C>> = joined_players
            .iter()
            .map(|(player_id, seat_preference, public_key)| {
                let seat_id = seat_preference.ok_or_else(|| {
                    GameSetupError::validation("player must have seat assignment")
                })?;

                // Determine starting stack based on whether player_stacks was provided
                let starting_stack = if params.player_stacks.is_some() {
                    // For subsequent hands: player MUST be in player_stacks
                    stack_map.get(player_id).copied().ok_or_else(|| {
                        GameSetupError::validation(format!(
                            "player {} missing from player_stacks (required for subsequent hands)",
                            player_id
                        ))
                    })?
                } else {
                    // For first hand: default to buy-in
                    game_config.buy_in
                };

                Ok(PlayerSeatSnapshot {
                    player: PlayerRecord {
                        display_name: String::new(), // Not needed for commence
                        public_key: public_key.clone(),
                        seat_preference: *seat_preference,
                        state: Saved { id: *player_id },
                    },
                    seat_id,
                    starting_stack,
                    public_key: public_key.clone(),
                })
            })
            .collect::<Result<Vec<_>, GameSetupError>>()?;

        // Compute aggregated public key
        let aggregated_public_key = registered_shufflers
            .iter()
            .fold(C::zero(), |acc, (_, _, public_key)| acc + public_key);

        // Reconstruct ShufflerAssignment from queried data
        let shuffler_assignments: Vec<ShufflerAssignment<C>> = registered_shufflers
            .iter()
            .map(|(shuffler_id, sequence, public_key)| ShufflerAssignment {
                shuffler: ShufflerRecord {
                    display_name: String::new(), // Not needed for commence
                    public_key: public_key.clone(),
                    state: Saved { id: *shuffler_id },
                },
                sequence: *sequence,
                public_key: public_key.clone(),
                aggregated_public_key: aggregated_public_key.clone(),
            })
            .collect();

        // Validation
        validate_blind_positions(
            params.button_seat,
            params.small_blind_seat,
            params.big_blind_seat,
        )?;
        ensure_unique_seats(&player_snapshots)?;
        ensure_min_players(game_config.min_players_to_start, &player_snapshots)?;
        ensure_shuffler_sequence(&shuffler_assignments)?;

        // Only enforce buy-in minimum for first hand (when player_stacks is None)
        // For subsequent hands, players may have less than buy-in due to chip losses
        if params.player_stacks.is_none() {
            ensure_buy_in(game_config.buy_in, &player_snapshots)?;
        }

        let prepared_players = prepare_players::<C>(&player_snapshots)?;
        let prepared_shufflers = prepare_shufflers::<C>(&shuffler_assignments)?;

        let result = async {
            let hand_config_id = txn.insert_hand_config(params.game_id, &hand_config).await?;

            let hand_id = txn
                .insert_hand(NewHand {
                    game_id: params.game_id,
                    hand_no: params.hand_no,
                    config_id: hand_config_id,
                    config: hand_config.clone(),
                    deck_commitment: params.deck_commitment.clone(),
                })
                .await?;

            for seat in &player_snapshots {
                txn.insert_hand_player(NewHandPlayer {
                    game_id: params.game_id,
                    hand_id,
                    player_id: seat.player.state.id,
                    seat: seat.seat_id,
                    starting_stack: seat.starting_stack,
                })
                .await?;
            }

            for assignment in &shuffler_assignments {
                txn.insert_hand_shuffler(NewHandShuffler {
                    hand_id,
                    shuffler_id: assignment.shuffler.state.id,
                    sequence: assignment.sequence,
                })
                .await?;
            }

            let snapshot = build_initial_snapshot::<C>(
                params.game_id,
                hand_id,
                &hand_config,
                &prepared_players,
                &prepared_shufflers,
                hasher,
            )?;
            let initial_snapshot = AnyTableSnapshot::Shuffling(snapshot.clone());
            let prepared = prepare_snapshot(&initial_snapshot, hasher)
                .map_err(|err| GameSetupError::Database(DbErr::Custom(err.to_string())))?;

            txn.persist_snapshot(prepared).await?;

            Ok((hand_id, snapshot))
        }
        .await;

        match result {
            Ok((hand_id, snapshot)) => {
                txn.commit().await?;

                Ok(CommenceGameOutcome {
                    hand: HandRecord {
                        game_id: params.game_id,
                        hand_no: params.hand_no,
                        status: crate::db::entity::sea_orm_active_enums::HandStatus::Pending,
                        state: Saved { id: hand_id },
                    },
                    nonce_seed: 0,
                    initial_snapshot: snapshot,
                })
            }
            Err(err) => {
                txn.rollback().await;
                Err(err)
            }
        }
    }
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
    C: CurveGroup,
{
    players
        .iter()
        .map(|seat| {
            Ok(PreparedPlayer {
                player_id: seat.player.state.id,
                seat: seat.seat_id,
                starting_stack: seat.starting_stack,
                public_key: seat.public_key.clone(),
            })
        })
        .collect()
}

fn prepare_shufflers<C>(
    shufflers: &[ShufflerAssignment<C>],
) -> Result<Vec<PreparedShuffler<C>>, GameSetupError>
where
    C: CurveGroup,
{
    shufflers
        .iter()
        .map(|assignment| {
            Ok(PreparedShuffler {
                shuffler_id: assignment.shuffler.state.id,
                sequence: assignment.sequence,
                public_key: assignment.public_key.clone(),
                aggregated_public_key: assignment.aggregated_public_key.clone(),
            })
        })
        .collect()
}

fn build_initial_snapshot<C>(
    game_id: GameId,
    hand_id: HandId,
    hand_config: &HandConfig,
    players: &[PreparedPlayer<C>],
    shufflers: &[PreparedShuffler<C>],
    hasher: &dyn LedgerHasher,
) -> Result<TableAtShuffling<C>, GameSetupError>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + CanonicalDeserialize + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + UniformRand + Absorb,
    C::Affine: Absorb,
{
    let mut player_roster: PlayerRoster<C> = BTreeMap::new();
    let mut seating: SeatingMap<C> = BTreeMap::new();
    let mut stacks: PlayerStacks<C> = BTreeMap::new();

    for player in players {
        let player_key = CanonicalKey::new(player.public_key.clone());
        player_roster.insert(
            player_key.clone(),
            PlayerIdentity {
                public_key: player.public_key.clone(),
                player_key: player_key.clone(),
                player_id: player.player_id,
                nonce: 0,
                seat: player.seat,
            },
        );
        seating.insert(player.seat, Some(player_key.clone()));
        let committed =
            compute_initial_commitment(hand_config, player.seat).min(player.starting_stack);
        stacks.insert(
            player.seat,
            PlayerStackInfo {
                seat: player.seat,
                player_key: Some(player_key),
                starting_stack: player.starting_stack,
                committed_blind: committed,
                status: PlayerStatus::Active,
            },
        );
    }

    let mut shuffler_roster: ShufflerRoster<C> = BTreeMap::new();
    let mut expected: Vec<(u16, CanonicalKey<C>)> = Vec::with_capacity(shufflers.len());
    for shuffler in shufflers {
        let shuffler_key = CanonicalKey::new(shuffler.public_key.clone());
        shuffler_roster.insert(
            shuffler_key.clone(),
            ShufflerIdentity {
                public_key: shuffler.public_key.clone(),
                shuffler_key: shuffler_key.clone(),
                shuffler_id: shuffler.shuffler_id,
                aggregated_public_key: shuffler.aggregated_public_key.clone(),
            },
        );
        expected.push((shuffler.sequence, shuffler_key));
    }
    expected.sort_by_key(|(sequence, _)| *sequence);
    let expected_order: Vec<CanonicalKey<C>> = expected.into_iter().map(|(_, key)| key).collect();

    if expected_order.is_empty() {
        return Err(GameSetupError::validation(
            "initial snapshot requires at least one shuffler",
        ));
    }

    let aggregated_public_key = shufflers
        .first()
        .map(|s| s.aggregated_public_key.clone())
        .ok_or_else(|| {
            GameSetupError::validation("initial snapshot requires at least one shuffler")
        })?;

    let mut rng = StdRng::from_entropy();
    let initial_deck = std::array::from_fn::<_, DECK_SIZE, _>(|i| {
        encrypt_zero::<C>(i, &aggregated_public_key, &mut rng)
    });
    let final_deck = initial_deck.clone();

    let mut snapshot: TableSnapshot<PhaseShuffling, C> = TableSnapshot {
        game_id,
        hand_id: Some(hand_id),
        sequence: 0,
        cfg: Arc::new(hand_config.clone()),
        shufflers: Arc::new(shuffler_roster),
        players: Arc::new(player_roster),
        seating: Arc::new(seating),
        stacks: Arc::new(stacks),
        previous_hash: None,
        state_hash: Default::default(),
        status: SnapshotStatus::Success,
        shuffling: ShufflingSnapshot {
            initial_deck: initial_deck.clone(),
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

fn encrypt_zero<C>(
    index: usize,
    aggregated_public_key: &C,
    rng: &mut StdRng,
) -> ElGamalCiphertext<C>
where
    C: CurveGroup,
    C::ScalarField: PrimeField + UniformRand,
{
    let message = C::ScalarField::from(index as u64);
    let randomness = C::ScalarField::rand(rng);
    let ciphertext =
        ElGamalCiphertext::encrypt_scalar(message, randomness, aggregated_public_key.clone());

    ciphertext
}

fn compute_initial_commitment(cfg: &HandConfig, seat: SeatId) -> Chips {
    let stakes: &TableStakes = &cfg.stakes;
    let mut committed = stakes.ante;
    if seat == cfg.small_blind_seat {
        committed = committed.saturating_add(stakes.small_blind);
    }
    if seat == cfg.big_blind_seat {
        committed = committed.saturating_add(stakes.big_blind);
    }
    committed
}
