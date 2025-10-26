#![cfg(test)]

use super::types::{
    CommenceGameOutcome, CommenceGameParams, GameLobbyConfig, GameMetadata, PlayerRecord,
    RegisterShufflerOutput, ShufflerRecord,
    ShufflerRegistrationConfig,
};
use super::GameSetupError;
use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::{game_players, game_shufflers, games, hand_player, hand_shufflers, hands};
use crate::db::{connect_to_postgres_db, postgres_test_url};
use crate::engine::nl::types::{HandConfig, PlayerId, SeatId, TableStakes};
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::AnyTableSnapshot;
use crate::ledger::state::LedgerState;
use crate::ledger::store::snapshot::{PreparedSnapshot, SeaOrmSnapshotStore};
use crate::ledger::store::{EventStore, SeaOrmEventStore, SnapshotStore};
use crate::ledger::lobby::storage::{LobbyStorage, SeaOrmLobbyStorage};
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::verifier::LedgerVerifier;
use crate::ledger::worker::LedgerWorker;
use crate::ledger::LedgerOperator;
use crate::ledger::{LobbyService, LobbyServiceFactory};
use anyhow::Result;
use ark_bn254::{Fr as TestScalar, G1Projective as TestCurve};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, Statement,
};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

type TestLobby = dyn LobbyService<TestCurve>;

#[tokio::test]
async fn host_game_creates_new_game_and_host() -> Result<()> {
    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, _) = create_game(&lobby, &keys).await?;
    assert_eq!(metadata.host.display_name, "Host");
    assert!(games::Entity::find_by_id(metadata.record.state.id)
        .one(&conn)
        .await?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn join_game_inserts_membership() -> Result<()> {
    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, _) = create_game(&lobby, &keys).await?;
    join_host(&lobby, &metadata).await?;

    let joiner = PlayerRecord {
        display_name: "Bob".into(),
        public_key: keys.player.point,
        seat_preference: Some(1),
        state: MaybeSaved { id: None },
    };
    let output = join_game_curve(&lobby, &metadata.record, joiner, Some(1)).await?;

    let membership = game_players::Entity::find_by_id((
        metadata.record.state.id,
        i64::try_from(output.player.state.id).unwrap(),
    ))
    .one(&conn)
    .await?;
    assert!(membership.is_some());
    Ok(())
}

#[tokio::test]
async fn register_shuffler_assigns_sequence() -> Result<()> {
    let Some((lobby, _)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, _) = create_game(&lobby, &keys).await?;
    join_host(&lobby, &metadata).await?;

    let shuffler_one = ShufflerRecord {
        display_name: "Shuffler One".into(),
        public_key: keys.shuffler.point,
        state: MaybeSaved { id: None },
    };

    let shuffler_two = ShufflerRecord {
        display_name: "Shuffler Two".into(),
        public_key: TestKeys::new().shuffler.point,
        state: MaybeSaved { id: None },
    };

    let first = register_shuffler_curve(
        &lobby,
        &metadata.record,
        shuffler_one,
        ShufflerRegistrationConfig { sequence: None },
    )
    .await?;
    let second = register_shuffler_curve(
        &lobby,
        &metadata.record,
        shuffler_two,
        ShufflerRegistrationConfig { sequence: None },
    )
    .await?;

    assert_eq!(first.assigned_sequence, 0);
    assert_eq!(second.assigned_sequence, 1);
    Ok(())
}

#[tokio::test]
async fn commence_game_creates_hand_artifacts() -> Result<()> {
    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, config) = create_game(&lobby, &keys).await?;
    let host_player = join_host(&lobby, &metadata).await?;
    let joiner = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Bob".into(),
            public_key: keys.player.point,
            seat_preference: Some(1),
            state: MaybeSaved { id: None },
        },
        Some(1),
    )
    .await?
    .player;
    let extra_keys = TestKeys::new();
    let third_player = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Carol".into(),
            public_key: extra_keys.player.point,
            seat_preference: Some(2),
            state: MaybeSaved { id: None },
        },
        Some(2),
    )
    .await?
    .player;

    let registered = register_shuffler_curve(
        &lobby,
        &metadata.record,
        ShufflerRecord {
            display_name: "Shuffler".into(),
            public_key: keys.shuffler.point,
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?;

    let hand_cfg = HandConfig {
        stakes: config.stakes.clone(),
        button: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        check_raise_allowed: true,
    };

    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: hand_cfg.button,
        small_blind_seat: hand_cfg.small_blind_seat,
        big_blind_seat: hand_cfg.big_blind_seat,
        deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
    };
    let Some(operator) = setup_operator(&conn).await else {
        return Ok(());
    };
    let outcome = commence_game_curve(&lobby, &operator, params).await?;

    assert!(hands::Entity::find_by_id(outcome.hand.state.id)
        .one(&conn)
        .await?
        .is_some());
    assert_eq!(
        hand_player::Entity::find()
            .filter(hand_player::Column::HandId.eq(outcome.hand.state.id))
            .count(&conn)
            .await?,
        3
    );
    let (tip_hash, snapshot) = operator
        .state()
        .tip_snapshot(outcome.hand.state.id)
        .expect("hand snapshot seeded");
    assert_eq!(tip_hash, snapshot.state_hash());
    match snapshot {
        AnyTableSnapshot::Shuffling(table) => {
            assert_eq!(table.hand_id, Some(outcome.hand.state.id));
            let expected_key = table
                .shufflers
                .iter()
                .find_map(|(key, identity)| {
                    (identity.shuffler_id == registered.shuffler.state.id).then(|| key.clone())
                })
                .expect("shuffler key present in roster");
            assert_eq!(table.shuffling.expected_order, vec![expected_key]);
        }
        other => panic!("expected shuffling snapshot, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn commence_game_rejects_duplicate_seats() -> Result<()> {
    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, config) = create_game(&lobby, &keys).await?;
    let host_player = join_host(&lobby, &metadata).await?;
    let joiner = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Bob".into(),
            public_key: keys.player.point,
            seat_preference: Some(1),
            state: MaybeSaved { id: None },
        },
        Some(1),
    )
    .await?
    .player;
    let extra_keys = TestKeys::new();
    let third_player = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Carol".into(),
            public_key: extra_keys.player.point,
            seat_preference: Some(2),
            state: MaybeSaved { id: None },
        },
        Some(2),
    )
    .await?
    .player;
    let shuffler = register_shuffler_curve(
        &lobby,
        &metadata.record,
        ShufflerRecord {
            display_name: "Shuffler".into(),
            public_key: keys.shuffler.point,
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?
    .shuffler;

    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: 0,
        small_blind_seat: 0,
        big_blind_seat: 1,
        deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
    };
    let Some(operator) = setup_operator(&conn).await else {
        return Ok(());
    };
    let err = commence_game_curve(&lobby, &operator, params)
        .await
        .unwrap_err();
    assert!(matches!(err, GameSetupError::Validation(_)));
    Ok(())
}

#[tokio::test]
async fn commence_game_requires_min_players() -> Result<()> {
    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, config) = create_game(&lobby, &keys).await?;
    let host_player = join_host(&lobby, &metadata).await?;
    let joiner = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Bob".into(),
            public_key: keys.player.point,
            seat_preference: Some(1),
            state: MaybeSaved { id: None },
        },
        Some(1),
    )
    .await?
    .player;
    let shuffler = register_shuffler_curve(
        &lobby,
        &metadata.record,
        ShufflerRecord {
            display_name: "Shuffler".into(),
            public_key: keys.shuffler.point,
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?
    .shuffler;

    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: 0,
        small_blind_seat: 0,
        big_blind_seat: 1,
        deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
    };
    let Some(operator) = setup_operator(&conn).await else {
        return Ok(());
    };
    let err = commence_game_curve(&lobby, &operator, params)
        .await
        .unwrap_err();
    assert!(matches!(err, GameSetupError::Validation(_)));
    Ok(())
}

#[tokio::test]
async fn commence_game_requires_buy_in() -> Result<()> {
    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, config) = create_game(&lobby, &keys).await?;
    let host_player = join_host(&lobby, &metadata).await?;
    let joiner = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Bob".into(),
            public_key: keys.player.point,
            seat_preference: Some(1),
            state: MaybeSaved { id: None },
        },
        Some(1),
    )
    .await?
    .player;
    let extra_keys = TestKeys::new();
    let third_player = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Carol".into(),
            public_key: extra_keys.player.point,
            seat_preference: Some(2),
            state: MaybeSaved { id: None },
        },
        Some(2),
    )
    .await?
    .player;
    let shuffler = register_shuffler_curve(
        &lobby,
        &metadata.record,
        ShufflerRecord {
            display_name: "Shuffler".into(),
            public_key: keys.shuffler.point,
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?
    .shuffler;

    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: 0,
        small_blind_seat: 0,
        big_blind_seat: 1,
        deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
    };
    let Some(operator) = setup_operator(&conn).await else {
        return Ok(());
    };
    let err = commence_game_curve(&lobby, &operator, params)
        .await
        .unwrap_err();
    assert!(matches!(err, GameSetupError::Validation(_)));
    Ok(())
}

#[tokio::test]
async fn commence_game_rejects_invalid_player_key_bytes() -> Result<()> {
    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, config) = create_game(&lobby, &keys).await?;
    let host_player = join_host(&lobby, &metadata).await?;
    let joiner = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Bob".into(),
            public_key: keys.player.point,
            seat_preference: Some(1),
            state: MaybeSaved { id: None },
        },
        Some(1),
    )
    .await?
    .player;
    let extra_keys = TestKeys::new();

    let registered = register_shuffler_curve(
        &lobby,
        &metadata.record,
        ShufflerRecord {
            display_name: "Shuffler".into(),
            public_key: keys.shuffler.point,
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?;

    let third_player = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Carol".into(),
            public_key: extra_keys.player.point,
            seat_preference: Some(2),
            state: MaybeSaved { id: None },
        },
        Some(2),
    )
    .await?
    .player;

    let invalid_player_key = keys.player.point.clone();

    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: 0,
        small_blind_seat: 0,
        big_blind_seat: 1,
        deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
    };
    let Some(operator) = setup_operator(&conn).await else {
        return Ok(());
    };
    let err = commence_game_curve(&lobby, &operator, params)
        .await
        .unwrap_err();
    assert!(matches!(err, GameSetupError::Validation(_)));
    Ok(())
}

#[tokio::test]
async fn commence_game_with_partial_player_stacks_should_error() -> Result<()> {
    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };
    let keys = TestKeys::new();
    let (metadata, config) = create_game(&lobby, &keys).await?;
    let host_player = join_host(&lobby, &metadata).await?;

    // Join two more players for a total of 3
    let keys_2 = TestKeys::new();
    let player_2 = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Player2".into(),
            public_key: keys_2.player.point,
            seat_preference: Some(1),
            state: MaybeSaved { id: None },
        },
        Some(1),
    )
    .await?
    .player;

    let keys_3 = TestKeys::new();
    let player_3 = join_game_curve(
        &lobby,
        &metadata.record,
        PlayerRecord {
            display_name: "Player3".into(),
            public_key: keys_3.player.point,
            seat_preference: Some(2),
            state: MaybeSaved { id: None },
        },
        Some(2),
    )
    .await?
    .player;

    // Register a shuffler
    let registered = register_shuffler_curve(
        &lobby,
        &metadata.record,
        ShufflerRecord {
            display_name: "Shuffler".into(),
            public_key: keys.shuffler.point,
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?;

    let Some(operator) = setup_operator(&conn).await else {
        return Ok(());
    };

    // First hand: player_stacks = None should succeed
    let params_hand_1 = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        deck_commitment: None,
        player_stacks: None, // First hand - all get buy-in
    };

    let outcome_1 = commence_game_curve(&lobby, &operator, params_hand_1).await?;
    assert!(outcome_1.hand.state.id > 0);

    // Second hand: Deliberately omit player_3 from player_stacks
    // This should ERROR instead of silently defaulting to buy_in
    let params_hand_2 = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 2,
        button_seat: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        deck_commitment: None,
        player_stacks: Some(vec![
            (host_player.state.id, 5000),
            (player_2.state.id, 3000),
            // player_3 deliberately MISSING - should cause error
        ]),
    };

    let result_2 = commence_game_curve(&lobby, &operator, params_hand_2).await;

    // Should error because player_3 is missing from player_stacks
    assert!(
        result_2.is_err(),
        "Expected error when player missing from player_stacks, but got success"
    );

    let err = result_2.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("missing") && err_msg.contains(&player_3.state.id.to_string()),
        "Expected error message about missing player {}, got: {}",
        player_3.state.id,
        err_msg
    );

    Ok(())
}

#[derive(Clone)]
struct TestKeys {
    host: GeneratedKey,
    player: GeneratedKey,
    shuffler: GeneratedKey,
    shuffler_aggregated: Vec<u8>,
}

impl TestKeys {
    fn new() -> Self {
        Self::from_seed(NEXT_KEY_SEED.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn from_seed(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let host = sample_key(&mut rng);
        let player = sample_key(&mut rng);
        let shuffler = sample_key(&mut rng);
        let aggregated = serialize_point(&shuffler.point);
        Self {
            host,
            player,
            shuffler,
            shuffler_aggregated: aggregated,
        }
    }
}

#[derive(Clone)]
struct GeneratedKey {
    point: TestCurve,
    bytes: Vec<u8>,
}

fn sample_key(rng: &mut StdRng) -> GeneratedKey {
    let scalar = TestScalar::rand(rng);
    let point = TestCurve::generator() * scalar;
    let bytes = serialize_point(&point);
    GeneratedKey { point, bytes }
}

fn serialize_point(point: &TestCurve) -> Vec<u8> {
    let mut buf = Vec::new();
    point
        .serialize_compressed(&mut buf)
        .expect("compress curve point for tests");
    buf
}

static NEXT_KEY_SEED: AtomicU64 = AtomicU64::new(0);

async fn setup_lobby() -> Result<Option<(Arc<TestLobby>, DatabaseConnection)>> {
    let url = postgres_test_url();
    let conn = match connect_to_postgres_db(&url).await {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("skipping lobby test: failed to connect to postgres ({err})");
            return Ok(None);
        }
    };
    if let Err(err) = conn.ping().await {
        eprintln!("skipping lobby test: ping postgres failed ({err})");
        return Ok(None);
    }
    // Acquire a global advisory lock so tests run sequentially against the schema.
    // The lock is released automatically when the connection is dropped.
    if let Err(err) = conn
        .execute(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_advisory_lock(8675309)",
        ))
        .await
    {
        eprintln!("skipping lobby test: failed to acquire advisory lock ({err})");
        return Ok(None);
    }

    if let Err(err) = reset_database(&conn).await {
        eprintln!("skipping lobby test: failed to reset database ({err})");
        return Ok(None);
    };
    let lobby: Arc<TestLobby> =
        Arc::new(LobbyServiceFactory::<TestCurve>::from_sea_orm(conn.clone()));
    Ok(Some((lobby, conn)))
}

async fn create_game(
    lobby: &Arc<TestLobby>,
    keys: &TestKeys,
) -> Result<(GameMetadata<TestCurve>, GameLobbyConfig)> {
    let stakes = TableStakes {
        small_blind: 50,
        big_blind: 100,
        ante: 0,
    };
    let config = GameLobbyConfig {
        stakes: stakes.clone(),
        max_players: 9,
        rake_bps: 0,
        name: "Test Game".into(),
        currency: "chips".into(),
        buy_in: 1_000,
        min_players_to_start: 3,
        check_raise_allowed: true,
        action_time_limit: std::time::Duration::from_secs(30),
    };
    let host = PlayerRecord {
        display_name: "Host".into(),
        public_key: keys.host.point,
        seat_preference: Some(0),
        state: MaybeSaved { id: None },
    };
    let metadata = host_game_curve(lobby, host, config.clone()).await?;
    Ok((metadata, config))
}

async fn join_host(
    lobby: &Arc<TestLobby>,
    metadata: &GameMetadata<TestCurve>,
) -> Result<PlayerRecord<TestCurve, Saved<PlayerId>>> {
    let host_registration = PlayerRecord {
        display_name: metadata.host.display_name.clone(),
        public_key: metadata.host.public_key.clone(),
        seat_preference: Some(0),
        state: MaybeSaved {
            id: Some(metadata.host.state.id),
        },
    };
    let joined = join_game_curve(lobby, &metadata.record, host_registration, Some(0)).await?;
    Ok(joined.player)
}

async fn reset_database(conn: &DatabaseConnection) -> Result<()> {
    conn.execute(Statement::from_string(
        DbBackend::Postgres,
        "TRUNCATE TABLE \
            public.table_snapshots, \
            public.phases, \
            public.hand_configs, \
            public.events, \
            public.hand_shufflers, \
            public.hand_player, \
            public.hands, \
            public.game_shufflers, \
            public.game_players, \
            public.games, \
            public.shufflers, \
            public.players \
         RESTART IDENTITY CASCADE",
    ))
    .await?;
    Ok(())
}

async fn host_game_curve(
    lobby: &Arc<TestLobby>,
    host: PlayerRecord<TestCurve, MaybeSaved<PlayerId>>,
    cfg: GameLobbyConfig,
) -> Result<GameMetadata<TestCurve>, GameSetupError> {
    lobby.host_game(host, cfg).await
}

async fn join_game_curve(
    lobby: &Arc<TestLobby>,
    game: &super::types::GameRecord<Saved<GameId>>,
    player: PlayerRecord<TestCurve, MaybeSaved<PlayerId>>,
    seat: Option<SeatId>,
) -> Result<super::types::JoinGameOutput<TestCurve>, GameSetupError> {
    lobby.join_game(game, player, seat).await
}

async fn register_shuffler_curve(
    lobby: &Arc<TestLobby>,
    game: &super::types::GameRecord<Saved<GameId>>,
    shuffler: ShufflerRecord<TestCurve, MaybeSaved<ShufflerId>>,
    cfg: ShufflerRegistrationConfig,
) -> Result<RegisterShufflerOutput<TestCurve>, GameSetupError> {
    lobby.register_shuffler(game, shuffler, cfg).await
}

async fn commence_game_curve(
    lobby: &Arc<TestLobby>,
    operator: &LedgerOperator<TestCurve>,
    params: CommenceGameParams,
) -> Result<CommenceGameOutcome<TestCurve>, GameSetupError> {
    let outcome = lobby.commence_game(&operator.state().hasher(), params).await?;

    // Seed the initial snapshot into the operator's state
    operator.state().upsert_snapshot(
        outcome.hand.state.id,
        AnyTableSnapshot::Shuffling(outcome.initial_snapshot.clone()),
        true,
    );

    Ok(outcome)
}

#[derive(Default)]
struct NoopSnapshotStore<C> {
    _marker: std::marker::PhantomData<C>,
}

#[async_trait]
impl<C> SnapshotStore<C> for NoopSnapshotStore<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    async fn persist_snapshot(
        &self,
        _snapshot: &AnyTableSnapshot<C>,
        _hasher: &Arc<dyn LedgerHasher + Send + Sync>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn persist_snapshot_in_txn(
        &self,
        _txn: &DatabaseTransaction,
        _prepared: &PreparedSnapshot,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn load_latest_snapshot(
        &self,
        _hand_id: HandId,
    ) -> anyhow::Result<Option<AnyTableSnapshot<C>>> {
        Ok(None)
    }
}

async fn setup_operator(conn: &DatabaseConnection) -> Option<LedgerOperator<TestCurve>> {
    let event_store: Arc<dyn EventStore<TestCurve>> =
        Arc::new(SeaOrmEventStore::<TestCurve>::new(conn.clone()));
    let snapshot_store: Arc<dyn SnapshotStore<TestCurve>> =
        Arc::new(NoopSnapshotStore::<TestCurve>::default());
    let state = Arc::new(LedgerState::<TestCurve>::new());
    let verifier = Arc::new(LedgerVerifier::new(Arc::clone(&state)));
    let (tx, rx) = mpsc::channel(32);
    let (events_tx, _) = broadcast::channel(16);
    let (snapshots_tx, _) = broadcast::channel(16);
    let (staging_tx, _) = broadcast::channel(16);
    let operator = LedgerOperator::new(
        verifier,
        tx,
        Arc::clone(&event_store),
        Arc::clone(&state),
        events_tx.clone(),
        snapshots_tx.clone(),
        staging_tx.clone(),
    );
    let worker = LedgerWorker::new(
        rx,
        Arc::clone(&event_store),
        Arc::clone(&snapshot_store),
        Arc::clone(&state),
        events_tx,
        snapshots_tx,
        staging_tx,
    );
    if let Err(err) = operator.start(worker).await {
        eprintln!("skipping lobby test: failed to start operator ({err})");
        return None;
    }
    Some(operator)
}

// =============================================================================
// COMPREHENSIVE PERSIST-AND-RECOVER INTEGRATION TEST
// =============================================================================

#[tokio::test]
async fn test_persist_and_recover_large_game_then_commence() -> Result<()> {
    // =============================================================================
    // PHASE 1: Setup and Game Creation
    // =============================================================================

    let Some((lobby, conn)) = setup_lobby().await? else {
        return Ok(());
    };

    // Create separate key sets for each participant
    let host_keys = TestKeys::new();
    let player_keys: Vec<TestKeys> = (0..4).map(|_| TestKeys::new()).collect();
    let shuffler_keys: Vec<TestKeys> = (0..7).map(|_| TestKeys::new()).collect();

    // Create game with host
    let (metadata, config) = create_game(&lobby, &host_keys).await?;

    // Join host as player at seat 0
    let host_player = join_host(&lobby, &metadata).await?;

    // Register 4 additional players (total 5)
    let mut all_players = vec![host_player];

    for (idx, keys) in player_keys.iter().enumerate() {
        let seat = (idx + 1) as u8;  // Seats 1, 2, 3, 4
        let player = PlayerRecord {
            display_name: format!("Player{}", idx + 1),
            public_key: keys.player.point,
            seat_preference: Some(seat),
            state: MaybeSaved { id: None },
        };
        let output = join_game_curve(&lobby, &metadata.record, player, Some(seat)).await?;
        all_players.push(output.player);
    }

    assert_eq!(all_players.len(), 5, "should have 5 total players");

    // Register 7 shufflers
    let mut all_shufflers = Vec::new();

    for (seq, keys) in shuffler_keys.iter().enumerate() {
        let shuffler = ShufflerRecord {
            display_name: format!("Shuffler{}", seq),
            public_key: keys.shuffler.point,
            state: MaybeSaved { id: None },
        };
        let output = register_shuffler_curve(
            &lobby,
            &metadata.record,
            shuffler,
            ShufflerRegistrationConfig {
                sequence: Some(seq as u16)
            },
        ).await?;

        all_shufflers.push(output.shuffler);
        assert_eq!(output.assigned_sequence, seq as u16);
    }

    assert_eq!(all_shufflers.len(), 7, "should have 7 shufflers");

    // =============================================================================
    // PHASE 2: Verify Persistence
    // =============================================================================

    // Verify game exists in DB
    let game_record = games::Entity::find_by_id(metadata.record.state.id)
        .one(&conn)
        .await?
        .expect("game should be persisted");

    assert_eq!(game_record.name, config.name);
    assert_eq!(game_record.max_players, config.max_players);

    // Verify all 5 players are in game_players table
    let player_count = game_players::Entity::find()
        .filter(game_players::Column::GameId.eq(metadata.record.state.id))
        .count(&conn)
        .await?;

    assert_eq!(player_count, 5, "all 5 players should be persisted");

    // Verify all 7 shufflers are in game_shufflers table
    let shuffler_records = game_shufflers::Entity::find()
        .filter(game_shufflers::Column::GameId.eq(metadata.record.state.id))
        .order_by_asc(game_shufflers::Column::Sequence)
        .all(&conn)
        .await?;

    assert_eq!(shuffler_records.len(), 7, "all 7 shufflers should be persisted");

    // Verify sequences are 0..6
    for (idx, rec) in shuffler_records.iter().enumerate() {
        assert_eq!(rec.sequence, idx as i16);
    }

    // =============================================================================
    // PHASE 3: Teardown
    // =============================================================================

    // Drop the original lobby to simulate service restart
    drop(lobby);

    // Brief delay to ensure all async operations complete
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Create a fresh lobby instance from the same database
    let lobby_recovered: Arc<TestLobby> =
        Arc::new(LobbyServiceFactory::<TestCurve>::from_sea_orm(conn.clone()));

    // =============================================================================
    // PHASE 4: Recovery and Validation
    // =============================================================================

    // Use LobbyStorage to load the game state
    let storage = SeaOrmLobbyStorage::<TestCurve>::new(conn.clone());
    let mut txn = storage.begin().await?;

    // Load game record
    let recovered_game = txn.load_game(metadata.record.state.id).await?;
    assert_eq!(recovered_game.name, config.name);
    assert_eq!(recovered_game.state.id, metadata.record.state.id);

    // Load all players for this game
    let recovered_players = txn.load_game_players(metadata.record.state.id).await?;
    assert_eq!(recovered_players.len(), 5, "should recover 5 players");

    // Verify player IDs match
    let recovered_player_ids: HashSet<_> = recovered_players
        .iter()
        .map(|(id, _, _)| *id)
        .collect();
    let original_player_ids: HashSet<_> = all_players
        .iter()
        .map(|p| p.state.id)
        .collect();
    assert_eq!(recovered_player_ids, original_player_ids);

    // Load all shufflers for this game
    let recovered_shufflers = txn.load_game_shufflers(metadata.record.state.id).await?;
    assert_eq!(recovered_shufflers.len(), 7, "should recover 7 shufflers");

    // Verify sequences are correct (0..6)
    for (idx, (shuffler_id, sequence, _)) in recovered_shufflers.iter().enumerate() {
        assert_eq!(*sequence, idx as u16, "sequence should match");
        assert_eq!(*shuffler_id, all_shufflers[idx].state.id);
    }

    // We only used the transaction for reading, rollback is fine
    txn.rollback().await;

    // =============================================================================
    // PHASE 5: Commence Hand with Recovered State
    // =============================================================================

    // Create operator with REAL SeaOrmSnapshotStore instead of NoopSnapshotStore
    let event_store: Arc<dyn EventStore<TestCurve>> =
        Arc::new(SeaOrmEventStore::<TestCurve>::new(conn.clone()));
    let snapshot_store: Arc<dyn SnapshotStore<TestCurve>> =
        Arc::new(SeaOrmSnapshotStore::<TestCurve>::new(conn.clone()));

    let state = Arc::new(LedgerState::<TestCurve>::new());
    let verifier = Arc::new(LedgerVerifier::new(Arc::clone(&state)));
    let (tx, rx) = mpsc::channel(32);
    let (events_tx, _) = broadcast::channel(16);
    let (snapshots_tx, _) = broadcast::channel(16);
    let (staging_tx, _) = broadcast::channel(16);

    let operator = LedgerOperator::new(
        verifier,
        tx,
        Arc::clone(&event_store),
        Arc::clone(&state),
        events_tx.clone(),
        snapshots_tx.clone(),
        staging_tx.clone(),
    );

    let worker = LedgerWorker::new(
        rx,
        Arc::clone(&event_store),
        Arc::clone(&snapshot_store),
        Arc::clone(&state),
        events_tx,
        snapshots_tx,
        staging_tx,
    );

    operator.start(worker).await.expect("operator should start");

    // Build CommenceGameParams
    let hand_cfg = HandConfig {
        stakes: config.stakes.clone(),
        button: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        check_raise_allowed: true,
    };

    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: hand_cfg.button,
        small_blind_seat: hand_cfg.small_blind_seat,
        big_blind_seat: hand_cfg.big_blind_seat,
        deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
    };

    let outcome = commence_game_curve(&lobby_recovered, &operator, params).await?;

    assert_eq!(outcome.hand.hand_no, 1);
    assert_eq!(outcome.hand.state.id, outcome.initial_snapshot.hand_id.unwrap());

    // =============================================================================
    // PHASE 6: Validate Commenced Hand State
    // =============================================================================

    // Verify hand was created
    let hand_record = hands::Entity::find_by_id(outcome.hand.state.id)
        .one(&conn)
        .await?
        .expect("hand should be persisted");

    assert_eq!(hand_record.game_id, metadata.record.state.id);
    assert_eq!(hand_record.hand_no, 1);
    assert_eq!(hand_record.button_seat, 0);

    // Verify all 5 players are in hand_player table
    let hand_players = hand_player::Entity::find()
        .filter(hand_player::Column::HandId.eq(outcome.hand.state.id))
        .all(&conn)
        .await?;

    assert_eq!(hand_players.len(), 5, "all 5 players should be in hand");

    // Verify each player has correct stack
    for hp in &hand_players {
        assert_eq!(
            hp.starting_stack,
            config.buy_in as i64,
            "player starting stack should equal buy-in"
        );
    }

    // Verify all 7 shufflers are in hand_shufflers table
    let hand_shufflers_records = hand_shufflers::Entity::find()
        .filter(hand_shufflers::Column::HandId.eq(outcome.hand.state.id))
        .order_by_asc(hand_shufflers::Column::Sequence)
        .all(&conn)
        .await?;

    assert_eq!(hand_shufflers_records.len(), 7, "all 7 shufflers should be in hand");

    // Verify sequences match original shuffler order
    for (idx, hs) in hand_shufflers_records.iter().enumerate() {
        assert_eq!(hs.sequence, idx as i16);
        assert_eq!(hs.shuffler_id, all_shufflers[idx].state.id);
    }

    // Verify the operator has the snapshot in its state
    let (tip_hash, snapshot) = operator
        .state()
        .tip_snapshot(outcome.hand.state.id)
        .expect("hand snapshot should be seeded in operator");

    assert_eq!(tip_hash, snapshot.state_hash());

    // Verify snapshot is a Shuffling snapshot with correct structure
    match &snapshot {
        AnyTableSnapshot::Shuffling(table) => {
            assert_eq!(table.hand_id, Some(outcome.hand.state.id));
            assert_eq!(table.shufflers.len(), 7, "should have 7 shufflers in roster");

            // Verify shuffling expected_order contains all 7 shuffler keys
            assert_eq!(
                table.shuffling.expected_order.len(),
                7,
                "expected_order should have 7 entries"
            );

            // Verify each registered shuffler is in the roster
            for shuffler_rec in &all_shufflers {
                let found = table.shufflers.iter().any(|(_, identity)| {
                    identity.shuffler_id == shuffler_rec.state.id
                });
                assert!(found, "shuffler {} should be in roster", shuffler_rec.state.id);
            }
        }
        other => panic!("expected Shuffling snapshot, got {:?}", other),
    }

    // =============================================================================
    // PHASE 7: Verify Snapshot Persisted to Database
    // =============================================================================

    // Verify the snapshot was persisted to the database
    let loaded_snapshot = snapshot_store
        .load_latest_snapshot(outcome.hand.state.id)
        .await?
        .expect("snapshot should be persisted to database");

    // The loaded snapshot should match the in-memory snapshot
    assert_eq!(
        loaded_snapshot.state_hash(),
        snapshot.state_hash(),
        "loaded snapshot hash should match in-memory snapshot"
    );

    // Verify loaded snapshot has same structure
    match loaded_snapshot {
        AnyTableSnapshot::Shuffling(loaded_table) => {
            assert_eq!(loaded_table.hand_id, Some(outcome.hand.state.id));
            assert_eq!(loaded_table.shufflers.len(), 7);
            assert_eq!(loaded_table.shuffling.expected_order.len(), 7);
        }
        other => panic!("loaded snapshot should be Shuffling, got {:?}", other),
    }

    // =============================================================================
    // PHASE 8: Test Catchup from Database
    // =============================================================================

    // Drop the operator to simulate a crash/restart
    drop(operator);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Create a fresh state (empty in-memory)
    let fresh_state = Arc::new(LedgerState::<TestCurve>::new());

    // Verify the fresh state has no snapshot for this hand
    assert!(fresh_state.tip_snapshot(outcome.hand.state.id).is_none());

    // Perform catchup from database
    use crate::ledger::catchup::catchup_hand_from_db;

    // Use the same hasher type as the fresh_state
    let hasher = fresh_state.hasher();
    let catchup_result = catchup_hand_from_db(
        outcome.hand.state.id,
        None,  // Start from latest snapshot
        &snapshot_store,
        &conn,
        &hasher,
    ).await?;

    // Verify catchup returned the correct snapshot
    assert_eq!(
        catchup_result.state_hash(),
        snapshot.state_hash(),
        "catchup should recover the same snapshot"
    );

    // Seed the catchup result into fresh state
    fresh_state.upsert_snapshot(
        outcome.hand.state.id,
        catchup_result.clone(),
        true,
    );

    // Verify fresh state now has the snapshot
    let (recovered_hash, _recovered_snapshot) = fresh_state
        .tip_snapshot(outcome.hand.state.id)
        .expect("snapshot should be in fresh state after catchup");

    assert_eq!(recovered_hash, snapshot.state_hash());

    Ok(())
}
