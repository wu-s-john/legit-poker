#![cfg(test)]

use super::types::{
    CommenceGameOutcome, CommenceGameParams, GameLobbyConfig, GameMetadata, PlayerRecord,
    PlayerSeatSnapshot, RegisterShufflerOutput, ShufflerAssignment, ShufflerRecord,
    ShufflerRegistrationConfig,
};
use super::GameSetupError;
use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::{game_players, games, hand_player, hands};
use crate::db::{connect_to_postgres_db, postgres_test_url};
use crate::engine::nl::types::{HandConfig, PlayerId, SeatId, TableStakes};
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::AnyTableSnapshot;
use crate::ledger::state::LedgerState;
use crate::ledger::store::snapshot::PreparedSnapshot;
use crate::ledger::store::{EventStore, SeaOrmEventStore, SnapshotStore};
use crate::ledger::types::{GameId, ShufflerId};
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
    PaginatorTrait, QueryFilter, Statement,
};
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
        public_key: keys.player.bytes.clone(),
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
        public_key: keys.shuffler.bytes.clone(),
        state: MaybeSaved { id: None },
    };

    let shuffler_two = ShufflerRecord {
        display_name: "Shuffler Two".into(),
        public_key: TestKeys::new().shuffler.bytes.clone(),
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
            public_key: keys.player.bytes.clone(),
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
            public_key: extra_keys.player.bytes.clone(),
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
            public_key: keys.shuffler.bytes.clone(),
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?;

    let hand_cfg = HandConfig {
        stakes: config.stakes.clone(),
        button: 0,
        small_blind_seat: 0,
        big_blind_seat: 1,
        check_raise_allowed: true,
    };

    let params = CommenceGameParams {
        game: metadata.record.clone(),
        hand_no: 1,
        hand_config: hand_cfg,
        players: vec![
            PlayerSeatSnapshot::new(
                host_player.clone(),
                0,
                config.buy_in,
                keys.host.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                joiner.clone(),
                1,
                config.buy_in,
                keys.player.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                third_player.clone(),
                2,
                config.buy_in,
                extra_keys.player.point.clone(),
            ),
        ],
        shufflers: vec![ShufflerAssignment::new(
            registered.shuffler.clone(),
            registered.assigned_sequence,
            keys.shuffler.bytes.clone(),
            keys.shuffler_aggregated.clone(),
        )],
        deck_commitment: None,
        buy_in: config.buy_in,
        min_players: config.min_players_to_start,
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
            public_key: keys.player.bytes.clone(),
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
            public_key: extra_keys.player.bytes.clone(),
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
            public_key: keys.shuffler.bytes.clone(),
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?
    .shuffler;

    let params = CommenceGameParams {
        game: metadata.record.clone(),
        hand_no: 1,
        hand_config: HandConfig {
            stakes: config.stakes.clone(),
            button: 0,
            small_blind_seat: 0,
            big_blind_seat: 1,
            check_raise_allowed: true,
        },
        players: vec![
            PlayerSeatSnapshot::new(
                host_player.clone(),
                0,
                config.buy_in,
                keys.host.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                joiner.clone(),
                1,
                config.buy_in,
                keys.player.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                third_player.clone(),
                1,
                config.buy_in,
                extra_keys.player.point.clone(),
            ),
        ],
        shufflers: vec![ShufflerAssignment::new(
            shuffler,
            0,
            keys.shuffler.bytes.clone(),
            keys.shuffler_aggregated.clone(),
        )],
        deck_commitment: None,
        buy_in: config.buy_in,
        min_players: config.min_players_to_start,
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
            public_key: keys.player.bytes.clone(),
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
            public_key: keys.shuffler.bytes.clone(),
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?
    .shuffler;

    let params = CommenceGameParams {
        game: metadata.record.clone(),
        hand_no: 1,
        hand_config: HandConfig {
            stakes: config.stakes.clone(),
            button: 0,
            small_blind_seat: 0,
            big_blind_seat: 1,
            check_raise_allowed: true,
        },
        players: vec![
            PlayerSeatSnapshot::new(
                host_player.clone(),
                0,
                config.buy_in,
                keys.host.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                joiner.clone(),
                1,
                config.buy_in,
                keys.player.point.clone(),
            ),
        ],
        shufflers: vec![ShufflerAssignment::new(
            shuffler,
            0,
            keys.shuffler.bytes.clone(),
            keys.shuffler_aggregated.clone(),
        )],
        deck_commitment: None,
        buy_in: config.buy_in,
        min_players: config.min_players_to_start,
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
            public_key: keys.player.bytes.clone(),
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
            public_key: extra_keys.player.bytes.clone(),
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
            public_key: keys.shuffler.bytes.clone(),
            state: MaybeSaved { id: None },
        },
        ShufflerRegistrationConfig { sequence: Some(0) },
    )
    .await?
    .shuffler;

    let params = CommenceGameParams {
        game: metadata.record.clone(),
        hand_no: 1,
        hand_config: HandConfig {
            stakes: config.stakes.clone(),
            button: 0,
            small_blind_seat: 0,
            big_blind_seat: 1,
            check_raise_allowed: true,
        },
        players: vec![
            PlayerSeatSnapshot::new(
                host_player.clone(),
                0,
                config.buy_in,
                keys.host.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                joiner.clone(),
                1,
                config.buy_in - 1,
                keys.player.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                third_player.clone(),
                2,
                config.buy_in,
                extra_keys.player.point.clone(),
            ),
        ],
        shufflers: vec![ShufflerAssignment::new(
            shuffler,
            0,
            keys.shuffler.bytes.clone(),
            keys.shuffler_aggregated.clone(),
        )],
        deck_commitment: None,
        buy_in: config.buy_in,
        min_players: config.min_players_to_start,
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
            public_key: keys.player.bytes.clone(),
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
            public_key: keys.shuffler.bytes.clone(),
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
            public_key: extra_keys.player.bytes.clone(),
            seat_preference: Some(2),
            state: MaybeSaved { id: None },
        },
        Some(2),
    )
    .await?
    .player;

    let invalid_player_key = keys.player.point.clone();

    let params = CommenceGameParams {
        game: metadata.record.clone(),
        hand_no: 1,
        hand_config: HandConfig {
            stakes: config.stakes.clone(),
            button: 0,
            small_blind_seat: 0,
            big_blind_seat: 1,
            check_raise_allowed: true,
        },
        players: vec![
            PlayerSeatSnapshot::new(
                host_player.clone(),
                0,
                config.buy_in,
                keys.host.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                joiner.clone(),
                1,
                config.buy_in,
                keys.player.point.clone(),
            ),
            PlayerSeatSnapshot::new(
                third_player.clone(),
                1,
                config.buy_in,
                invalid_player_key.clone(),
            ),
        ],
        shufflers: vec![ShufflerAssignment::new(
            registered.shuffler.clone(),
            registered.assigned_sequence,
            keys.shuffler.bytes.clone(),
            keys.shuffler_aggregated.clone(),
        )],
        deck_commitment: None,
        buy_in: config.buy_in,
        min_players: config.min_players_to_start,
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
) -> Result<(GameMetadata, GameLobbyConfig)> {
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
        public_key: keys.host.bytes.clone(),
        seat_preference: Some(0),
        state: MaybeSaved { id: None },
    };
    let metadata = host_game_curve(lobby, host, config.clone()).await?;
    Ok((metadata, config))
}

async fn join_host(
    lobby: &Arc<TestLobby>,
    metadata: &GameMetadata,
) -> Result<PlayerRecord<Saved<PlayerId>>> {
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
    host: PlayerRecord<MaybeSaved<PlayerId>>,
    cfg: GameLobbyConfig,
) -> Result<GameMetadata, GameSetupError> {
    lobby.host_game(host, cfg).await
}

async fn join_game_curve(
    lobby: &Arc<TestLobby>,
    game: &super::types::GameRecord<Saved<GameId>>,
    player: PlayerRecord<MaybeSaved<PlayerId>>,
    seat: Option<SeatId>,
) -> Result<super::types::JoinGameOutput, GameSetupError> {
    lobby.join_game(game, player, seat).await
}

async fn register_shuffler_curve(
    lobby: &Arc<TestLobby>,
    game: &super::types::GameRecord<Saved<GameId>>,
    shuffler: ShufflerRecord<MaybeSaved<ShufflerId>>,
    cfg: ShufflerRegistrationConfig,
) -> Result<RegisterShufflerOutput, GameSetupError> {
    lobby.register_shuffler(game, shuffler, cfg).await
}

async fn commence_game_curve(
    lobby: &Arc<TestLobby>,
    operator: &LedgerOperator<TestCurve>,
    params: CommenceGameParams<TestCurve>,
) -> Result<CommenceGameOutcome<TestCurve>, GameSetupError> {
    lobby.commence_game(operator, params).await
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
    let operator = LedgerOperator::new(
        verifier,
        tx,
        Arc::clone(&event_store),
        Arc::clone(&state),
        events_tx.clone(),
        snapshots_tx.clone(),
    );
    let worker = LedgerWorker::new(
        rx,
        Arc::clone(&event_store),
        Arc::clone(&snapshot_store),
        Arc::clone(&state),
        events_tx,
        snapshots_tx,
    );
    if let Err(err) = operator.start(worker).await {
        eprintln!("skipping lobby test: failed to start operator ({err})");
        return None;
    }
    Some(operator)
}
