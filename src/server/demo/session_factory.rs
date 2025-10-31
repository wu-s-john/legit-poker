use std::sync::Arc;

use anyhow::Result;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tracing::{debug, info};
use uuid::Uuid;

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::{HandConfig, PlayerId, SeatId, TableStakes};
use crate::ledger::lobby::service::LobbyServiceFactory;
use crate::ledger::lobby::types::{
    CommenceGameParams, GameLobbyConfig, PlayerRecord, ShufflerRecord, ShufflerRegistrationConfig,
};
use crate::ledger::snapshot::AnyTableSnapshot;
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::typestate::MaybeSaved;
use crate::ledger::LobbyService;
use crate::shuffler::{ShufflerEngine, ShufflerHandState};

use super::state::DemoState;

const LOG_TARGET: &str = "legit_poker::server::demo::session_factory";
const NUM_SHUFFLERS: usize = 5;
const NUM_PLAYERS: usize = 7;

type Schnorr254<C> = Schnorr<C, Sha256>;

/// Create a new demo session with all necessary setup.
/// Returns a DemoState in Initialized phase ready for shuffling.
pub fn create_demo_session<C>() -> Result<DemoState<C>>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    let demo_id = Uuid::new_v4();
    info!(
        target: LOG_TARGET,
        demo_id = %demo_id,
        "🎰 Creating new demo session"
    );

    // Step 1: Initialize RNG and hasher
    let mut rng = StdRng::from_entropy();
    let hasher = Arc::new(crate::ledger::hash::LedgerHasherSha256);

    // Step 2: Set up in-memory lobby service
    let lobby: Arc<dyn LobbyService<C>> = Arc::new(LobbyServiceFactory::<C>::in_memory());

    // Step 3: Generate shuffler identities and keys
    info!(
        target: LOG_TARGET,
        num_shufflers = NUM_SHUFFLERS,
        "🔀 Generating shuffler identities"
    );
    let shuffler_engines = generate_shuffler_engines(&mut rng)?;
    let shuffler_records = create_shuffler_records(&shuffler_engines);
    let aggregated_public_key = compute_aggregated_public_key(&shuffler_engines);

    // Step 4: Generate player identities
    info!(
        target: LOG_TARGET,
        num_players = NUM_PLAYERS,
        "👥 Generating player identities"
    );
    let player_keys = generate_player_keys(&mut rng, NUM_PLAYERS);
    let player_records = create_player_records(&player_keys);

    // Step 5: Host a game (using player 0 as host)
    info!(target: LOG_TARGET, "🎮 Hosting game");
    let host = player_records[0].clone();

    let lobby_config = build_lobby_config();
    let metadata = tokio::runtime::Handle::current()
        .block_on(lobby.host_game(host, lobby_config.clone()))?;

    let game_id: GameId = metadata.record.state.id;

    // Step 6: Register shufflers
    info!(
        target: LOG_TARGET,
        num_shufflers = NUM_SHUFFLERS,
        "🔀 Registering shufflers"
    );
    for (idx, shuffler_record) in shuffler_records.into_iter().enumerate() {
        let cfg = ShufflerRegistrationConfig {
            sequence: Some(idx as u16),
        };
        let output = tokio::runtime::Handle::current().block_on(
            lobby.register_shuffler(&metadata.record, shuffler_record.clone(), cfg),
        )?;
        debug!(
            target: LOG_TARGET,
            shuffler_index = idx,
            shuffler_id = ?output.shuffler.state.id,
            "✅ Shuffler registered"
        );
    }

    // Step 7: Join players to the game
    info!(
        target: LOG_TARGET,
        num_players = NUM_PLAYERS,
        "👥 Joining players"
    );
    let mut saved_player_records = Vec::with_capacity(NUM_PLAYERS);
    for (idx, player_record) in player_records.into_iter().enumerate() {
        let seat_id = idx as SeatId;
        let output = tokio::runtime::Handle::current().block_on(
            lobby.join_game(&metadata.record, player_record.clone(), Some(seat_id)),
        )?;
        saved_player_records.push((output.player, seat_id));
    }

    // Step 8: Commence the game
    info!(target: LOG_TARGET, "🚀 Commencing game");
    let hand_config = build_hand_config();
    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: hand_config.button,
        small_blind_seat: hand_config.small_blind_seat,
        big_blind_seat: hand_config.big_blind_seat,
        deck_commitment: None,
        player_stacks: None,
    };

    let outcome = tokio::runtime::Handle::current()
        .block_on(lobby.commence_game(hasher.as_ref(), params))?;

    let hand_id: HandId = outcome.hand.state.id;
    let initial_snapshot = outcome.initial_snapshot.clone();

    // Step 9: Initialize shuffler hand states
    info!(
        target: LOG_TARGET,
        "🎲 Initializing shuffler states"
    );
    let mut shuffler_states = Vec::with_capacity(NUM_SHUFFLERS);
    for (idx, engine) in shuffler_engines.iter().enumerate() {
        let mut hand_seed = [0u8; 32];
        rng.fill_bytes(&mut hand_seed);

        let state = ShufflerHandState::from_shuffling_snapshot(
            &initial_snapshot,
            &engine.public_key,
            hand_seed,
        )?;
        debug!(
            target: LOG_TARGET,
            shuffler_index = idx,
            "✅ Shuffler state initialized"
        );
        shuffler_states.push(state);
    }

    // Step 10: Create DemoState
    let demo_state = DemoState::new(
        demo_id,
        game_id,
        hand_id,
        outcome.nonce_seed,
        AnyTableSnapshot::Shuffling(initial_snapshot),
        shuffler_engines,
        shuffler_states,
        saved_player_records,
        player_keys,
        aggregated_public_key,
        rng,
    );

    info!(
        target: LOG_TARGET,
        demo_id = %demo_id,
        game_id = game_id,
        hand_id = hand_id,
        "✅ Demo session created successfully"
    );

    Ok(demo_state)
}

// Helper functions

fn generate_shuffler_engines<C>(rng: &mut StdRng) -> Result<Vec<ShufflerEngine<C, Schnorr254<C>>>>
where
    C: CurveGroup,
    C::ScalarField: PrimeField + UniformRand,
{
    (0..NUM_SHUFFLERS)
        .map(|_| ShufflerEngine::generate(rng))
        .collect()
}

fn create_shuffler_records<C>(
    engines: &[ShufflerEngine<C, Schnorr254<C>>],
) -> Vec<ShufflerRecord<C, MaybeSaved<ShufflerId>>>
where
    C: CurveGroup,
{
    engines
        .iter()
        .enumerate()
        .map(|(idx, engine)| ShufflerRecord {
            display_name: format!("Shuffler-{}", idx),
            public_key: engine.public_key.clone(),
            state: MaybeSaved { id: None },
        })
        .collect()
}

fn compute_aggregated_public_key<C>(engines: &[ShufflerEngine<C, Schnorr254<C>>]) -> C
where
    C: CurveGroup,
{
    engines
        .iter()
        .fold(C::zero(), |acc, engine| acc + engine.public_key)
}

fn generate_player_keys<C>(rng: &mut StdRng, count: usize) -> Vec<(C::ScalarField, C)>
where
    C: CurveGroup,
    C::ScalarField: PrimeField + UniformRand,
{
    (0..count)
        .map(|_| {
            let secret = C::ScalarField::rand(rng);
            let public_key = C::generator() * secret;
            (secret, public_key)
        })
        .collect()
}

fn create_player_records<C>(
    keys: &[(C::ScalarField, C)],
) -> Vec<PlayerRecord<C, MaybeSaved<PlayerId>>>
where
    C: CurveGroup,
{
    keys.iter()
        .enumerate()
        .map(|(idx, (_, public_key))| PlayerRecord {
            display_name: format!("Player-{}", idx),
            public_key: public_key.clone(),
            seat_preference: Some(idx as SeatId),
            state: MaybeSaved { id: None },
        })
        .collect()
}

fn build_lobby_config() -> GameLobbyConfig {
    use std::time::Duration;

    GameLobbyConfig {
        stakes: TableStakes {
            ante: 10,
            small_blind: 50,
            big_blind: 100,
        },
        max_players: 9,
        rake_bps: 500,
        name: "High Stakes ZK Poker".to_string(),
        currency: "CHIPS".to_string(),
        buy_in: 10_000,
        min_players_to_start: 6,
        check_raise_allowed: true,
        action_time_limit: Duration::from_secs(30),
    }
}

fn build_hand_config() -> HandConfig {
    HandConfig {
        stakes: TableStakes {
            ante: 10,
            small_blind: 50,
            big_blind: 100,
        },
        button: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        check_raise_allowed: true,
    }
}
