/// # Complete Game Launch and Shuffle Flow Example
///
/// This example demonstrates:
/// 1. Setting up a lobby service with in-memory storage
/// 2. Hosting a game
/// 3. Registering 7 shufflers and 9 players
/// 4. Commencing the game to create an initial shuffling snapshot
/// 5. Having shufflers perform their turns using ShufflerHandState::try_emit_shuffle
/// 6. Using the transition system to process shuffle messages
///
/// Run with: `cargo run --example game_launch_and_shuffle_flow`
use anyhow::Result;
use ark_bn254::G1Projective as Curve;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_ec::PrimeGroup;
use ark_ff::Zero;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use ark_std::UniformRand;
use std::sync::Arc;

use legit_poker::engine::nl::types::{HandConfig, PlayerId, SeatId, TableStakes};
use legit_poker::ledger::actor::ShufflerActor;
use legit_poker::ledger::hash::LedgerHasherSha256;
use legit_poker::ledger::lobby::service::{LobbyService, LobbyServiceFactory};
use legit_poker::ledger::lobby::types::{
    CommenceGameParams, GameLobbyConfig, PlayerRecord, ShufflerRecord, ShufflerRegistrationConfig,
};
use legit_poker::ledger::messages::AnyMessageEnvelope;
use legit_poker::ledger::snapshot::AnyTableSnapshot;
use legit_poker::ledger::transition::apply_transition;
use legit_poker::ledger::types::ShufflerId;
use legit_poker::ledger::typestate::MaybeSaved;
use legit_poker::ledger::CanonicalKey;
use legit_poker::shuffler::{ShufflerEngine, ShufflerHandState};

// Type aliases for clarity
type Schnorr254 = Schnorr<Curve, Sha256>;

const NUM_SHUFFLERS: usize = 7;
const NUM_PLAYERS: usize = 9;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(true)
        .init();

    println!("🎰 Starting Complete Game Launch and Shuffle Flow Example");
    println!("================================================\n");

    // Step 1: Initialize RNG and hasher
    println!("📊 Step 1: Initializing cryptographic components");
    let mut rng = StdRng::seed_from_u64(42);
    let hasher = Arc::new(LedgerHasherSha256);

    // Step 2: Set up the lobby service
    println!("🏛️  Step 2: Setting up lobby service with in-memory storage");
    let lobby_service = LobbyServiceFactory::<Curve>::in_memory();

    // Step 3: Generate shuffler identities and keys
    println!(
        "🔀 Step 3: Generating {} shuffler identities",
        NUM_SHUFFLERS
    );
    let shuffler_engines = generate_shuffler_engines(&mut rng)?;
    let shuffler_records = create_shuffler_records(&shuffler_engines);

    // Compute aggregated public key for all shufflers
    let _aggregated_public_key = compute_aggregated_public_key(&shuffler_engines);
    println!(
        "   ✅ Aggregated public key computed from {} shufflers",
        NUM_SHUFFLERS
    );

    // Step 4: Generate player identities and keys
    println!("👥 Step 4: Generating {} player identities", NUM_PLAYERS);
    let player_keys = generate_player_keys(&mut rng, NUM_PLAYERS);
    let player_records = create_player_records(&player_keys);

    // Step 5: Host a game
    println!("\n🎮 Step 5: Hosting a new game");
    let host = player_records[0].clone();
    let lobby_config = GameLobbyConfig {
        stakes: TableStakes {
            ante: 10,
            small_blind: 50,
            big_blind: 100,
        },
        max_players: 9,
        rake_bps: 500, // 5%
        name: "High Stakes ZK Poker".to_string(),
        currency: "CHIPS".to_string(),
        buy_in: 10_000,
        min_players_to_start: 6,
        check_raise_allowed: true,
        action_time_limit: std::time::Duration::from_secs(30),
    };

    let game_metadata = lobby_service.host_game(host, lobby_config).await?;
    let game_record = game_metadata.record;
    println!("   ✅ Game created with ID: {}", game_record.state.id);

    // Step 6: Register shufflers
    println!("\n🔀 Step 6: Registering {} shufflers", NUM_SHUFFLERS);
    let mut registered_shufflers = Vec::new();
    for (idx, shuffler_record) in shuffler_records.into_iter().enumerate() {
        let cfg = ShufflerRegistrationConfig {
            sequence: Some(idx as u16),
        };
        let output = lobby_service
            .register_shuffler(&game_record, shuffler_record.clone(), cfg)
            .await?;
        println!(
            "   ✅ Shuffler {} registered with sequence {}",
            idx, output.assigned_sequence
        );
        registered_shufflers.push((output.shuffler, output.assigned_sequence));
    }

    // Step 7: Join players to the game
    println!("\n👥 Step 7: Joining {} players to the game", NUM_PLAYERS);
    let mut joined_players = Vec::new();
    for (idx, player_record) in player_records.into_iter().enumerate() {
        let seat_id = idx as SeatId;
        let output = lobby_service
            .join_game(&game_record, player_record.clone(), Some(seat_id))
            .await?;
        println!("   ✅ Player {} joined and seated at seat {}", idx, seat_id);
        joined_players.push((output.player, seat_id));
    }

    // Step 8: Prepare and commence the game
    println!("\n🚀 Step 8: Commencing the game");
    let hand_config = HandConfig {
        stakes: game_record.stakes.clone(),
        button: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        check_raise_allowed: true,
    };

    let commence_params = CommenceGameParams {
        game_id: game_record.state.id,
        hand_no: 1,
        button_seat: hand_config.button,
        small_blind_seat: hand_config.small_blind_seat,
        big_blind_seat: hand_config.big_blind_seat,
        deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
    };

    let outcome = lobby_service
        .commence_game(hasher.as_ref(), commence_params)
        .await?;

    let hand_id = outcome.hand.state.id;
    let mut current_snapshot = outcome.initial_snapshot.clone();

    println!("   ✅ Game commenced!");
    println!("      Hand ID: {}", hand_id);
    println!("      Initial sequence: {}", current_snapshot.sequence);
    println!(
        "      Shuffler order: {} shufflers expected",
        current_snapshot.shuffling.expected_order.len()
    );
    println!(
        "      Initial deck size: {}",
        current_snapshot.shuffling.initial_deck.len()
    );

    // Step 9: Create ShufflerHandState for each shuffler
    println!("\n🎲 Step 9: Initializing shuffler states");
    let mut shuffler_states = Vec::new();
    for (idx, engine) in shuffler_engines.iter().enumerate() {
        let mut hand_seed = [0u8; 32];
        rng.fill_bytes(&mut hand_seed);

        let state = ShufflerHandState::from_shuffling_snapshot(
            &current_snapshot,
            &engine.public_key,
            hand_seed,
        )?;
        shuffler_states.push(state);
        println!("   ✅ Shuffler {} state initialized", idx);
    }

    // Step 10: Execute the shuffle phase
    println!("\n🔄 Step 10: Executing shuffle phase");
    println!("   Each shuffler will shuffle the deck in order...\n");

    // Loop through each expected shuffle operation
    for shuffle_round in 0..NUM_SHUFFLERS {
        // Try each shuffler to find whose turn it is
        let mut acted = false;
        for shuffler_index in 0..NUM_SHUFFLERS {
            let engine = &shuffler_engines[shuffler_index];
            let (shuffler_record, _sequence) = &registered_shufflers[shuffler_index];
            let shuffler_state = &mut shuffler_states[shuffler_index];

            // Create actor
            let shuffler_key = CanonicalKey::new(engine.public_key.clone());
            let actor = ShufflerActor {
                shuffler_id: shuffler_record.state.id,
                shuffler_key,
            };

            // Try to emit shuffle - will return None if not this shuffler's turn
            let any_envelope =
                match shuffler_state.try_emit_shuffle::<Schnorr254, _>(engine, &actor)? {
                    Some(env) => env,
                    None => continue, // Not this shuffler's turn, try next one
                };

            // This shuffler successfully generated a shuffle
            println!(
                "   🎯 Shuffler {} performing shuffle {}/{}...",
                shuffler_index,
                shuffle_round + 1,
                NUM_SHUFFLERS
            );
            acted = true;

            // Extract the shuffle message to apply transition
            let shuffle_envelope = extract_shuffle_envelope(&any_envelope)?;

            // Apply the transition - errors will propagate via ?
            let next_snapshot =
                apply_transition(current_snapshot.clone(), &shuffle_envelope, hasher.as_ref())?;

            match next_snapshot {
                AnyTableSnapshot::Shuffling(snapshot) => {
                    println!(
                        "      ✅ Shuffle applied, sequence: {}, steps: {}/{}",
                        snapshot.sequence,
                        snapshot.shuffling.steps.len(),
                        NUM_SHUFFLERS
                    );

                    // Update all shuffler states with the new deck and buffered message
                    // This simulates how the coordinator updates states after receiving messages
                    for state in shuffler_states.iter_mut() {
                        state.shuffling.latest_deck = snapshot.shuffling.final_deck.clone();
                        // Add the shuffle envelope to buffered for turn tracking
                        state.shuffling.buffered.push(shuffle_envelope.clone());
                    }

                    current_snapshot = snapshot;
                    break; // Break inner loop to proceed to next shuffle round
                }
                AnyTableSnapshot::Dealing(snapshot) => {
                    println!("\n   🎉 Shuffling phase complete!");
                    println!("      ✅ Transitioned to Dealing phase");
                    println!("      Final sequence: {}", snapshot.sequence);
                    println!("      Card plan size: {}", snapshot.dealing.card_plan.len());
                    println!("      Assignments: {}", snapshot.dealing.assignments.len());
                    println!(
                        "      Total shuffle steps: {}",
                        snapshot.shuffling.steps.len()
                    );
                    return Ok(()); // Successfully completed - exit function
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "unexpected snapshot variant after shuffle: {:?}",
                        std::mem::discriminant(&other)
                    ));
                }
            }
        }

        if !acted {
            return Err(anyhow::anyhow!(
                "No shuffler was able to act in shuffle round {}",
                shuffle_round + 1
            ));
        }
    }

    println!("\n✅ Complete flow executed successfully!");
    println!("   - Lobby service initialized");
    println!("   - Game hosted and configured");
    println!("   - {} shufflers registered", NUM_SHUFFLERS);
    println!("   - {} players joined", NUM_PLAYERS);
    println!("   - Game commenced with initial snapshot");
    println!("   - {} shuffle operations completed", NUM_SHUFFLERS);
    println!("   - Transitioned to dealing phase");
    println!("\n🎉 All systems operational!\n");

    Ok(())
}

// Helper functions

fn generate_shuffler_engines(rng: &mut StdRng) -> Result<Vec<ShufflerEngine<Curve, Schnorr254>>> {
    (0..NUM_SHUFFLERS)
        .map(|_| ShufflerEngine::generate(rng))
        .collect()
}

fn create_shuffler_records(
    engines: &[ShufflerEngine<Curve, Schnorr254>],
) -> Vec<ShufflerRecord<Curve, MaybeSaved<ShufflerId>>> {
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

fn compute_aggregated_public_key(engines: &[ShufflerEngine<Curve, Schnorr254>]) -> Curve {
    engines
        .iter()
        .fold(Curve::zero(), |acc, engine| acc + engine.public_key)
}

fn generate_player_keys(
    rng: &mut StdRng,
    count: usize,
) -> Vec<(<Curve as PrimeGroup>::ScalarField, Curve)> {
    (0..count)
        .map(|_| {
            let secret = <Curve as PrimeGroup>::ScalarField::rand(rng);
            let public_key = Curve::generator() * secret;
            (secret, public_key)
        })
        .collect()
}

fn create_player_records(
    keys: &[(<Curve as PrimeGroup>::ScalarField, Curve)],
) -> Vec<PlayerRecord<Curve, MaybeSaved<PlayerId>>> {
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

fn extract_shuffle_envelope(
    envelope: &AnyMessageEnvelope<Curve>,
) -> Result<
    legit_poker::ledger::messages::EnvelopedMessage<
        Curve,
        legit_poker::ledger::messages::GameShuffleMessage<Curve>,
    >,
> {
    use legit_poker::ledger::actor::AnyActor;
    use legit_poker::ledger::messages::{AnyGameMessage, EnvelopedMessage};
    use legit_poker::signing::WithSignature;

    let actor = match &envelope.actor {
        AnyActor::Shuffler {
            shuffler_id,
            shuffler_key,
        } => ShufflerActor {
            shuffler_id: *shuffler_id,
            shuffler_key: shuffler_key.clone(),
        },
        _ => {
            return Err(anyhow::anyhow!(
                "expected shuffler actor, got different actor type"
            ))
        }
    };

    match &envelope.message.value {
        AnyGameMessage::Shuffle(message) => Ok(EnvelopedMessage {
            hand_id: envelope.hand_id,
            game_id: envelope.game_id,
            actor,
            nonce: envelope.nonce,
            public_key: envelope.public_key.clone(),
            message: WithSignature {
                value: message.clone(),
                signature: envelope.message.signature.clone(),
            },
        }),
        _ => Err(anyhow::anyhow!(
            "expected shuffle message, got different message type"
        )),
    }
}
