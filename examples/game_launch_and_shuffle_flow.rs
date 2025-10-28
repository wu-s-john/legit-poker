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
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Zero;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use ark_std::UniformRand;
use std::sync::Arc;
use tracing_subscriber::fmt::time::Uptime;
use tracing_subscriber::EnvFilter;

use legit_poker::engine::nl::types::{HandConfig, PlayerId, SeatId, TableStakes};
use legit_poker::ledger::actor::ShufflerActor;
use legit_poker::ledger::hash::LedgerHasherSha256;
use legit_poker::ledger::lobby::service::{LobbyService, LobbyServiceFactory};
use legit_poker::ledger::lobby::types::{
    CommenceGameParams, GameLobbyConfig, PlayerRecord, ShufflerRecord, ShufflerRegistrationConfig,
};
use legit_poker::ledger::messages::{
    AnyMessageEnvelope, GameBlindingDecryptionMessage, GamePartialUnblindingShareMessage,
};
use legit_poker::ledger::snapshot::{AnyTableSnapshot, TableAtDealing};
use legit_poker::ledger::transition::apply_transition;
use legit_poker::ledger::types::ShufflerId;
use legit_poker::ledger::typestate::MaybeSaved;
use legit_poker::ledger::CanonicalKey;
use legit_poker::showdown::decode_card;
use legit_poker::shuffler::{ShufflerApi, ShufflerEngine, ShufflerHandState};
use legit_poker::shuffling::player_decryption::combine_unblinding_shares;
use legit_poker::shuffling::recover_card_value;

// Type aliases for clarity
type Schnorr254 = Schnorr<Curve, Sha256>;

const NUM_SHUFFLERS: usize = 5;
const NUM_PLAYERS: usize = 7;
const LOG_TARGET: &str = "example::game_launch_and_shuffle_flow";

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing - honor RUST_LOG if provided
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_timer(Uptime::default())
        .init();

    tracing::info!(target: LOG_TARGET, "🎰 Starting Complete Game Launch and Shuffle Flow Example");
    tracing::info!(target: LOG_TARGET, "================================================");

    // Step 1: Initialize RNG and hasher
    tracing::info!(target: LOG_TARGET, "📊 Step 1: Initializing cryptographic components");
    let mut rng = StdRng::seed_from_u64(42);
    let hasher = Arc::new(LedgerHasherSha256);

    // Step 2: Set up the lobby service
    tracing::info!(target: LOG_TARGET, "🏛️  Step 2: Setting up lobby service with in-memory storage");
    let lobby_service = LobbyServiceFactory::<Curve>::in_memory();

    // Step 3: Generate shuffler identities and keys
    tracing::info!(
        target: LOG_TARGET,
        num_shufflers = NUM_SHUFFLERS,
        "🔀 Step 3: Generating shuffler identities"
    );
    let shuffler_engines = generate_shuffler_engines(&mut rng)?;
    let shuffler_records = create_shuffler_records(&shuffler_engines);

    // Compute aggregated public key for all shufflers
    let _aggregated_public_key = compute_aggregated_public_key(&shuffler_engines);
    tracing::debug!(
        target: LOG_TARGET,
        num_shufflers = NUM_SHUFFLERS,
        "✅ Aggregated public key computed from shufflers"
    );

    // Step 4: Generate player identities and keys
    tracing::info!(
        target: LOG_TARGET,
        num_players = NUM_PLAYERS,
        "👥 Step 4: Generating player identities"
    );
    let player_keys = generate_player_keys(&mut rng, NUM_PLAYERS);
    let player_records = create_player_records(&player_keys);

    // Step 5: Host a game
    tracing::info!(target: LOG_TARGET, "🎮 Step 5: Hosting a new game");
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
    tracing::debug!(
        target: LOG_TARGET,
        game_id = game_record.state.id,
        "✅ Game created"
    );

    // Step 6: Register shufflers
    tracing::info!(
        target: LOG_TARGET,
        num_shufflers = NUM_SHUFFLERS,
        "🔀 Step 6: Registering shufflers"
    );
    let mut registered_shufflers = Vec::new();
    for (idx, shuffler_record) in shuffler_records.into_iter().enumerate() {
        let cfg = ShufflerRegistrationConfig {
            sequence: Some(idx as u16),
        };
        let output = lobby_service
            .register_shuffler(&game_record, shuffler_record.clone(), cfg)
            .await?;
        tracing::debug!(
            target: LOG_TARGET,
            shuffler_index = idx,
            sequence = output.assigned_sequence,
            "✅ Shuffler registered"
        );
        registered_shufflers.push((output.shuffler, output.assigned_sequence));
    }

    // Step 7: Join players to the game
    tracing::info!(
        target: LOG_TARGET,
        num_players = NUM_PLAYERS,
        "👥 Step 7: Joining players to the game"
    );
    let mut joined_players = Vec::new();
    for (idx, player_record) in player_records.into_iter().enumerate() {
        let seat_id = idx as SeatId;
        let output = lobby_service
            .join_game(&game_record, player_record.clone(), Some(seat_id))
            .await?;
        tracing::debug!(
            target: LOG_TARGET,
            player_index = idx,
            seat_id = seat_id,
            "✅ Player joined and seated"
        );
        joined_players.push((output.player, seat_id));
    }

    // Step 8: Prepare and commence the game
    tracing::info!(target: LOG_TARGET, "🚀 Step 8: Commencing the game");
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

    tracing::info!(target: LOG_TARGET, "   ✅ Game commenced!");
    tracing::debug!(
        target: LOG_TARGET,
        hand_id = hand_id,
        sequence = current_snapshot.sequence,
        expected_shufflers = current_snapshot.shuffling.expected_order.len(),
        initial_deck_size = current_snapshot.shuffling.initial_deck.len(),
        "Game commencement details"
    );

    // Step 9: Create ShufflerHandState for each shuffler
    tracing::info!(target: LOG_TARGET, "🎲 Step 9: Initializing shuffler states");
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
        tracing::debug!(
            target: LOG_TARGET,
            shuffler_index = idx,
            "✅ Shuffler state initialized"
        );
    }

    // Step 10: Execute the shuffle phase
    tracing::info!(target: LOG_TARGET, "🔄 Step 10: Executing shuffle phase");
    tracing::info!(target: LOG_TARGET, "   Each shuffler will shuffle the deck in order...");

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
            tracing::info!(
                target: LOG_TARGET,
                shuffler_index = shuffler_index,
                shuffle_number = shuffle_round + 1,
                total_shuffles = NUM_SHUFFLERS,
                "🎯 Shuffler performing shuffle"
            );
            acted = true;

            // Extract the shuffle message to apply transition
            let shuffle_envelope = extract_shuffle_envelope(&any_envelope)?;

            // Apply the transition - errors will propagate via ?
            let next_snapshot =
                apply_transition(current_snapshot.clone(), &shuffle_envelope, hasher.as_ref())?;

            match next_snapshot {
                AnyTableSnapshot::Shuffling(snapshot) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        sequence = snapshot.sequence,
                        steps_completed = snapshot.shuffling.steps.len(),
                        total_steps = NUM_SHUFFLERS,
                        "✅ Shuffle applied"
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
                AnyTableSnapshot::Dealing(dealing_snapshot) => {
                    tracing::info!(target: LOG_TARGET, "🎉 Shuffling phase complete!");
                    tracing::info!(target: LOG_TARGET, "   ✅ Transitioned to Dealing phase");
                    tracing::debug!(
                        target: LOG_TARGET,
                        sequence = dealing_snapshot.sequence,
                        card_plan_size = dealing_snapshot.dealing.card_plan.len(),
                        assignments = dealing_snapshot.dealing.assignments.len(),
                        total_shuffle_steps = dealing_snapshot.shuffling.steps.len(),
                        "Dealing phase details"
                    );

                    // Shadow current_snapshot with the dealing snapshot and exit the shuffle loop
                    let mut current_snapshot = dealing_snapshot;

                    // Continue directly into Step 11 & 12 here before breaking
                    execute_decryption_phase(
                        &mut current_snapshot,
                        &shuffler_engines,
                        &joined_players,
                        &player_keys,
                        &_aggregated_public_key,
                        &mut rng,
                        hasher.as_ref(),
                    )?;

                    break; // Exit shuffle loop - decryption is complete
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

    tracing::info!(
        target: LOG_TARGET,
        num_shufflers = NUM_SHUFFLERS,
        num_players = NUM_PLAYERS,
        "{}",
        format!(
            "✅ Complete flow executed successfully!\n\
             ================================================\n\
             - Lobby service initialized\n\
             - Game hosted and configured\n\
             - {} shufflers registered\n\
             - {} players joined\n\
             - Game commenced with initial snapshot\n\
             - {} shuffle operations completed\n\
             - Transitioned to dealing phase\n\
             - All players decrypted their hole cards\n\
             🎉 All systems operational!",
            NUM_SHUFFLERS, NUM_PLAYERS, NUM_SHUFFLERS
        )
    );

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

/// Execute the decryption phase (Steps 11-12)
fn execute_decryption_phase(
    current_snapshot: &mut TableAtDealing<Curve>,
    shuffler_engines: &[ShufflerEngine<Curve, Schnorr254>],
    joined_players: &[(
        PlayerRecord<Curve, legit_poker::ledger::typestate::Saved<PlayerId>>,
        SeatId,
    )],
    player_secret_keys: &[(<Curve as PrimeGroup>::ScalarField, Curve)],
    aggregated_shuffler_public_key: &Curve,
    rng: &mut StdRng,
    hasher: &dyn legit_poker::ledger::hash::LedgerHasher,
) -> Result<()> {
    // Step 11: Create ShufflerHandStates from dealing snapshot
    tracing::info!(target: LOG_TARGET, "📋 Step 11: Creating shuffler hand states from dealing snapshot");

    let mut shuffler_states: Vec<ShufflerHandState<Curve>> = shuffler_engines
        .iter()
        .map(|engine| {
            let mut rng_seed = [0u8; 32];
            rng.fill_bytes(&mut rng_seed);

            ShufflerHandState::from_dealing_snapshot(
                &current_snapshot,
                &engine.public_key,
                rng_seed,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    tracing::debug!(
        target: LOG_TARGET,
        num_states = shuffler_states.len(),
        "✅ Created shuffler hand states"
    );

    let aggregated_secret = shuffler_engines
        .iter()
        .fold(<Curve as PrimeGroup>::ScalarField::zero(), |acc, engine| {
            acc + engine.encryption_scalar()
        });
    for (idx, engine) in shuffler_engines.iter().enumerate() {
        let reconstructed = Curve::generator() * engine.encryption_scalar();
        tracing::debug!(
            target: LOG_TARGET,
            shuffler_index = idx,
            ?reconstructed,
            matches = (reconstructed == engine.public_key),
            "Shuffler key consistency check"
        );
    }
    let aggregated_public_from_secret = Curve::generator() * aggregated_secret;
    tracing::debug!(
        target: LOG_TARGET,
        ?aggregated_public_from_secret,
        matches = (aggregated_public_from_secret == *aggregated_shuffler_public_key),
        "Aggregated secret/public key consistency check"
    );

    // Step 12: Extract and decrypt player hole cards
    tracing::info!(target: LOG_TARGET, "🎴 Step 12: Extracting and decrypting player hole cards");

    let player_hole_cards = current_snapshot.dealing.get_player_hole_cards()?;
    tracing::info!(
        target: LOG_TARGET,
        num_players = player_hole_cards.len(),
        "✅ Found players with hole cards"
    );

    // Create a map from seat ID to player public key for correct lookups
    let seat_to_player: std::collections::HashMap<_, _> = joined_players
        .iter()
        .map(|(player, seat)| (*seat, player.public_key.clone()))
        .collect();

    tracing::debug!(
        target: LOG_TARGET,
        example_seat_map = ?seat_to_player.iter().collect::<Vec<_>>(),
        snapshot_seating = ?current_snapshot
            .seating
            .iter()
            .map(|(seat, key)| (*seat, key.clone()))
            .collect::<Vec<_>>(),
        "Debug seat mappings"
    );

    // Create a map from seat ID to player secret key for correct lookups
    let seat_to_secret: std::collections::HashMap<_, _> = joined_players
        .iter()
        .enumerate()
        .map(|(idx, (_, seat))| (*seat, player_secret_keys[idx].0))
        .collect();

    for (seat, hole_cards) in &player_hole_cards {
        let player_pk = seat_to_player
            .get(seat)
            .ok_or_else(|| anyhow::anyhow!("Player public key not found for seat {}", seat))?
            .clone();
        let player_secret = *seat_to_secret
            .get(seat)
            .ok_or_else(|| anyhow::anyhow!("Player secret key not found for seat {}", seat))?;

        let derived_public = Curve::generator() * player_secret;
        tracing::debug!(
            target: LOG_TARGET,
            seat = seat,
            ?player_pk,
            ?derived_public,
            matches = (derived_public == player_pk),
            "Player secret/public key consistency check"
        );

        tracing::info!(target: LOG_TARGET, seat = seat, "👤 Processing player");

        for hole_card in hole_cards {
            tracing::info!(
                target: LOG_TARGET,
                hole_index = hole_card.hole_index,
                "   🎴 Decrypting hole card"
            );

            // Use the snapshot-provided deal index, which encodes the global dealing order
            let deal_index = hole_card.deal_index;
            if deal_index != hole_card.hole_index {
                tracing::debug!(
                    target: LOG_TARGET,
                    seat = hole_card.seat,
                    hole_index = hole_card.hole_index,
                    deal_index,
                    "Hole card has non-trivial deal index"
                );
            }

            let deck_cipher = &hole_card.cipher;
            let deck_plain = (deck_cipher.c2 - (deck_cipher.c1 * aggregated_secret)).into_affine();
            let mut expected_card_index = None;
            for candidate in 0u8..52 {
                let candidate_point = (Curve::generator()
                    * <Curve as PrimeGroup>::ScalarField::from(candidate as u64))
                .into_affine();
                if candidate_point == deck_plain {
                    expected_card_index = Some(candidate);
                    break;
                }
            }
            tracing::debug!(
                target: LOG_TARGET,
                ?deck_plain,
                expected_card_index = ?expected_card_index,
                "Deck plaintext before blinding"
            );

            // Phase A: Blinding contributions
            tracing::debug!(
                target: LOG_TARGET,
                num_shufflers = NUM_SHUFFLERS,
                "      📦 Collecting blinding contributions"
            );
            for (idx, engine) in shuffler_engines.iter().enumerate() {
                let state = &mut shuffler_states[idx];
                let ctx = state.next_metadata_envelope();

                let (_, any_envelope) = engine.player_blinding_and_sign(
                    aggregated_shuffler_public_key,
                    &ctx,
                    deal_index,
                    &player_pk,
                    rng,
                )?;

                let blinding_envelope: legit_poker::ledger::messages::EnvelopedMessage<
                    Curve,
                    GameBlindingDecryptionMessage<Curve>,
                > = (&any_envelope).try_into()?;
                let any_snapshot =
                    apply_transition(current_snapshot.clone(), &blinding_envelope, hasher)?;
                let dealing_ref: &TableAtDealing<Curve> = (&any_snapshot).try_into()?;
                *current_snapshot = dealing_ref.clone();

                tracing::debug!(
                    target: LOG_TARGET,
                    shuffler_index = idx,
                    "         ✅ Shuffler blinding applied"
                );
            }

            // Get player ciphertext from snapshot
            let player_ciphertext = current_snapshot
                .dealing
                .player_ciphertexts
                .get(&(hole_card.seat, hole_card.hole_index))
                .ok_or_else(|| anyhow::anyhow!("player ciphertext not found"))?
                .clone();

            // Phase B: Unblinding shares
            tracing::debug!(
                target: LOG_TARGET,
                num_shufflers = NUM_SHUFFLERS,
                "      🔓 Collecting unblinding shares"
            );
            let mut collected_unblinding_shares = Vec::with_capacity(NUM_SHUFFLERS);
            let mut advanced_past_dealing = false;
            for (idx, engine) in shuffler_engines.iter().enumerate() {
                let state = &mut shuffler_states[idx];
                let ctx = state.next_metadata_envelope();

                let (_, any_envelope) = engine.player_unblinding_and_sign(
                    &ctx,
                    deal_index,
                    &player_pk,
                    &player_ciphertext,
                    rng,
                )?;

                let unblinding_envelope: legit_poker::ledger::messages::EnvelopedMessage<
                    Curve,
                    GamePartialUnblindingShareMessage<Curve>,
                > = (&any_envelope).try_into()?;
                collected_unblinding_shares.push(unblinding_envelope.message.value.share.clone());
                let any_snapshot =
                    apply_transition(current_snapshot.clone(), &unblinding_envelope, hasher)?;
                match any_snapshot {
                    AnyTableSnapshot::Dealing(dealing_ref) => {
                        *current_snapshot = dealing_ref.clone();
                    }
                    AnyTableSnapshot::Preflop(_) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            seat = hole_card.seat,
                            hole_index = hole_card.hole_index,
                            "Dealing phase complete after final unblinding share"
                        );
                        advanced_past_dealing = true;
                    }
                    other => {
                        return Err(anyhow::anyhow!(
                            "unexpected snapshot variant during unblinding: {:?}",
                            std::mem::discriminant(&other)
                        ));
                    }
                }

                tracing::debug!(
                    target: LOG_TARGET,
                    shuffler_index = idx,
                    "         ✅ Shuffler unblinding applied"
                );

                if advanced_past_dealing {
                    break;
                }
            }

            // Decrypt from snapshot shares
            let expected_mu = (player_ciphertext.blinded_base * aggregated_secret).into_affine();
            let combined_unblinding_debug =
                combine_unblinding_shares(&collected_unblinding_shares, NUM_SHUFFLERS)
                    .map_err(|e| anyhow::anyhow!(e))?
                    .into_affine();
            tracing::debug!(
                target: LOG_TARGET,
                ?expected_mu,
                ?combined_unblinding_debug,
                "Committee share comparison (expected vs combined)"
            );

            let decrypted_card = recover_card_value::<Curve>(
                &player_ciphertext,
                player_secret,
                collected_unblinding_shares,
                NUM_SHUFFLERS,
            )
            .map_err(|e| anyhow::anyhow!("{}", e))?;

            tracing::info!(
                target: LOG_TARGET,
                card_index = decrypted_card,
                card = %decode_card(decrypted_card),
                "      🎯 Decrypted card"
            );

            if advanced_past_dealing {
                return Ok(());
            }
        }
    }

    Ok(())
}
