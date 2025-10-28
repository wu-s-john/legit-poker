use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::StreamExt;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::{HandConfig, PlayerId, SeatId, TableStakes};
use crate::ledger::actor::ShufflerActor;
use crate::ledger::hash::{LedgerHasher, LedgerHasherSha256};
use crate::ledger::lobby::service::LobbyServiceFactory;
use crate::ledger::lobby::types::{
    CommenceGameParams, GameLobbyConfig, PlayerRecord, ShufflerRecord, ShufflerRegistrationConfig,
};
use crate::ledger::messages::{AnyMessageEnvelope, EnvelopedMessage, FinalizedAnyMessageEnvelope};
use crate::ledger::snapshot::{
    clone_snapshot_for_failure, AnyTableSnapshot, SnapshotStatus, TableAtDealing, TableAtShuffling,
};
use crate::ledger::transition::apply_transition;
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::CanonicalKey;
use crate::server::demo::{DemoStreamEvent, VIEWER_NAME};
use crate::server::error::ApiError;
use crate::server::routes::ServerContext;
use crate::showdown::{decode_card, Index as CardIndex};
use crate::shuffler::{ShufflerApi, ShufflerEngine, ShufflerHandState};
use crate::shuffling::player_decryption::{recover_card_value, PartialUnblindingShare};

const LOG_TARGET: &str = "legit_poker::server::demo::in_memory_stream";
const NUM_SHUFFLERS: usize = 5;
const NUM_PLAYERS: usize = 7;
const CHANNEL_BUFFER_SIZE: usize = 512;

type Schnorr254<C> = Schnorr<C, Sha256>;

#[derive(Debug, Deserialize)]
pub struct DemoStreamQuery {
    pub public_key: Option<String>,
}

/// Entry point for the in-memory SSE demo stream.
/// Each request runs independently with no database or coordinator dependencies.
pub async fn stream_demo_game_in_memory<C>(
    ctx: Arc<ServerContext<C>>,
    query: DemoStreamQuery,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError>
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
    if query.public_key.is_some() {
        return Err(ApiError::bad_request(
            "public_key query parameter is not supported for the in-memory demo stream",
        ));
    }

    let (event_tx, event_rx) = mpsc::channel::<DemoStreamEvent<C>>(CHANNEL_BUFFER_SIZE);

    // Run the game flow in a blocking task to avoid blocking the async runtime
    tokio::task::spawn_blocking(move || {
        if let Err(err) = execute_demo_flow(event_tx, ctx) {
            error!(target: LOG_TARGET, ?err, "demo flow failed");
        }
    });

    // Convert events to SSE
    let sse_stream = ReceiverStream::new(event_rx).map(|event| {
        let event_name = event.event_name();
        let data = serde_json::to_string(&event)
            .unwrap_or_else(|err| json!({ "error": err.to_string() }).to_string());
        Ok::<Event, Infallible>(Event::default().event(event_name).data(data))
    });

    Ok(Sse::new(sse_stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text(":")))
}

/// Main execution flow - runs synchronously in a blocking task.
fn execute_demo_flow<C>(
    event_tx: mpsc::Sender<DemoStreamEvent<C>>,
    _ctx: Arc<ServerContext<C>>,
) -> Result<()>
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
    // Macro for fire-and-forget event emission
    macro_rules! emit {
        ($event:expr) => {
            if event_tx.try_send($event).is_err() {
                warn!(target: LOG_TARGET, "dropped event (buffer full or closed)");
            }
        };
    }

    info!(target: LOG_TARGET, "🎰 Starting in-memory demo flow");

    // Step 1: Initialize RNG and keys
    let mut rng = StdRng::from_entropy();
    let viewer_secret = C::ScalarField::rand(&mut rng);
    let viewer_public = C::generator() * viewer_secret.clone();
    let hasher = Arc::new(LedgerHasherSha256);

    // Step 2: Set up in-memory lobby service
    let lobby: Arc<dyn crate::ledger::LobbyService<C>> =
        Arc::new(LobbyServiceFactory::<C>::in_memory());

    // Step 3: Generate shuffler identities and keys
    info!(target: LOG_TARGET, num_shufflers = NUM_SHUFFLERS, "🔀 Generating shuffler identities");
    let shuffler_engines = generate_shuffler_engines(&mut rng)?;
    let shuffler_records = create_shuffler_records(&shuffler_engines);
    let aggregated_public_key = compute_aggregated_public_key(&shuffler_engines);

    // Step 4: Generate player identities
    info!(target: LOG_TARGET, num_players = NUM_PLAYERS, "👥 Generating player identities");
    let player_keys = generate_player_keys(&mut rng, NUM_PLAYERS);
    let player_records = create_player_records(&player_keys);

    // Step 5: Host a game
    info!(target: LOG_TARGET, "🎮 Hosting game");
    let host = PlayerRecord {
        display_name: VIEWER_NAME.into(),
        public_key: viewer_public.clone(),
        seat_preference: Some(0),
        state: MaybeSaved { id: None },
    };

    let lobby_config = build_lobby_config();
    let metadata = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(lobby.host_game(host, lobby_config.clone()))
    })?;

    let game_id: GameId = metadata.record.state.id;
    let viewer_seat: SeatId = 0;

    // Emit PlayerCreated for viewer
    emit!(DemoStreamEvent::PlayerCreated {
        game_id,
        seat: viewer_seat,
        display_name: VIEWER_NAME.into(),
        public_key: viewer_public.clone(),
    });

    // Step 6: Register shufflers
    info!(target: LOG_TARGET, num_shufflers = NUM_SHUFFLERS, "🔀 Registering shufflers");
    let mut registered_shufflers = Vec::new();
    for (idx, shuffler_record) in shuffler_records.into_iter().enumerate() {
        let cfg = ShufflerRegistrationConfig {
            sequence: Some(idx as u16),
        };
        let output = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(lobby.register_shuffler(
                &metadata.record,
                shuffler_record.clone(),
                cfg,
            ))
        })?;
        registered_shufflers.push((output.shuffler, output.assigned_sequence));
    }

    // Step 7: Join players to the game
    info!(target: LOG_TARGET, num_players = NUM_PLAYERS, "👥 Joining players");
    for (idx, player_record) in player_records.into_iter().enumerate() {
        let seat_id = idx as SeatId;
        let _output = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(lobby.join_game(
                &metadata.record,
                player_record.clone(),
                Some(seat_id),
            ))
        })?;
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

    let outcome = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(lobby.commence_game(hasher.as_ref(), params))
    })?;

    let hand_id: HandId = outcome.hand.state.id;
    let initial_snapshot = outcome.initial_snapshot.clone();

    // Emit HandCreated
    emit!(DemoStreamEvent::HandCreated {
        game_id,
        hand_id,
        player_count: NUM_PLAYERS,
        shuffler_count: NUM_SHUFFLERS,
        snapshot: initial_snapshot.clone(),
    });

    // Step 9: Execute shuffle phase
    info!(target: LOG_TARGET, "🔄 Executing shuffle phase");
    let dealing_snapshot = emit_shuffle_phase(
        initial_snapshot,
        &shuffler_engines,
        &registered_shufflers,
        hasher.as_ref(),
        &event_tx,
    )?;

    // Step 10: Execute dealing phase
    info!(target: LOG_TARGET, "🎴 Executing dealing phase");
    emit_dealing_phase(
        dealing_snapshot,
        &shuffler_engines,
        &registered_shufflers,
        viewer_seat,
        viewer_secret,
        &aggregated_public_key,
        &mut rng,
        hasher.as_ref(),
        &event_tx,
        game_id,
        hand_id,
    )?;

    info!(target: LOG_TARGET, "✅ Demo flow completed successfully");
    Ok(())
}

/// Process a message envelope and return the finalized envelope with snapshot.
/// Mirrors the logic in LedgerWorker::handle_event for consistency.
fn process_message_envelope<C>(
    envelope: AnyMessageEnvelope<C>,
    current_snapshot: &AnyTableSnapshot<C>,
    hasher: &dyn LedgerHasher,
) -> (
    FinalizedAnyMessageEnvelope<C>,
    AnyTableSnapshot<C>,
    Option<String>,
)
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    // Try to apply the transition
    let preview_result =
        apply_transition_from_envelope(current_snapshot.clone(), &envelope, hasher);

    match preview_result {
        Ok(snapshot) => {
            let finalized = FinalizedAnyMessageEnvelope::new(
                envelope,
                SnapshotStatus::Success,
                snapshot.event_phase(),
                snapshot.sequence(),
            );
            (finalized, snapshot, None)
        }
        Err(apply_err) => {
            warn!(
                target: LOG_TARGET,
                error = ?apply_err,
                "message transition failed"
            );
            let reason = apply_err.to_string();
            let failure_snapshot =
                clone_snapshot_for_failure(current_snapshot, hasher, reason.clone());
            let finalized = FinalizedAnyMessageEnvelope::new(
                envelope,
                SnapshotStatus::Failure(reason.clone()),
                failure_snapshot.event_phase(),
                failure_snapshot.sequence(),
            );
            (finalized, failure_snapshot, Some(reason))
        }
    }
}

/// Apply transition based on envelope type - dispatches to correct transition handler.
fn apply_transition_from_envelope<C>(
    snapshot: AnyTableSnapshot<C>,
    envelope: &AnyMessageEnvelope<C>,
    hasher: &dyn LedgerHasher,
) -> Result<AnyTableSnapshot<C>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    use crate::ledger::actor::AnyActor;
    use crate::ledger::messages::AnyGameMessage;

    // Extract the appropriate envelope type and apply transition
    match &envelope.message.value {
        AnyGameMessage::Shuffle(msg) => {
            let shuffling_snapshot = match snapshot {
                AnyTableSnapshot::Shuffling(s) => s,
                _ => return Err(anyhow!("expected shuffling snapshot for shuffle message")),
            };

            let actor = match &envelope.actor {
                AnyActor::Shuffler {
                    shuffler_id,
                    shuffler_key,
                } => ShufflerActor {
                    shuffler_id: *shuffler_id,
                    shuffler_key: shuffler_key.clone(),
                },
                _ => return Err(anyhow!("expected shuffler actor for shuffle message")),
            };
            let typed_envelope = EnvelopedMessage {
                hand_id: envelope.hand_id,
                game_id: envelope.game_id,
                actor,
                nonce: envelope.nonce,
                public_key: envelope.public_key.clone(),
                message: crate::signing::WithSignature {
                    value: msg.clone(),
                    signature: envelope.message.signature.clone(),
                },
            };
            apply_transition(shuffling_snapshot, &typed_envelope, hasher)
        }
        AnyGameMessage::Blinding(msg) => {
            let dealing_snapshot = match snapshot {
                AnyTableSnapshot::Dealing(s) => s,
                _ => return Err(anyhow!("expected dealing snapshot for blinding message")),
            };

            let actor = match &envelope.actor {
                AnyActor::Shuffler {
                    shuffler_id,
                    shuffler_key,
                } => ShufflerActor {
                    shuffler_id: *shuffler_id,
                    shuffler_key: shuffler_key.clone(),
                },
                _ => return Err(anyhow!("expected shuffler actor for blinding message")),
            };
            let typed_envelope = EnvelopedMessage {
                hand_id: envelope.hand_id,
                game_id: envelope.game_id,
                actor,
                nonce: envelope.nonce,
                public_key: envelope.public_key.clone(),
                message: crate::signing::WithSignature {
                    value: msg.clone(),
                    signature: envelope.message.signature.clone(),
                },
            };
            apply_transition(dealing_snapshot, &typed_envelope, hasher)
        }
        AnyGameMessage::PartialUnblinding(msg) => {
            let dealing_snapshot = match snapshot {
                AnyTableSnapshot::Dealing(s) => s,
                _ => return Err(anyhow!("expected dealing snapshot for unblinding message")),
            };

            let actor = match &envelope.actor {
                AnyActor::Shuffler {
                    shuffler_id,
                    shuffler_key,
                } => ShufflerActor {
                    shuffler_id: *shuffler_id,
                    shuffler_key: shuffler_key.clone(),
                },
                _ => return Err(anyhow!("expected shuffler actor for unblinding message")),
            };
            let typed_envelope = EnvelopedMessage {
                hand_id: envelope.hand_id,
                game_id: envelope.game_id,
                actor,
                nonce: envelope.nonce,
                public_key: envelope.public_key.clone(),
                message: crate::signing::WithSignature {
                    value: msg.clone(),
                    signature: envelope.message.signature.clone(),
                },
            };
            apply_transition(dealing_snapshot, &typed_envelope, hasher)
        }
        _ => Err(anyhow!("unsupported message type for in-memory demo")),
    }
}

/// Execute the shuffle phase and emit events.
fn emit_shuffle_phase<C>(
    mut current_snapshot: TableAtShuffling<C>,
    shuffler_engines: &[ShufflerEngine<C, Schnorr254<C>>],
    registered_shufflers: &[(ShufflerRecord<C, Saved<ShufflerId>>, u16)],
    hasher: &dyn LedgerHasher,
    event_tx: &mpsc::Sender<DemoStreamEvent<C>>,
) -> Result<TableAtDealing<C>>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField>,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Clone,
    C::BaseField: PrimeField,
    C::Affine: Absorb + CanonicalSerialize,
{
    let num_shufflers = shuffler_engines.len();

    // Create shuffler hand states
    let mut shuffler_states: Vec<ShufflerHandState<C>> = shuffler_engines
        .iter()
        .map(|engine| {
            let hand_seed = rand::random::<[u8; 32]>();
            ShufflerHandState::from_shuffling_snapshot(
                &current_snapshot,
                &engine.public_key,
                hand_seed,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    // Execute each shuffle round
    for shuffle_round in 0..num_shufflers {
        let mut acted = false;

        for shuffler_index in 0..num_shufflers {
            let engine = &shuffler_engines[shuffler_index];
            let (shuffler_record, _sequence) = &registered_shufflers[shuffler_index];
            let shuffler_state = &mut shuffler_states[shuffler_index];

            // Create actor
            let shuffler_key = CanonicalKey::new(engine.public_key.clone());
            let actor = ShufflerActor {
                shuffler_id: shuffler_record.state.id,
                shuffler_key,
            };

            // Try to emit shuffle
            let any_envelope =
                match shuffler_state.try_emit_shuffle::<Schnorr254<C>, _>(engine, &actor)? {
                    Some(env) => env,
                    None => continue,
                };

            acted = true;

            // Process message with error handling
            let current_snapshot_any = AnyTableSnapshot::Shuffling(current_snapshot.clone());
            let (finalized_envelope, next_snapshot, apply_error) =
                process_message_envelope(any_envelope.clone(), &current_snapshot_any, hasher);

            // Always emit the finalized envelope
            if event_tx
                .try_send(DemoStreamEvent::GameEvent {
                    envelope: finalized_envelope,
                })
                .is_err()
            {
                warn!(target: LOG_TARGET, "dropped shuffle event");
            }

            // Check for failure
            if let Some(reason) = apply_error {
                return Err(anyhow!("Shuffle failed: {}", reason));
            }

            // Extract shuffle envelope for state updates
            let shuffle_envelope = extract_shuffle_envelope(&any_envelope)?;

            // Update state based on next snapshot
            match next_snapshot {
                AnyTableSnapshot::Shuffling(snapshot) => {
                    for state in shuffler_states.iter_mut() {
                        state.shuffling.latest_deck = snapshot.shuffling.final_deck.clone();
                        state.shuffling.buffered.push(shuffle_envelope.clone());
                    }
                    current_snapshot = snapshot;
                    break;
                }
                AnyTableSnapshot::Dealing(dealing_snapshot) => {
                    info!(target: LOG_TARGET, "🎉 Shuffling phase complete");
                    return Ok(dealing_snapshot);
                }
                _ => return Err(anyhow!("unexpected snapshot variant after shuffle")),
            }
        }

        if !acted {
            return Err(anyhow!(
                "No shuffler acted in shuffle round {}",
                shuffle_round + 1
            ));
        }
    }

    unreachable!("Should have transitioned to dealing")
}

/// Execute the dealing phase with card decryption and emit events.
#[allow(clippy::too_many_arguments)]
fn emit_dealing_phase<C>(
    mut current_snapshot: TableAtDealing<C>,
    shuffler_engines: &[ShufflerEngine<C, Schnorr254<C>>],
    _registered_shufflers: &[(ShufflerRecord<C, Saved<ShufflerId>>, u16)],
    viewer_seat: SeatId,
    viewer_secret: C::ScalarField,
    aggregated_public_key: &C,
    rng: &mut StdRng,
    hasher: &dyn LedgerHasher,
    event_tx: &mpsc::Sender<DemoStreamEvent<C>>,
    game_id: GameId,
    hand_id: HandId,
) -> Result<()>
where
    C: CurveGroup + CanonicalSerialize + CurveAbsorb<C::BaseField>,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Clone,
    C::BaseField: PrimeField,
    C::Affine: Absorb + CanonicalSerialize,
{
    let num_shufflers = shuffler_engines.len();

    // Create shuffler hand states from dealing snapshot
    let mut shuffler_states: Vec<ShufflerHandState<C>> = shuffler_engines
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

    // Get player hole cards for viewer
    let player_hole_cards = current_snapshot.dealing.get_player_hole_cards()?;
    let viewer_cards = player_hole_cards
        .iter()
        .find(|(&seat, _)| seat == viewer_seat)
        .map(|(_, cards)| cards)
        .ok_or_else(|| anyhow!("Viewer has no hole cards"))?;

    let mut card_decryptable_emitted = [false; 2];
    let mut hole_cards_decrypted = [false; 2];

    let viewer_public = C::generator() * viewer_secret.clone();

    // Process each hole card
    for hole_card in viewer_cards {
        let card_position = hole_card.hole_index as usize;

        // Use explicit deal index carried by the snapshot
        let deal_index = hole_card.deal_index;

        // Phase A: Blinding contributions
        for (idx, engine) in shuffler_engines.iter().enumerate() {
            let state = &mut shuffler_states[idx];
            let ctx = state.next_metadata_envelope();

            let (_, any_envelope) = engine.player_blinding_and_sign(
                aggregated_public_key,
                &ctx,
                deal_index,
                &viewer_public,
                rng,
            )?;

            // Process message with error handling
            let current_snapshot_any = AnyTableSnapshot::Dealing(current_snapshot.clone());
            let (finalized_envelope, next_snapshot, apply_error) =
                process_message_envelope(any_envelope, &current_snapshot_any, hasher);

            // Always emit the finalized envelope
            if event_tx
                .try_send(DemoStreamEvent::GameEvent {
                    envelope: finalized_envelope,
                })
                .is_err()
            {
                warn!(target: LOG_TARGET, "dropped blinding event");
            }

            // Check for failure
            if let Some(reason) = apply_error {
                return Err(anyhow!("Blinding failed: {}", reason));
            }

            // Update current snapshot
            let dealing_ref: &TableAtDealing<C> = (&next_snapshot).try_into()?;
            current_snapshot = dealing_ref.clone();
        }

        // Get player ciphertext
        let player_ciphertext = current_snapshot
            .dealing
            .player_ciphertexts
            .get(&(viewer_seat, hole_card.hole_index))
            .ok_or_else(|| anyhow!("player ciphertext not found"))?
            .clone();

        // Phase B: Unblinding shares
        for (idx, engine) in shuffler_engines.iter().enumerate() {
            let state = &mut shuffler_states[idx];
            let ctx = state.next_metadata_envelope();

            let (_, any_envelope) = engine.player_unblinding_and_sign(
                &ctx,
                deal_index,
                &viewer_public,
                &player_ciphertext,
                rng,
            )?;

            // Process message with error handling
            let current_snapshot_any = AnyTableSnapshot::Dealing(current_snapshot.clone());
            let (finalized_envelope, next_snapshot, apply_error) =
                process_message_envelope(any_envelope, &current_snapshot_any, hasher);

            // Always emit the finalized envelope
            if event_tx
                .try_send(DemoStreamEvent::GameEvent {
                    envelope: finalized_envelope,
                })
                .is_err()
            {
                warn!(target: LOG_TARGET, "dropped unblinding event");
            }

            // Check for failure
            if let Some(reason) = apply_error {
                return Err(anyhow!("Unblinding failed: {}", reason));
            }

            // Update current snapshot
            let dealing_ref: &TableAtDealing<C> = (&next_snapshot).try_into()?;
            current_snapshot = dealing_ref.clone();

            // Check if card is decryptable after each unblinding
            if can_decrypt_card(
                &current_snapshot,
                viewer_seat,
                hole_card.hole_index,
                num_shufflers,
            ) {
                // Emit CardDecryptable once
                if !card_decryptable_emitted[card_position] {
                    if event_tx
                        .try_send(DemoStreamEvent::CardDecryptable {
                            game_id,
                            hand_id,
                            seat: viewer_seat,
                            card_position,
                        })
                        .is_err()
                    {
                        warn!(target: LOG_TARGET, "dropped card_decryptable event");
                    }
                    card_decryptable_emitted[card_position] = true;
                }

                // Try to decrypt
                if !hole_cards_decrypted[card_position] {
                    if let Some(card_index) = try_decrypt_single_card(
                        &current_snapshot,
                        viewer_seat,
                        hole_card.hole_index,
                        num_shufflers,
                        &viewer_secret,
                    ) {
                        let card = decode_card(card_index);
                        if event_tx
                            .try_send(DemoStreamEvent::HoleCardsDecrypted {
                                game_id,
                                hand_id,
                                seat: viewer_seat,
                                card_position,
                                card,
                            })
                            .is_err()
                        {
                            warn!(target: LOG_TARGET, "dropped hole_cards_decrypted event");
                        }
                        hole_cards_decrypted[card_position] = true;
                    }
                }
            }
        }
    }

    // Check if both cards are decrypted
    if hole_cards_decrypted[0] && hole_cards_decrypted[1] {
        if event_tx
            .try_send(DemoStreamEvent::HandCompleted { game_id, hand_id })
            .is_err()
        {
            warn!(target: LOG_TARGET, "dropped hand_completed event");
        }
    }

    Ok(())
}

// Helper functions for card decryption (reused from stream.rs logic)

fn can_decrypt_card<C>(
    snapshot: &TableAtDealing<C>,
    seat: SeatId,
    card_position: u8,
    expected_shares: usize,
) -> bool
where
    C: CurveGroup,
{
    let key = (seat, card_position);

    if !snapshot.dealing.player_ciphertexts.contains_key(&key) {
        return false;
    }

    let Some(shares_map) = snapshot.dealing.player_unblinding_shares.get(&key) else {
        return false;
    };

    shares_map.len() >= expected_shares
}

fn try_decrypt_single_card<C>(
    snapshot: &TableAtDealing<C>,
    seat: SeatId,
    card_position: u8,
    expected_shares: usize,
    secret: &C::ScalarField,
) -> Option<CardIndex>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    let key = (seat, card_position);

    let shares_map = snapshot.dealing.player_unblinding_shares.get(&key)?;
    if shares_map.len() < expected_shares {
        return None;
    }

    let shares: Vec<PartialUnblindingShare<C>> = shares_map.values().cloned().collect();
    let ciphertext = snapshot.dealing.player_ciphertexts.get(&key)?;

    recover_card_value(ciphertext, secret.clone(), shares, expected_shares).ok()
}

// Helper functions from game_launch_and_shuffle_flow.rs

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

fn extract_shuffle_envelope<C>(
    envelope: &AnyMessageEnvelope<C>,
) -> Result<EnvelopedMessage<C, crate::ledger::messages::GameShuffleMessage<C>>>
where
    C: CurveGroup,
{
    use crate::ledger::actor::AnyActor;
    use crate::ledger::messages::AnyGameMessage;
    use crate::signing::WithSignature;

    let actor = match &envelope.actor {
        AnyActor::Shuffler {
            shuffler_id,
            shuffler_key,
        } => ShufflerActor {
            shuffler_id: *shuffler_id,
            shuffler_key: shuffler_key.clone(),
        },
        _ => return Err(anyhow!("expected shuffler actor, got different actor type")),
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
        _ => Err(anyhow!(
            "expected shuffle message, got different message type"
        )),
    }
}

fn build_lobby_config() -> GameLobbyConfig {
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
