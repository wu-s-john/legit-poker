use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::{PlayerId, SeatId};
use crate::ledger::lobby::types::{
    CommenceGameParams, GameLobbyConfig, GameMetadata, PlayerRecord, PlayerSeatSnapshot,
};
use crate::ledger::serialization::serialize_curve_bytes;
use crate::ledger::snapshot::{AnyTableSnapshot, DealingSnapshot};
use crate::ledger::types::{GameId, HandId, HandStatus};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::LobbyService;
use crate::server::demo::{
    build_hand_config, build_lobby_config, generate_npc_specs, register_shufflers, DemoStreamEvent,
    NPC_COUNT, RNG_SEED, VIEWER_NAME,
};
use crate::server::error::ApiError;
use crate::server::routes::ServerContext;
use crate::showdown::{decode_card, Card, Index as CardIndex};
use crate::shuffling::player_decryption::recover_card_value;
use crate::shuffling::player_decryption::PartialUnblindingShare;

use rand::{rngs::StdRng, SeedableRng};

#[derive(Debug, Deserialize)]
pub struct DemoStreamQuery {
    pub public_key: Option<String>,
}

/// Entry-point for the SSE demo stream.
pub async fn stream_demo_game<C>(
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
            "public_key query parameter is not supported for the demo stream",
        ));
    }

    let (event_tx, event_rx) = mpsc::channel::<DemoStreamEvent<C>>(128);

    // Prepare RNGs
    let mut rng = StdRng::from_entropy();
    let viewer_secret = C::ScalarField::rand(&mut rng);
    let viewer_public = C::generator() * viewer_secret.clone();

    // Host the demo lobby and seat the viewer
    let lobby = Arc::clone(&ctx.lobby);
    let coordinator = Arc::clone(&ctx.coordinator);

    let viewer_bytes =
        serialize_curve_bytes(&viewer_public).map_err(|err| ApiError::internal(err.to_string()))?;

    let game_setup = host_and_seed_players(&lobby, viewer_public.clone(), viewer_bytes)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    let GameSetup {
        lobby_config,
        metadata,
        player_snapshots,
        viewer_seat,
        viewer_player,
    } = game_setup;

    let game_id: GameId = metadata.record.state.id;

    // Emit viewer creation event immediately
    event_tx
        .send(DemoStreamEvent::PlayerCreated {
            game_id,
            seat: viewer_seat,
            display_name: viewer_player.display_name.clone(),
            public_key: viewer_public.clone(),
        })
        .await
        .map_err(|_| ApiError::internal("viewer event channel closed"))?;

    // Register NPCs (already in player_snapshots)
    // Register shufflers and commence the demo hand
    let descriptors = coordinator.shuffler_descriptors();
    if descriptors.is_empty() {
        return Err(ApiError::internal(
            "coordinator has no shufflers configured",
        ));
    }
    let shuffler_assignments = register_shufflers(&lobby, &metadata, &descriptors)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;

    let hand_config = build_hand_config();
    let operator = coordinator.operator();
    let params = CommenceGameParams {
        game: metadata.record.clone(),
        hand_no: 1,
        hand_config,
        players: player_snapshots.clone(),
        shufflers: shuffler_assignments,
        deck_commitment: None,
        buy_in: lobby_config.buy_in,
        min_players: lobby_config.min_players_to_start,
    };

    let outcome = lobby
        .commence_game(operator.as_ref(), params)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;

    let initial_snapshot = outcome.initial_snapshot.clone();
    let hand_id: HandId = outcome.hand.state.id;
    let player_count = player_snapshots.len();

    event_tx
        .send(DemoStreamEvent::HandCreated {
            game_id,
            hand_id,
            player_count,
            snapshot: initial_snapshot,
        })
        .await
        .map_err(|_| ApiError::internal("hand event channel closed"))?;

    // Attach hand to the coordinator (launch shufflers)
    coordinator
        .attach_hand(outcome)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;

    let expected_shufflers = descriptors.len();

    // Spawn producer task to relay staging updates
    let mut staging_rx = coordinator.operator().staging_updates();
    let event_tx_loop = event_tx.clone();
    let coordinator_loop = Arc::clone(&coordinator);
    let viewer_secret_loop = viewer_secret.clone();

    tokio::spawn(async move {
        let mut community_emitted = false;
        let mut hole_emitted = false;

        loop {
            let update = match staging_rx.recv().await {
                Ok(update) => update,
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        target = "demo_stream",
                        ?skipped,
                        "lagged on staging updates"
                    );
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!(target = "demo_stream", "staging channel closed");
                    break;
                }
            };

            if update.event.envelope.hand_id != hand_id || update.event.envelope.game_id != game_id
            {
                continue;
            }

            if event_tx_loop
                .send(DemoStreamEvent::GameEvent {
                    envelope: update.event.clone(),
                })
                .await
                .is_err()
            {
                break;
            }

            let snapshot = update.snapshot.as_ref();

            if !community_emitted {
                if let Some(cards) = extract_community_cards(snapshot) {
                    community_emitted = true;
                    if event_tx_loop
                        .send(DemoStreamEvent::CommunityDecrypted {
                            game_id,
                            hand_id,
                            cards,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }

            if !hole_emitted {
                if let Some(card_indices) = try_decrypt_viewer_cards(
                    snapshot,
                    viewer_seat,
                    expected_shufflers,
                    &viewer_secret_loop,
                ) {
                    let cards = [decode_card(card_indices[0]), decode_card(card_indices[1])];
                    if event_tx_loop
                        .send(DemoStreamEvent::HoleCardsDecrypted {
                            game_id,
                            hand_id,
                            seat: viewer_seat,
                            cards,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }

                    hole_emitted = true;
                }
            }

            let status = snapshot_hand_status(snapshot);
            if hole_emitted && is_status_at_least(status, HandStatus::Betting) {
                if event_tx_loop
                    .send(DemoStreamEvent::HandCompleted { game_id, hand_id })
                    .await
                    .is_err()
                {
                    break;
                }
                break;
            }
        }

        coordinator_loop.release_hand(game_id, hand_id);
        // Drop the channel sender so the SSE stream terminates naturally.
        drop(event_tx_loop);
    });

    drop(event_tx);

    let sse_stream = ReceiverStream::new(event_rx).map(|event| {
        let event_name = event.event_name();
        let data = serde_json::to_string(&event)
            .unwrap_or_else(|err| json!({ "error": err.to_string() }).to_string());
        Ok::<Event, Infallible>(Event::default().event(event_name).data(data))
    });

    Ok(Sse::new(sse_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text(":\n"),
    ))
}

struct GameSetup<C: CurveGroup> {
    lobby_config: GameLobbyConfig,
    metadata: GameMetadata,
    player_snapshots: Vec<PlayerSeatSnapshot<C>>,
    viewer_seat: SeatId,
    viewer_player: PlayerRecord<Saved<PlayerId>>,
}

async fn host_and_seed_players<C>(
    lobby: &Arc<dyn LobbyService<C>>,
    viewer_public: C,
    viewer_public_bytes: Vec<u8>,
) -> Result<GameSetup<C>>
where
    C: CurveGroup
        + CurveAbsorb<C::BaseField>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + CanonicalSerialize + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let lobby_config = build_lobby_config();

    let host_registration = PlayerRecord {
        display_name: VIEWER_NAME.into(),
        public_key: viewer_public_bytes.clone(),
        seat_preference: Some(0),
        state: MaybeSaved { id: None },
    };
    let metadata = lobby
        .host_game(host_registration, lobby_config.clone())
        .await
        .map_err(|err| anyhow!("failed to host demo game: {err}"))?;

    let viewer_join = lobby
        .join_game(
            &metadata.record,
            PlayerRecord {
                display_name: metadata.host.display_name.clone(),
                public_key: metadata.host.public_key.clone(),
                seat_preference: Some(0),
                state: MaybeSaved {
                    id: Some(metadata.host.state.id),
                },
            },
            Some(0),
        )
        .await
        .map_err(|err| anyhow!("failed to seat viewer in demo game: {err}"))?;

    let viewer_player = viewer_join.player.clone();

    let mut players = Vec::with_capacity(NPC_COUNT + 1);
    players.push(PlayerSeatSnapshot::new(
        viewer_join.player,
        0,
        lobby_config.buy_in,
        viewer_public,
    ));

    for (idx, spec) in generate_npc_specs::<C>(&mut rng)?.into_iter().enumerate() {
        let seat = (idx + 1) as SeatId;
        let public_key_bytes = serialize_curve_bytes(&spec.public_key)
            .map_err(|err| anyhow!("failed to serialize NPC public key: {err}"))?;
        let join = lobby
            .join_game(
                &metadata.record,
                PlayerRecord {
                    display_name: spec.display_name,
                    public_key: public_key_bytes,
                    seat_preference: Some(seat),
                    state: MaybeSaved { id: None },
                },
                Some(seat),
            )
            .await
            .map_err(|err| anyhow!("failed to seat NPC at seat {}: {err}", seat))?;

        players.push(PlayerSeatSnapshot::new(
            join.player,
            seat,
            lobby_config.buy_in,
            spec.public_key,
        ));
    }

    Ok(GameSetup {
        lobby_config,
        metadata,
        player_snapshots: players,
        viewer_seat: 0,
        viewer_player,
    })
}

fn extract_community_cards<C>(snapshot: &AnyTableSnapshot<C>) -> Option<Vec<Card>>
where
    C: CurveGroup,
{
    let dealing = dealing_from_snapshot(snapshot)?;
    if dealing.community_cards.len() < 5 {
        return None;
    }

    let mut cards: Vec<(u8, CardIndex)> = dealing
        .community_cards
        .iter()
        .map(|(k, v)| (*k, *v))
        .collect();
    cards.sort_by_key(|(index, _)| *index);
    Some(
        cards
            .into_iter()
            .map(|(_, card)| decode_card(card))
            .collect(),
    )
}

fn try_decrypt_viewer_cards<C>(
    snapshot: &AnyTableSnapshot<C>,
    viewer_seat: SeatId,
    expected_shares: usize,
    viewer_secret: &C::ScalarField,
) -> Option<[CardIndex; 2]>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    let dealing = dealing_from_snapshot(snapshot)?;
    let mut result = [0u8; 2];

    for hole_index in 0u8..2 {
        let key = (viewer_seat, hole_index);
        let shares_map = dealing.player_unblinding_shares.get(&key)?;
        if shares_map.len() < expected_shares {
            return None;
        }
        let shares: Vec<PartialUnblindingShare<C>> = shares_map.values().cloned().collect();
        let ciphertext = dealing.player_ciphertexts.get(&key)?;
        let card =
            recover_card_value(ciphertext, viewer_secret.clone(), shares, expected_shares).ok()?;
        result[hole_index as usize] = card;
    }

    Some(result)
}

fn dealing_from_snapshot<C>(snapshot: &AnyTableSnapshot<C>) -> Option<&DealingSnapshot<C>>
where
    C: CurveGroup,
{
    match snapshot {
        AnyTableSnapshot::Dealing(table) => Some(&table.dealing),
        AnyTableSnapshot::Preflop(table) => Some(&table.dealing),
        AnyTableSnapshot::Flop(table) => Some(&table.dealing),
        AnyTableSnapshot::Turn(table) => Some(&table.dealing),
        AnyTableSnapshot::River(table) => Some(&table.dealing),
        AnyTableSnapshot::Showdown(table) => Some(&table.dealing),
        AnyTableSnapshot::Complete(table) => Some(&table.dealing),
        AnyTableSnapshot::Shuffling(_) => None,
    }
}

fn snapshot_hand_status<C>(snapshot: &AnyTableSnapshot<C>) -> HandStatus
where
    C: CurveGroup,
{
    match snapshot {
        AnyTableSnapshot::Shuffling(_) => HandStatus::Shuffling,
        AnyTableSnapshot::Dealing(_) => HandStatus::Dealing,
        AnyTableSnapshot::Preflop(_)
        | AnyTableSnapshot::Flop(_)
        | AnyTableSnapshot::Turn(_)
        | AnyTableSnapshot::River(_) => HandStatus::Betting,
        AnyTableSnapshot::Showdown(_) => HandStatus::Showdown,
        AnyTableSnapshot::Complete(_) => HandStatus::Complete,
    }
}

fn is_status_at_least(current: HandStatus, threshold: HandStatus) -> bool {
    fn score(status: HandStatus) -> u8 {
        match status {
            HandStatus::Pending => 0,
            HandStatus::Shuffling => 1,
            HandStatus::Dealing => 2,
            HandStatus::Betting => 3,
            HandStatus::Showdown => 4,
            HandStatus::Complete => 5,
            HandStatus::Cancelled => 6,
        }
    }

    score(current) >= score(threshold)
}
