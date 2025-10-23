use crate::tokio_tools::spawn_named_task;
use ark_crypto_primitives::signature::schnorr::{Schnorr, SecretKey as SchnorrSecretKey};
use sha2::Sha256;

mod api;
mod dealing;
mod hand_runtime;
mod service;

pub use dealing::{
    BoardCardShufflerRequest, BoardCardSlot, DealShufflerRequest, DealingHandState,
    PlayerBlindingRequest, PlayerUnblindingRequest,
};
pub use hand_runtime::{HandRuntime, HandSubscription, ShufflingHandState};
pub use service::{ShufflerRunConfig, ShufflerService};

use crate::shuffling::ElGamalCiphertext;

pub use api::{ShufflerApi, ShufflerEngine};

pub type Deck<C, const N: usize> = [ElGamalCiphertext<C>; N];

pub type ShufflerScheme<C> = Schnorr<C, Sha256>;

impl<C> api::ShufflerSigningSecret<C> for SchnorrSecretKey<C>
where
    C: ark_ec::CurveGroup,
{
    fn as_scalar(&self) -> C::ScalarField {
        self.0.clone()
    }
}

const LOG_TARGET: &str = "legit_poker::game::shuffler";
const DEAL_CHANNEL_CAPACITY: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaum_pedersen::ChaumPedersenProof;
    use crate::ledger::actor::ShufflerActor;
    use crate::ledger::messages::AnyGameMessage;
    use crate::ledger::snapshot::{CardDestination, DealtCard};
    use crate::ledger::test_support::{
        fixture_dealing_snapshot, fixture_preflop_snapshot, FixtureContext,
    };
    use crate::shuffler::BoardCardSlot;
    use crate::shuffling::player_decryption::PlayerAccessibleCiphertext;
    use crate::shuffling::{
        combine_blinding_contributions_for_player, decrypt_community_card,
        generate_random_ciphertexts, make_global_public_keys, recover_card_value,
        PartialUnblindingShare, PlayerTargetedBlindingContribution, DECK_SIZE,
    };
    use ark_crypto_primitives::signature::SignatureScheme;
    use ark_ec::PrimeGroup;
    use ark_ff::Zero;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_std::{test_rng, UniformRand};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::{Arc, Weak};
    use tokio::sync::{broadcast, mpsc};
    use tokio::time::{timeout, Duration};

    const N_SHUFFLERS: usize = 3;
    const DECK_N: usize = 52;

    #[test]
    fn test_shuffle_and_player_targeted_recovery() {
        let mut rng = test_rng();

        // Build shufflers from random secrets
        let mut secrets = Vec::with_capacity(N_SHUFFLERS);
        let mut public_keys = Vec::with_capacity(N_SHUFFLERS);
        for _ in 0..N_SHUFFLERS {
            let secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
            let public_key = GrumpkinProjective::generator() * secret;
            secrets.push(secret);
            public_keys.push(public_key);
        }
        let aggregated_public_key = make_global_public_keys(public_keys.clone());
        let signing_params = Arc::new(
            ShufflerScheme::<GrumpkinProjective>::setup(&mut rng).expect("schnorr params"),
        );
        let shufflers: Vec<_> = secrets
            .into_iter()
            .zip(public_keys.into_iter())
            .map(|(secret, public_key)| {
                let sign_sk = SchnorrSecretKey::<GrumpkinProjective>(secret.clone());
                ShufflerEngine::<GrumpkinProjective, ShufflerScheme<GrumpkinProjective>>::new(
                    Arc::new(sign_sk),
                    public_key,
                    aggregated_public_key.clone(),
                    Arc::clone(&signing_params),
                )
            })
            .collect();

        let agg_pk = aggregated_public_key.clone();

        // Generate an initial encrypted deck using the aggregated public key
        let (mut deck, _r) =
            generate_random_ciphertexts::<GrumpkinProjective, DECK_N>(&agg_pk, &mut rng);

        // Sequentially shuffle across all shufflers
        for s in &shufflers {
            let (next_deck, _proof) = s.shuffle(&deck, &mut rng).expect("shuffle");
            deck = next_deck;
        }

        // Choose an arbitrary card index (0-based deck encoding)
        let card_index = 10usize;
        let card_ct = deck[card_index].clone();

        // Player keys
        let player_sk = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let player_pk = GrumpkinProjective::generator() * player_sk;

        // Each shuffler provides a blinding contribution for this player
        let mut contributions = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            let c = s
                .provide_blinding_player_decryption_share(player_pk, &mut rng)
                .expect("blinding share");
            contributions.push(c);
        }

        // Combine into a player-accessible ciphertext
        let player_ciphertext =
            combine_blinding_contributions_for_player(&card_ct, &contributions, agg_pk, player_pk)
                .expect("combine blinding contributions");

        // Each shuffler provides partial unblinding
        let mut unblinding_shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            let u = s
                .provide_unblinding_decryption_share(&player_ciphertext)
                .expect("unblinding share");
            unblinding_shares.push(u);
        }

        // Recover card value via player-targeted path
        let recovered = recover_card_value::<GrumpkinProjective>(
            &player_ciphertext,
            player_sk,
            unblinding_shares,
            N_SHUFFLERS,
        )
        .expect("recover card value");

        // Also derive expected value via community decryption of the same post-shuffle ciphertext
        let mut comm_shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            comm_shares.push(
                s.provide_community_decryption_share(&card_ct, &mut rng)
                    .expect("community share"),
            );
        }
        let expected_value =
            decrypt_community_card::<GrumpkinProjective>(&card_ct, comm_shares, N_SHUFFLERS)
                .expect("community decrypt");

        // Player-targeted recovery should match community decryption result
        assert_eq!(recovered, expected_value);
    }

    #[test]
    fn test_community_decryption_flow() {
        let mut rng = test_rng();

        let mut secrets = Vec::with_capacity(N_SHUFFLERS);
        let mut public_keys = Vec::with_capacity(N_SHUFFLERS);
        for _ in 0..N_SHUFFLERS {
            let secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
            let public_key = GrumpkinProjective::generator() * secret;
            secrets.push(secret);
            public_keys.push(public_key);
        }
        let aggregated_public_key = make_global_public_keys(public_keys.clone());
        let signing_params = Arc::new(
            ShufflerScheme::<GrumpkinProjective>::setup(&mut rng).expect("schnorr params"),
        );
        let shufflers: Vec<_> = secrets
            .into_iter()
            .zip(public_keys.into_iter())
            .map(|(secret, public_key)| {
                let sign_sk = SchnorrSecretKey::<GrumpkinProjective>(secret.clone());
                ShufflerEngine::<GrumpkinProjective, ShufflerScheme<GrumpkinProjective>>::new(
                    Arc::new(sign_sk),
                    public_key,
                    aggregated_public_key.clone(),
                    Arc::clone(&signing_params),
                )
            })
            .collect();
        let agg_pk = aggregated_public_key;

        // Encrypt a community card with known value in [0..51]
        let card_value: u8 = 25;
        let message = <GrumpkinProjective as PrimeGroup>::ScalarField::from(card_value as u64);
        let msg_point = GrumpkinProjective::generator() * message;
        let randomness = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let ciphertext = ElGamalCiphertext::encrypt(msg_point, randomness, agg_pk);

        // Collect community decryption shares from all shufflers
        let mut shares = Vec::with_capacity(N_SHUFFLERS);
        for s in &shufflers {
            let share = s
                .provide_community_decryption_share(&ciphertext, &mut rng)
                .expect("community share");
            shares.push(share);
        }

        // Decrypt using all shares (n-of-n)
        let recovered =
            decrypt_community_card::<GrumpkinProjective>(&ciphertext, shares, N_SHUFFLERS)
                .expect("community decrypt");
        assert_eq!(recovered, card_value);
    }

    #[tokio::test]
    async fn deal_loop_handles_player_request() {
        type Curve = GrumpkinProjective;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEFu64);
        let shuffle_secret = <Curve as PrimeGroup>::ScalarField::rand(&mut rng);
        let public_key = Curve::generator() * shuffle_secret;

        let schnorr_params = ShufflerScheme::<Curve>::setup(&mut rng).expect("schnorr params");
        let signing_secret = SchnorrSecretKey::<Curve>(shuffle_secret.clone());

        let (submit_tx, mut submit_rx) = mpsc::channel(8);
        let (events_tx, _) = broadcast::channel(8);
        let (snapshots_tx, _) = broadcast::channel(8);
        let shuffler = ShufflerService::<Curve, ShufflerScheme<Curve>>::new(
            0,
            public_key.clone(),
            public_key.clone(),
            signing_secret,
            schnorr_params,
            submit_tx,
            ShufflerRunConfig::new([1u8; 32]),
            events_tx.subscribe(),
            snapshots_tx.subscribe(),
        );

        let key = (11i64, 22i64);
        let zero_cipher = ElGamalCiphertext::new(Curve::generator(), Curve::generator());
        let deck: [ElGamalCiphertext<Curve>; DECK_SIZE] =
            core::array::from_fn(|_| zero_cipher.clone());
        let runtime_key = crate::ledger::CanonicalKey::new(Curve::zero());
        let runtime = Arc::new(HandRuntime::new(
            key.0,
            key.1,
            0,
            0,
            runtime_key.clone(),
            ShufflingHandState {
                expected_order: vec![runtime_key.clone()],
                buffered: Vec::new(),
                next_nonce: 0,
                turn_index: 0,
                initial_deck: deck.clone(),
                latest_deck: deck,
                acted: false,
                rng: StdRng::seed_from_u64(0xABCDu64),
            },
            Weak::new(),
        ));

        let (deal_tx, deal_rx) = broadcast::channel(8);
        let shuffler_key = crate::ledger::CanonicalKey::new(shuffler.public_key().clone());
        let actor = ShufflerActor {
            shuffler_id: 0,
            shuffler_key,
        };
        let deal_handle = crate::shuffler::service::spawn_dealing_request_worker_for_tests(
            0,
            Arc::clone(&runtime),
            deal_rx,
            crate::shuffler::service::submit_sender_for_tests(&shuffler),
            crate::shuffler::service::engine_for_tests(&shuffler),
            &actor,
        );

        let player_public_key = Curve::generator();
        let ciphertext = PlayerAccessibleCiphertext {
            blinded_base: Curve::generator(),
            blinded_message_with_player_key: Curve::generator(),
            player_unblinding_helper: Curve::generator(),
            shuffler_proofs: Vec::new(),
        };
        deal_tx
            .send(DealShufflerRequest::PlayerBlinding(PlayerBlindingRequest {
                game_id: key.0,
                hand_id: key.1,
                deal_index: 0,
                seat: 3,
                hole_index: 0,
                player_public_key: player_public_key.clone(),
            }))
            .expect("send player blinding request");

        let first = timeout(Duration::from_secs(1), submit_rx.recv())
            .await
            .expect("wait blinding")
            .expect("blinding message");
        matches!(first.message.value, AnyGameMessage::Blinding(_))
            .then_some(())
            .expect("expected blinding message");

        deal_tx
            .send(DealShufflerRequest::PlayerUnblinding(
                PlayerUnblindingRequest {
                    game_id: key.0,
                    hand_id: key.1,
                    deal_index: 0,
                    seat: 3,
                    hole_index: 0,
                    player_public_key,
                    ciphertext,
                },
            ))
            .expect("send player unblinding request");

        let second = timeout(Duration::from_secs(1), submit_rx.recv())
            .await
            .expect("wait partial")
            .expect("partial message");
        matches!(second.message.value, AnyGameMessage::PartialUnblinding(_))
            .then_some(())
            .expect("expected partial unblinding message");

        runtime.cancel.cancel();
        deal_handle.abort();
        shuffler.cancel_all();
    }

    #[tokio::test]
    async fn deal_loop_board_request_no_output() {
        type Curve = GrumpkinProjective;

        let mut rng = StdRng::seed_from_u64(0xFACEu64);
        let shuffle_secret = <Curve as PrimeGroup>::ScalarField::rand(&mut rng);
        let public_key = Curve::generator() * shuffle_secret;

        let schnorr_params = ShufflerScheme::<Curve>::setup(&mut rng).expect("schnorr params");
        let signing_secret = SchnorrSecretKey::<Curve>(shuffle_secret.clone());

        let (submit_tx, mut submit_rx) = mpsc::channel(4);
        let (events_tx, _) = broadcast::channel(4);
        let (snapshots_tx, _) = broadcast::channel(4);
        let shuffler = ShufflerService::<Curve, ShufflerScheme<Curve>>::new(
            0,
            public_key.clone(),
            public_key.clone(),
            signing_secret,
            schnorr_params,
            submit_tx,
            ShufflerRunConfig::new([2u8; 32]),
            events_tx.subscribe(),
            snapshots_tx.subscribe(),
        );

        let key = (5i64, 6i64);
        let zero_cipher = ElGamalCiphertext::new(Curve::zero(), Curve::zero());
        let deck = core::array::from_fn(|_| zero_cipher.clone());
        let runtime_key = crate::ledger::CanonicalKey::new(Curve::zero());
        let runtime = Arc::new(HandRuntime::new(
            key.0,
            key.1,
            0,
            0,
            runtime_key.clone(),
            ShufflingHandState {
                expected_order: vec![runtime_key.clone()],
                buffered: Vec::new(),
                next_nonce: 0,
                turn_index: 0,
                initial_deck: deck.clone(),
                latest_deck: deck,
                acted: false,
                rng: StdRng::seed_from_u64(0xEEEEu64),
            },
            Weak::new(),
        ));

        let (deal_tx, deal_rx) = broadcast::channel(4);
        let shuffler_key = crate::ledger::CanonicalKey::new(shuffler.public_key().clone());
        let actor = ShufflerActor {
            shuffler_id: 0,
            shuffler_key,
        };
        let deal_handle = crate::shuffler::service::spawn_dealing_request_worker_for_tests(
            0,
            Arc::clone(&runtime),
            deal_rx,
            crate::shuffler::service::submit_sender_for_tests(&shuffler),
            crate::shuffler::service::engine_for_tests(&shuffler),
            &actor,
        );

        let board_request = BoardCardShufflerRequest {
            game_id: key.0,
            hand_id: key.1,
            deal_index: 7,
            slot: BoardCardSlot::Flop(0),
            ciphertext: DealtCard {
                cipher: ElGamalCiphertext::new(Curve::generator(), Curve::generator()),
                source_index: Some(0),
            },
        };
        deal_tx
            .send(DealShufflerRequest::Board(board_request))
            .expect("send board request");

        assert!(timeout(Duration::from_millis(100), submit_rx.recv())
            .await
            .is_err());

        runtime.cancel.cancel();
        deal_handle.abort();
        shuffler.cancel_all();
    }

    #[test]
    fn dealing_state_emits_blinding_then_unblinding() {
        type Curve = GrumpkinProjective;

        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2, 3], &[0]);
        let mut table = fixture_dealing_snapshot(&ctx);
        let mut state = DealingHandState::<Curve>::new();

        // Simulate initial dealing snapshot before ciphertexts exist.
        table.dealing.player_ciphertexts.clear();

        let requests = state
            .process_snapshot_and_make_responses(
                &table,
                0,
                &crate::ledger::CanonicalKey::new(Curve::zero()),
            )
            .expect("process snapshot");
        let mut blinding_requests: Vec<_> = requests
            .into_iter()
            .filter_map(|req| match req {
                DealShufflerRequest::PlayerBlinding(player) => Some(player),
                _ => None,
            })
            .collect();

        assert!(!blinding_requests.is_empty(), "expected blinding requests");
        let first_player = blinding_requests.remove(0);
        let seat = first_player.seat;
        let hole_index = first_player.hole_index;

        // Populate ciphertext for same card and ensure unblinding request is emitted.
        let cipher = PlayerAccessibleCiphertext {
            blinded_base: Curve::zero(),
            blinded_message_with_player_key: Curve::zero(),
            player_unblinding_helper: Curve::zero(),
            shuffler_proofs: Vec::new(),
        };

        table
            .dealing
            .player_ciphertexts
            .insert((seat, hole_index), cipher);

        let requests = state
            .process_snapshot_and_make_responses(
                &table,
                0,
                &crate::ledger::CanonicalKey::new(Curve::zero()),
            )
            .expect("process snapshot");
        let unblinding_requests: Vec<_> = requests
            .into_iter()
            .filter_map(|req| match req {
                DealShufflerRequest::PlayerUnblinding(player) => Some(player),
                _ => None,
            })
            .collect();

        assert!(unblinding_requests
            .iter()
            .any(|req| req.seat == seat && req.hole_index == hole_index));
    }

    #[test]
    fn dealing_state_skips_cards_with_existing_contributions() {
        type Curve = GrumpkinProjective;

        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2, 3], &[0]);
        let mut table = fixture_dealing_snapshot(&ctx);
        let mut state = DealingHandState::<Curve>::new();

        let (deal_index, seat, hole_index) = table
            .dealing
            .card_plan
            .iter()
            .find_map(|(&idx, destination)| match destination {
                CardDestination::Hole { seat, hole_index } => Some((idx, *seat, *hole_index)),
                _ => None,
            })
            .expect("fixture hole card");

        let shuffler_id = 42;
        let test_key = crate::ledger::CanonicalKey::new(Curve::generator());

        let faux_contribution = PlayerTargetedBlindingContribution {
            blinding_base_contribution: Curve::zero(),
            blinding_combined_contribution: Curve::zero(),
            proof: ChaumPedersenProof {
                t_g: Curve::zero(),
                t_h: Curve::zero(),
                z: <Curve as PrimeGroup>::ScalarField::zero(),
            },
        };
        table
            .dealing
            .player_blinding_contribs
            .insert((test_key.clone(), seat, hole_index), faux_contribution);

        let faux_share = PartialUnblindingShare {
            share: Curve::zero(),
            member_key: test_key.clone(),
        };
        table
            .dealing
            .player_unblinding_shares
            .entry((seat, hole_index))
            .or_default()
            .insert(test_key.clone(), faux_share);

        let requests = state
            .process_snapshot_and_make_responses(&table, shuffler_id, &test_key)
            .expect("process snapshot");

        assert!(
            !requests.iter().any(|req| match req {
                DealShufflerRequest::PlayerBlinding(player) => player.deal_index == deal_index,
                DealShufflerRequest::PlayerUnblinding(player) => {
                    player.deal_index == deal_index
                }
                DealShufflerRequest::Board(_) => false,
            }),
            "expected no duplicate requests for prior contributions"
        );
    }

    #[test]
    fn dealing_state_processes_preflop_snapshot() {
        type Curve = GrumpkinProjective;

        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2, 3], &[0]);
        let mut table = fixture_preflop_snapshot(&ctx);
        let mut state = DealingHandState::<Curve>::new();

        let (seat, hole_index) = table
            .dealing
            .card_plan
            .values()
            .find_map(|destination| match destination {
                CardDestination::Hole { seat, hole_index } => Some((*seat, *hole_index)),
                _ => None,
            })
            .expect("preflop hole card");

        let shuffler_id = 17;
        let test_key = crate::ledger::CanonicalKey::new(Curve::generator() + Curve::generator());

        let faux_contribution = PlayerTargetedBlindingContribution {
            blinding_base_contribution: Curve::zero(),
            blinding_combined_contribution: Curve::zero(),
            proof: ChaumPedersenProof {
                t_g: Curve::zero(),
                t_h: Curve::zero(),
                z: <Curve as PrimeGroup>::ScalarField::zero(),
            },
        };
        table
            .dealing
            .player_blinding_contribs
            .insert((test_key.clone(), seat, hole_index), faux_contribution);

        table.dealing.player_ciphertexts.insert(
            (seat, hole_index),
            PlayerAccessibleCiphertext {
                blinded_base: Curve::zero(),
                blinded_message_with_player_key: Curve::zero(),
                player_unblinding_helper: Curve::zero(),
                shuffler_proofs: Vec::new(),
            },
        );

        let requests = state
            .process_snapshot_and_make_responses(&table, shuffler_id, &test_key)
            .expect("process preflop snapshot");

        assert!(
            requests.iter().any(|req| matches!(
                req,
                DealShufflerRequest::PlayerUnblinding(player)
                    if player.seat == seat && player.hole_index == hole_index
            )),
            "expected unblinding request to be emitted from preflop snapshot"
        );
    }

    #[test]
    fn dealing_state_emits_board_requests_in_stages() {
        type Curve = GrumpkinProjective;

        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2, 3], &[0, 1]);
        let mut table = fixture_dealing_snapshot(&ctx);
        let mut state = DealingHandState::<Curve>::new();

        table.dealing.player_ciphertexts.clear();
        table.dealing.community_cards.clear();

        // Initial snapshot should only request player shares.
        let initial = state
            .process_snapshot_and_make_responses(
                &table,
                0,
                &crate::ledger::CanonicalKey::new(Curve::zero()),
            )
            .expect("process snapshot");
        assert!(initial
            .iter()
            .all(|req| matches!(req, DealShufflerRequest::PlayerBlinding(_))));

        // Provide ciphertexts for every hole card to trigger unblinding.
        let dummy_cipher = PlayerAccessibleCiphertext {
            blinded_base: Curve::zero(),
            blinded_message_with_player_key: Curve::zero(),
            player_unblinding_helper: Curve::zero(),
            shuffler_proofs: Vec::new(),
        };

        for destination in table.dealing.card_plan.values() {
            if let CardDestination::Hole { seat, hole_index } = destination {
                table
                    .dealing
                    .player_ciphertexts
                    .insert((*seat, *hole_index), dummy_cipher.clone());
            }
        }

        // Flop requests should be emitted together once hole cards are ready.
        let second = state
            .process_snapshot_and_make_responses(
                &table,
                0,
                &crate::ledger::CanonicalKey::new(Curve::zero()),
            )
            .expect("process snapshot");
        let mut flop_slots: Vec<u8> = second
            .iter()
            .filter_map(|req| match req {
                DealShufflerRequest::Board(board) => match board.slot {
                    BoardCardSlot::Flop(idx) => Some(idx),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        flop_slots.sort_unstable();
        assert_eq!(flop_slots, vec![0, 1, 2]);
        assert!(second.iter().all(|req| match req {
            DealShufflerRequest::Board(board) => matches!(board.slot, BoardCardSlot::Flop(_)),
            _ => true,
        }));

        // Mark flop cards as revealed to unlock the turn.
        for (&deal_index, destination) in table.dealing.card_plan.iter() {
            if let CardDestination::Board { board_index } = destination {
                if *board_index < 3 {
                    table.dealing.community_cards.insert(deal_index, deal_index);
                }
            }
        }

        let third = state
            .process_snapshot_and_make_responses(
                &table,
                0,
                &crate::ledger::CanonicalKey::new(Curve::zero()),
            )
            .expect("process snapshot");
        let turn_count = third
            .iter()
            .filter(|req| {
                matches!(
                    req,
                    DealShufflerRequest::Board(board) if matches!(board.slot, BoardCardSlot::Turn)
                )
            })
            .count();
        let river_count = third
            .iter()
            .filter(|req| {
                matches!(
                    req,
                    DealShufflerRequest::Board(board) if matches!(board.slot, BoardCardSlot::River)
                )
            })
            .count();
        assert_eq!(turn_count, 1);
        assert_eq!(river_count, 0);

        // Reveal turn card to allow the river request.
        for (&deal_index, destination) in table.dealing.card_plan.iter() {
            if let CardDestination::Board { board_index } = destination {
                if *board_index == 3 {
                    table.dealing.community_cards.insert(deal_index, deal_index);
                }
            }
        }

        let fourth = state
            .process_snapshot_and_make_responses(
                &table,
                0,
                &crate::ledger::CanonicalKey::new(Curve::zero()),
            )
            .expect("process snapshot");
        let river_count = fourth
            .iter()
            .filter(|req| {
                matches!(
                    req,
                    DealShufflerRequest::Board(board) if matches!(board.slot, BoardCardSlot::River)
                )
            })
            .count();
        assert_eq!(river_count, 1);

        // Further snapshots should not emit additional board requests.
        let fifth = state
            .process_snapshot_and_make_responses(
                &table,
                0,
                &crate::ledger::CanonicalKey::new(Curve::zero()),
            )
            .expect("process snapshot");
        assert!(fifth.iter().all(|req| matches!(
            req,
            DealShufflerRequest::PlayerBlinding(_) | DealShufflerRequest::PlayerUnblinding(_)
        )));
    }
}
