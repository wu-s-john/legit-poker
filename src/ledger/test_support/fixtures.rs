#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use ark_ec::{CurveConfig, CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::engine::nl::engine::{BettingEngineNL, EngineNL};
use crate::engine::nl::types::{HandConfig, PlayerId, PlayerStatus, SeatId, TableStakes};
use crate::ledger::hash::{default_poseidon_hasher, LedgerHasher};
use crate::ledger::snapshot::{
    build_default_card_plan, build_initial_betting_state, BettingSnapshot, CardDestination,
    CardPlan, DealingSnapshot, DealtCard, PlayerRoster, PlayerStackInfo, PlayerStacks,
    RevealedHand, RevealsSnapshot, SeatingMap, Shared, ShufflerIdentity, ShufflerRoster,
    ShufflingSnapshot, SnapshotStatus, TableAtComplete, TableAtDealing, TableAtFlop,
    TableAtPreflop, TableAtRiver, TableAtShowdown, TableAtShuffling, TableAtTurn, TableSnapshot,
};
use crate::ledger::types::{GameId, HandId, ShufflerId, StateHash};
use crate::ledger::CanonicalKey;
use crate::showdown::HandCategory;
use crate::shuffling::data_structures::{ElGamalCiphertext, DECK_SIZE};
use crate::shuffling::generate_random_ciphertexts;
use crate::shuffling::player_decryption::PlayerAccessibleCiphertext;

const FIXTURE_GAME_ID: GameId = 42;
const FIXTURE_HAND_ID: HandId = 7;
const FIXTURE_STACK: u64 = 1_000;
const FIXTURE_SEED: u64 = 0x05ee_df1c;

pub struct FixtureContext<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub cfg: Shared<HandConfig>,
    pub players: Shared<PlayerRoster<C>>,
    pub player_keys: BTreeMap<PlayerId, CanonicalKey<C>>,
    pub player_secrets: BTreeMap<PlayerId, C::ScalarField>,
    pub shufflers: Shared<ShufflerRoster<C>>,
    pub shuffler_keys: BTreeMap<ShufflerId, CanonicalKey<C>>,
    pub shuffler_secrets: BTreeMap<ShufflerId, C::ScalarField>,
    pub seating: Shared<SeatingMap<C>>,
    pub stacks: Shared<PlayerStacks<C>>,
    pub expected_shuffler_order: Vec<CanonicalKey<C>>,
    pub aggregated_shuffler_pk: C,
    pub initial_deck: Arc<[ElGamalCiphertext<C>; DECK_SIZE]>,
    pub hasher: Arc<dyn LedgerHasher + Send + Sync>,
}

impl<C> FixtureContext<C>
where
    C: CurveGroup + PrimeGroup,
    C::ScalarField: PrimeField + UniformRand,
    C::BaseField: PrimeField,
    C::Config: CurveConfig<ScalarField = C::ScalarField>,
{
    pub fn new(seat_ids: &[SeatId], shuffler_ids: &[ShufflerId]) -> Self {
        assert!(
            seat_ids.len() >= 3,
            "fixture context requires at least button, small blind, and big blind seats"
        );
        assert!(
            shuffler_ids.iter().all(|id| *id >= 0),
            "shuffler ids must be non-negative"
        );

        let mut rng = fixture_rng();
        let cfg = fixture_hand_config(seat_ids[0], seat_ids[1], seat_ids[2]);

        let (players, seating, stacks, player_keys, player_secrets) =
            build_player_context::<C>(&mut rng, seat_ids, &cfg);
        let (
            shufflers,
            shuffler_secrets,
            shuffler_keys,
            expected_shuffler_order,
            aggregated_shuffler_pk,
        ) = build_shuffler_context::<C>(&mut rng, shuffler_ids);

        let (deck, _) =
            generate_random_ciphertexts::<C, DECK_SIZE>(&aggregated_shuffler_pk, &mut rng);
        let initial_deck = Arc::new(deck);
        let hasher = default_poseidon_hasher::<C::BaseField>();

        Self {
            game_id: FIXTURE_GAME_ID,
            hand_id: FIXTURE_HAND_ID,
            cfg: Arc::new(cfg),
            players: Arc::new(players),
            player_keys,
            player_secrets,
            shufflers: Arc::new(shufflers),
            shuffler_keys,
            shuffler_secrets,
            seating: Arc::new(seating),
            stacks: Arc::new(stacks),
            expected_shuffler_order,
            aggregated_shuffler_pk,
            initial_deck,
            hasher,
        }
    }
}

pub fn active_seats<C: CurveGroup>(ctx: &FixtureContext<C>) -> Vec<SeatId> {
    ctx.stacks
        .iter()
        .filter_map(|(&seat, info)| {
            if matches!(info.status, PlayerStatus::Active | PlayerStatus::AllIn) {
                Some(seat)
            } else {
                None
            }
        })
        .collect()
}

pub fn fixture_rng() -> StdRng {
    StdRng::seed_from_u64(FIXTURE_SEED)
}

pub fn fixture_hand_config(button: SeatId, small_blind: SeatId, big_blind: SeatId) -> HandConfig {
    HandConfig {
        stakes: TableStakes {
            small_blind: 1,
            big_blind: 2,
            ante: 0,
        },
        button,
        small_blind_seat: small_blind,
        big_blind_seat: big_blind,
        check_raise_allowed: true,
    }
}

fn build_player_context<C>(
    rng: &mut impl RngCore,
    seat_ids: &[SeatId],
    cfg: &HandConfig,
) -> (
    PlayerRoster<C>,
    SeatingMap<C>,
    PlayerStacks<C>,
    BTreeMap<PlayerId, CanonicalKey<C>>,
    BTreeMap<PlayerId, C::ScalarField>,
)
where
    C: CurveGroup,
    C::ScalarField: PrimeField + UniformRand,
{
    let mut roster: PlayerRoster<C> = BTreeMap::new();
    let mut seating: SeatingMap<C> = BTreeMap::new();
    let mut stacks: PlayerStacks<C> = BTreeMap::new();
    let mut key_map = BTreeMap::new();
    let mut secrets = BTreeMap::new();

    for (idx, seat) in seat_ids.iter().enumerate() {
        let player_id = (idx as PlayerId) + 100;
        let secret = C::ScalarField::rand(rng);
        let public = C::generator() * secret;
        let player_key = CanonicalKey::new(public);

        roster.insert(
            player_key.clone(),
            crate::ledger::snapshot::PlayerIdentity {
                public_key: public,
                player_key: player_key.clone(),
                player_id,
                nonce: 0,
                seat: *seat,
            },
        );
        seating.insert(*seat, Some(player_key.clone()));

        let committed_blind = if *seat == cfg.small_blind_seat {
            cfg.stakes.small_blind
        } else if *seat == cfg.big_blind_seat {
            cfg.stakes.big_blind
        } else {
            0
        };

        stacks.insert(
            *seat,
            PlayerStackInfo {
                seat: *seat,
                player_key: Some(player_key.clone()),
                starting_stack: FIXTURE_STACK,
                committed_blind,
                status: if *seat == cfg.button {
                    PlayerStatus::SittingOut
                } else {
                    PlayerStatus::Active
                },
            },
        );
        key_map.insert(player_id, player_key.clone());
        secrets.insert(player_id, secret);
    }

    (roster, seating, stacks, key_map, secrets)
}

fn build_shuffler_context<C>(
    rng: &mut impl RngCore,
    shuffler_ids: &[ShufflerId],
) -> (
    ShufflerRoster<C>,
    BTreeMap<ShufflerId, C::ScalarField>,
    BTreeMap<ShufflerId, CanonicalKey<C>>,
    Vec<CanonicalKey<C>>,
    C,
)
where
    C: CurveGroup,
    C::ScalarField: PrimeField + UniformRand,
{
    let mut roster: ShufflerRoster<C> = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    let mut key_map = BTreeMap::new();

    let mut entries = Vec::new();
    for shuffler_id in shuffler_ids {
        let secret = C::ScalarField::rand(rng);
        let public = C::generator() * secret;
        entries.push((*shuffler_id, secret, public));
    }

    let aggregated = entries
        .iter()
        .fold(C::zero(), |acc, (_, _, public)| acc + *public);

    let mut expected_order = Vec::with_capacity(entries.len());
    for (shuffler_id, secret, public) in entries {
        let canonical = CanonicalKey::new(public.clone());
        roster.insert(
            canonical.clone(),
            ShufflerIdentity {
                public_key: public.clone(),
                shuffler_key: canonical.clone(),
                shuffler_id,
                aggregated_public_key: aggregated,
            },
        );
        secrets.insert(shuffler_id, secret);
        key_map.insert(shuffler_id, canonical.clone());
        expected_order.push(canonical);
    }

    (roster, secrets, key_map, expected_order, aggregated)
}

fn zero_player_ciphertext<C: CurveGroup>() -> PlayerAccessibleCiphertext<C> {
    PlayerAccessibleCiphertext {
        blinded_base: C::zero(),
        blinded_message_with_player_key: C::zero(),
        player_unblinding_helper: C::zero(),
        shuffler_proofs: Vec::new(),
    }
}

fn card_value_for_ref(card_ref: u8) -> u8 {
    card_ref
}

pub fn populate_board_cards_upto<C: CurveGroup>(dealing: &mut DealingSnapshot<C>, limit: usize) {
    for (&card_ref, destination) in dealing.card_plan.iter() {
        if let CardDestination::Board { board_index } = destination {
            if (*board_index as usize) < limit {
                dealing
                    .community_cards
                    .insert(card_ref, card_value_for_ref(card_ref));
            }
        }
    }
}

fn board_cards_in_order(
    card_plan: &CardPlan,
    community_cards: &BTreeMap<u8, u8>,
    limit: Option<usize>,
) -> Vec<u8> {
    let mut ordered: Vec<(u8, u8)> = card_plan
        .iter()
        .filter_map(|(&card_ref, dest)| match dest {
            CardDestination::Board { board_index } => community_cards
                .get(&card_ref)
                .copied()
                .map(|value| (*board_index, value)),
            _ => None,
        })
        .collect();
    ordered.sort_by_key(|(board_index, _)| *board_index);
    if let Some(limit) = limit {
        ordered.truncate(limit);
    }
    ordered.into_iter().map(|(_, value)| value).collect()
}

fn hole_card_refs_for_seat(card_plan: &CardPlan, seat: SeatId) -> Vec<(u8, u8)> {
    let mut refs: Vec<(u8, u8)> = card_plan
        .iter()
        .filter_map(|(&card_ref, dest)| match dest {
            CardDestination::Hole {
                seat: dest_seat,
                hole_index,
            } if *dest_seat == seat => Some((*hole_index, card_ref)),
            _ => None,
        })
        .collect();
    refs.sort_by_key(|(hole_index, _)| *hole_index);
    refs
}

fn build_shuffling_snapshot<C>(ctx: &FixtureContext<C>) -> ShufflingSnapshot<C>
where
    C: CurveGroup,
{
    let initial = (*ctx.initial_deck).clone();
    ShufflingSnapshot {
        initial_deck: initial.clone(),
        steps: Vec::new(),
        final_deck: initial,
        expected_order: ctx.expected_shuffler_order.clone(),
    }
}

fn build_dealing_snapshot<C>(ctx: &FixtureContext<C>) -> DealingSnapshot<C>
where
    C: CurveGroup,
{
    let mut assignments = BTreeMap::new();
    let mut player_ciphertexts = BTreeMap::new();
    let mut player_unblinding_combined = BTreeMap::new();
    let community_cards = BTreeMap::new();
    let card_plan = build_default_card_plan(ctx.cfg.as_ref(), ctx.seating.as_ref());

    for (&card_ref, destination) in card_plan.iter() {
        let index = card_ref as usize;
        let cipher = ctx.initial_deck[index].clone();
        assignments.insert(
            card_ref,
            DealtCard {
                cipher,
                source_index: Some(card_ref),
            },
        );

        match destination {
            CardDestination::Hole { seat, hole_index } => {
                player_ciphertexts.insert((*seat, *hole_index), zero_player_ciphertext::<C>());
                player_unblinding_combined
                    .entry((*seat, *hole_index))
                    .or_insert_with(C::zero);
            }
            CardDestination::Board { .. } => {}
            _ => {}
        }
    }

    DealingSnapshot {
        assignments,
        player_ciphertexts,
        player_blinding_contribs: Default::default(),
        player_unblinding_shares: Default::default(),
        player_unblinding_combined,
        community_decryption_shares: Default::default(),
        community_cards,
        card_plan,
    }
}

pub fn fixture_shuffling_snapshot<C>(ctx: &FixtureContext<C>) -> TableAtShuffling<C>
where
    C: CurveGroup,
{
    let mut snapshot = TableSnapshot {
        game_id: ctx.game_id,
        hand_id: Some(ctx.hand_id),
        sequence: 0,
        cfg: Arc::clone(&ctx.cfg),
        shufflers: Arc::clone(&ctx.shufflers),
        players: Arc::clone(&ctx.players),
        seating: Arc::clone(&ctx.seating),
        stacks: Arc::clone(&ctx.stacks),
        previous_hash: None,
        state_hash: StateHash::default(),
        status: SnapshotStatus::Success,
        shuffling: build_shuffling_snapshot(ctx),
        dealing: (),
        betting: (),
        reveals: (),
    };
    snapshot.initialize_hash(ctx.hasher.as_ref());
    snapshot
}

pub fn fixture_dealing_snapshot<C>(ctx: &FixtureContext<C>) -> TableAtDealing<C>
where
    C: CurveGroup,
{
    let mut snapshot = TableSnapshot {
        game_id: ctx.game_id,
        hand_id: Some(ctx.hand_id),
        sequence: 0,
        cfg: Arc::clone(&ctx.cfg),
        shufflers: Arc::clone(&ctx.shufflers),
        players: Arc::clone(&ctx.players),
        seating: Arc::clone(&ctx.seating),
        stacks: Arc::clone(&ctx.stacks),
        previous_hash: None,
        state_hash: StateHash::default(),
        status: SnapshotStatus::Success,
        shuffling: build_shuffling_snapshot(ctx),
        dealing: build_dealing_snapshot(ctx),
        betting: (),
        reveals: (),
    };
    snapshot.initialize_hash(ctx.hasher.as_ref());
    snapshot
}

pub fn fixture_preflop_snapshot<C>(ctx: &FixtureContext<C>) -> TableAtPreflop<C>
where
    C: CurveGroup,
{
    let dealing = build_dealing_snapshot(ctx);
    let mut snapshot = TableSnapshot {
        game_id: ctx.game_id,
        hand_id: Some(ctx.hand_id),
        sequence: 0,
        cfg: Arc::clone(&ctx.cfg),
        shufflers: Arc::clone(&ctx.shufflers),
        players: Arc::clone(&ctx.players),
        seating: Arc::clone(&ctx.seating),
        stacks: Arc::clone(&ctx.stacks),
        previous_hash: None,
        state_hash: StateHash::default(),
        status: SnapshotStatus::Success,
        shuffling: build_shuffling_snapshot(ctx),
        dealing,
        betting: BettingSnapshot {
            state: build_initial_betting_state(
                ctx.cfg.as_ref(),
                ctx.stacks.as_ref(),
                ctx.players.as_ref(),
            ),
            last_events: Vec::new(),
        },
        reveals: RevealsSnapshot {
            board: Vec::new(),
            revealed_holes: BTreeMap::new(),
        },
    };
    snapshot.initialize_hash(ctx.hasher.as_ref());
    snapshot
}

pub fn fixture_flop_snapshot<C>(ctx: &FixtureContext<C>) -> TableAtFlop<C>
where
    C: CurveGroup,
{
    let preflop = fixture_preflop_snapshot(ctx);
    let TableSnapshot {
        game_id,
        hand_id,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        shuffling,
        mut dealing,
        mut betting,
        mut reveals,
        ..
    } = preflop;

    EngineNL::advance_street(&mut betting.state).expect("fixture flop advance failed unexpectedly");
    populate_board_cards_upto(&mut dealing, 3);

    reveals.board = board_cards_in_order(&dealing.card_plan, &dealing.community_cards, Some(3));

    let mut snapshot: TableAtFlop<C> = TableSnapshot {
        game_id,
        hand_id,
        sequence: 0,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash: None,
        state_hash: StateHash::default(),
        status: SnapshotStatus::Success,
        shuffling,
        dealing,
        betting,
        reveals,
    };
    snapshot.initialize_hash(ctx.hasher.as_ref());
    snapshot
}

pub fn fixture_turn_snapshot<C>(ctx: &FixtureContext<C>) -> TableAtTurn<C>
where
    C: CurveGroup,
{
    let flop = fixture_flop_snapshot(ctx);
    let TableSnapshot {
        game_id,
        hand_id,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        shuffling,
        mut dealing,
        mut betting,
        mut reveals,
        ..
    } = flop;

    EngineNL::advance_street(&mut betting.state).expect("fixture turn advance failed unexpectedly");
    populate_board_cards_upto(&mut dealing, 4);
    reveals.board = board_cards_in_order(&dealing.card_plan, &dealing.community_cards, Some(4));

    let mut snapshot: TableAtTurn<C> = TableSnapshot {
        game_id,
        hand_id,
        sequence: 0,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash: None,
        state_hash: StateHash::default(),
        status: SnapshotStatus::Success,
        shuffling,
        dealing,
        betting,
        reveals,
    };
    snapshot.initialize_hash(ctx.hasher.as_ref());
    snapshot
}

pub fn fixture_river_snapshot<C>(ctx: &FixtureContext<C>) -> TableAtRiver<C>
where
    C: CurveGroup,
{
    let turn = fixture_turn_snapshot(ctx);
    let TableSnapshot {
        game_id,
        hand_id,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        shuffling,
        mut dealing,
        mut betting,
        mut reveals,
        ..
    } = turn;

    EngineNL::advance_street(&mut betting.state)
        .expect("fixture river advance failed unexpectedly");
    populate_board_cards_upto(&mut dealing, 5);
    reveals.board = board_cards_in_order(&dealing.card_plan, &dealing.community_cards, Some(5));

    let mut snapshot: TableAtRiver<C> = TableSnapshot {
        game_id,
        hand_id,
        sequence: 0,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash: None,
        state_hash: StateHash::default(),
        status: SnapshotStatus::Success,
        shuffling,
        dealing,
        betting,
        reveals,
    };
    snapshot.initialize_hash(ctx.hasher.as_ref());
    snapshot
}

pub fn fixture_showdown_snapshot<C>(ctx: &FixtureContext<C>) -> TableAtShowdown<C>
where
    C: CurveGroup,
{
    let river = fixture_river_snapshot(ctx);
    let TableSnapshot {
        game_id,
        hand_id,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        shuffling,
        dealing,
        betting,
        reveals,
        ..
    } = river;

    let mut snapshot = TableSnapshot {
        game_id,
        hand_id,
        sequence: 0,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash: None,
        state_hash: StateHash::default(),
        status: SnapshotStatus::Success,
        shuffling,
        dealing,
        betting,
        reveals,
    };
    snapshot.initialize_hash(ctx.hasher.as_ref());
    snapshot
}

pub fn fixture_complete_snapshot<C>(ctx: &FixtureContext<C>) -> TableAtComplete<C>
where
    C: CurveGroup,
{
    let showdown = fixture_showdown_snapshot(ctx);
    finalize_showdown(ctx, showdown)
}

fn finalize_showdown<C>(ctx: &FixtureContext<C>, table: TableAtShowdown<C>) -> TableAtComplete<C>
where
    C: CurveGroup,
{
    let TableSnapshot {
        game_id,
        hand_id,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        shuffling,
        dealing,
        betting,
        mut reveals,
        ..
    } = table;

    for (&seat, player_id) in seating.iter() {
        if player_id.is_none() {
            continue;
        }

        let hole_refs = hole_card_refs_for_seat(&dealing.card_plan, seat);
        if hole_refs.len() < 2 {
            continue;
        }

        let hole_values = [
            card_value_for_ref(hole_refs[0].1),
            card_value_for_ref(hole_refs[1].1),
        ];

        let hole_ciphertexts = [
            dealing
                .player_ciphertexts
                .get(&(seat, 0))
                .cloned()
                .unwrap_or_else(|| zero_player_ciphertext::<C>()),
            dealing
                .player_ciphertexts
                .get(&(seat, 1))
                .cloned()
                .unwrap_or_else(|| zero_player_ciphertext::<C>()),
        ];

        let mut best_five = [0u8; 5];
        for (idx, value) in reveals
            .board
            .iter()
            .copied()
            .chain(hole_values)
            .take(5)
            .enumerate()
        {
            best_five[idx] = value;
        }

        reveals.revealed_holes.insert(
            seat,
            RevealedHand {
                hole: hole_values,
                hole_ciphertexts,
                best_five,
                best_category: HandCategory::HighCard,
                best_tiebreak: [0; 5],
                best_score: 0,
            },
        );
    }

    let mut snapshot = TableSnapshot {
        game_id,
        hand_id,
        sequence: 0,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash: None,
        state_hash: StateHash::default(),
        status: SnapshotStatus::Success,
        shuffling,
        dealing,
        betting,
        reveals,
    };
    snapshot.initialize_hash(ctx.hasher.as_ref());
    snapshot
}
