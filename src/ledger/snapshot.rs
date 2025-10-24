use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::db::entity::sea_orm_active_enums::{ApplicationStatus, PhaseKind};
use crate::db::entity::{
    hand_configs, hand_player, hand_shufflers, phases as phase_table, players, shufflers,
    table_snapshots,
};
use crate::engine::nl::actions::PlayerBetAction;
use crate::engine::nl::engine::{BettingEngineNL, EngineNL};
use crate::engine::nl::state::BettingState;
use crate::engine::nl::types::{
    HandConfig, PlayerId, PlayerState, PlayerStatus, Pot, Pots, SeatId, Street,
};
use crate::ledger::hash::{chain_hash, initial_snapshot_hash, message_hash, LedgerHasher};
use crate::ledger::messages::{
    EnvelopedMessage, FlopStreet, GameMessage, GamePlayerMessage, PreflopStreet, RiverStreet,
    TurnStreet,
};
use crate::ledger::serialization::deserialize_curve_bytes;
use crate::ledger::types::{EventPhase, GameId, HandId, ShufflerId, StateHash};
use crate::ledger::CanonicalKey;
use crate::showdown::HandCategory;
use crate::shuffling::community_decryption::CommunityDecryptionShare;
use crate::shuffling::data_structures::{
    append_curve_point, ElGamalCiphertext, ShuffleProof, DECK_SIZE,
};
use crate::shuffling::player_decryption::{
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
};
use crate::signing::Signable;
use crate::signing::TranscriptBuilder;
use ark_ff::PrimeField;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};

pub mod phases;

pub use phases::{
    HandPhase, PhaseBetting, PhaseComplete, PhaseDealing, PhaseShowdown, PhaseShuffling,
};

// Shared alias used throughout snapshots
pub type Shared<T> = Arc<T>;
pub type SnapshotSeq = u32;

// ---- Player identity / seating --------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct PlayerIdentity<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::curve")]
    pub public_key: C,
    pub player_key: CanonicalKey<C>,
    pub player_id: PlayerId,
    pub nonce: u64,
    pub seat: SeatId,
}

impl<C: CurveGroup> PlayerIdentity<C> {
    pub fn append_to_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(self.seat);
        builder.append_u64(self.nonce);
        builder.append_u64(self.player_id);
        append_curve_point(builder, &self.public_key);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct ShufflerIdentity<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::curve")]
    pub public_key: C,
    pub shuffler_key: CanonicalKey<C>,
    pub shuffler_id: ShufflerId,
    #[serde(with = "crate::crypto_serde::curve")]
    pub aggregated_public_key: C,
}

pub type PlayerRoster<C> = BTreeMap<CanonicalKey<C>, PlayerIdentity<C>>;
pub type ShufflerRoster<C> = BTreeMap<CanonicalKey<C>, ShufflerIdentity<C>>;
pub type SeatingMap<C> = BTreeMap<SeatId, Option<CanonicalKey<C>>>;
pub type PlayerStacks<C> = BTreeMap<SeatId, PlayerStackInfo<C>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Success,
    Failure(String),
}

impl<C: CurveGroup> Signable for PlayerIdentity<C> {
    fn domain_kind(&self) -> &'static str {
        "ledger/player_identity_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        self.append_to_transcript(builder);
    }
}

impl<C: CurveGroup> Signable for ShufflerIdentity<C> {
    fn domain_kind(&self) -> &'static str {
        "ledger/shuffler_identity_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_i64(self.shuffler_id);
        append_curve_point(builder, &self.public_key);
        append_curve_point(builder, &self.aggregated_public_key);
    }
}

// ---- Shuffling -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct ShufflingStep<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::curve")]
    pub shuffler_public_key: C,
    pub proof: ShuffleProof<C>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct ShufflingSnapshot<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::elgamal_array")]
    pub initial_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub steps: Vec<ShufflingStep<C>>,
    #[serde(with = "crate::crypto_serde::elgamal_array")]
    pub final_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub expected_order: Vec<CanonicalKey<C>>,
}

// ---- Dealing -------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct DealtCard<C: CurveGroup> {
    pub cipher: ElGamalCiphertext<C>,
    pub source_index: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct PlayerStackInfo<C: CurveGroup> {
    pub seat: SeatId,
    pub player_key: Option<CanonicalKey<C>>,
    pub starting_stack: u64,
    pub committed_blind: u64,
    pub status: PlayerStatus,
}

impl<C: CurveGroup> PlayerStackInfo<C> {
    pub fn append_to_transcript(&self, builder: &mut TranscriptBuilder) {
        match &self.player_key {
            Some(player_key) => {
                builder.append_u8(1);
                builder.append_bytes(player_key.bytes());
            }
            None => builder.append_u8(0),
        }
        builder.append_u64(self.starting_stack);
        builder.append_u64(self.committed_blind);
        builder.append_u8(self.status.as_byte());
    }
}

impl<C: CurveGroup> Signable for PlayerStackInfo<C> {
    fn domain_kind(&self) -> &'static str {
        "ledger/player_stack_info_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        self.append_to_transcript(builder);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CardDestination {
    Hole { seat: SeatId, hole_index: u8 },
    Board { board_index: u8 },
    Burn,
    Unused,
}

pub type CardPlan = BTreeMap<u8, CardDestination>;

pub fn build_default_card_plan<C>(cfg: &HandConfig, seating: &SeatingMap<C>) -> CardPlan
where
    C: CurveGroup,
{
    let mut plan = CardPlan::new();

    let mut active_seats: Vec<SeatId> = seating
        .iter()
        .filter_map(|(&seat, player)| player.as_ref().map(|_| seat))
        .collect();
    active_seats.sort();

    if !active_seats.is_empty() {
        if let Some(button_pos) = active_seats.iter().position(|&seat| seat == cfg.button) {
            let mut rotated = Vec::with_capacity(active_seats.len());
            for idx in 1..=active_seats.len() {
                let seat = active_seats[(button_pos + idx) % active_seats.len()];
                rotated.push(seat);
            }
            active_seats = rotated;
        }
    }

    let mut next_card: u8 = 0;
    for hole_index in 0..2 {
        for &seat in &active_seats {
            plan.insert(next_card, CardDestination::Hole { seat, hole_index });
            next_card += 1;
        }
    }

    let push_burn = |plan: &mut CardPlan, next: &mut u8| {
        plan.insert(*next, CardDestination::Burn);
        *next += 1;
    };
    let push_board = |plan: &mut CardPlan, next: &mut u8, board_index: u8| {
        plan.insert(*next, CardDestination::Board { board_index });
        *next += 1;
    };

    push_burn(&mut plan, &mut next_card);
    for board_index in 0..3 {
        push_board(&mut plan, &mut next_card, board_index);
    }
    push_burn(&mut plan, &mut next_card);
    push_board(&mut plan, &mut next_card, 3);
    push_burn(&mut plan, &mut next_card);
    push_board(&mut plan, &mut next_card, 4);

    while (next_card as usize) < DECK_SIZE {
        plan.insert(next_card, CardDestination::Unused);
        next_card += 1;
    }

    plan
}

pub fn build_initial_betting_state<C>(
    cfg: &HandConfig,
    stacks: &PlayerStacks<C>,
    players: &PlayerRoster<C>,
) -> BettingStateNL
where
    C: CurveGroup,
{
    let mut player_states: Vec<PlayerState> = stacks
        .values()
        .map(|info| {
            let committed = info.committed_blind;
            let player_id = info
                .player_key
                .as_ref()
                .and_then(|key| players.get(key).map(|identity| identity.player_id));
            PlayerState {
                seat: info.seat,
                player_id,
                stack: info.starting_stack.saturating_sub(committed),
                committed_this_round: committed,
                committed_total: 0,
                status: info.status,
                has_acted_this_round: false,
            }
        })
        .collect();

    player_states.sort_by_key(|p| p.seat);

    let main_amount: u64 = player_states.iter().map(|p| p.committed_this_round).sum();

    let eligible: Vec<SeatId> = player_states
        .iter()
        .filter(|p| p.status != PlayerStatus::Folded && p.status != PlayerStatus::SittingOut)
        .map(|p| p.seat)
        .collect();

    let pots = Pots {
        main: Pot {
            amount: main_amount,
            eligible,
        },
        sides: Vec::new(),
    };

    EngineNL::new_after_deal(cfg.clone(), player_states, pots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::nl::types::Street;
    use crate::ledger::snapshot::phases::AnyPhase;
    use crate::ledger::test_support::{
        fixture_complete_snapshot, fixture_dealing_snapshot, fixture_flop_snapshot,
        fixture_preflop_snapshot, fixture_river_snapshot, fixture_showdown_snapshot,
        fixture_shuffling_snapshot, fixture_turn_snapshot, FixtureContext,
    };
    use crate::ledger::CanonicalKey;
    use crate::test_utils::serde::{assert_round_trip_eq, assert_round_trip_json};
    use crate::{
        chaum_pedersen::ChaumPedersenProof,
        shuffling::{
            community_decryption::CommunityDecryptionShare,
            data_structures::ElGamalCiphertext,
            player_decryption::{
                PartialUnblindingShare, PlayerAccessibleCiphertext,
                PlayerTargetedBlindingContribution,
            },
        },
    };
    use ark_bn254::G1Projective;
    use ark_ec::PrimeGroup;
    use ark_serialize::CanonicalSerialize;
    use serde::{de::DeserializeOwned, Serialize};

    type Curve = G1Projective;

    fn assert_named_round_trip<T>(label: &str, value: &T)
    where
        T: Serialize + DeserializeOwned,
    {
        let json = serde_json::to_value(value)
            .unwrap_or_else(|err| panic!("{label} serialization failed: {err}"));
        let restored: T = serde_json::from_value(json.clone())
            .unwrap_or_else(|err| panic!("{label} deserialization failed: {err}"));
        let json_after = serde_json::to_value(restored)
            .unwrap_or_else(|err| panic!("{label} reserialization failed: {err}"));
        assert_eq!(json_after, json, "{label} round-trip altered payload");
    }

    fn sample_cipher<C: CurveGroup>() -> ElGamalCiphertext<C> {
        let generator = C::generator();
        ElGamalCiphertext::new(generator, generator)
    }

    fn sample_cp_proof<C: CurveGroup>() -> ChaumPedersenProof<C> {
        ChaumPedersenProof {
            t_g: C::generator(),
            t_h: C::generator(),
            z: <C as PrimeGroup>::ScalarField::from(7u64),
        }
    }

    fn sample_accessible_ciphertext<C: CurveGroup>() -> PlayerAccessibleCiphertext<C> {
        PlayerAccessibleCiphertext {
            blinded_base: C::generator(),
            blinded_message_with_player_key: C::generator(),
            player_unblinding_helper: C::generator(),
            shuffler_proofs: vec![sample_cp_proof::<C>()],
        }
    }

    fn sample_blinding_contribution<C: CurveGroup>() -> PlayerTargetedBlindingContribution<C> {
        PlayerTargetedBlindingContribution {
            blinding_base_contribution: C::generator(),
            blinding_combined_contribution: C::generator(),
            proof: sample_cp_proof::<C>(),
        }
    }

    fn sample_partial_unblinding_share<C: CurveGroup + CanonicalSerialize>(
    ) -> PartialUnblindingShare<C> {
        PartialUnblindingShare {
            share: C::generator(),
            member_key: CanonicalKey::new(C::generator()),
        }
    }

    fn sample_community_share<C: CurveGroup + CanonicalSerialize>() -> CommunityDecryptionShare<C> {
        CommunityDecryptionShare {
            share: C::generator(),
            proof: sample_cp_proof::<C>(),
            member_key: CanonicalKey::new(C::generator()),
        }
    }

    #[ignore]
    #[test]
    fn build_initial_betting_state_uses_stack_info() {
        let cfg = HandConfig {
            stakes: crate::engine::nl::types::TableStakes {
                small_blind: 1,
                big_blind: 2,
                ante: 0,
            },
            button: 0,
            small_blind_seat: 1,
            big_blind_seat: 2,
            check_raise_allowed: true,
        };

        let key1 = CanonicalKey::new(Curve::generator());
        let key2 = CanonicalKey::new(Curve::generator() + Curve::generator());

        let mut stacks: PlayerStacks<Curve> = BTreeMap::new();
        stacks.insert(
            1,
            PlayerStackInfo {
                seat: 1,
                player_key: Some(key1.clone()),
                starting_stack: 100,
                committed_blind: 1,
                status: PlayerStatus::Active,
            },
        );
        stacks.insert(
            2,
            PlayerStackInfo {
                seat: 2,
                player_key: Some(key2.clone()),
                starting_stack: 120,
                committed_blind: 2,
                status: PlayerStatus::Active,
            },
        );

        let mut roster: PlayerRoster<Curve> = BTreeMap::new();
        roster.insert(
            key1.clone(),
            PlayerIdentity {
                public_key: Curve::generator(),
                player_key: key1.clone(),
                player_id: 10,
                nonce: 0,
                seat: 1,
            },
        );
        roster.insert(
            key2.clone(),
            PlayerIdentity {
                public_key: Curve::generator() + Curve::generator(),
                player_key: key2.clone(),
                player_id: 11,
                nonce: 0,
                seat: 2,
            },
        );

        let state = build_initial_betting_state(&cfg, &stacks, &roster);

        assert_eq!(state.street, Street::Preflop);
        assert_eq!(state.players.len(), 2);
        let bb = state.players.iter().find(|p| p.seat == 2).unwrap();
        assert_eq!(bb.stack, 118);
        assert_eq!(bb.committed_this_round, 2);
        assert_eq!(state.pots.main.amount, 3);
    }

    #[test]
    fn snapshot_components_round_trip_with_serde() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11, 12]);
        let shuffling = fixture_shuffling_snapshot(&ctx);
        let dealing = fixture_dealing_snapshot(&ctx);
        let preflop = fixture_preflop_snapshot(&ctx);
        let showdown = fixture_showdown_snapshot(&ctx);

        let player_identity = ctx
            .players
            .iter()
            .next()
            .map(|(_, identity)| identity.clone())
            .expect("fixture players present");
        assert_round_trip_json(&player_identity);

        let shuffler_identity = ctx
            .shufflers
            .iter()
            .next()
            .map(|(_, identity)| identity.clone())
            .expect("fixture shufflers present");
        assert_round_trip_json(&shuffler_identity);

        let player_stack = ctx
            .stacks
            .iter()
            .next()
            .map(|(_, stack)| stack.clone())
            .expect("fixture stacks present");
        assert_round_trip_json(&player_stack);

        assert_round_trip_eq(&SnapshotStatus::Failure("boom".to_string()));
        assert_round_trip_eq(&CardDestination::Hole {
            seat: 1,
            hole_index: 0,
        });

        assert_named_round_trip("shuffling", &shuffling.shuffling);
        assert_named_round_trip("dealing", &dealing.dealing);
        assert_named_round_trip("betting", &preflop.betting);
        assert_named_round_trip("reveals", &showdown.reveals);

        let action = AnyPlayerActionMsg::Turn(GamePlayerMessage::<TurnStreet, Curve>::new(
            crate::engine::nl::actions::PlayerBetAction::Call,
        ));
        assert_round_trip_json(&action);

        let phase = AnyPhase::Dealing(dealing.dealing.clone());
        assert_round_trip_json(&phase);
    }

    #[test]
    fn table_snapshots_round_trip_with_serde() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11, 12]);
        let shuffling = fixture_shuffling_snapshot(&ctx);
        let dealing = fixture_dealing_snapshot(&ctx);
        let preflop = fixture_preflop_snapshot(&ctx);
        let flop = fixture_flop_snapshot(&ctx);
        let turn = fixture_turn_snapshot(&ctx);
        let river = fixture_river_snapshot(&ctx);
        let showdown = fixture_showdown_snapshot(&ctx);
        let complete = fixture_complete_snapshot(&ctx);

        assert_round_trip_json(&shuffling);
        assert_round_trip_json(&dealing);
        assert_round_trip_json(&preflop);
        assert_round_trip_json(&flop);
        assert_round_trip_json(&turn);
        assert_round_trip_json(&river);
        assert_round_trip_json(&showdown);
        assert_round_trip_json(&complete);

        let any_shuffling = AnyTableSnapshot::Shuffling(shuffling.clone());
        let any_dealing = AnyTableSnapshot::Dealing(dealing.clone());
        let any_preflop = AnyTableSnapshot::Preflop(preflop.clone());
        let any_flop = AnyTableSnapshot::Flop(flop.clone());
        let any_turn = AnyTableSnapshot::Turn(turn.clone());
        let any_river = AnyTableSnapshot::River(river.clone());
        let any_showdown = AnyTableSnapshot::Showdown(showdown.clone());
        let any_complete = AnyTableSnapshot::Complete(complete.clone());

        assert_named_round_trip("any_shuffling", &any_shuffling);
        assert_named_round_trip("any_dealing", &any_dealing);
        assert_named_round_trip("any_preflop", &any_preflop);
        assert_named_round_trip("any_flop", &any_flop);
        assert_named_round_trip("any_turn", &any_turn);
        assert_named_round_trip("any_river", &any_river);
        assert_named_round_trip("any_showdown", &any_showdown);
        assert_named_round_trip("any_complete", &any_complete);
    }

    #[test]
    fn dealing_snapshot_tuple_maps_serialize() {
        let mut assignments = BTreeMap::new();
        assignments.insert(
            0,
            DealtCard {
                cipher: sample_cipher::<Curve>(),
                source_index: Some(0),
            },
        );

        let mut player_ciphertexts = BTreeMap::new();
        player_ciphertexts.insert((0, 0), sample_accessible_ciphertext::<Curve>());

        let shuffler_key = CanonicalKey::new(Curve::generator());
        let mut player_blinding_contribs = BTreeMap::new();
        player_blinding_contribs.insert(
            (shuffler_key.clone(), 0, 0),
            sample_blinding_contribution::<Curve>(),
        );

        let mut shares_map = BTreeMap::new();
        let share = sample_partial_unblinding_share::<Curve>();
        shares_map.insert(share.member_key.clone(), share);
        let mut player_unblinding_shares = BTreeMap::new();
        player_unblinding_shares.insert((0, 0), shares_map);

        let mut community_shares = BTreeMap::new();
        community_shares.insert((shuffler_key.clone(), 0), sample_community_share::<Curve>());

        let snapshot = DealingSnapshot {
            assignments,
            player_ciphertexts,
            player_blinding_contribs,
            player_unblinding_shares,
            player_unblinding_combined: BTreeMap::new(),
            community_decryption_shares: community_shares,
            community_cards: BTreeMap::new(),
            card_plan: BTreeMap::new(),
        };

        let _ = serde_json::to_string(&snapshot).expect("dealing snapshot should serialize");
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct DealingSnapshot<C: CurveGroup> {
    #[serde(
        serialize_with = "crate::crypto_serde::simple_map::serialize",
        deserialize_with = "crate::crypto_serde::simple_map::deserialize"
    )]
    pub assignments: BTreeMap<u8, DealtCard<C>>,
    #[serde(
        serialize_with = "crate::crypto_serde::player_ciphertext_map::serialize",
        deserialize_with = "crate::crypto_serde::player_ciphertext_map::deserialize"
    )]
    pub player_ciphertexts: BTreeMap<(SeatId, u8), PlayerAccessibleCiphertext<C>>,
    #[serde(
        serialize_with = "crate::crypto_serde::player_blinding_map::serialize",
        deserialize_with = "crate::crypto_serde::player_blinding_map::deserialize"
    )]
    pub player_blinding_contribs:
        BTreeMap<(CanonicalKey<C>, SeatId, u8), PlayerTargetedBlindingContribution<C>>,
    #[serde(
        serialize_with = "crate::crypto_serde::player_unblinding_map::serialize",
        deserialize_with = "crate::crypto_serde::player_unblinding_map::deserialize"
    )]
    pub player_unblinding_shares:
        BTreeMap<(SeatId, u8), BTreeMap<CanonicalKey<C>, PartialUnblindingShare<C>>>,
    #[serde(
        serialize_with = "crate::crypto_serde::player_unblinding_combined_map::serialize",
        deserialize_with = "crate::crypto_serde::player_unblinding_combined_map::deserialize"
    )]
    pub player_unblinding_combined: BTreeMap<(SeatId, u8), C>,
    #[serde(
        serialize_with = "crate::crypto_serde::community_decryption_map::serialize",
        deserialize_with = "crate::crypto_serde::community_decryption_map::deserialize"
    )]
    pub community_decryption_shares: BTreeMap<(CanonicalKey<C>, u8), CommunityDecryptionShare<C>>,
    #[serde(
        serialize_with = "crate::crypto_serde::simple_map::serialize",
        deserialize_with = "crate::crypto_serde::simple_map::deserialize"
    )]
    pub community_cards: BTreeMap<u8, CardIndex>,
    #[serde(
        serialize_with = "crate::crypto_serde::simple_map::serialize",
        deserialize_with = "crate::crypto_serde::simple_map::deserialize"
    )]
    pub card_plan: CardPlan,
}

// ---- Betting --------------------------------------------------------------------------------

type BettingStateNL = BettingState;

#[derive(Clone, Debug)]
pub enum AnyPlayerActionMsg<C: CurveGroup> {
    Preflop(GamePlayerMessage<PreflopStreet, C>),
    Flop(GamePlayerMessage<FlopStreet, C>),
    Turn(GamePlayerMessage<TurnStreet, C>),
    River(GamePlayerMessage<RiverStreet, C>),
}

#[derive(Serialize, Deserialize)]
struct PlayerActionSerde {
    street: String,
    action: PlayerBetAction,
}

impl<C> Serialize for AnyPlayerActionMsg<C>
where
    C: CurveGroup,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let helper = match self {
            AnyPlayerActionMsg::Preflop(msg) => PlayerActionSerde {
                street: "preflop".to_string(),
                action: msg.action.clone(),
            },
            AnyPlayerActionMsg::Flop(msg) => PlayerActionSerde {
                street: "flop".to_string(),
                action: msg.action.clone(),
            },
            AnyPlayerActionMsg::Turn(msg) => PlayerActionSerde {
                street: "turn".to_string(),
                action: msg.action.clone(),
            },
            AnyPlayerActionMsg::River(msg) => PlayerActionSerde {
                street: "river".to_string(),
                action: msg.action.clone(),
            },
        };
        helper.serialize(serializer)
    }
}

impl<'de, C> Deserialize<'de> for AnyPlayerActionMsg<C>
where
    C: CurveGroup,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = PlayerActionSerde::deserialize(deserializer)?;
        let action = helper.action;
        match helper.street.as_str() {
            "preflop" => Ok(AnyPlayerActionMsg::Preflop(GamePlayerMessage::new(action))),
            "flop" => Ok(AnyPlayerActionMsg::Flop(GamePlayerMessage::new(action))),
            "turn" => Ok(AnyPlayerActionMsg::Turn(GamePlayerMessage::new(action))),
            "river" => Ok(AnyPlayerActionMsg::River(GamePlayerMessage::new(action))),
            other => Err(serde::de::Error::custom(format!(
                "unknown betting action street {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct BettingSnapshot<C: CurveGroup> {
    pub state: BettingStateNL,
    pub last_events: Vec<AnyPlayerActionMsg<C>>,
}

// ---- Reveals -------------------------------------------------------------------------------

pub type CardIndex = u8;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct RevealedHand<C: CurveGroup> {
    pub hole: [CardIndex; 2],
    pub hole_ciphertexts: [PlayerAccessibleCiphertext<C>; 2],
    pub best_five: [CardIndex; 5],
    pub best_category: HandCategory,
    pub best_tiebreak: [u8; 5],
    pub best_score: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct RevealsSnapshot<C: CurveGroup> {
    pub board: Vec<CardIndex>,
    #[serde(
        serialize_with = "crate::crypto_serde::simple_map::serialize",
        deserialize_with = "crate::crypto_serde::simple_map::deserialize"
    )]
    pub revealed_holes: BTreeMap<SeatId, RevealedHand<C>>,
}

// ---- Table snapshot ------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P::ShufflingS: Serialize, P::DealingS: Serialize, P::BettingS: Serialize, P::RevealsS: Serialize, C: CanonicalSerialize",
    deserialize = "P::ShufflingS: DeserializeOwned, P::DealingS: DeserializeOwned, P::BettingS: DeserializeOwned, P::RevealsS: DeserializeOwned, C: CanonicalDeserialize"
))]
pub struct TableSnapshot<P, C>
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    pub game_id: GameId,
    pub hand_id: Option<HandId>,
    pub sequence: SnapshotSeq,
    #[serde(with = "crate::crypto_serde::arc")]
    pub cfg: Shared<HandConfig>,
    #[serde(with = "crate::crypto_serde::arc")]
    pub shufflers: Shared<ShufflerRoster<C>>,
    #[serde(with = "crate::crypto_serde::arc")]
    pub players: Shared<PlayerRoster<C>>,
    #[serde(with = "crate::crypto_serde::arc_simple_map")]
    pub seating: Shared<SeatingMap<C>>,
    #[serde(with = "crate::crypto_serde::arc_simple_map")]
    pub stacks: Shared<PlayerStacks<C>>,
    pub previous_hash: Option<StateHash>,
    pub state_hash: StateHash,
    pub status: SnapshotStatus,
    pub shuffling: P::ShufflingS,
    pub dealing: P::DealingS,
    pub betting: P::BettingS,
    pub reveals: P::RevealsS,
}

pub type TableAtShuffling<C> = TableSnapshot<PhaseShuffling, C>;
pub type TableAtDealing<C> = TableSnapshot<PhaseDealing, C>;
pub type TableAtPreflop<C> = TableSnapshot<PhaseBetting<PreflopStreet>, C>;
pub type TableAtFlop<C> = TableSnapshot<PhaseBetting<FlopStreet>, C>;
pub type TableAtTurn<C> = TableSnapshot<PhaseBetting<TurnStreet>, C>;
pub type TableAtRiver<C> = TableSnapshot<PhaseBetting<RiverStreet>, C>;
pub type TableAtShowdown<C> = TableSnapshot<PhaseShowdown, C>;
pub type TableAtComplete<C> = TableSnapshot<PhaseComplete, C>;

impl<P, C> TableSnapshot<P, C>
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    pub fn player_identity_by_id(&self, player_id: PlayerId) -> Option<&PlayerIdentity<C>> {
        self.players
            .values()
            .find(|identity| identity.player_id == player_id)
    }

    pub fn shuffler_identity_by_id(&self, shuffler_id: ShufflerId) -> Option<&ShufflerIdentity<C>> {
        self.shufflers
            .values()
            .find(|identity| identity.shuffler_id == shuffler_id)
    }

    pub fn shuffler_key_by_id(&self, shuffler_id: ShufflerId) -> Option<&CanonicalKey<C>> {
        self.shufflers
            .iter()
            .find_map(|(key, identity)| (identity.shuffler_id == shuffler_id).then_some(key))
    }

    pub fn initialize_hash(&mut self, hasher: &dyn LedgerHasher) {
        self.sequence = 0;
        self.previous_hash = None;
        self.state_hash = initial_snapshot_hash(self, hasher);
        self.status = SnapshotStatus::Success;
    }

    pub fn advance_state_with_message<M>(
        &mut self,
        envelope: &EnvelopedMessage<C, M>,
        hasher: &dyn LedgerHasher,
    ) where
        M: GameMessage<C> + Signable,
        M::Actor: Signable,
    {
        let message = message_hash(envelope, hasher);
        let chained = chain_hash(self.state_hash, message, hasher);
        self.previous_hash = Some(self.state_hash);
        self.state_hash = chained;
        self.sequence = self.sequence.saturating_add(1);
        self.status = SnapshotStatus::Success;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    tag = "type",
    bound(
        serialize = "C: CanonicalSerialize",
        deserialize = "C: CanonicalDeserialize"
    )
)]
pub enum AnyTableSnapshot<C: CurveGroup> {
    Shuffling(TableAtShuffling<C>),
    Dealing(TableAtDealing<C>),
    Preflop(TableAtPreflop<C>),
    Flop(TableAtFlop<C>),
    Turn(TableAtTurn<C>),
    River(TableAtRiver<C>),
    Showdown(TableAtShowdown<C>),
    Complete(TableAtComplete<C>),
}

impl<C: CurveGroup> AnyTableSnapshot<C> {
    pub fn state_hash(&self) -> StateHash {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.state_hash,
            AnyTableSnapshot::Dealing(table) => table.state_hash,
            AnyTableSnapshot::Preflop(table) => table.state_hash,
            AnyTableSnapshot::Flop(table) => table.state_hash,
            AnyTableSnapshot::Turn(table) => table.state_hash,
            AnyTableSnapshot::River(table) => table.state_hash,
            AnyTableSnapshot::Showdown(table) => table.state_hash,
            AnyTableSnapshot::Complete(table) => table.state_hash,
        }
    }

    pub fn player_identity_by_id(&self, player_id: PlayerId) -> Option<&PlayerIdentity<C>> {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.player_identity_by_id(player_id),
            AnyTableSnapshot::Dealing(table) => table.player_identity_by_id(player_id),
            AnyTableSnapshot::Preflop(table) => table.player_identity_by_id(player_id),
            AnyTableSnapshot::Flop(table) => table.player_identity_by_id(player_id),
            AnyTableSnapshot::Turn(table) => table.player_identity_by_id(player_id),
            AnyTableSnapshot::River(table) => table.player_identity_by_id(player_id),
            AnyTableSnapshot::Showdown(table) => table.player_identity_by_id(player_id),
            AnyTableSnapshot::Complete(table) => table.player_identity_by_id(player_id),
        }
    }

    pub fn shuffler_identity_by_id(&self, shuffler_id: ShufflerId) -> Option<&ShufflerIdentity<C>> {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.shuffler_identity_by_id(shuffler_id),
            AnyTableSnapshot::Dealing(table) => table.shuffler_identity_by_id(shuffler_id),
            AnyTableSnapshot::Preflop(table) => table.shuffler_identity_by_id(shuffler_id),
            AnyTableSnapshot::Flop(table) => table.shuffler_identity_by_id(shuffler_id),
            AnyTableSnapshot::Turn(table) => table.shuffler_identity_by_id(shuffler_id),
            AnyTableSnapshot::River(table) => table.shuffler_identity_by_id(shuffler_id),
            AnyTableSnapshot::Showdown(table) => table.shuffler_identity_by_id(shuffler_id),
            AnyTableSnapshot::Complete(table) => table.shuffler_identity_by_id(shuffler_id),
        }
    }

    pub fn shuffler_key_by_id(&self, shuffler_id: ShufflerId) -> Option<&CanonicalKey<C>> {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.shuffler_key_by_id(shuffler_id),
            AnyTableSnapshot::Dealing(table) => table.shuffler_key_by_id(shuffler_id),
            AnyTableSnapshot::Preflop(table) => table.shuffler_key_by_id(shuffler_id),
            AnyTableSnapshot::Flop(table) => table.shuffler_key_by_id(shuffler_id),
            AnyTableSnapshot::Turn(table) => table.shuffler_key_by_id(shuffler_id),
            AnyTableSnapshot::River(table) => table.shuffler_key_by_id(shuffler_id),
            AnyTableSnapshot::Showdown(table) => table.shuffler_key_by_id(shuffler_id),
            AnyTableSnapshot::Complete(table) => table.shuffler_key_by_id(shuffler_id),
        }
    }

    pub fn previous_hash(&self) -> Option<StateHash> {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.previous_hash,
            AnyTableSnapshot::Dealing(table) => table.previous_hash,
            AnyTableSnapshot::Preflop(table) => table.previous_hash,
            AnyTableSnapshot::Flop(table) => table.previous_hash,
            AnyTableSnapshot::Turn(table) => table.previous_hash,
            AnyTableSnapshot::River(table) => table.previous_hash,
            AnyTableSnapshot::Showdown(table) => table.previous_hash,
            AnyTableSnapshot::Complete(table) => table.previous_hash,
        }
    }

    pub fn sequence(&self) -> SnapshotSeq {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.sequence,
            AnyTableSnapshot::Dealing(table) => table.sequence,
            AnyTableSnapshot::Preflop(table) => table.sequence,
            AnyTableSnapshot::Flop(table) => table.sequence,
            AnyTableSnapshot::Turn(table) => table.sequence,
            AnyTableSnapshot::River(table) => table.sequence,
            AnyTableSnapshot::Showdown(table) => table.sequence,
            AnyTableSnapshot::Complete(table) => table.sequence,
        }
    }

    pub fn event_phase(&self) -> EventPhase {
        match self {
            AnyTableSnapshot::Shuffling(_) => EventPhase::Shuffling,
            AnyTableSnapshot::Dealing(_) => EventPhase::Dealing,
            AnyTableSnapshot::Preflop(_) => EventPhase::Betting,
            AnyTableSnapshot::Flop(_) => EventPhase::Betting,
            AnyTableSnapshot::Turn(_) => EventPhase::Betting,
            AnyTableSnapshot::River(_) => EventPhase::Betting,
            AnyTableSnapshot::Showdown(_) => EventPhase::Showdown,
            AnyTableSnapshot::Complete(_) => EventPhase::Complete,
        }
    }

    pub fn status(&self) -> &SnapshotStatus {
        match self {
            AnyTableSnapshot::Shuffling(table) => &table.status,
            AnyTableSnapshot::Dealing(table) => &table.status,
            AnyTableSnapshot::Preflop(table) => &table.status,
            AnyTableSnapshot::Flop(table) => &table.status,
            AnyTableSnapshot::Turn(table) => &table.status,
            AnyTableSnapshot::River(table) => &table.status,
            AnyTableSnapshot::Showdown(table) => &table.status,
            AnyTableSnapshot::Complete(table) => &table.status,
        }
    }

    pub fn failure_reason(&self) -> Option<&str> {
        match self.status() {
            SnapshotStatus::Success => None,
            SnapshotStatus::Failure(reason) => Some(reason.as_str()),
        }
    }

    pub fn set_status(&mut self, status: SnapshotStatus) {
        match self {
            AnyTableSnapshot::Shuffling(table) => table.status = status,
            AnyTableSnapshot::Dealing(table) => table.status = status,
            AnyTableSnapshot::Preflop(table) => table.status = status,
            AnyTableSnapshot::Flop(table) => table.status = status,
            AnyTableSnapshot::Turn(table) => table.status = status,
            AnyTableSnapshot::River(table) => table.status = status,
            AnyTableSnapshot::Showdown(table) => table.status = status,
            AnyTableSnapshot::Complete(table) => table.status = status,
        }
    }
}

fn failure_chain_hash(previous: StateHash, reason: &str, hasher: &dyn LedgerHasher) -> StateHash {
    let mut builder = TranscriptBuilder::new("ledger/state/failure");
    builder.append_bytes(reason.as_bytes());
    let failure_message = hasher.hash(&builder.finish());
    chain_hash(previous, failure_message, hasher)
}

fn mark_failure<P, C>(table: &mut TableSnapshot<P, C>, reason: &str, hasher: &dyn LedgerHasher)
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    let previous = table.state_hash;
    table.previous_hash = Some(previous);
    table.sequence = table.sequence.saturating_add(1);
    table.state_hash = failure_chain_hash(previous, reason, hasher);
    table.status = SnapshotStatus::Failure(reason.to_string());
}

fn hand_config_from_model(model: &hand_configs::Model) -> Result<HandConfig> {
    Ok(HandConfig {
        stakes: crate::engine::nl::types::TableStakes {
            small_blind: u64::try_from(model.small_blind)
                .map_err(|_| anyhow!("small blind exceeds u64 range"))?,
            big_blind: u64::try_from(model.big_blind)
                .map_err(|_| anyhow!("big blind exceeds u64 range"))?,
            ante: u64::try_from(model.ante).map_err(|_| anyhow!("ante exceeds u64 range"))?,
        },
        button: u8::try_from(model.button_seat)
            .map_err(|_| anyhow!("button seat exceeds u8 range"))?,
        small_blind_seat: u8::try_from(model.small_blind_seat)
            .map_err(|_| anyhow!("small blind seat exceeds u8 range"))?,
        big_blind_seat: u8::try_from(model.big_blind_seat)
            .map_err(|_| anyhow!("big blind seat exceeds u8 range"))?,
        check_raise_allowed: model.check_raise_allowed,
    })
}

async fn load_player_roster<C>(
    conn: &DatabaseConnection,
    game_id: GameId,
    hand_id: HandId,
) -> Result<(PlayerRoster<C>, SeatingMap<C>)>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let rows = hand_player::Entity::find()
        .filter(hand_player::Column::GameId.eq(game_id))
        .filter(hand_player::Column::HandId.eq(hand_id))
        .order_by_asc(hand_player::Column::Seat)
        .find_also_related(players::Entity)
        .all(conn)
        .await?;

    let mut roster: PlayerRoster<C> = BTreeMap::new();
    let mut seating: SeatingMap<C> = BTreeMap::new();

    for (seat_row, player_row) in rows {
        let player = player_row.context("player row missing public key")?;
        let seat = u8::try_from(seat_row.seat)
            .map_err(|_| anyhow!("seat {} exceeds u8 range", seat_row.seat))?;
        let player_id = u64::try_from(seat_row.player_id)
            .map_err(|_| anyhow!("player id {} exceeds u64 range", seat_row.player_id))?;
        let nonce = u64::try_from(seat_row.nonce)
            .map_err(|_| anyhow!("nonce {} exceeds u64 range", seat_row.nonce))?;
        let public_key = deserialize_curve_bytes::<C>(&player.public_key)
            .context("failed to deserialize player public key")?;
        let player_key = CanonicalKey::new(public_key.clone());

        roster.insert(
            player_key.clone(),
            PlayerIdentity {
                public_key,
                player_key: player_key.clone(),
                player_id,
                nonce,
                seat,
            },
        );
        seating.insert(seat, Some(player_key));
    }

    Ok((roster, seating))
}

async fn load_shuffler_roster<C>(
    conn: &DatabaseConnection,
    _game_id: GameId,
    hand_id: HandId,
) -> Result<ShufflerRoster<C>>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let assignments = hand_shufflers::Entity::find()
        .filter(hand_shufflers::Column::HandId.eq(hand_id))
        .order_by_asc(hand_shufflers::Column::Sequence)
        .all(conn)
        .await?;

    if assignments.is_empty() {
        return Ok(BTreeMap::new());
    }

    let shuffler_ids: Vec<i64> = assignments.iter().map(|row| row.shuffler_id).collect();
    let shuffler_models = shufflers::Entity::find()
        .filter(shufflers::Column::Id.is_in(shuffler_ids.clone()))
        .all(conn)
        .await?;

    let mut public_keys: HashMap<i64, (C, CanonicalKey<C>)> = HashMap::new();
    for model in shuffler_models {
        let pk = deserialize_curve_bytes::<C>(&model.public_key)
            .context("failed to deserialize shuffler public key")?;
        let canonical = CanonicalKey::new(pk.clone());
        public_keys.insert(model.id, (pk, canonical));
    }

    let mut aggregated = C::zero();
    for id in &shuffler_ids {
        let (pk, _canonical) = public_keys
            .get(id)
            .context("shuffler assignment missing public key")?;
        aggregated += pk.clone();
    }

    let mut roster = BTreeMap::new();
    for assignment in assignments {
        let (pk, canonical) = public_keys
            .get(&assignment.shuffler_id)
            .context("shuffler assignment missing public key")?
            .clone();
        roster.insert(
            canonical.clone(),
            ShufflerIdentity {
                public_key: pk.clone(),
                shuffler_key: canonical,
                shuffler_id: assignment.shuffler_id,
                aggregated_public_key: aggregated.clone(),
            },
        );
    }

    Ok(roster)
}

async fn load_phase_payload<T>(
    conn: &DatabaseConnection,
    hash: &Option<Vec<u8>>,
    expected: PhaseKind,
    label: &str,
) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    if let Some(bytes) = hash {
        let row = phase_table::Entity::find_by_id(bytes.clone())
            .one(conn)
            .await?
            .with_context(|| format!("{label} phase payload not found"))?;

        anyhow::ensure!(
            row.phase_type == expected,
            "{label} phase type mismatch: expected {:?}, found {:?}",
            expected,
            row.phase_type
        );

        let payload = serde_json::from_value(row.payload.clone())
            .with_context(|| format!("failed to decode {label} phase payload"))?;
        Ok(Some(payload))
    } else {
        Ok(None)
    }
}

pub async fn rehydrate_snapshot<C>(
    conn: &DatabaseConnection,
    game_id: GameId,
    hand_id: HandId,
    state_hash: Option<StateHash>,
) -> Result<AnyTableSnapshot<C>>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
    C::ScalarField: PrimeField + Absorb + CanonicalSerialize + CanonicalDeserialize,
    C::BaseField: PrimeField + CanonicalSerialize + CanonicalDeserialize,
    C::Affine: Absorb,
{
    let snapshot_model = match state_hash {
        Some(state_hash) => table_snapshots::Entity::find()
            .filter(table_snapshots::Column::GameId.eq(game_id))
            .filter(table_snapshots::Column::HandId.eq(hand_id))
            .filter(table_snapshots::Column::SnapshotHash.eq(state_hash.into_bytes().to_vec()))
            .one(conn)
            .await?
            .with_context(|| format!("snapshot {:?} not found", state_hash))?,
        None => table_snapshots::Entity::find()
            .filter(table_snapshots::Column::GameId.eq(game_id))
            .filter(table_snapshots::Column::HandId.eq(hand_id))
            .order_by_desc(table_snapshots::Column::Sequence)
            .one(conn)
            .await?
            .with_context(|| format!("no snapshots found for game {} hand {}", game_id, hand_id))?,
    };

    let snapshot_sequence = u32::try_from(snapshot_model.sequence).map_err(|_| {
        anyhow!(
            "snapshot sequence {} exceeds u32::MAX",
            snapshot_model.sequence
        )
    })?;
    let previous_hash = snapshot_model
        .previous_hash
        .map(StateHash::from_bytes)
        .transpose()?;
    let status = match snapshot_model.application_status {
        ApplicationStatus::Success => SnapshotStatus::Success,
        ApplicationStatus::Failure => SnapshotStatus::Failure(
            snapshot_model
                .failure_reason
                .clone()
                .unwrap_or_else(|| "unknown failure".to_string()),
        ),
    };
    let state_hash = StateHash::from_bytes(snapshot_model.state_hash)?;
    let player_stacks: PlayerStacks<C> =
        serde_json::from_value(snapshot_model.player_stacks.clone())
            .context("failed to deserialize player stacks")?;

    let hand_config_model = hand_configs::Entity::find_by_id(snapshot_model.hand_config_id)
        .one(conn)
        .await?
        .context("hand config not found")?;
    let hand_config = hand_config_from_model(&hand_config_model)?;

    let (player_roster, seating) = load_player_roster::<C>(conn, game_id, hand_id).await?;
    let shuffler_roster = load_shuffler_roster::<C>(conn, game_id, hand_id).await?;

    let shuffling: ShufflingSnapshot<C> = load_phase_payload(
        conn,
        &snapshot_model.shuffling_hash,
        PhaseKind::Shuffling,
        "shuffling",
    )
    .await?
    .context("snapshot missing shuffling payload")?;
    let dealing: Option<DealingSnapshot<C>> = load_phase_payload(
        conn,
        &snapshot_model.dealing_hash,
        PhaseKind::Dealing,
        "dealing",
    )
    .await?;
    let betting: Option<BettingSnapshot<C>> = load_phase_payload(
        conn,
        &snapshot_model.betting_hash,
        PhaseKind::Betting,
        "betting",
    )
    .await?;
    let reveals: Option<RevealsSnapshot<C>> = load_phase_payload(
        conn,
        &snapshot_model.reveals_hash,
        PhaseKind::Reveals,
        "reveals",
    )
    .await?;

    let cfg_arc = Arc::new(hand_config);
    let shufflers_arc = Arc::new(shuffler_roster);
    let players_arc = Arc::new(player_roster);
    let seating_arc = Arc::new(seating);
    let stacks_arc = Arc::new(player_stacks);

    if let Some(reveals_snapshot) = reveals {
        let dealing_snapshot = dealing
            .clone()
            .context("reveals snapshot missing dealing payload")?;
        let betting_snapshot = betting
            .clone()
            .context("reveals snapshot missing betting payload")?;

        let table = TableSnapshot::<PhaseShowdown, C> {
            game_id,
            hand_id: Some(hand_id),
            sequence: snapshot_sequence,
            cfg: Arc::clone(&cfg_arc),
            shufflers: Arc::clone(&shufflers_arc),
            players: Arc::clone(&players_arc),
            seating: Arc::clone(&seating_arc),
            stacks: Arc::clone(&stacks_arc),
            previous_hash,
            state_hash,
            status,
            shuffling: shuffling.clone(),
            dealing: dealing_snapshot,
            betting: betting_snapshot,
            reveals: reveals_snapshot,
        };
        return Ok(AnyTableSnapshot::Showdown(table));
    }

    if let Some(betting_snapshot) = betting {
        let dealing_snapshot = dealing
            .clone()
            .context("betting snapshot missing dealing payload")?;

        let empty_reveals = || RevealsSnapshot::<C> {
            board: Vec::new(),
            revealed_holes: BTreeMap::new(),
        };

        let table = match betting_snapshot.state.street {
            Street::Preflop => {
                AnyTableSnapshot::Preflop(TableSnapshot::<PhaseBetting<PreflopStreet>, C> {
                    game_id,
                    hand_id: Some(hand_id),
                    sequence: snapshot_sequence,
                    cfg: Arc::clone(&cfg_arc),
                    shufflers: Arc::clone(&shufflers_arc),
                    players: Arc::clone(&players_arc),
                    seating: Arc::clone(&seating_arc),
                    stacks: Arc::clone(&stacks_arc),
                    previous_hash,
                    state_hash,
                    status,
                    shuffling: shuffling.clone(),
                    dealing: dealing_snapshot,
                    betting: betting_snapshot,
                    reveals: empty_reveals(),
                })
            }
            Street::Flop => AnyTableSnapshot::Flop(TableSnapshot::<PhaseBetting<FlopStreet>, C> {
                game_id,
                hand_id: Some(hand_id),
                sequence: snapshot_sequence,
                cfg: Arc::clone(&cfg_arc),
                shufflers: Arc::clone(&shufflers_arc),
                players: Arc::clone(&players_arc),
                seating: Arc::clone(&seating_arc),
                stacks: Arc::clone(&stacks_arc),
                previous_hash,
                state_hash,
                status,
                shuffling: shuffling.clone(),
                dealing: dealing_snapshot,
                betting: betting_snapshot,
                reveals: empty_reveals(),
            }),
            Street::Turn => AnyTableSnapshot::Turn(TableSnapshot::<PhaseBetting<TurnStreet>, C> {
                game_id,
                hand_id: Some(hand_id),
                sequence: snapshot_sequence,
                cfg: Arc::clone(&cfg_arc),
                shufflers: Arc::clone(&shufflers_arc),
                players: Arc::clone(&players_arc),
                seating: Arc::clone(&seating_arc),
                stacks: Arc::clone(&stacks_arc),
                previous_hash,
                state_hash,
                status,
                shuffling: shuffling.clone(),
                dealing: dealing_snapshot,
                betting: betting_snapshot,
                reveals: empty_reveals(),
            }),
            Street::River => {
                AnyTableSnapshot::River(TableSnapshot::<PhaseBetting<RiverStreet>, C> {
                    game_id,
                    hand_id: Some(hand_id),
                    sequence: snapshot_sequence,
                    cfg: Arc::clone(&cfg_arc),
                    shufflers: Arc::clone(&shufflers_arc),
                    players: Arc::clone(&players_arc),
                    seating: Arc::clone(&seating_arc),
                    stacks: Arc::clone(&stacks_arc),
                    previous_hash,
                    state_hash,
                    status,
                    shuffling: shuffling.clone(),
                    dealing: dealing_snapshot,
                    betting: betting_snapshot,
                    reveals: empty_reveals(),
                })
            }
        };

        return Ok(table);
    }

    if let Some(dealing_snapshot) = dealing {
        let table = TableSnapshot::<PhaseDealing, C> {
            game_id,
            hand_id: Some(hand_id),
            sequence: snapshot_sequence,
            cfg: Arc::clone(&cfg_arc),
            shufflers: Arc::clone(&shufflers_arc),
            players: Arc::clone(&players_arc),
            seating: Arc::clone(&seating_arc),
            stacks: Arc::clone(&stacks_arc),
            previous_hash,
            state_hash,
            status,
            shuffling: shuffling.clone(),
            dealing: dealing_snapshot,
            betting: (),
            reveals: (),
        };
        return Ok(AnyTableSnapshot::Dealing(table));
    }

    let table = TableSnapshot::<PhaseShuffling, C> {
        game_id,
        hand_id: Some(hand_id),
        sequence: snapshot_sequence,
        cfg: cfg_arc,
        shufflers: shufflers_arc,
        players: players_arc,
        seating: seating_arc,
        stacks: stacks_arc,
        previous_hash,
        state_hash,
        status,
        shuffling,
        dealing: (),
        betting: (),
        reveals: (),
    };

    Ok(AnyTableSnapshot::Shuffling(table))
}
pub fn clone_snapshot_for_failure<C: CurveGroup>(
    snapshot: &AnyTableSnapshot<C>,
    hasher: &dyn LedgerHasher,
    reason: String,
) -> AnyTableSnapshot<C> {
    let mut failed = snapshot.clone();
    match &mut failed {
        AnyTableSnapshot::Shuffling(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Dealing(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Preflop(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Flop(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Turn(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::River(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Showdown(table) => mark_failure(table, &reason, hasher),
        AnyTableSnapshot::Complete(table) => mark_failure(table, &reason, hasher),
    }
    failed
}
