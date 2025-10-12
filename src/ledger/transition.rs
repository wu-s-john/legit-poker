use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::engine::{BettingEngineNL, EngineNL, Transition};
use crate::engine::nl::types::{PlayerStatus, Street as EngineStreet};
use crate::ledger::hash::LedgerHasher;
use crate::ledger::messages::{
    EnvelopedMessage, GameBlindingDecryptionMessage, GameMessage,
    GamePartialUnblindingShareMessage, GamePlayerMessage, GameShowdownMessage, GameShuffleMessage,
};
use crate::ledger::snapshot::{
    build_default_card_plan, build_initial_betting_state, AnyPlayerActionMsg, AnyTableSnapshot,
    BettingSnapshot, CardDestination, DealingSnapshot, DealtCard, PhaseBetting, PhaseShowdown,
    PhaseShuffling, RevealedHand, RevealsSnapshot, ShufflingStep, SnapshotStatus, TableSnapshot,
};
use crate::ledger::{FlopStreet, PreflopStreet, RiverStreet, TurnStreet};
use crate::poseidon_config;
use crate::showdown::{choose_best5_from7, idx_of};
use crate::shuffling::player_decryption::combine_unblinding_shares;
use crate::signing::Signable;
use std::collections::BTreeMap;

pub trait TransitionHandler<C>: GameMessage<C> + Signable
where
    C: CurveGroup,
{
    fn apply_transition<H>(
        snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        Self: Sized,
        H: LedgerHasher;
}

pub fn apply_transition<C, M, H>(
    snapshot: TableSnapshot<M::Phase, C>,
    envelope: &EnvelopedMessage<C, M>,
    hasher: &H,
) -> Result<AnyTableSnapshot<C>>
where
    C: CurveGroup,
    M: TransitionHandler<C>,
    H: LedgerHasher,
{
    <M as TransitionHandler<C>>::apply_transition(snapshot, envelope, hasher)
}

fn promote_to_dealing<C: CurveGroup>(
    table: TableSnapshot<PhaseShuffling, C>,
) -> Result<AnyTableSnapshot<C>> {
    let TableSnapshot {
        game_id,
        hand_id,
        sequence,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash,
        state_hash,
        status: _,
        shuffling,
        ..
    } = table;

    let card_plan = cfg
        .as_ref()
        .map(|cfg| build_default_card_plan(cfg, &seating))
        .unwrap_or_default();

    let dealing = DealingSnapshot {
        assignments: Default::default(),
        player_ciphertexts: Default::default(),
        player_blinding_contribs: Default::default(),
        player_unblinding_shares: Default::default(),
        player_unblinding_combined: Default::default(),
        community_decryption_shares: Default::default(),
        community_cards: Default::default(),
        card_plan,
    };

    Ok(AnyTableSnapshot::Dealing(TableSnapshot {
        game_id,
        hand_id,
        sequence,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash,
        state_hash,
        status: SnapshotStatus::Success,
        shuffling,
        dealing,
        betting: (),
        reveals: (),
    }))
}

fn promote_to_showdown_from_river<C: CurveGroup>(
    table: TableSnapshot<PhaseBetting<RiverStreet>, C>,
) -> TableSnapshot<PhaseShowdown, C> {
    let TableSnapshot {
        game_id,
        hand_id,
        sequence,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash,
        state_hash,
        status: _,
        shuffling,
        dealing,
        betting,
        reveals,
    } = table;

    TableSnapshot {
        game_id,
        hand_id,
        sequence,
        cfg,
        shufflers,
        players,
        seating,
        stacks,
        previous_hash,
        state_hash,
        status: SnapshotStatus::Success,
        shuffling,
        dealing,
        betting,
        reveals,
    }
}

// ---- Transition handler implementations -----------------------------------------------------

impl<C> TransitionHandler<C> for GameShuffleMessage<C>
where
    C: CurveGroup,
{
    fn apply_transition<H>(
        mut snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        H: LedgerHasher,
    {
        let shuffler_id = envelope.actor.shuffler_id;
        let shuffler = snapshot
            .shufflers
            .get(&shuffler_id)
            .context("unknown shuffler for shuffle message")?;

        let message = &envelope.message.value;

        if snapshot.shuffling.steps.is_empty() {
            snapshot.shuffling.initial_deck = message.deck_in.clone();
        } else {
            ensure!(
                snapshot.shuffling.final_deck == message.deck_in,
                "shuffle input deck mismatch with previous output"
            );
        }

        snapshot.shuffling.final_deck = message.deck_out.clone();
        snapshot.shuffling.steps.push(ShufflingStep {
            shuffler_public_key: shuffler.public_key.clone(),
            proof: message.proof.clone(),
        });

        snapshot.advance_state_with_message(envelope, hasher);

        if snapshot.shuffling.steps.len() == snapshot.shuffling.expected_order.len() {
            promote_to_dealing(snapshot)
        } else {
            Ok(AnyTableSnapshot::Shuffling(snapshot))
        }
    }
}

impl<C> TransitionHandler<C> for GameBlindingDecryptionMessage<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    fn apply_transition<H>(
        mut snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        H: LedgerHasher,
    {
        let shuffler_id = envelope.actor.shuffler_id;
        let card_pos = envelope.message.value.card_in_deck_position;
        let card_ref = card_pos
            .checked_add(1)
            .context("deck position overflowed when computing card reference")?;

        let shuffler = snapshot
            .shufflers
            .get(&shuffler_id)
            .context("unknown shuffler for blinding message")?;

        let destination = snapshot
            .dealing
            .card_plan
            .get(&card_ref)
            .context("card reference not found in dealing plan")?;

        let (seat, hole_index) = match destination {
            CardDestination::Hole { seat, hole_index } => (*seat, *hole_index),
            other => bail!("blinding contribution targets non-hole card: {other:?}"),
        };

        let player_id = snapshot
            .seating
            .get(&seat)
            .and_then(|id| *id)
            .context("seat has no player assigned")?;

        let player_identity = snapshot
            .players
            .get(&player_id)
            .context("player identity not found")?;

        let aggregated_key = shuffler.aggregated_public_key.clone();

        ensure!(
            envelope
                .message
                .value
                .share
                .verify(aggregated_key, player_identity.public_key),
            "invalid blinding contribution proof"
        );

        let key = (shuffler_id, seat, hole_index);
        if snapshot.dealing.player_blinding_contribs.contains_key(&key) {
            bail!("duplicate blinding contribution for shuffler {shuffler_id} seat {seat} hole {hole_index}");
        }

        snapshot
            .dealing
            .player_blinding_contribs
            .insert(key, envelope.message.value.share.clone());

        let ready_contribs: Vec<_> = snapshot
            .dealing
            .player_blinding_contribs
            .iter()
            .filter(|((_, s, h), _)| *s == seat && *h == hole_index)
            .map(|(_, v)| v.clone())
            .collect();

        if ready_contribs.len() == snapshot.shufflers.len() {
            let deck_cipher = snapshot
                .shuffling
                .final_deck
                .get(card_pos as usize)
                .context("deck position out of range")?
                .clone();

            let combined =
                crate::shuffling::player_decryption::combine_blinding_contributions_for_player(
                    &deck_cipher,
                    &ready_contribs,
                    aggregated_key,
                    player_identity.public_key,
                )
                .map_err(|err| anyhow!(err))?;

            snapshot
                .dealing
                .player_ciphertexts
                .insert((seat, hole_index), combined);

            snapshot.dealing.assignments.insert(
                card_ref,
                DealtCard {
                    cipher: deck_cipher,
                    source_index: Some(card_pos),
                },
            );
        }

        snapshot.advance_state_with_message(envelope, hasher);

        let all_hole_cards_ready = snapshot
            .stacks
            .values()
            .filter(|info| matches!(info.status, PlayerStatus::Active | PlayerStatus::AllIn))
            .map(|info| info.seat)
            .all(|seat| {
                snapshot.dealing.player_ciphertexts.contains_key(&(seat, 0))
                    && snapshot.dealing.player_ciphertexts.contains_key(&(seat, 1))
            });

        if all_hole_cards_ready {
            let cfg = snapshot
                .cfg
                .as_ref()
                .map(|cfg| cfg.as_ref())
                .context("hand configuration missing for betting transition")?;

            let betting_state = build_initial_betting_state(cfg, snapshot.stacks.as_ref());
            let betting = BettingSnapshot {
                state: betting_state,
                last_events: Vec::new(),
            };

            let reveals = RevealsSnapshot {
                board: Vec::new(),
                revealed_holes: BTreeMap::new(),
            };

            Ok(AnyTableSnapshot::Preflop(TableSnapshot {
                game_id: snapshot.game_id,
                hand_id: snapshot.hand_id,
                sequence: snapshot.sequence,
                cfg: snapshot.cfg,
                shufflers: snapshot.shufflers,
                players: snapshot.players,
                seating: snapshot.seating,
                stacks: snapshot.stacks,
                previous_hash: snapshot.previous_hash,
                state_hash: snapshot.state_hash,
                status: SnapshotStatus::Success,
                shuffling: snapshot.shuffling,
                dealing: snapshot.dealing,
                betting,
                reveals,
            }))
        } else {
            Ok(AnyTableSnapshot::Dealing(snapshot))
        }
    }
}

impl<C> TransitionHandler<C> for GamePartialUnblindingShareMessage<C>
where
    C: CurveGroup,
{
    fn apply_transition<H>(
        mut snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        H: LedgerHasher,
    {
        let _shuffler_id = envelope.actor.shuffler_id;
        let card_pos = envelope.message.value.card_in_deck_position;
        let card_ref = card_pos
            .checked_add(1)
            .context("deck position overflowed when computing card reference")?;

        let destination = snapshot
            .dealing
            .card_plan
            .get(&card_ref)
            .context("card reference not found in dealing plan")?;

        let (seat, hole_index) = match destination {
            CardDestination::Hole { seat, hole_index } => (*seat, *hole_index),
            other => bail!("partial unblinding share targets non-hole card: {other:?}"),
        };

        let entry = snapshot
            .dealing
            .player_unblinding_shares
            .entry((seat, hole_index))
            .or_insert_with(BTreeMap::new);

        let share = envelope.message.value.share.clone();
        if entry.contains_key(&share.member_index) {
            bail!(
                "duplicate partial unblinding share for member {} seat {} hole {}",
                share.member_index,
                seat,
                hole_index
            );
        }
        entry.insert(share.member_index, share);

        if entry.len() == snapshot.shufflers.len() {
            let mut shares: Vec<_> = entry.values().cloned().collect();
            shares.sort_by_key(|s| s.member_index);
            let combined = combine_unblinding_shares(&shares, snapshot.shufflers.len())
                .map_err(|err| anyhow!(err))?;
            snapshot
                .dealing
                .player_unblinding_combined
                .insert((seat, hole_index), combined);
        }

        snapshot.advance_state_with_message(envelope, hasher);

        Ok(AnyTableSnapshot::Dealing(snapshot))
    }
}

impl<C> TransitionHandler<C> for GamePlayerMessage<PreflopStreet, C>
where
    C: CurveGroup,
{
    fn apply_transition<H>(
        mut snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        H: LedgerHasher,
    {
        let seat = envelope.actor.seat_id;
        let actor_id = envelope.actor.player_id;

        let player = snapshot
            .betting
            .state
            .players
            .iter()
            .find(|p| p.seat == seat)
            .context("player seat not found in betting state")?
            .player_id;
        ensure!(
            player == Some(actor_id),
            "betting actor id mismatch: expected {:?}, got {}",
            player,
            actor_id
        );

        let action = envelope.message.value.action.clone();
        let result = EngineNL::apply_action(&mut snapshot.betting.state, seat, action)
            .map_err(|err| anyhow!("betting action failed: {:?}", err))?;

        snapshot
            .betting
            .last_events
            .push(AnyPlayerActionMsg::Preflop(envelope.message.value.clone()));

        snapshot.advance_state_with_message(envelope, hasher);

        match result {
            Transition::Continued { .. } => Ok(AnyTableSnapshot::Preflop(snapshot)),
            Transition::StreetEnd { street, .. } => {
                ensure!(street == EngineStreet::Preflop);

                // Ensure flop cards exist
                let flop_refs: Vec<_> = snapshot
                    .dealing
                    .card_plan
                    .iter()
                    .filter_map(|(&card_ref, dest)| match dest {
                        CardDestination::Board { board_index } if *board_index < 3 => {
                            Some(card_ref)
                        }
                        _ => None,
                    })
                    .collect();
                ensure!(flop_refs.len() == 3, "flop card plan incomplete");
                ensure!(
                    flop_refs
                        .iter()
                        .all(|r| snapshot.dealing.community_cards.contains_key(r)),
                    "flop community cards not fully decrypted"
                );

                EngineNL::advance_street(&mut snapshot.betting.state)
                    .map_err(|err| anyhow!("failed to advance street: {:?}", err))?;

                let reveals = RevealsSnapshot {
                    board: flop_refs
                        .iter()
                        .map(|r| snapshot.dealing.community_cards[r])
                        .collect(),
                    revealed_holes: snapshot.reveals.revealed_holes.clone(),
                };

                Ok(AnyTableSnapshot::Flop(TableSnapshot {
                    game_id: snapshot.game_id,
                    hand_id: snapshot.hand_id,
                    sequence: snapshot.sequence,
                    cfg: snapshot.cfg,
                    shufflers: snapshot.shufflers,
                    players: snapshot.players,
                    seating: snapshot.seating,
                    stacks: snapshot.stacks,
                    previous_hash: snapshot.previous_hash,
                    state_hash: snapshot.state_hash,
                    status: SnapshotStatus::Success,
                    shuffling: snapshot.shuffling,
                    dealing: snapshot.dealing,
                    betting: snapshot.betting,
                    reveals,
                }))
            }
            Transition::HandEnd { .. } => Ok(AnyTableSnapshot::Showdown(TableSnapshot {
                game_id: snapshot.game_id,
                hand_id: snapshot.hand_id,
                sequence: snapshot.sequence,
                cfg: snapshot.cfg,
                shufflers: snapshot.shufflers,
                players: snapshot.players,
                seating: snapshot.seating,
                stacks: snapshot.stacks,
                previous_hash: snapshot.previous_hash,
                state_hash: snapshot.state_hash,
                status: SnapshotStatus::Success,
                shuffling: snapshot.shuffling,
                dealing: snapshot.dealing,
                betting: snapshot.betting,
                reveals: snapshot.reveals,
            })),
        }
    }
}

impl<C> TransitionHandler<C> for GamePlayerMessage<FlopStreet, C>
where
    C: CurveGroup,
{
    fn apply_transition<H>(
        mut snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        H: LedgerHasher,
    {
        let seat = envelope.actor.seat_id;
        let actor_id = envelope.actor.player_id;

        let player = snapshot
            .betting
            .state
            .players
            .iter()
            .find(|p| p.seat == seat)
            .context("player seat not found in betting state")?
            .player_id;
        ensure!(
            player == Some(actor_id),
            "betting actor id mismatch: expected {:?}, got {}",
            player,
            actor_id
        );

        let action = envelope.message.value.action.clone();
        let result = EngineNL::apply_action(&mut snapshot.betting.state, seat, action)
            .map_err(|err| anyhow!("betting action failed: {:?}", err))?;

        snapshot
            .betting
            .last_events
            .push(AnyPlayerActionMsg::Flop(envelope.message.value.clone()));

        snapshot.advance_state_with_message(envelope, hasher);

        match result {
            Transition::Continued { .. } => Ok(AnyTableSnapshot::Flop(snapshot)),
            Transition::StreetEnd { street, .. } => {
                ensure!(street == EngineStreet::Flop);

                // Ensure turn card exists
                let turn_ref = snapshot
                    .dealing
                    .card_plan
                    .iter()
                    .find_map(|(&card_ref, dest)| match dest {
                        CardDestination::Board { board_index } if *board_index == 3 => {
                            Some(card_ref)
                        }
                        _ => None,
                    })
                    .context("turn card not present in card plan")?;

                let turn_card = snapshot
                    .dealing
                    .community_cards
                    .get(&turn_ref)
                    .context("turn community card not fully decrypted")?;

                EngineNL::advance_street(&mut snapshot.betting.state)
                    .map_err(|err| anyhow!("failed to advance street: {:?}", err))?;

                let mut board = if snapshot.reveals.board.len() >= 3 {
                    snapshot.reveals.board.clone()
                } else {
                    snapshot
                        .dealing
                        .card_plan
                        .iter()
                        .filter_map(|(&card_ref, dest)| match dest {
                            CardDestination::Board { board_index } if *board_index < 3 => {
                                snapshot.dealing.community_cards.get(&card_ref).cloned()
                            }
                            _ => None,
                        })
                        .collect()
                };
                board.push(*turn_card);

                let reveals = RevealsSnapshot {
                    board,
                    revealed_holes: snapshot.reveals.revealed_holes.clone(),
                };

                Ok(AnyTableSnapshot::Turn(TableSnapshot {
                    game_id: snapshot.game_id,
                    hand_id: snapshot.hand_id,
                    sequence: snapshot.sequence,
                    cfg: snapshot.cfg,
                    shufflers: snapshot.shufflers,
                    players: snapshot.players,
                    seating: snapshot.seating,
                    stacks: snapshot.stacks,
                    previous_hash: snapshot.previous_hash,
                    state_hash: snapshot.state_hash,
                    status: SnapshotStatus::Success,
                    shuffling: snapshot.shuffling,
                    dealing: snapshot.dealing,
                    betting: snapshot.betting,
                    reveals,
                }))
            }
            Transition::HandEnd { .. } => Ok(AnyTableSnapshot::Showdown(TableSnapshot {
                game_id: snapshot.game_id,
                hand_id: snapshot.hand_id,
                sequence: snapshot.sequence,
                cfg: snapshot.cfg,
                shufflers: snapshot.shufflers,
                players: snapshot.players,
                seating: snapshot.seating,
                stacks: snapshot.stacks,
                previous_hash: snapshot.previous_hash,
                state_hash: snapshot.state_hash,
                status: SnapshotStatus::Success,
                shuffling: snapshot.shuffling,
                dealing: snapshot.dealing,
                betting: snapshot.betting,
                reveals: snapshot.reveals,
            })),
        }
    }
}

impl<C> TransitionHandler<C> for GamePlayerMessage<TurnStreet, C>
where
    C: CurveGroup,
{
    fn apply_transition<H>(
        mut snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        H: LedgerHasher,
    {
        let seat = envelope.actor.seat_id;
        let actor_id = envelope.actor.player_id;

        let player = snapshot
            .betting
            .state
            .players
            .iter()
            .find(|p| p.seat == seat)
            .context("player seat not found in betting state")?
            .player_id;
        ensure!(
            player == Some(actor_id),
            "betting actor id mismatch: expected {:?}, got {}",
            player,
            actor_id
        );

        let action = envelope.message.value.action.clone();
        let result = EngineNL::apply_action(&mut snapshot.betting.state, seat, action)
            .map_err(|err| anyhow!("betting action failed: {:?}", err))?;

        snapshot
            .betting
            .last_events
            .push(AnyPlayerActionMsg::Turn(envelope.message.value.clone()));

        snapshot.advance_state_with_message(envelope, hasher);

        match result {
            Transition::Continued { .. } => Ok(AnyTableSnapshot::Turn(snapshot)),
            Transition::StreetEnd { street, .. } => {
                ensure!(street == EngineStreet::Turn);

                let river_ref = snapshot
                    .dealing
                    .card_plan
                    .iter()
                    .find_map(|(&card_ref, dest)| match dest {
                        CardDestination::Board { board_index } if *board_index == 4 => {
                            Some(card_ref)
                        }
                        _ => None,
                    })
                    .context("river card not present in card plan")?;

                let river_card = snapshot
                    .dealing
                    .community_cards
                    .get(&river_ref)
                    .context("river community card not fully decrypted")?;

                EngineNL::advance_street(&mut snapshot.betting.state)
                    .map_err(|err| anyhow!("failed to advance street: {:?}", err))?;

                let mut board = snapshot.reveals.board.clone();
                if board.len() < 4 {
                    let mut flop_turn: Vec<_> = snapshot
                        .dealing
                        .card_plan
                        .iter()
                        .filter_map(|(&card_ref, dest)| match dest {
                            CardDestination::Board { board_index } if *board_index <= 3 => {
                                snapshot.dealing.community_cards.get(&card_ref)
                            }
                            _ => None,
                        })
                        .cloned()
                        .collect();
                    board.append(&mut flop_turn);
                }
                board.push(*river_card);

                let reveals = RevealsSnapshot {
                    board,
                    revealed_holes: snapshot.reveals.revealed_holes.clone(),
                };

                Ok(AnyTableSnapshot::River(TableSnapshot {
                    game_id: snapshot.game_id,
                    hand_id: snapshot.hand_id,
                    sequence: snapshot.sequence,
                    cfg: snapshot.cfg,
                    shufflers: snapshot.shufflers,
                    players: snapshot.players,
                    seating: snapshot.seating,
                    stacks: snapshot.stacks,
                    previous_hash: snapshot.previous_hash,
                    state_hash: snapshot.state_hash,
                    status: SnapshotStatus::Success,
                    shuffling: snapshot.shuffling,
                    dealing: snapshot.dealing,
                    betting: snapshot.betting,
                    reveals,
                }))
            }
            Transition::HandEnd { .. } => Ok(AnyTableSnapshot::Showdown(TableSnapshot {
                game_id: snapshot.game_id,
                hand_id: snapshot.hand_id,
                sequence: snapshot.sequence,
                cfg: snapshot.cfg,
                shufflers: snapshot.shufflers,
                players: snapshot.players,
                seating: snapshot.seating,
                stacks: snapshot.stacks,
                previous_hash: snapshot.previous_hash,
                state_hash: snapshot.state_hash,
                status: SnapshotStatus::Success,
                shuffling: snapshot.shuffling,
                dealing: snapshot.dealing,
                betting: snapshot.betting,
                reveals: snapshot.reveals,
            })),
        }
    }
}

impl<C> TransitionHandler<C> for GamePlayerMessage<RiverStreet, C>
where
    C: CurveGroup,
{
    fn apply_transition<H>(
        mut snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        H: LedgerHasher,
    {
        let seat = envelope.actor.seat_id;
        let actor_id = envelope.actor.player_id;

        let player = snapshot
            .betting
            .state
            .players
            .iter()
            .find(|p| p.seat == seat)
            .context("player seat not found in betting state")?
            .player_id;
        ensure!(
            player == Some(actor_id),
            "betting actor id mismatch: expected {:?}, got {}",
            player,
            actor_id
        );

        let action = envelope.message.value.action.clone();
        let result = EngineNL::apply_action(&mut snapshot.betting.state, seat, action)
            .map_err(|err| anyhow!("betting action failed: {:?}", err))?;

        snapshot
            .betting
            .last_events
            .push(AnyPlayerActionMsg::River(envelope.message.value.clone()));

        snapshot.advance_state_with_message(envelope, hasher);

        match result {
            Transition::Continued { .. } => Ok(AnyTableSnapshot::River(snapshot)),
            Transition::StreetEnd { street, .. } => {
                ensure!(street == EngineStreet::River);
                EngineNL::advance_street(&mut snapshot.betting.state)
                    .map_err(|err| anyhow!("failed to advance street: {:?}", err))?;

                let showdown_snapshot = promote_to_showdown_from_river(snapshot);
                Ok(AnyTableSnapshot::Showdown(showdown_snapshot))
            }
            Transition::HandEnd { .. } => {
                let showdown_snapshot = promote_to_showdown_from_river(snapshot);
                Ok(AnyTableSnapshot::Showdown(showdown_snapshot))
            }
        }
    }
}

impl<C> TransitionHandler<C> for GameShowdownMessage<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField, PoseidonSponge<C::BaseField>>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
{
    fn apply_transition<H>(
        mut snapshot: TableSnapshot<Self::Phase, C>,
        envelope: &EnvelopedMessage<C, Self>,
        hasher: &H,
    ) -> Result<AnyTableSnapshot<C>>
    where
        H: LedgerHasher,
    {
        let seat = envelope.actor.seat_id;
        let actor_id = envelope.actor.player_id;

        let player_entry = snapshot
            .betting
            .state
            .players
            .iter()
            .find(|p| p.seat == seat)
            .context("player seat not found in betting state")?;
        ensure!(
            player_entry.player_id == Some(actor_id),
            "showdown actor mismatch: expected {:?}, got {}",
            player_entry.player_id,
            actor_id
        );

        ensure!(
            !snapshot.reveals.revealed_holes.contains_key(&seat),
            "player at seat {seat} has already revealed their hand"
        );

        let player_identity = snapshot
            .players
            .get(&actor_id)
            .context("player identity not found")?;
        ensure!(
            player_identity.seat == seat,
            "player identity seat mismatch: expected {}, got {}",
            player_identity.seat,
            seat
        );

        ensure!(
            snapshot.reveals.board.len() == 5,
            "showdown requires all five community cards to be revealed"
        );

        let message = &envelope.message.value;
        let poseidon_params = poseidon_config::<C::BaseField>();
        let mut revealed_hole_cards = [0u8; 2];

        for hole_idx in 0..2 {
            let hole_index_u8 = hole_idx as u8;
            let deck_position = message.card_in_deck_position[hole_idx];
            let provided_cipher = &message.hole_ciphertexts[hole_idx];

            let card_ref = snapshot
                .dealing
                .card_plan
                .iter()
                .find_map(|(&card_ref, destination)| match destination {
                    CardDestination::Hole {
                        seat: dest_seat,
                        hole_index,
                    } if *dest_seat == seat && *hole_index == hole_index_u8 => Some(card_ref),
                    _ => None,
                })
                .context("hole card reference not found in dealing plan")?;

            let dealt_card = snapshot
                .dealing
                .assignments
                .get(&card_ref)
                .context("hole card assignment missing for showdown")?;
            let source_index = dealt_card
                .source_index
                .context("hole card assignment missing deck position")?;
            ensure!(
                source_index == deck_position,
                "showdown deck position mismatch for seat {seat} hole {hole_index_u8}: expected {source_index}, got {deck_position}"
            );

            let stored_cipher = snapshot
                .dealing
                .player_ciphertexts
                .get(&(seat, hole_index_u8))
                .context("player ciphertext missing for showdown")?;

            ensure!(
                stored_cipher.blinded_base == provided_cipher.blinded_base,
                "blinded base mismatch for seat {seat} hole {hole_index_u8}"
            );
            ensure!(
                stored_cipher.player_unblinding_helper == provided_cipher.player_unblinding_helper,
                "player unblinding helper mismatch for seat {seat} hole {hole_index_u8}"
            );

            let player_component = stored_cipher.blinded_message_with_player_key.clone()
                - provided_cipher.blinded_message_with_player_key.clone();

            let mut sponge = PoseidonSponge::new(&poseidon_params);
            ensure!(
                message.chaum_pedersen_proofs[hole_idx].verify(
                    &mut sponge,
                    C::generator(),
                    stored_cipher.player_unblinding_helper,
                    player_identity.public_key,
                    player_component,
                ),
                "invalid Chaum-Pedersen proof for seat {seat} hole {hole_index_u8}"
            );

            let combined_unblinding = snapshot
                .dealing
                .player_unblinding_combined
                .get(&(seat, hole_index_u8))
                .context("combined unblinding share missing for showdown")?;

            let recovered_point = provided_cipher.blinded_message_with_player_key.clone()
                - combined_unblinding.clone();

            let card_value = decode_card_from_point::<C>(&recovered_point)
                .context("unrecognized decrypted card")?;
            let card_index = card_value
                .checked_add(1)
                .context("card index overflow when converting decrypted card")?;
            revealed_hole_cards[hole_idx] = card_index;
        }

        let board_slice = snapshot.reveals.board.as_slice();
        let cards7 = std::array::from_fn(|idx| {
            if idx < 5 {
                board_slice[idx]
            } else {
                revealed_hole_cards[idx - 5]
            }
        });

        let best = choose_best5_from7(cards7);
        let best_indices: [u8; 5] = best.hand.cards.map(|card| idx_of(card.rank, card.suit));

        let revealed_hand = RevealedHand {
            hole: revealed_hole_cards,
            hole_ciphertexts: message.hole_ciphertexts.clone(),
            best_five: best_indices,
            best_category: best.hand.category,
            best_tiebreak: best.tiebreak,
            best_score: best.score_u32,
        };

        let previous = snapshot.reveals.revealed_holes.insert(seat, revealed_hand);
        ensure!(
            previous.is_none(),
            "duplicate showdown reveal for seat {seat}"
        );

        snapshot.advance_state_with_message(envelope, hasher);

        let pending_reveals: Vec<_> = snapshot
            .stacks
            .values()
            .filter(|info| {
                info.player_id.is_some()
                    && matches!(info.status, PlayerStatus::Active | PlayerStatus::AllIn)
            })
            .map(|info| info.seat)
            .collect();
        let all_revealed = pending_reveals
            .iter()
            .all(|seat_id| snapshot.reveals.revealed_holes.contains_key(seat_id));

        if all_revealed {
            Ok(AnyTableSnapshot::Complete(TableSnapshot {
                game_id: snapshot.game_id,
                hand_id: snapshot.hand_id,
                sequence: snapshot.sequence,
                cfg: snapshot.cfg,
                shufflers: snapshot.shufflers,
                players: snapshot.players,
                seating: snapshot.seating,
                stacks: snapshot.stacks,
                previous_hash: snapshot.previous_hash,
                state_hash: snapshot.state_hash,
                status: SnapshotStatus::Success,
                shuffling: snapshot.shuffling,
                dealing: snapshot.dealing,
                betting: snapshot.betting,
                reveals: snapshot.reveals,
            }))
        } else {
            Ok(AnyTableSnapshot::Showdown(snapshot))
        }
    }
}

fn decode_card_from_point<C>(point: &C) -> Option<u8>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    let generator = C::generator();
    for value in 0u8..52 {
        let scalar = C::ScalarField::from(value as u64);
        if generator * scalar == *point {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaum_pedersen::ChaumPedersenProof;
    use crate::engine::nl::actions::PlayerBetAction;
    use crate::engine::nl::types::{PlayerId, PlayerStatus, SeatId, Street as EngineStreet};
    use crate::ledger::actor::{PlayerActor, ShufflerActor};
    use crate::ledger::messages::Street;
    use crate::ledger::messages::{
        EnvelopedMessage, GameBlindingDecryptionMessage, GameMessage, GamePlayerMessage,
        GameShowdownMessage, GameShuffleMessage,
    };
    use crate::ledger::snapshot::{
        AnyPlayerActionMsg, AnyTableSnapshot, CardDestination, TableAtDealing, TableAtShowdown,
    };
    use crate::ledger::test_support::{
        active_seats, fixture_dealing_snapshot, fixture_flop_snapshot, fixture_preflop_snapshot,
        fixture_river_snapshot, fixture_showdown_snapshot, fixture_shuffling_snapshot,
        fixture_turn_snapshot, FixtureContext,
    };
    use crate::ledger::types::ShufflerId;
    use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
    use crate::shuffling::player_decryption::PlayerTargetedBlindingContribution;
    use crate::signing::WithSignature;
    use ark_bn254::G1Projective as Curve;
    use ark_ec::PrimeGroup;
    use ark_ff::Zero;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use std::sync::Arc;

    fn dummy_shuffle_proof<C: CurveGroup>(
        deck_in: &[ElGamalCiphertext<C>; DECK_SIZE],
        deck_out: &[ElGamalCiphertext<C>; DECK_SIZE],
    ) -> ShuffleProof<C>
    where
        C::BaseField: Zero,
        C::ScalarField: Zero,
    {
        let input = deck_in.iter().cloned().collect::<Vec<_>>();
        let sorted = deck_out
            .iter()
            .cloned()
            .map(|cipher| (cipher, C::BaseField::zero()))
            .collect::<Vec<_>>();
        let rerand = vec![C::ScalarField::zero(); DECK_SIZE];
        ShuffleProof::new(input, sorted, rerand).expect("dummy proof to have valid lengths")
    }

    fn build_shuffle_message<C: CurveGroup>(
        deck_in: &[ElGamalCiphertext<C>; DECK_SIZE],
        deck_out: &[ElGamalCiphertext<C>; DECK_SIZE],
    ) -> GameShuffleMessage<C>
    where
        C::BaseField: Zero,
        C::ScalarField: Zero,
    {
        GameShuffleMessage::new(
            deck_in.clone(),
            deck_out.clone(),
            dummy_shuffle_proof(deck_in, deck_out),
        )
    }

    fn build_shuffle_envelope<C: CurveGroup>(
        ctx: &FixtureContext<C>,
        shuffler_id: ShufflerId,
        message: GameShuffleMessage<C>,
    ) -> EnvelopedMessage<C, GameShuffleMessage<C>>
    where
        C::BaseField: Zero,
        C::ScalarField: Zero,
    {
        let transcript = message.to_signing_bytes();
        let with_sig = WithSignature {
            value: message,
            signature: Vec::new(),
            transcript,
        };

        let public_key = ctx
            .shufflers
            .get(&shuffler_id)
            .expect("shuffler identity")
            .public_key
            .clone();

        EnvelopedMessage {
            hand_id: ctx.hand_id,
            game_id: ctx.game_id,
            actor: ShufflerActor { shuffler_id },
            nonce: 0,
            public_key,
            message: with_sig,
        }
    }

    fn build_blinding_envelope<C: CurveGroup>(
        ctx: &FixtureContext<C>,
        shuffler_id: ShufflerId,
        message: GameBlindingDecryptionMessage<C>,
    ) -> EnvelopedMessage<C, GameBlindingDecryptionMessage<C>> {
        let transcript = message.to_signing_bytes();
        let with_sig = WithSignature {
            value: message,
            signature: Vec::new(),
            transcript,
        };

        let public_key = ctx
            .shufflers
            .get(&shuffler_id)
            .expect("shuffler identity")
            .public_key
            .clone();

        EnvelopedMessage {
            hand_id: ctx.hand_id,
            game_id: ctx.game_id,
            actor: ShufflerActor { shuffler_id },
            nonce: 0,
            public_key,
            message: with_sig,
        }
    }

    fn swap_deck_entries<C: CurveGroup>(
        deck: &[ElGamalCiphertext<C>; DECK_SIZE],
        i: usize,
        j: usize,
    ) -> [ElGamalCiphertext<C>; DECK_SIZE] {
        let mut new_deck = deck.clone();
        new_deck.swap(i, j);
        new_deck
    }

    fn player_actor_info(
        ctx: &FixtureContext<Curve>,
        seat: SeatId,
    ) -> (PlayerActor, PlayerId, Curve) {
        let player_id = ctx
            .seating
            .get(&seat)
            .and_then(|id| *id)
            .expect("player id for seat");
        let identity = ctx.players.get(&player_id).expect("player identity");
        (
            PlayerActor {
                seat_id: seat,
                player_id,
            },
            player_id,
            identity.public_key,
        )
    }

    fn build_player_envelope<R>(
        ctx: &FixtureContext<Curve>,
        seat: SeatId,
        action: PlayerBetAction,
    ) -> EnvelopedMessage<Curve, GamePlayerMessage<R, Curve>>
    where
        R: Street + Default,
        GamePlayerMessage<R, Curve>: GameMessage<Curve, Actor = PlayerActor>,
    {
        let (actor, _, public_key) = player_actor_info(ctx, seat);
        let message = GamePlayerMessage::<R, Curve>::new(action);
        let transcript = message.to_signing_bytes();
        let with_sig = WithSignature {
            value: message,
            signature: Vec::new(),
            transcript,
        };
        EnvelopedMessage {
            hand_id: ctx.hand_id,
            game_id: ctx.game_id,
            actor,
            nonce: 0,
            public_key,
            message: with_sig,
        }
    }

    fn build_showdown_message(
        snapshot: &TableAtShowdown<Curve>,
        seat: SeatId,
        player_secret: <Curve as PrimeGroup>::ScalarField,
    ) -> GameShowdownMessage<Curve> {
        let mut positions = [0u8; 2];
        let ciphertexts = [
            snapshot
                .dealing
                .player_ciphertexts
                .get(&(seat, 0))
                .cloned()
                .expect("hole 0 ciphertext present"),
            snapshot
                .dealing
                .player_ciphertexts
                .get(&(seat, 1))
                .cloned()
                .expect("hole 1 ciphertext present"),
        ];

        for hole_index in 0..2u8 {
            let card_ref = snapshot
                .dealing
                .card_plan
                .iter()
                .find_map(|(&card_ref, destination)| match destination {
                    CardDestination::Hole {
                        seat: dest_seat,
                        hole_index: dest_hole,
                    } if *dest_seat == seat && *dest_hole == hole_index => Some(card_ref),
                    _ => None,
                })
                .expect("card reference for showdown hole");

            let deck_pos = snapshot
                .dealing
                .assignments
                .get(&card_ref)
                .and_then(|dealt| dealt.source_index)
                .expect("deck position for showdown card");
            positions[hole_index as usize] = deck_pos;
        }

        let poseidon_params = poseidon_config::<<Curve as CurveGroup>::BaseField>();
        let proofs = std::array::from_fn(|idx| {
            let mut sponge = PoseidonSponge::new(&poseidon_params);
            let mut rng = StdRng::seed_from_u64(0xC0DEC0DEu64 ^ idx as u64);
            ChaumPedersenProof::prove(
                &mut sponge,
                player_secret,
                Curve::generator(),
                ciphertexts[idx].player_unblinding_helper,
                &mut rng,
            )
        });

        GameShowdownMessage::new(proofs, positions, ciphertexts)
    }

    fn build_showdown_envelope(
        ctx: &FixtureContext<Curve>,
        snapshot: &TableAtShowdown<Curve>,
        seat: SeatId,
    ) -> EnvelopedMessage<Curve, GameShowdownMessage<Curve>> {
        let (actor, player_id, public_key) = player_actor_info(ctx, seat);
        let player_secret = ctx
            .player_secrets
            .get(&player_id)
            .cloned()
            .expect("player secret available");
        let message = build_showdown_message(snapshot, seat, player_secret);
        let transcript = message.to_signing_bytes();
        let with_sig = WithSignature {
            value: message,
            signature: Vec::new(),
            transcript,
        };
        EnvelopedMessage {
            hand_id: ctx.hand_id,
            game_id: ctx.game_id,
            actor,
            nonce: 0,
            public_key,
            message: with_sig,
        }
    }

    #[test]
    fn shuffle_stays_in_phase_until_final_step() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let snapshot = fixture_shuffling_snapshot(&ctx);

        let deck_out = swap_deck_entries(&snapshot.shuffling.final_deck, 0, 1);
        let message = build_shuffle_message(&snapshot.shuffling.final_deck, &deck_out);
        let envelope = build_shuffle_envelope(&ctx, 10, message);

        let result =
            GameShuffleMessage::<Curve>::apply_transition(snapshot, &envelope, &ctx.hasher)
                .expect("shuffle transition should succeed");

        match result {
            AnyTableSnapshot::Shuffling(next) => {
                assert_eq!(next.shuffling.steps.len(), 1);
                assert_eq!(next.shuffling.final_deck, deck_out);
            }
            other => panic!("expected shuffling snapshot, got {:?}", other),
        }
    }

    #[test]
    fn shuffle_promotes_to_dealing_after_last_shuffler() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_shuffling_snapshot(&ctx);

        // Simulate first shuffler already acted.
        let prefinal_deck = swap_deck_entries(&snapshot.shuffling.final_deck, 0, 1);
        let identity = ctx
            .shufflers
            .get(&10)
            .expect("first shuffler identity should exist");
        snapshot.shuffling.steps.push(ShufflingStep {
            shuffler_public_key: identity.public_key.clone(),
            proof: dummy_shuffle_proof(&snapshot.shuffling.final_deck, &prefinal_deck),
        });
        snapshot.shuffling.final_deck = prefinal_deck.clone();

        let final_deck = swap_deck_entries(&prefinal_deck, 2, 3);
        let message = build_shuffle_message(&prefinal_deck, &final_deck);
        let envelope = build_shuffle_envelope(&ctx, 11, message);

        let result =
            GameShuffleMessage::<Curve>::apply_transition(snapshot, &envelope, &ctx.hasher)
                .expect("shuffle transition should succeed");

        match result {
            AnyTableSnapshot::Dealing(next) => {
                assert_eq!(next.dealing.card_plan.len(), DECK_SIZE);
                assert_eq!(next.shuffling.final_deck, final_deck);
                assert_eq!(
                    next.shuffling.steps.len(),
                    ctx.expected_shuffler_order.len()
                );
            }
            other => panic!("expected dealing snapshot, got {:?}", other),
        }
    }

    fn first_player<C: CurveGroup>(ctx: &FixtureContext<C>) -> (SeatId, PlayerId, C) {
        ctx.seating
            .iter()
            .find_map(|(&seat, player)| player.map(|id| (seat, id)))
            .and_then(|(seat, id)| {
                ctx.players
                    .get(&id)
                    .map(|identity| (seat, id, identity.public_key))
            })
            .expect("fixture to contain at least one player")
    }

    fn card_position_for(snapshot: &TableAtDealing<Curve>, seat: u8, hole_index: u8) -> u8 {
        let card_ref = snapshot
            .dealing
            .card_plan
            .iter()
            .find_map(|(&card_ref, dest)| match dest {
                CardDestination::Hole {
                    seat: dest_seat,
                    hole_index: dest_hole,
                } if *dest_seat == seat && *dest_hole == hole_index => Some(card_ref),
                _ => None,
            })
            .expect("card reference for seat/hole");
        snapshot
            .dealing
            .assignments
            .get(&card_ref)
            .and_then(|dealt| dealt.source_index)
            .expect("deck position for card reference")
    }

    fn generate_blinding_contribution(
        ctx: &FixtureContext<Curve>,
        shuffler_id: ShufflerId,
        player_public_key: Curve,
        seed_offset: u64,
    ) -> PlayerTargetedBlindingContribution<Curve> {
        let secret = ctx
            .shuffler_secrets
            .get(&shuffler_id)
            .expect("shuffler secret")
            .clone();
        let aggregated = ctx.aggregated_shuffler_pk;
        let seed = 0xB1D1_D00Du64
            .wrapping_add(shuffler_id as u64 * 97)
            .wrapping_add(seed_offset);
        let mut rng = StdRng::seed_from_u64(seed);
        PlayerTargetedBlindingContribution::generate(
            secret,
            aggregated,
            player_public_key,
            &mut rng,
        )
    }

    #[test]
    fn blinding_contribution_stays_in_dealing_until_hole_complete() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_dealing_snapshot(&ctx);
        let (seat, _player_id, player_pk) = first_player(&ctx);

        snapshot.dealing.player_ciphertexts.clear();
        snapshot.dealing.player_unblinding_combined.clear();

        let card_pos = card_position_for(&snapshot, seat, 0);
        let share = generate_blinding_contribution(&ctx, 10, player_pk, 0);
        let message = GameBlindingDecryptionMessage::new(card_pos, share.clone());
        let envelope = build_blinding_envelope(&ctx, 10, message);

        let result = GameBlindingDecryptionMessage::<Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("blinding transition should succeed");

        match result {
            AnyTableSnapshot::Dealing(next) => {
                assert!(
                    next.dealing
                        .player_blinding_contribs
                        .contains_key(&(10, seat, 0)),
                    "contribution recorded in snapshot"
                );
                assert!(
                    !next.dealing.player_ciphertexts.contains_key(&(seat, 1)),
                    "second hole card still pending"
                );
                assert!(
                    !next.dealing.player_ciphertexts.contains_key(&(seat, 0)),
                    "current hole ciphertext remains pending until all shares arrive"
                );
            }
            other => panic!("expected dealing snapshot, got {:?}", other),
        }
    }

    #[test]
    fn blinding_contributions_promote_to_preflop_when_all_ready() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_dealing_snapshot(&ctx);
        let (seat, _player_id, player_pk) = first_player(&ctx);
        let hole_positions: Vec<u8> = (0..=1)
            .map(|hole| card_position_for(&snapshot, seat, hole))
            .collect();

        snapshot.dealing.player_ciphertexts.remove(&(seat, 0));
        snapshot.dealing.player_ciphertexts.clear();
        snapshot.dealing.player_unblinding_combined.clear();

        {
            let stacks = Arc::make_mut(&mut snapshot.stacks);
            for (&stack_seat, info) in stacks.iter_mut() {
                if stack_seat != seat {
                    info.status = PlayerStatus::SittingOut;
                }
            }
        }

        let mut current_snapshot = AnyTableSnapshot::Dealing(snapshot);
        for (hole_index, &card_pos) in hole_positions.iter().enumerate() {
            for (order, shuffler_id) in ctx.expected_shuffler_order.iter().enumerate() {
                let dealing_snapshot = match current_snapshot {
                    AnyTableSnapshot::Dealing(ref dealing) => dealing.clone(),
                    _ => panic!("unexpected snapshot state during blinding sequence"),
                };
                let share = generate_blinding_contribution(
                    &ctx,
                    *shuffler_id,
                    player_pk,
                    (hole_index as u64) * 10 + order as u64,
                );
                let message = GameBlindingDecryptionMessage::new(card_pos, share);
                let envelope = build_blinding_envelope(&ctx, *shuffler_id, message);
                let result = GameBlindingDecryptionMessage::<Curve>::apply_transition(
                    dealing_snapshot,
                    &envelope,
                    &ctx.hasher,
                )
                .expect("blinding transition should succeed");

                match result {
                    AnyTableSnapshot::Preflop(next) => {
                        assert_eq!(
                            next.betting.state.street,
                            EngineStreet::Preflop,
                            "betting state advanced to preflop street"
                        );
                        return;
                    }
                    AnyTableSnapshot::Dealing(next) => {
                        current_snapshot = AnyTableSnapshot::Dealing(next);
                    }
                    other => panic!("unexpected snapshot variant during blinding: {:?}", other),
                }
            }
        }

        panic!("final share did not produce preflop snapshot");
    }

    #[test]
    fn preflop_check_continues_phase() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_preflop_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];
        let opponent = seats[1];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Preflop;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match = vec![opponent];
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.last_full_raise_amount = 0;
            state.last_aggressor = None;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<PreflopStreet>(&ctx, seat, PlayerBetAction::Check);
        let result = GamePlayerMessage::<PreflopStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("preflop action should succeed");

        match result {
            AnyTableSnapshot::Preflop(next) => {
                assert_eq!(next.betting.state.street, EngineStreet::Preflop);
                assert_eq!(next.betting.state.to_act, opponent);
                assert_eq!(next.betting.last_events.len(), 1);
                assert!(
                    matches!(
                        next.betting.last_events.last(),
                        Some(AnyPlayerActionMsg::Preflop(_))
                    ),
                    "last event recorded as preflop action"
                );
            }
            other => panic!("expected preflop snapshot, got {:?}", other),
        }
    }

    #[test]
    fn preflop_check_advances_to_flop_when_round_complete() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_preflop_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[1];
        let opponent = seats[0];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Preflop;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match.clear();
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.last_full_raise_amount = 0;
            state.last_aggressor = None;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = true;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<PreflopStreet>(&ctx, seat, PlayerBetAction::Check);
        let result = GamePlayerMessage::<PreflopStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("preflop action should succeed");

        match result {
            AnyTableSnapshot::Flop(next) => {
                assert_eq!(next.betting.state.street, EngineStreet::Flop);
                assert_eq!(next.reveals.board.len(), 3);
                assert!(
                    matches!(
                        next.betting.last_events.last(),
                        Some(AnyPlayerActionMsg::Preflop(_))
                    ),
                    "last event recorded as preflop action"
                );
            }
            other => panic!("expected flop snapshot, got {:?}", other),
        }
    }

    #[test]
    fn preflop_fold_ends_hand() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_preflop_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];
        let opponent = seats[1];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Preflop;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match = vec![seat];
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = true;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<PreflopStreet>(&ctx, seat, PlayerBetAction::Fold);
        let result = GamePlayerMessage::<PreflopStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("preflop fold should succeed");

        match result {
            AnyTableSnapshot::Showdown(next) => {
                assert!(
                    matches!(
                        next.betting.last_events.last(),
                        Some(AnyPlayerActionMsg::Preflop(_))
                    ),
                    "last event recorded as preflop action"
                );
                let still_active: Vec<_> = next
                    .betting
                    .state
                    .players
                    .iter()
                    .filter(|p| p.status == PlayerStatus::Active)
                    .map(|p| p.seat)
                    .collect();
                assert_eq!(still_active, vec![opponent]);
            }
            other => panic!("expected showdown snapshot, got {:?}", other),
        }
    }

    #[test]
    fn flop_check_continues_phase() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_flop_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];
        let opponent = seats[1];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Flop;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match = vec![opponent];
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.last_full_raise_amount = 0;
            state.last_aggressor = None;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<FlopStreet>(&ctx, seat, PlayerBetAction::Check);
        let result = GamePlayerMessage::<FlopStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("flop action should succeed");

        match result {
            AnyTableSnapshot::Flop(next) => {
                assert_eq!(next.betting.state.street, EngineStreet::Flop);
                assert_eq!(next.betting.state.to_act, opponent);
                assert!(matches!(
                    next.betting.last_events.last(),
                    Some(AnyPlayerActionMsg::Flop(_))
                ));
            }
            other => panic!("expected flop snapshot, got {:?}", other),
        }
    }

    #[test]
    fn flop_check_advances_to_turn_when_round_complete() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_flop_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[1];
        let opponent = seats[0];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Flop;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match.clear();
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.last_full_raise_amount = 0;
            state.last_aggressor = None;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = true;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<FlopStreet>(&ctx, seat, PlayerBetAction::Check);
        let result = GamePlayerMessage::<FlopStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("flop action should succeed");

        match result {
            AnyTableSnapshot::Turn(next) => {
                assert_eq!(next.betting.state.street, EngineStreet::Turn);
                assert_eq!(next.reveals.board.len(), 4);
            }
            other => panic!("expected turn snapshot, got {:?}", other),
        }
    }

    #[test]
    fn flop_fold_ends_hand() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_flop_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];
        let opponent = seats[1];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Flop;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match = vec![seat];
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = true;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<FlopStreet>(&ctx, seat, PlayerBetAction::Fold);
        let result = GamePlayerMessage::<FlopStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("flop fold should succeed");

        match result {
            AnyTableSnapshot::Showdown(next) => {
                let still_active: Vec<_> = next
                    .betting
                    .state
                    .players
                    .iter()
                    .filter(|p| p.status == PlayerStatus::Active)
                    .map(|p| p.seat)
                    .collect();
                assert_eq!(still_active, vec![opponent]);
            }
            other => panic!("expected showdown snapshot, got {:?}", other),
        }
    }

    #[test]
    fn turn_check_continues_phase() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_turn_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];
        let opponent = seats[1];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Turn;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match = vec![opponent];
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.last_full_raise_amount = 0;
            state.last_aggressor = None;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<TurnStreet>(&ctx, seat, PlayerBetAction::Check);
        let result = GamePlayerMessage::<TurnStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("turn action should succeed");

        match result {
            AnyTableSnapshot::Turn(next) => {
                assert_eq!(next.betting.state.street, EngineStreet::Turn);
                assert_eq!(next.betting.state.to_act, opponent);
            }
            other => panic!("expected turn snapshot, got {:?}", other),
        }
    }

    #[test]
    fn turn_check_advances_to_river_when_round_complete() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_turn_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[1];
        let opponent = seats[0];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Turn;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match.clear();
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.last_full_raise_amount = 0;
            state.last_aggressor = None;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = true;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<TurnStreet>(&ctx, seat, PlayerBetAction::Check);
        let result = GamePlayerMessage::<TurnStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("turn action should succeed");

        match result {
            AnyTableSnapshot::River(next) => {
                assert_eq!(next.betting.state.street, EngineStreet::River);
            }
            other => panic!("expected river snapshot, got {:?}", other),
        }
    }

    #[test]
    fn turn_fold_ends_hand() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_turn_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];
        let opponent = seats[1];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::Turn;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match = vec![seat];
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = true;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<TurnStreet>(&ctx, seat, PlayerBetAction::Fold);
        let result = GamePlayerMessage::<TurnStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("turn fold should succeed");

        match result {
            AnyTableSnapshot::Showdown(next) => {
                let still_active: Vec<_> = next
                    .betting
                    .state
                    .players
                    .iter()
                    .filter(|p| p.status == PlayerStatus::Active)
                    .map(|p| p.seat)
                    .collect();
                assert_eq!(still_active, vec![opponent]);
            }
            other => panic!("expected showdown snapshot, got {:?}", other),
        }
    }

    #[test]
    fn river_check_continues_phase() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_river_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];
        let opponent = seats[1];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::River;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match = vec![opponent];
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.last_full_raise_amount = 0;
            state.last_aggressor = None;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<RiverStreet>(&ctx, seat, PlayerBetAction::Check);
        let result = GamePlayerMessage::<RiverStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("river action should succeed");

        match result {
            AnyTableSnapshot::River(next) => {
                assert_eq!(next.betting.state.street, EngineStreet::River);
                assert_eq!(next.betting.state.to_act, opponent);
            }
            other => panic!("expected river snapshot, got {:?}", other),
        }
    }

    #[test]
    fn river_fold_moves_to_showdown() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let mut snapshot = fixture_river_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];
        let opponent = seats[1];

        {
            let state = &mut snapshot.betting.state;
            state.street = EngineStreet::River;
            state.first_to_act = seat;
            state.to_act = seat;
            state.pending_to_match = vec![seat];
            state.voluntary_bet_opened = false;
            state.current_bet_to_match = 0;
            state.betting_locked_all_in = false;
            for player in state.players.iter_mut() {
                if player.seat == seat {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = false;
                } else if player.seat == opponent {
                    player.status = PlayerStatus::Active;
                    player.has_acted_this_round = true;
                } else {
                    player.status = PlayerStatus::Folded;
                }
                player.committed_this_round = 0;
            }
        }

        let envelope = build_player_envelope::<RiverStreet>(&ctx, seat, PlayerBetAction::Fold);
        let result = GamePlayerMessage::<RiverStreet, Curve>::apply_transition(
            snapshot,
            &envelope,
            &ctx.hasher,
        )
        .expect("river fold should succeed");

        match result {
            AnyTableSnapshot::Showdown(next) => {
                let still_active: Vec<_> = next
                    .betting
                    .state
                    .players
                    .iter()
                    .filter(|p| p.status == PlayerStatus::Active)
                    .map(|p| p.seat)
                    .collect();
                assert_eq!(still_active, vec![opponent]);
            }
            other => panic!("expected showdown snapshot, got {:?}", other),
        }
    }

    #[test]
    fn showdown_reveal_stays_in_showdown() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let snapshot = fixture_showdown_snapshot(&ctx);
        let seats = active_seats(&ctx);
        let seat = seats[0];

        let envelope = build_showdown_envelope(&ctx, &snapshot, seat);
        let result =
            GameShowdownMessage::<Curve>::apply_transition(snapshot, &envelope, &ctx.hasher)
                .expect("showdown reveal should succeed");

        match result {
            AnyTableSnapshot::Showdown(next) => {
                assert!(next.reveals.revealed_holes.contains_key(&seat));
                assert_eq!(next.reveals.revealed_holes.len(), 1);
            }
            other => panic!("expected showdown snapshot, got {:?}", other),
        }
    }

    #[test]
    fn showdown_reveals_all_players_completes_hand() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[10, 11]);
        let seats = active_seats(&ctx);
        let mut current = AnyTableSnapshot::Showdown(fixture_showdown_snapshot(&ctx));

        for (index, seat) in seats.iter().enumerate() {
            let showdown_snapshot = match &current {
                AnyTableSnapshot::Showdown(snapshot) => snapshot.clone(),
                other => panic!("unexpected snapshot variant before completion: {:?}", other),
            };
            let envelope = build_showdown_envelope(&ctx, &showdown_snapshot, *seat);
            let result = GameShowdownMessage::<Curve>::apply_transition(
                showdown_snapshot,
                &envelope,
                &ctx.hasher,
            )
            .expect("showdown reveal should succeed");

            if index + 1 == seats.len() {
                match result {
                    AnyTableSnapshot::Complete(next) => {
                        assert_eq!(next.reveals.revealed_holes.len(), seats.len());
                        return;
                    }
                    other => panic!("expected complete snapshot, got {:?}", other),
                }
            } else {
                current = result;
            }
        }

        panic!("showdown did not complete after revealing all seats");
    }
}
