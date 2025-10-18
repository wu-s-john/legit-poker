use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ark_ec::CurveGroup;
use async_trait::async_trait;

use crate::engine::nl::types::SeatId;
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::{
    AnyTableSnapshot, CardDestination, CardPlan, DealtCard, SnapshotSeq, TableAtDealing,
};
use crate::ledger::types::{GameId, HandId, ShufflerId, StateHash};
use crate::shuffling::{ElGamalCiphertext, PlayerAccessibleCiphertext};

/// Request emitted to shufflers when they must contribute shares for a specific card.
#[derive(Clone, Debug)]
pub enum DealShufflerRequest<C: CurveGroup> {
    Player(PlayerCardShufflerRequest<C>),
    Board(BoardCardShufflerRequest<C>),
}

/// Player card contribution request (requires blinding + unblinding share).
#[derive(Clone, Debug)]
pub struct PlayerCardShufflerRequest<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub deal_index: u8,
    pub seat: SeatId,
    pub hole_index: u8,
    pub player_public_key: C,
    pub ciphertext: PlayerAccessibleCiphertext<C>,
}

/// Community card contribution request (requires community blinding share).
#[derive(Clone, Debug)]
pub struct BoardCardShufflerRequest<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub deal_index: u8,
    pub slot: BoardCardSlot,
    pub ciphertext: ElGamalCiphertext<C>,
}

/// Location of a community card within the board.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoardCardSlot {
    Flop(u8),
    Turn,
    River,
}

/// One-time signal indicating a hand has entered dealing.
#[derive(Clone, Debug)]
pub struct DealingPhaseStarted<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub shuffle_tip_hash: StateHash,
    pub shufflers: Vec<ShufflerId>,
    pub card_plan: CardPlan,
    pub assignments: BTreeMap<u8, DealtCard<C>>,
}

/// Abstraction over the transport used to fan signals out to shufflers.
#[async_trait]
pub trait ShufflerSignalRouter<C: CurveGroup>: Send + Sync {
    async fn broadcast_dealing_started(
        &self,
        shufflers: &[ShufflerId],
        signal: &DealingPhaseStarted<C>,
    ) -> Result<()>;

    async fn broadcast_deal_request(
        &self,
        shufflers: &[ShufflerId],
        request: &DealShufflerRequest<C>,
    ) -> Result<()>;
}

type DealLocator = u8;

/// Per-hand bookkeeping to ensure signals are emitted exactly once.
struct HandSignalState<C: CurveGroup> {
    /// Roster to notify on every signal.
    shufflers: Vec<ShufflerId>,
    /// Planned destination for each draw index (hole, board, burn, unused).
    card_plan: CardPlan,
    /// Draw indices that have already been announced.
    announced_cards: BTreeSet<DealLocator>,
    /// Prevents duplicate phase signals.
    dealing_started_emitted: bool,
    /// Last snapshot sequence processed for this hand.
    last_snapshot_seq: SnapshotSeq,
    /// Marker so the struct stays generic without storing curve data.
    _marker: PhantomData<C>,
}

impl<C: CurveGroup> HandSignalState<C> {
    fn new(shufflers: Vec<ShufflerId>, card_plan: CardPlan, sequence: SnapshotSeq) -> Self {
        Self {
            shufflers,
            card_plan,
            announced_cards: BTreeSet::new(),
            dealing_started_emitted: false,
            last_snapshot_seq: sequence,
            _marker: PhantomData,
        }
    }
}

/// Dispatcher that inspects snapshots and emits shuffler signals through the router.
pub struct ShufflerDealSignalDispatcher<C>
where
    C: CurveGroup,
{
    router: Arc<dyn ShufflerSignalRouter<C>>,
    hands: dashmap::DashMap<(GameId, HandId), HandSignalState<C>>,
    _hasher: Arc<dyn LedgerHasher + Send + Sync>,
    _marker: PhantomData<C>,
}

impl<C> ShufflerDealSignalDispatcher<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub fn new(
        router: Arc<dyn ShufflerSignalRouter<C>>,
        hasher: Arc<dyn LedgerHasher + Send + Sync>,
    ) -> Self {
        Self {
            router,
            hands: dashmap::DashMap::new(),
            _hasher: hasher,
            _marker: PhantomData,
        }
    }

    pub async fn observe_snapshot(&self, snapshot: &AnyTableSnapshot<C>) -> Result<()> {
        match snapshot {
            AnyTableSnapshot::Dealing(table) => self.handle_dealing_snapshot(table).await,
            AnyTableSnapshot::Preflop(table) => {
                if let Some(hand_id) = table.hand_id {
                    self.teardown_hand((table.game_id, hand_id));
                }
                Ok(())
            }
            AnyTableSnapshot::Flop(table) => {
                if let Some(hand_id) = table.hand_id {
                    self.teardown_hand((table.game_id, hand_id));
                }
                Ok(())
            }
            AnyTableSnapshot::Turn(table) => {
                if let Some(hand_id) = table.hand_id {
                    self.teardown_hand((table.game_id, hand_id));
                }
                Ok(())
            }
            AnyTableSnapshot::River(table) => {
                if let Some(hand_id) = table.hand_id {
                    self.teardown_hand((table.game_id, hand_id));
                }
                Ok(())
            }
            AnyTableSnapshot::Showdown(table) => {
                if let Some(hand_id) = table.hand_id {
                    self.teardown_hand((table.game_id, hand_id));
                }
                Ok(())
            }
            AnyTableSnapshot::Complete(table) => {
                if let Some(hand_id) = table.hand_id {
                    self.teardown_hand((table.game_id, hand_id));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn teardown_hand(&self, key: (GameId, HandId)) {
        self.hands.remove(&key);
    }

    async fn handle_dealing_snapshot(&self, table: &TableAtDealing<C>) -> Result<()> {
        let hand_id = table
            .hand_id
            .ok_or_else(|| anyhow!("dealing snapshot missing hand_id"))?;
        let key = (table.game_id, hand_id);

        let mut state_entry = self.ensure_hand_state(key, table)?;
        state_entry.card_plan = table.dealing.card_plan.clone();
        state_entry.shufflers = table.shufflers.iter().map(|(id, _)| *id).collect();
        let should_mark_phase_started = !state_entry.dealing_started_emitted;

        // Prepare optional phase-start signal.
        let maybe_phase_signal = if should_mark_phase_started {
            let signal = self.build_dealing_started(table, &state_entry)?;
            Some(signal)
        } else {
            None
        };

        // Collect new deal requests; they will be marked after successful dispatch.
        let (requests, new_indices) = self.collect_new_requests(table, &state_entry, hand_id)?;
        let shufflers = state_entry.shufflers.clone();
        drop(state_entry);

        if let Some(signal) = maybe_phase_signal {
            self.router
                .broadcast_dealing_started(&shufflers, &signal)
                .await?;
        }

        for request in &requests {
            self.router
                .broadcast_deal_request(&shufflers, request)
                .await?;
        }

        if let Some(mut state_entry) = self.hands.get_mut(&key) {
            if should_mark_phase_started {
                state_entry.dealing_started_emitted = true;
            }
            state_entry
                .announced_cards
                .extend(new_indices.into_iter());
            state_entry.last_snapshot_seq = table.sequence;
        }

        Ok(())
    }

    fn ensure_hand_state<'a>(
        &'a self,
        key: (GameId, HandId),
        table: &TableAtDealing<C>,
    ) -> Result<dashmap::mapref::one::RefMut<'a, (GameId, HandId), HandSignalState<C>>> {
        let shufflers: Vec<ShufflerId> = table.shufflers.iter().map(|(id, _)| *id).collect();
        let card_plan = table.dealing.card_plan.clone();
        Ok(self
            .hands
            .entry(key)
            .or_insert_with(|| HandSignalState::new(shufflers, card_plan, table.sequence)))
    }

    fn build_dealing_started(
        &self,
        table: &TableAtDealing<C>,
        state: &HandSignalState<C>,
    ) -> Result<DealingPhaseStarted<C>> {
        let hand_id = table
            .hand_id
            .ok_or_else(|| anyhow!("dealing snapshot missing hand_id"))?;
        Ok(DealingPhaseStarted {
            game_id: table.game_id,
            hand_id,
            shuffle_tip_hash: table.state_hash,
            shufflers: state.shufflers.clone(),
            card_plan: state.card_plan.clone(),
            assignments: table.dealing.assignments.clone(),
        })
    }

    fn collect_new_requests(
        &self,
        table: &TableAtDealing<C>,
        state: &HandSignalState<C>,
        hand_id: HandId,
    ) -> Result<(Vec<DealShufflerRequest<C>>, Vec<DealLocator>)> {
        let mut requests = Vec::new();
        let mut new_indices = Vec::new();

        for (deal_index, destination) in &state.card_plan {
            if state.announced_cards.contains(deal_index) {
                continue;
            }

            match destination {
                CardDestination::Hole { seat, hole_index } => {
                    let key = (*seat, *hole_index);
                    let ciphertext = match table.dealing.player_ciphertexts.get(&key) {
                        Some(ct) => ct.clone(),
                        None => continue,
                    };

                    let player_public_key = self.player_public_key_for_seat(table, *seat)?;

                    requests.push(self.build_player_request(
                        (table.game_id, hand_id),
                        *deal_index,
                        *seat,
                        *hole_index,
                        &ciphertext,
                        player_public_key,
                    )?);
                    new_indices.push(*deal_index);
                }
                CardDestination::Board { board_index } => {
                    if let Some(ct) = self.board_ciphertext(table, *deal_index)? {
                        let slot = board_slot_from_index(*board_index)
                            .ok_or_else(|| anyhow!("invalid board index {}", board_index))?;
                        requests.push(self.build_board_request(
                            (table.game_id, hand_id),
                            *deal_index,
                            slot,
                            &ct,
                        )?);
                        new_indices.push(*deal_index);
                    }
                }
                CardDestination::Burn | CardDestination::Unused => {
                    continue;
                }
            }
        }

        Ok((requests, new_indices))
    }

    fn build_player_request(
        &self,
        key: (GameId, HandId),
        deal_index: u8,
        seat: SeatId,
        hole_index: u8,
        ciphertext: &PlayerAccessibleCiphertext<C>,
        player_public_key: C,
    ) -> Result<DealShufflerRequest<C>> {
        Ok(DealShufflerRequest::Player(PlayerCardShufflerRequest {
            game_id: key.0,
            hand_id: key.1,
            deal_index,
            seat,
            hole_index,
            player_public_key,
            ciphertext: ciphertext.clone(),
        }))
    }

    fn build_board_request(
        &self,
        key: (GameId, HandId),
        deal_index: u8,
        board_slot: BoardCardSlot,
        ciphertext: &ElGamalCiphertext<C>,
    ) -> Result<DealShufflerRequest<C>> {
        Ok(DealShufflerRequest::Board(BoardCardShufflerRequest {
            game_id: key.0,
            hand_id: key.1,
            deal_index,
            slot: board_slot,
            ciphertext: ciphertext.clone(),
        }))
    }

    fn board_ciphertext(
        &self,
        table: &TableAtDealing<C>,
        deal_index: u8,
    ) -> Result<Option<ElGamalCiphertext<C>>> {
        Ok(table
            .dealing
            .assignments
            .get(&deal_index)
            .map(|assignment| assignment.cipher.clone()))
    }

    fn player_public_key_for_seat(&self, table: &TableAtDealing<C>, seat: SeatId) -> Result<C> {
        let player_id = table
            .seating
            .get(&seat)
            .copied()
            .flatten()
            .ok_or_else(|| anyhow!("no player seated at seat {}", seat))?;
        let identity = table
            .players
            .get(&player_id)
            .context("missing player identity for seated player")?;
        Ok(identity.public_key.clone())
    }
}

fn board_slot_from_index(index: u8) -> Option<BoardCardSlot> {
    match index {
        0..=2 => Some(BoardCardSlot::Flop(index)),
        3 => Some(BoardCardSlot::Turn),
        4 => Some(BoardCardSlot::River),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::snapshot::{AnyTableSnapshot, CardDestination};
    use crate::ledger::test_support::{
        fixture_dealing_snapshot, fixture_preflop_snapshot, fixture_shuffling_snapshot,
        FixtureContext,
    };
    use ark_bn254::G1Projective as Curve;
    use anyhow::anyhow;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Mutex;

    use crate::engine::nl::types::SeatId;
    use crate::ledger::snapshot::TableAtDealing;

    #[derive(Default)]
    struct MockRouter<C: CurveGroup> {
        dealing_started: Mutex<Vec<DealingPhaseStarted<C>>>,
        deal_requests: Mutex<Vec<DealShufflerRequest<C>>>,
    }

    #[async_trait]
    impl<C: CurveGroup> ShufflerSignalRouter<C> for MockRouter<C> {
        async fn broadcast_dealing_started(
            &self,
            _shufflers: &[ShufflerId],
            signal: &DealingPhaseStarted<C>,
        ) -> Result<()> {
            self.dealing_started.lock().await.push(signal.clone());
            Ok(())
        }

        async fn broadcast_deal_request(
            &self,
            _shufflers: &[ShufflerId],
            request: &DealShufflerRequest<C>,
        ) -> Result<()> {
            self.deal_requests.lock().await.push(request.clone());
            Ok(())
        }
    }

    struct FlakyRouter<C: CurveGroup> {
        dealing_started: Mutex<Vec<DealingPhaseStarted<C>>>,
        deal_requests: Mutex<Vec<DealShufflerRequest<C>>>,
        fail_next_dealing_started: AtomicBool,
        fail_next_request: AtomicBool,
    }

    impl<C: CurveGroup> FlakyRouter<C> {
        fn fail_request_once() -> Self {
            Self {
                dealing_started: Mutex::default(),
                deal_requests: Mutex::default(),
                fail_next_dealing_started: AtomicBool::new(false),
                fail_next_request: AtomicBool::new(true),
            }
        }
    }

    #[async_trait]
    impl<C: CurveGroup> ShufflerSignalRouter<C> for FlakyRouter<C> {
        async fn broadcast_dealing_started(
            &self,
            _shufflers: &[ShufflerId],
            signal: &DealingPhaseStarted<C>,
        ) -> Result<()> {
            if self
                .fail_next_dealing_started
                .swap(false, Ordering::SeqCst)
            {
                return Err(anyhow!("synthetic failure while broadcasting dealing start"));
            }
            self.dealing_started.lock().await.push(signal.clone());
            Ok(())
        }

        async fn broadcast_deal_request(
            &self,
            _shufflers: &[ShufflerId],
            request: &DealShufflerRequest<C>,
        ) -> Result<()> {
            if self.fail_next_request.swap(false, Ordering::SeqCst) {
                return Err(anyhow!("synthetic failure while broadcasting deal request"));
            }
            self.deal_requests.lock().await.push(request.clone());
            Ok(())
        }
    }

    fn first_active_seat<C: CurveGroup>(ctx: &FixtureContext<C>) -> SeatId {
        ctx.seating
            .iter()
            .find_map(|(&seat, player)| player.map(|_| seat))
            .expect("fixture must have an active seat")
    }

    fn isolate_cards<C: CurveGroup>(
        snapshot: &mut TableAtDealing<C>,
        selected: &[(u8, CardDestination)],
    ) {
        use std::collections::BTreeSet;

        let mut refs: BTreeSet<u8> = BTreeSet::new();
        let mut allowed_holes: BTreeSet<(SeatId, u8)> = BTreeSet::new();

        for (card_ref, destination) in selected {
            refs.insert(*card_ref);
            if let CardDestination::Hole { seat, hole_index } = destination {
                allowed_holes.insert((*seat, *hole_index));
            }
        }

        snapshot.dealing.card_plan.clear();
        for (card_ref, destination) in selected {
            snapshot
                .dealing
                .card_plan
                .insert(*card_ref, destination.clone());
        }

        snapshot
            .dealing
            .assignments
            .retain(|card_ref, _| refs.contains(card_ref));
        snapshot
            .dealing
            .player_ciphertexts
            .retain(|key, _| allowed_holes.contains(key));
    }

    fn isolate_player_card<C: CurveGroup>(
        snapshot: &mut TableAtDealing<C>,
        card_ref: u8,
        seat: SeatId,
        hole_index: u8,
    ) {
        isolate_cards(
            snapshot,
            &[(card_ref, CardDestination::Hole { seat, hole_index })],
        );
    }

    fn isolate_board_card<C: CurveGroup>(
        snapshot: &mut TableAtDealing<C>,
        card_ref: u8,
        board_index: u8,
    ) {
        isolate_cards(
            snapshot,
            &[(card_ref, CardDestination::Board { board_index })],
        );
    }

    #[tokio::test]
    async fn emits_phase_started_once() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[0]);
        let mut snapshot = fixture_dealing_snapshot(&ctx);
        let seat = first_active_seat(&ctx);
        isolate_player_card(&mut snapshot, 1, seat, 0);

        let router = Arc::new(MockRouter::<Curve>::default());
        let dispatcher = ShufflerDealSignalDispatcher::new(
            router.clone() as Arc<dyn ShufflerSignalRouter<Curve>>,
            Arc::clone(&ctx.hasher),
        );

        let any_snapshot = AnyTableSnapshot::Dealing(snapshot.clone());
        dispatcher.observe_snapshot(&any_snapshot).await.unwrap();
        dispatcher.observe_snapshot(&any_snapshot).await.unwrap();

        assert_eq!(
            router.dealing_started.lock().await.len(),
            1,
            "phase signal should emit once"
        );
    }

    #[tokio::test]
    async fn emits_player_request_for_new_ciphertext() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[0]);
        let mut snapshot = fixture_dealing_snapshot(&ctx);
        let seat = first_active_seat(&ctx);
        isolate_player_card(&mut snapshot, 1, seat, 0);

        let router = Arc::new(MockRouter::<Curve>::default());
        let dispatcher = ShufflerDealSignalDispatcher::new(
            router.clone() as Arc<dyn ShufflerSignalRouter<Curve>>,
            Arc::clone(&ctx.hasher),
        );

        dispatcher
            .observe_snapshot(&AnyTableSnapshot::Dealing(snapshot))
            .await
            .unwrap();

        let requests = router.deal_requests.lock().await;
        assert_eq!(requests.len(), 1, "expected one player request");
        match &requests[0] {
            DealShufflerRequest::Player(req) => {
                assert_eq!(req.seat, seat);
                assert_eq!(req.hole_index, 0);
                assert_eq!(req.deal_index, 1);
            }
            _ => panic!("expected player request"),
        }
    }

    #[tokio::test]
    async fn suppresses_duplicate_player_requests() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[0]);
        let mut snapshot = fixture_dealing_snapshot(&ctx);
        let seat = first_active_seat(&ctx);
        isolate_player_card(&mut snapshot, 1, seat, 0);

        let router = Arc::new(MockRouter::<Curve>::default());
        let dispatcher = ShufflerDealSignalDispatcher::new(
            router.clone() as Arc<dyn ShufflerSignalRouter<Curve>>,
            Arc::clone(&ctx.hasher),
        );

        let any_snapshot = AnyTableSnapshot::Dealing(snapshot.clone());
        dispatcher.observe_snapshot(&any_snapshot).await.unwrap();
        dispatcher.observe_snapshot(&any_snapshot).await.unwrap();

        let requests = router.deal_requests.lock().await;
        assert_eq!(
            requests.len(),
            1,
            "duplicate observation should not create extra requests"
        );
    }

    #[tokio::test]
    async fn emits_board_request_for_flop_card() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[0]);
        let mut snapshot = fixture_dealing_snapshot(&ctx);
        // First flop card lives at card_ref 8 in the default plan.
        isolate_board_card(&mut snapshot, 8, 0);

        let router = Arc::new(MockRouter::<Curve>::default());
        let dispatcher = ShufflerDealSignalDispatcher::new(
            router.clone() as Arc<dyn ShufflerSignalRouter<Curve>>,
            Arc::clone(&ctx.hasher),
        );

        dispatcher
            .observe_snapshot(&AnyTableSnapshot::Dealing(snapshot))
            .await
            .unwrap();

        let requests = router.deal_requests.lock().await;
        assert_eq!(requests.len(), 1, "expected one board request");
        match &requests[0] {
            DealShufflerRequest::Board(req) => {
                assert_eq!(req.deal_index, 8);
                assert!(matches!(req.slot, BoardCardSlot::Flop(0)));
            }
            _ => panic!("expected board request"),
        }
    }

    #[tokio::test]
    async fn emits_incremental_requests_for_new_cards() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[0]);
        let full = fixture_dealing_snapshot(&ctx);

        let dest1 = full.dealing.card_plan.get(&1).expect("card 1").clone();
        let dest2 = full.dealing.card_plan.get(&2).expect("card 2").clone();

        let mut first = full.clone();
        isolate_cards(&mut first, &[(1, dest1.clone())]);

        let mut second = full.clone();
        isolate_cards(&mut second, &[(1, dest1), (2, dest2.clone())]);

        let router = Arc::new(MockRouter::<Curve>::default());
        let dispatcher = ShufflerDealSignalDispatcher::new(
            router.clone() as Arc<dyn ShufflerSignalRouter<Curve>>,
            Arc::clone(&ctx.hasher),
        );

        dispatcher
            .observe_snapshot(&AnyTableSnapshot::Dealing(first))
            .await
            .unwrap();
        dispatcher
            .observe_snapshot(&AnyTableSnapshot::Dealing(second))
            .await
            .unwrap();

        let requests = router.deal_requests.lock().await;
        assert_eq!(
            requests.len(),
            2,
            "expected one request per new card across snapshots"
        );
    }

    #[tokio::test]
    async fn clears_state_when_hand_advances() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[0]);
        let mut snapshot = fixture_dealing_snapshot(&ctx);
        let seat = first_active_seat(&ctx);
        isolate_player_card(&mut snapshot, 1, seat, 0);

        let router = Arc::new(MockRouter::<Curve>::default());
        let dispatcher = ShufflerDealSignalDispatcher::new(
            router.clone() as Arc<dyn ShufflerSignalRouter<Curve>>,
            Arc::clone(&ctx.hasher),
        );

        dispatcher
            .observe_snapshot(&AnyTableSnapshot::Dealing(snapshot))
            .await
            .unwrap();

        let preflop = fixture_preflop_snapshot(&ctx);
        dispatcher
            .observe_snapshot(&AnyTableSnapshot::Preflop(preflop))
            .await
            .unwrap();

        assert!(
            dispatcher.hands.is_empty(),
            "hand state should be removed after leaving dealing"
        );
    }

    #[tokio::test]
    async fn non_dealing_snapshots_do_not_emit() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[0]);
        let router = Arc::new(MockRouter::<Curve>::default());
        let dispatcher = ShufflerDealSignalDispatcher::new(
            router.clone() as Arc<dyn ShufflerSignalRouter<Curve>>,
            Arc::clone(&ctx.hasher),
        );

        let shuffling = fixture_shuffling_snapshot(&ctx);
        dispatcher
            .observe_snapshot(&AnyTableSnapshot::Shuffling(shuffling))
            .await
            .unwrap();

        assert!(
            router.deal_requests.lock().await.is_empty()
                && router.dealing_started.lock().await.is_empty(),
            "non-dealing snapshots should not emit signals"
        );
    }

    #[tokio::test]
    async fn retries_after_router_error() {
        let ctx = FixtureContext::<Curve>::new(&[0, 1, 2], &[0]);
        let mut snapshot = fixture_dealing_snapshot(&ctx);
        let seat = first_active_seat(&ctx);
        isolate_player_card(&mut snapshot, 1, seat, 0);
        let snapshot_retry = snapshot.clone();

        let router = Arc::new(FlakyRouter::<Curve>::fail_request_once());
        let dispatcher = ShufflerDealSignalDispatcher::new(
            router.clone() as Arc<dyn ShufflerSignalRouter<Curve>>,
            Arc::clone(&ctx.hasher),
        );

        let first_attempt = dispatcher
            .observe_snapshot(&AnyTableSnapshot::Dealing(snapshot))
            .await;
        assert!(
            first_attempt.is_err(),
            "synthetic router failure should bubble up"
        );
        assert!(
            router.deal_requests.lock().await.is_empty(),
            "failed dispatch should not record requests"
        );

        dispatcher
            .observe_snapshot(&AnyTableSnapshot::Dealing(snapshot_retry))
            .await
            .expect("second observation should succeed after router recovers");

        let requests = router.deal_requests.lock().await;
        assert_eq!(
            requests.len(),
            1,
            "dispatcher should retry player request after router error"
        );
        let phases = router.dealing_started.lock().await;
        assert!(
            !phases.is_empty(),
            "dealing start should still be emitted despite earlier error"
        );
    }
}
