# Ledger Operator RFC

## Background
zkPoker needs a single authority that accepts signed game messages, enforces turn order, and produces an immutable history. This RFC specifies the ledger operator, message formats, queueing, verification rules, and Postgres persistence so any engineer can build or extend it.

## Goals
- Deterministic ordering of all player/shuffler messages per hand.
- Persist every accepted event before mutating in-memory state.
- Capture the sequence-0 snapshot (seating, stacks, shufflers) when a hand is created so crash recovery can replay from a known baseline.
- Provide simple APIs for submitting actions, reading hand state, and ending games.
- Keep codecs generic over `CurveGroup` so cryptographic proofs remain flexible.

## Non-Goals
- No streaming/WebSocket feeds in v1 (polling only).
- No historical snapshot archival beyond sequence-0; the system still rebuilds everything after the opening snapshot from the `events` log.
- No multi-worker sharding; a single ledger worker consumes the queue.

## Message Flow
1. Client submits `ActionEnvelope<Sig, Pk, Message, C>` over HTTP.
2. Verifier checks signature, nonce, turn legality, and message structure.
3. If verification passes, the message enters the single FIFO queue.
4. Ledger worker pops messages FIFO, inserts them into Postgres, applies them to the in-memory state, commits, and moves on.

## Nonce Definition
A nonce is a per-actor, per-hand sequence number. Each actor (player seat or shuffler) maintains its own `nonce`. The ledger enforces `nonce == last_nonce + 1`. A nonce lower than expected (replay) or higher than expected (future jump) is rejected with `409 Conflict`. Only one pending message per actor is allowed—new messages must replace the same nonce or wait until the actor’s turn advances.

## Rust Message Types
```rust
pub struct GamePlayerMessage<R, C> where R: Street + Clone, C: CurveGroup {
    pub street: R,
    pub action: PlayerBetAction,
}

pub struct GameShuffleMessage<C> where C: CurveGroup {
    pub deck_in: [ElGamalCiphertext<C>; DECK_SIZE],
    pub deck_out: [ElGamalCiphertext<C>; DECK_SIZE],
    pub proof: ShuffleProof<C>,
}

pub struct GameBlindingDecryptionMessage<C> where C: CurveGroup {
    pub card_in_deck_position: u8,
    pub share: PlayerTargetedBlindingContribution<C>,
}

pub struct GamePartialUnblindingShareMessage<C> where C: CurveGroup {
    pub card_in_deck_position: u8,
    pub share: PartialUnblindingShare<C>,
}

pub struct GameShowdownMessage<C> where C: CurveGroup {
    pub chaum_pedersen_proofs: [ChaumPedersenProof<C>; 2],
    pub card_in_deck_position: [u8; 2],
    pub hole_ciphertexts: [PlayerAccessibleCiphertext<C>; 2],
}

pub struct ActionEnvelope<Sig, Pk, A, C>
where
    A: GameMessage<C>,
    C: CurveGroup,
{
    pub public_key: Pk,
    pub actor: ActorKind,
    pub nonce: u64,
    pub signed_message: WithSignature<Sig, A>,
}

pub struct VerifiedEnvelope<C>
where
    C: CurveGroup,
{
    pub key: NonceKey,
    pub nonce: u64,
    pub phase: HandStatus,
    pub message: LedgerMessage<C>,
    pub raw: ActionEnvelope<SignatureBytes, PublicKey, LedgerMessage<C>, C>,
}
```
Every message implements `GameMessage<C>` with its `PhaseIn`.

## Verifier Responsibilities
- **Signature**: Validate the `WithSignature` transcript using the provided public key.
- **Authorization**: Ensure the actor belongs to the game/hand.
- **Phase / Turn legality**: Confirm the message’s `PhaseIn` matches the hand’s current phase and that it is the actor’s turn.
- **Nonce progression**: Require `nonce == last_nonce + 1`; reject lower or higher values with `409 Conflict`.
- **Structural sanity**: Validate message-specific invariants (bet sizes, card indices, etc.).
- **Output**: Deserialize the payload into `LedgerMessage`, wrap it in a `VerifiedEnvelope`, and hand it to the queue only on success.

## Queue (Single Instance)
- Accepts only `VerifiedEnvelope`s from the verifier and stores them in FIFO order.
- Holds at most one pending message per actor in practice because nonces advance turn by turn.
- Provides `push`, `pop`, and `len` helpers; it performs no additional validation.
- No backpressure logic; the queue simply buffers verified actions for the single worker.

```rust
pub trait LedgerQueue<C>
where
    C: CurveGroup,
{
    fn push(&self, item: VerifiedEnvelope<C>) -> Result<(), QueueError>;
    async fn pop(&self) -> Option<VerifiedEnvelope<C>>;
    fn len(&self) -> usize;
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue closed")]
    Closed,
}

pub struct FifoLedgerQueue<C>
where
    C: CurveGroup,
{
    tx: tokio::sync::mpsc::Sender<VerifiedEnvelope<C>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<VerifiedEnvelope<C>>>,
}
```

## Worker Workflow
```
loop {
    if let Some(verified) = queue.pop().await {
        let mut tx = pool.begin().await?;
        let event_id = insert_event(&mut tx, &verified).await?;
        ledger.apply(&mut tx, event_id, &verified).await?;
        tx.commit().await?;
        ledger.advance_turn(verified.key);
    } else {
        break;
    }
}
```
- Persistence occurs before state mutation.
- On `apply` failure, roll back and drop the event.
- On startup, replay `events` ordered by `(hand_id, id)` to rebuild state.

### Initial Snapshot Persistence
- `commence_game` inserts the `hands`, `hand_player`, and `hand_shufflers` rows, then builds the sequence-0 `TableSnapshot`.
- The same SeaORM snapshot store code serialises the snapshot (including `player_stacks` JSON, shuffler roster, and phase hashes) and writes it to `table_snapshots`/`phases` inside the in-flight transaction.
- Only after the snapshot insert succeeds do we `txn.commit()` and call `state.upsert_snapshot` so both the database and in-memory state start from the exact baseline.
- Subsequent snapshots (sequence ≥ 1) are still persisted by the worker after each successful event application.

## Database Schema
```sql
create table players (
    id bigserial primary key,
    display_name text not null,
    public_key bytea not null unique,
    created_at timestamptz not null default now()
);

create table shufflers (
    id bigserial primary key,
    display_name text not null,
    public_key bytea not null unique,
    created_at timestamptz not null default now()
);

create type game_status as enum ('open','active','completed','archived');
create type hand_status as enum ('pending','shuffling','dealing','betting','showdown','complete','cancelled');

create table games (
    id bigserial primary key,
    created_at timestamptz not null default now(),
    host_player_id bigint not null references players(id),
    name text not null,
    currency text not null default 'chips',
    max_players smallint not null,
    small_blind bigint not null check (small_blind >= 0),
    big_blind bigint not null check (big_blind >= 0),
    ante bigint not null default 0 check (ante >= 0),
    rake_bps smallint not null default 0,
    status game_status not null default 'open'
);

create table game_players (
    game_id bigint not null references games(id) on delete cascade,
    player_id bigint not null references players(id),
    seat_preference smallint,
    joined_at timestamptz not null default now(),
    primary key (game_id, player_id)
);

create table game_shufflers (
    game_id bigint not null references games(id) on delete cascade,
    shuffler_id bigint not null references shufflers(id),
    public_key bytea not null,
    joined_at timestamptz not null default now(),
    primary key (game_id, shuffler_id)
);

create table hands (
    id bigserial primary key,
    game_id bigint not null references games(id) on delete cascade,
    created_at timestamptz not null default now(),
    hand_no bigint not null,
    button_seat smallint not null,
    small_blind_seat smallint not null,
    big_blind_seat smallint not null,
    deck_commitment bytea,
    status hand_status not null default 'pending',
    unique (game_id, hand_no)
);

create table hand_seating (
    hand_id bigint not null references hands(id) on delete cascade,
    seat smallint not null,
    player_id bigint not null,
    player_public_key bytea not null,
    starting_stack bigint not null check (starting_stack >= 0),
    primary key (hand_id, seat),
    unique (hand_id, player_id),
    foreign key (hand_id, player_id) references game_players(game_id, player_id) on delete cascade
);

create table hand_shufflers (
    hand_id bigint not null references hands(id) on delete cascade,
    shuffler_id bigint not null references shufflers(id),
    sequence smallint not null,
    primary key (hand_id, shuffler_id)
);

create table events (
    id bigserial primary key,
    hand_id bigint not null references hands(id) on delete cascade,
    entity_kind smallint not null,
    entity_id bigint not null,
    actor_kind smallint not null,
    seat_id smallint,
    shuffler_id smallint,
    public_key bytea not null,
    nonce bigint not null,
    phase hand_status not null,
    message_type text not null,
    payload jsonb not null,
    signature bytea not null,
    inserted_at timestamptz not null default now(),
    unique (hand_id, entity_kind, entity_id, nonce)
);

create index idx_hands_game_status on hands (game_id, status);
create index idx_events_hand_instant on events (hand_id, inserted_at);
create index idx_hand_seating_game_seat on hand_seating (hand_id, seat);
create index idx_hand_seating_game_player on hand_seating (hand_id, player_id);
```

`payload` stores `serde_json` for the tagged message enum; replay deserializes it back to concrete types.

## API Endpoints
- `POST /games/{game_id}/hands/{hand_id}/events`
  - Body: signed envelope JSON (actor, nonce, message, signature).
  - Responses: `202 Accepted { event_id }`, `409` on nonce conflict, `422` on phase/turn violation, `403/401` for auth failures.
- `GET /games/{game_id}/hands/current`
  - Returns metadata + latest HUD projection for the current hand.
- `GET /games/{game_id}/hands/{hand_id}/state`
  - Rebuilds or returns the current table snapshot for that hand.
- `POST /games/{game_id}/end`
  - Host-only; marks the game `completed` and cancels unfinished hands.

## Implementation Steps
1. Ship SQL migration for the tables/types/indexes above.
2. Define Rust enums (`GameStatus`, `HandStatus`, `ActorKind`, `LedgerMessage`).
3. Implement verifier enforcing signature, authorization, phase, and nonce rules.
4. Build the nonce queue module over Tokio `mpsc` with per-actor tracking.
5. Implement worker loop: `pop → insert event → apply → commit`.
6. Add startup replay to rebuild in-memory state.
7. Implement REST endpoints with host authorization.
8. Write the unit/integration tests listed below.

## Unit Tests to Cover
- `nonce_conflict_returns_409`: duplicate nonce is rejected.
- `invalid_signature_rejected`: forged signature fails verification.
- `out_of_turn_rejected`: message for wrong phase/actor returns `422`.
- `push_pop_fifo`: queue enforces nonce/phase and maintains FIFO ordering.
- `apply_failure_rolls_back`: forced failure keeps DB/state clean.
- `replay_matches_live_state`: scripted hand replay matches live state.
- `game_end_cancels_active_hands`: host endpoint updates statuses and cancels hands.

## Operational Notes
- Document integer mappings (e.g., `entity_kind`) alongside enums.
- No backpressure logic; the queue holds at most one message per actor.
- When a hand completes, optionally drop its nonce entry to free memory.
- Consider archiving old `events` rows once exported for analytics.

## Open Questions
- Do we need a system actor (`entity_kind = 2`) for admin events?
- Should we persist HUD projections later for faster reads?
- What overwrite semantics do we support for same-nonce resubmissions?

## Next Steps
1. Land the migration.
2. Scaffold message types, verifier, nonce queue, and worker loop.
3. Build REST endpoints + auth.
4. Write the specified tests.
5. Run an end-to-end scripted hand to validate behaviour.
