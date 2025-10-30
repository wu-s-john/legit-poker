# Catchup Feature Test Tickets

## Infrastructure Tickets (Required First)

### INFRA-1: Create Message Builder Test Helper
**Priority**: P0 (Blocker)
**Estimated Effort**: 4 hours

**Description**:
Create a builder pattern helper for constructing test messages with minimal boilerplate. This is required before any catchup tests can be written.

**Tasks**:
- [ ] Create `src/ledger/test_support/message_builder.rs`
- [ ] Implement `TestMessageBuilder` struct
- [ ] Add methods: `actor()`, `sequence()`, `nonce()`, `game_id()`, `hand_id()`
- [ ] Add message-specific methods: `shuffle_message()`, `blinding_message()`, `player_message()`
- [ ] Add `sign()` method that generates valid signatures
- [ ] Add `build()` method that produces `AnyMessageEnvelope<C>`
- [ ] Add doc comments with usage examples

**Acceptance Criteria**:
- Can create a valid GameShuffleMessage in <10 lines of code
- Builder validates required fields
- Messages produced pass signature verification
- Works with all message types (shuffle, blinding, player, showdown)

**Example API**:
```rust
let msg = TestMessageBuilder::new()
    .game_id(1)
    .hand_id(42)
    .sequence(11)
    .nonce(0)
    .actor_shuffler(shuffler_id, &shuffler_key)
    .shuffle_message(deck_in, deck_out, proof)
    .sign(&secret_key)
    .build();
```

---

### INFRA-2: Create Database Test Fixture
**Priority**: P0 (Blocker for integration tests)
**Estimated Effort**: 6 hours
**Depends on**: INFRA-1

**Description**:
Create utilities for setting up test databases with snapshots and messages. Required for all integration tests.

**Tasks**:
- [ ] Create `tests/support/database_fixture.rs`
- [ ] Implement `TestDatabase::new()` that creates temporary DB
- [ ] Add `with_snapshot()` method to insert snapshot
- [ ] Add `with_messages()` method to insert message sequence
- [ ] Add `with_hand()` method to set up complete hand state
- [ ] Implement automatic cleanup on drop
- [ ] Add connection pooling for parallel tests
- [ ] Add helper to verify database state

**Acceptance Criteria**:
- Creates isolated test database per test
- Cleans up automatically after test
- Can insert snapshots and messages in one call
- Supports async operations
- Works with parallel test execution

**Example API**:
```rust
let db = TestDatabase::new()
    .with_snapshot(hand_id, snapshot)
    .with_messages(hand_id, vec![msg1, msg2, msg3])
    .build()
    .await?;
```

---

### INFRA-3: Create Assertion Helpers
**Priority**: P1 (Nice to have)
**Estimated Effort**: 2 hours

**Description**:
Create custom assertion macros for common test patterns.

**Tasks**:
- [ ] Create `tests/support/assertions.rs`
- [ ] Implement `assert_snapshot_at_sequence!` macro
- [ ] Implement `assert_catchup_error!` macro with pattern matching
- [ ] Implement `assert_snapshot_phase!` macro
- [ ] Add helper to compare snapshots for equality
- [ ] Add helper to extract error details

**Acceptance Criteria**:
- Macros provide clear error messages on failure
- Work with common test patterns
- Include file/line information in failures

---

## Unit Test Tickets (src/ledger/catchup.rs)

### TEST-1: Empty Message Replay Test
**Priority**: P0
**Estimated Effort**: 1 hour
**Depends on**: INFRA-1

**Description**:
Test that `replay_messages` correctly handles an empty message list.

**Tasks**:
- [ ] Create test function `test_replay_messages_empty_list`
- [ ] Set up fixture snapshot using test_support
- [ ] Call replay_messages with empty vector
- [ ] Assert result is Ok
- [ ] Assert snapshot unchanged (same sequence)

**Acceptance Criteria**:
- Test passes
- Test is deterministic
- Clear failure messages if assertions fail

---

### TEST-2: Sequential Message Replay Test
**Priority**: P0
**Estimated Effort**: 3 hours
**Depends on**: INFRA-1

**Description**:
Test that `replay_messages` successfully applies multiple valid messages in sequence.

**Tasks**:
- [ ] Create test function `test_replay_messages_sequential`
- [ ] Create snapshot at sequence 10
- [ ] Create 3 valid messages with sequences 11, 12, 13 using message builder
- [ ] Call replay_messages
- [ ] Assert result is Ok
- [ ] Assert final sequence is 13
- [ ] Verify snapshot progressed through expected state changes

**Acceptance Criteria**:
- All 3 messages applied successfully
- Final snapshot has correct sequence number
- Snapshot state reflects all transitions

---

### TEST-3: Discontinuity Detection Test
**Priority**: P0
**Estimated Effort**: 2 hours
**Depends on**: INFRA-1

**Description**:
Test that `replay_messages` detects and reports sequence gaps.

**Tasks**:
- [ ] Create test function `test_replay_messages_discontinuity`
- [ ] Create snapshot at sequence 10
- [ ] Create messages with sequences 11, 12, 14 (missing 13)
- [ ] Call replay_messages
- [ ] Assert result is Err(CatchupError::Discontinuity)
- [ ] Assert error contains expected=13, found=14

**Acceptance Criteria**:
- Discontinuity detected at correct sequence number
- Error contains accurate expected/found values
- No panic or undefined behavior

---

### TEST-4: Invalid Message Rejection Test
**Priority**: P1
**Estimated Effort**: 3 hours
**Depends on**: INFRA-1

**Description**:
Test that replay_messages rejects messages with invalid signatures or proofs.

**Tasks**:
- [ ] Create test function `test_replay_messages_invalid_signature`
- [ ] Create valid snapshot
- [ ] Create message with invalid signature (wrong key)
- [ ] Call replay_messages
- [ ] Assert result is Err(CatchupError::TransitionFailed)
- [ ] Verify error message indicates signature failure

**Acceptance Criteria**:
- Invalid messages rejected
- Clear error indicating what failed (signature vs proof)
- No state corruption on failure

---

### TEST-5: Phase Mismatch Test
**Priority**: P1
**Estimated Effort**: 2 hours
**Depends on**: INFRA-1

**Description**:
Test that messages invalid for current phase are rejected.

**Tasks**:
- [ ] Create test function `test_apply_message_phase_mismatch`
- [ ] Create shuffling phase snapshot
- [ ] Create GamePlayerMessage (only valid in betting phases)
- [ ] Call apply_message_dispatch directly
- [ ] Assert result is Err with phase mismatch error

**Acceptance Criteria**:
- Phase mismatch detected
- Error indicates expected vs actual phase
- No state corruption

---

### TEST-6: Actor Validation Test
**Priority**: P1
**Estimated Effort**: 2 hours
**Depends on**: INFRA-1

**Description**:
Test that messages with wrong actor type are rejected.

**Tasks**:
- [ ] Create test function `test_apply_message_wrong_actor`
- [ ] Create dealing phase snapshot
- [ ] Create GamePartialUnblindingShareMessage with PlayerActor (should be ShufflerActor)
- [ ] Call apply_message_dispatch
- [ ] Assert result is Err with actor type mismatch

**Acceptance Criteria**:
- Wrong actor type detected
- Error indicates expected actor type
- No state corruption

---

## Integration Test Tickets (tests/integration/catchup_integration.rs)

### TEST-7: Full Database Catchup Flow
**Priority**: P0
**Estimated Effort**: 4 hours
**Depends on**: INFRA-1, INFRA-2

**Description**:
End-to-end test of catchup_hand_from_db with real database.

**Tasks**:
- [ ] Create test file `tests/integration/catchup_integration.rs`
- [ ] Create test function `test_catchup_from_database_full_flow`
- [ ] Set up test database with migrations
- [ ] Insert snapshot at sequence 0
- [ ] Insert 10 valid messages (sequences 1-10)
- [ ] Call catchup_hand_from_db
- [ ] Assert result is Ok
- [ ] Assert final sequence is 10
- [ ] Verify final state matches expectations

**Acceptance Criteria**:
- Complete catchup succeeds
- All messages applied
- Final state is correct
- Database cleaned up after test

---

### TEST-8: Catchup with No Gap
**Priority**: P1
**Estimated Effort**: 2 hours
**Depends on**: INFRA-1, INFRA-2

**Description**:
Test catchup when messages immediately follow snapshot.

**Tasks**:
- [ ] Create test function `test_catchup_no_gap`
- [ ] Set up database with snapshot at sequence 5
- [ ] Insert messages 6, 7, 8 (no gap)
- [ ] Call catchup_hand_from_db
- [ ] Assert successful replay
- [ ] Assert final sequence is 8

**Acceptance Criteria**:
- Seamless catchup with no errors
- Efficient database queries (check query count)

---

### TEST-9: Catchup with Large Gap
**Priority**: P1
**Estimated Effort**: 3 hours
**Depends on**: INFRA-1, INFRA-2

**Description**:
Test that catchup handles many messages efficiently.

**Tasks**:
- [ ] Create test function `test_catchup_large_gap`
- [ ] Set up database with snapshot at sequence 10
- [ ] Insert 100 messages (sequences 11-110)
- [ ] Call catchup_hand_from_db
- [ ] Assert successful replay
- [ ] Assert final sequence is 110
- [ ] Measure memory usage and execution time

**Acceptance Criteria**:
- Large replay completes successfully
- Reasonable performance (<5 seconds for 100 messages)
- Memory usage stays bounded

---

### TEST-10: No Snapshot Error Test
**Priority**: P0
**Estimated Effort**: 1 hour
**Depends on**: INFRA-2

**Description**:
Test error handling when no snapshot exists.

**Tasks**:
- [ ] Create test function `test_catchup_no_snapshot_error`
- [ ] Set up database with messages but no snapshot
- [ ] Call catchup_hand_from_db with from_sequence=None
- [ ] Assert result is Err
- [ ] Verify error message is clear

**Acceptance Criteria**:
- Appropriate error returned
- Error message indicates missing snapshot
- No panic

---

### TEST-11: Partial Catchup Test
**Priority**: P2
**Estimated Effort**: 2 hours
**Depends on**: INFRA-1, INFRA-2

**Description**:
Test catchup with from_sequence parameter.

**Tasks**:
- [ ] Create test function `test_catchup_partial_from_sequence`
- [ ] Set up database with snapshot at 10, messages 11-20
- [ ] Call catchup_hand_from_db with from_sequence=Some(15)
- [ ] Assert only messages 15-20 applied
- [ ] Verify correct starting state

**Acceptance Criteria**:
- Partial replay works correctly
- Messages before from_sequence ignored
- Final state is correct

---

### TEST-12: Database Discontinuity Detection
**Priority**: P0
**Estimated Effort**: 2 hours
**Depends on**: INFRA-1, INFRA-2

**Description**:
Integration test for detecting sequence gaps in database.

**Tasks**:
- [ ] Create test function `test_catchup_database_discontinuity`
- [ ] Set up database with snapshot at 10
- [ ] Insert messages 11, 12, 15 (missing 13, 14)
- [ ] Call catchup_hand_from_db
- [ ] Assert result is Err(CatchupError::Discontinuity)
- [ ] Verify error details

**Acceptance Criteria**:
- Database discontinuity detected
- Error indicates which sequence is missing
- No partial state corruption

---

### TEST-13: Empty Database Catchup
**Priority**: P2
**Estimated Effort**: 1 hour
**Depends on**: INFRA-2

**Description**:
Test catchup when only snapshot exists, no messages.

**Tasks**:
- [ ] Create test function `test_catchup_empty_no_messages`
- [ ] Set up database with only snapshot
- [ ] Call catchup_hand_from_db
- [ ] Assert result is Ok
- [ ] Assert returned snapshot matches stored snapshot

**Acceptance Criteria**:
- No-op catchup succeeds
- No errors or warnings
- Returned snapshot unchanged

---

### TEST-14: Concurrent Catchup Safety
**Priority**: P2
**Estimated Effort**: 3 hours
**Depends on**: INFRA-1, INFRA-2

**Description**:
Test that concurrent catchup operations are safe.

**Tasks**:
- [ ] Create test function `test_catchup_concurrent_safety`
- [ ] Set up database with snapshot and messages
- [ ] Spawn 5 async tasks calling catchup simultaneously
- [ ] Wait for all to complete
- [ ] Assert all results are Ok
- [ ] Assert all produce identical snapshots

**Acceptance Criteria**:
- Concurrent reads succeed
- No deadlocks or race conditions
- All results identical

---

### TEST-15: Message Deserialization Error
**Priority**: P1
**Estimated Effort**: 2 hours
**Depends on**: INFRA-2

**Description**:
Test handling of corrupted database messages.

**Tasks**:
- [ ] Create test function `test_catchup_corrupted_message`
- [ ] Set up database with valid snapshot
- [ ] Insert message with corrupted binary data
- [ ] Call catchup_hand_from_db
- [ ] Assert result is Err(CatchupError::MessageDeserialization)
- [ ] Verify error includes debugging info

**Acceptance Criteria**:
- Deserialization errors handled gracefully
- Error includes row/sequence information
- No panic

---

## Performance Test Tickets (tests/benchmarks/)

### PERF-1: Replay Performance Benchmark
**Priority**: P2
**Estimated Effort**: 3 hours
**Depends on**: INFRA-1

**Description**:
Benchmark message replay performance at different scales.

**Tasks**:
- [ ] Create `tests/benchmarks/catchup_bench.rs`
- [ ] Set up criterion benchmark harness
- [ ] Benchmark replay of 10 messages
- [ ] Benchmark replay of 100 messages
- [ ] Benchmark replay of 1000 messages
- [ ] Collect metrics: time, memory, CPU

**Acceptance Criteria**:
- Benchmarks run successfully
- Results tracked over time
- Linear scaling with message count

---

### PERF-2: Database Query Performance
**Priority**: P2
**Estimated Effort**: 2 hours
**Depends on**: INFRA-2

**Description**:
Benchmark database query efficiency.

**Tasks**:
- [ ] Create benchmark for database queries
- [ ] Measure query execution time
- [ ] Count number of queries issued
- [ ] Measure data transfer size
- [ ] Verify index usage

**Acceptance Criteria**:
- Single query loads all needed messages
- Query plan uses indexes
- Performance acceptable for production

---

## Summary

**Total Tickets**: 21
- Infrastructure: 3 tickets (12 hours)
- Unit Tests: 6 tickets (13 hours)
- Integration Tests: 9 tickets (20 hours)
- Performance Tests: 2 tickets (5 hours)
- **Total Estimated Effort**: ~50 hours

**Critical Path**:
1. INFRA-1 (Message Builder) - Blocks all tests
2. INFRA-2 (Database Fixture) - Blocks integration tests
3. TEST-1 through TEST-6 (Unit tests)
4. TEST-7 through TEST-15 (Integration tests)
5. PERF-1, PERF-2 (Performance tests)

**Recommended Order**:
1. Start with INFRA-1 (highest impact)
2. Implement TEST-1 (simplest) to validate infrastructure
3. Build INFRA-2 for integration tests
4. Complete remaining unit tests (TEST-2 through TEST-6)
5. Complete integration tests (TEST-7 through TEST-15)
6. Add performance benchmarks last (PERF-1, PERF-2)
