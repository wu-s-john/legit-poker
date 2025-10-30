# Catchup Feature Test Plan

## Overview
This document outlines the comprehensive test plan for the ledger catchup functionality. The catchup feature allows reconstructing hand state by replaying messages from a snapshot.

## Prerequisites for Testing
Before implementing these tests, the following test infrastructure improvements are needed:

1. **Test Helpers for Message Creation**
   - Helper to create valid signed messages with proper structure
   - Helper to create envelope wrappers with correct actor types
   - Builder pattern for constructing test messages with minimal boilerplate

2. **Test Database Utilities**
   - Helper to populate database with snapshot + messages
   - Helper to query and verify database state
   - Fixture for creating temporary test databases
   - Migration utilities for test schemas

3. **Mock/Test Implementations**
   - Mock snapshot store that can track calls
   - Mock hasher that can be deterministic
   - Test curve types that are faster to work with

## Unit Tests (src/ledger/catchup.rs)

### Test 1: Empty Message Replay
**Status**: Partially implemented (needs message creation helpers)

**What it tests**: replay_messages handles empty message list correctly

**Steps**:
1. Create a fixture snapshot at any phase (use test_support::fixture_shuffling_snapshot)
2. Create an empty message vector
3. Call replay_messages with the snapshot and empty messages
4. Assert result is Ok
5. Assert returned snapshot is unchanged (same sequence number)

**Success criteria**: Function returns Ok with original snapshot

### Test 2: Sequential Message Replay
**What it tests**: replay_messages successfully applies multiple valid messages in sequence

**Steps**:
1. Create a shuffling phase snapshot with sequence 10
2. Create 3 valid GameShuffleMessage envelopes with sequences 11, 12, 13
3. Each message should have valid proof, correct actor, incrementing nonces
4. Call replay_messages
5. Assert result is Ok
6. Assert final snapshot has sequence 13
7. Assert snapshot progressed through expected phases

**Success criteria**: Messages applied successfully, snapshot state matches expectations

### Test 3: Discontinuity Detection
**What it tests**: replay_messages detects missing sequence numbers

**Steps**:
1. Create a snapshot at sequence 10
2. Create messages with sequences: 11, 12, 14 (missing 13)
3. Call replay_messages
4. Assert result is Err(CatchupError::Discontinuity)
5. Assert error contains expected=13, found=14

**Success criteria**: Discontinuity error raised with correct details

### Test 4: Invalid Message Rejection
**What it tests**: replay_messages rejects messages with invalid signatures/proofs

**Steps**:
1. Create a valid snapshot
2. Create a message with valid structure but invalid signature
3. Call replay_messages
4. Assert result is Err(CatchupError::TransitionFailed)
5. Assert error message indicates signature/proof verification failure

**Success criteria**: Invalid message rejected with descriptive error

### Test 5: Phase Mismatch Detection
**What it tests**: apply_message_dispatch rejects messages not valid for current phase

**Steps**:
1. Create a shuffling phase snapshot
2. Create a GamePlayerMessage (only valid in betting phases)
3. Call apply_message_dispatch directly
4. Assert result is Err(CatchupError::TransitionFailed)
5. Assert error indicates phase mismatch

**Success criteria**: Phase mismatch detected and reported

### Test 6: Actor Validation
**What it tests**: Messages are rejected if actor type doesn't match message type

**Steps**:
1. Create a dealing phase snapshot
2. Create a GamePartialUnblindingShareMessage with PlayerActor (should be ShufflerActor)
3. Call apply_message_dispatch
4. Assert result is Err(CatchupError::TransitionFailed)
5. Assert error indicates actor type mismatch

**Success criteria**: Invalid actor type detected

## Integration Tests (tests/integration/catchup_integration.rs - new file)

### Test 7: Full Database Catchup Flow
**What it tests**: catchup_hand_from_db successfully reconstructs state from database

**Steps**:
1. Set up test database with migrations
2. Create a hand with initial snapshot at sequence 0
3. Insert snapshot into table_snapshots table
4. Create and insert 10 valid event messages (sequences 1-10) into events table
5. Call catchup_hand_from_db(hand_id, None, snapshot_store, conn, hasher)
6. Assert result is Ok
7. Assert final snapshot has sequence 10
8. Assert final snapshot state matches expected game state after 10 messages
9. Verify no messages were skipped by checking snapshot metadata

**Success criteria**: Complete reconstruction from database succeeds

### Test 8: Catchup with No Sequence Gap
**What it tests**: Catchup when database messages immediately follow snapshot

**Steps**:
1. Set up database with snapshot at sequence 5
2. Insert messages with sequences 6, 7, 8 (no gap)
3. Call catchup_hand_from_db
4. Assert successful replay
5. Assert final sequence is 8
6. Verify database queries were efficient (check logs)

**Success criteria**: Seamless catchup with no errors

### Test 9: Catchup with Large Gap
**What it tests**: Catchup handles many messages between snapshot and current state

**Steps**:
1. Set up database with snapshot at sequence 10
2. Insert 100 messages (sequences 11-110)
3. Call catchup_hand_from_db
4. Assert successful replay
5. Assert final sequence is 110
6. Assert memory usage is reasonable (check for message batching if implemented)

**Success criteria**: Large replay completes successfully

### Test 10: No Snapshot Error
**What it tests**: catchup_hand_from_db errors when no snapshot exists

**Steps**:
1. Set up database with messages but no snapshot
2. Call catchup_hand_from_db with from_sequence=None
3. Assert result is Err(CatchupError::SnapshotLoad or appropriate error)
4. Assert error message indicates no snapshot available

**Success criteria**: Appropriate error when no starting point exists

### Test 11: Partial Catchup with from_sequence
**What it tests**: catchup_hand_from_db respects from_sequence parameter

**Steps**:
1. Set up database with snapshot at sequence 10
2. Insert messages 11-20
3. Call catchup_hand_from_db with from_sequence=Some(15)
4. Assert result includes only messages 15-20
5. Assert starting snapshot sequence is validated

**Success criteria**: Partial replay works correctly

### Test 12: Database Discontinuity Detection
**What it tests**: Integration test for sequence gaps in database

**Steps**:
1. Set up database with snapshot at sequence 10
2. Insert messages: 11, 12, 15 (missing 13, 14)
3. Call catchup_hand_from_db
4. Assert result is Err(CatchupError::Discontinuity)
5. Assert error indicates expected=13, found=15

**Success criteria**: Database discontinuities detected

### Test 13: Empty Database Catchup
**What it tests**: Catchup when snapshot exists but no subsequent messages

**Steps**:
1. Set up database with only a snapshot, no messages
2. Call catchup_hand_from_db
3. Assert result is Ok
4. Assert returned snapshot matches the stored snapshot
5. Assert no errors or warnings logged

**Success criteria**: Graceful handling of no-op catchup

### Test 14: Concurrent Catchup Safety
**What it tests**: Multiple concurrent catchup operations don't interfere

**Steps**:
1. Set up database with snapshot and messages
2. Spawn 5 async tasks calling catchup_hand_from_db simultaneously for same hand
3. Wait for all tasks to complete
4. Assert all results are Ok
5. Assert all results produce identical final snapshots
6. Verify database locks work correctly

**Success criteria**: Concurrent reads are safe

### Test 15: Message Deserialization Error Handling
**What it tests**: Graceful handling of corrupted database messages

**Steps**:
1. Set up database with snapshot
2. Insert a message with corrupted binary data in events table
3. Call catchup_hand_from_db
4. Assert result is Err(CatchupError::MessageDeserialization)
5. Assert error includes row information for debugging

**Success criteria**: Deserialization errors handled gracefully

## Performance Tests (tests/benchmarks/catchup_bench.rs - new file)

### Benchmark 1: Replay Performance
**What it tests**: Time to replay various message counts

**Scenarios**:
- 10 messages
- 100 messages
- 1000 messages
- 10000 messages

**Metrics to collect**:
- Total time
- Time per message
- Memory allocation
- CPU usage

### Benchmark 2: Database Query Performance
**What it tests**: Database query efficiency

**Metrics**:
- Query execution time
- Number of queries issued
- Data transfer size
- Index usage

## Edge Cases & Error Conditions

### Edge Case 1: Maximum Sequence Number
Test behavior at i64::MAX sequence numbers

### Edge Case 2: Snapshot at Hand Start
Test when snapshot is at sequence 0 (hand initialization)

### Edge Case 3: Snapshot at Hand Complete
Test when snapshot is at final phase (hand complete)

### Edge Case 4: Unicode in Error Messages
Test error messages with non-ASCII characters are handled correctly

### Edge Case 5: Large Proof Data
Test messages with maximum-size proof data

## Test Infrastructure Needed (Priority Order)

1. **Message Builder Helper** (HIGH)
   ```rust
   TestMessageBuilder::new()
       .actor(ShufflerActor { ... })
       .sequence(11)
       .nonce(0)
       .shuffle_message(deck_in, deck_out)
       .sign(&key)
       .build()
   ```

2. **Database Test Fixture** (HIGH)
   ```rust
   TestDatabase::new()
       .with_snapshot(snapshot)
       .with_messages(vec![msg1, msg2, msg3])
       .build()
       .await
   ```

3. **Assertion Helpers** (MEDIUM)
   ```rust
   assert_snapshot_at_sequence!(snapshot, expected_seq);
   assert_catchup_error!(result, CatchupError::Discontinuity { .. });
   ```

4. **Mock Implementations** (MEDIUM)
   - InMemorySnapshotStore for unit tests
   - MockLedgerHasher for deterministic testing

5. **Test Data Generators** (LOW)
   - Generate valid game progressions
   - Random but valid message sequences

## Implementation Order

1. Build test infrastructure (message builders, database fixtures)
2. Implement unit tests 1-6
3. Implement integration tests 7-13
4. Add concurrent safety test (14)
5. Add error handling test (15)
6. Add performance benchmarks
7. Document any issues discovered during testing

## Notes

- Tests should be deterministic (use seeded RNGs)
- Each test should clean up database state
- Integration tests may need longer timeouts
- Consider adding property-based tests with proptest
- All tests should have clear failure messages
- Tests should not depend on each other's execution order
