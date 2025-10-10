# Ledger Verifier Validation Logic

## Purpose

The ledger verifier decides whether an incoming `ActionEnvelope` can enter the
event queue. Responsibilities include signature checking, actor authorization,
phase/turn gating, structural validation, and basic crypto sanity so that the
ledger worker never processes malformed input.

## Inputs & Data Sources

- **ActionEnvelope<Sig, Pk, A, C>** received from the API.
- **LedgerState<C>** for the current table tip (`AnyTableSnapshot<C>`).
- **Nonce cache** (in-memory or backing store) tracking last accepted nonce per
  `(hand_id, entity_kind, entity_id)`.
- **Table configuration** (seating, shufflers, card plan, stacks) embedded in
  the snapshot.
- **Cryptographic utilities** provided by existing modules (transcript builder,
  signature scheme, Poseidon config, Chaum-Pedersen verification).

## Validation Flow

1. **Basic sanity**  
   - Ensure the `hand_id` exists and the hand is not already complete.

2. **Signature verification**  
   - Use `WithSignature::verify`; reject with `VerifyError::BadSignature` on
     failure.

3. **Actor authorization**  
   - Resolve player or shuffler from snapshot, compare registered public key.
   - Reject with `VerifyError::Unauthorized` if not found or mismatched.

4. **Nonce enforcement**  
   - Derive `NonceKey`; expect `submitted == last_nonce + 1`.
   - Reject stale or future submissions with `VerifyError::NonceConflict`.

5. **Phase gating**  
   - Map `AnyTableSnapshot` variant to allowed message types:
     - `Shuffling` → `GameShuffleMessage`
     - `Dealing` → blinding / unblinding messages
     - `PhaseBetting<Street>` → respective `GamePlayerMessage`
     - `PhaseShowdown` → `GameShowdownMessage`
     - `PhaseComplete` → reject all
   - Reject mismatches with `VerifyError::PhaseMismatch`.

6. **Turn/order validation**  
   - For betting streets, consult `snapshot.betting.state` to ensure the seat is
     the correct actor (or eligible pending seat) and status is `Active` /
     `AllIn` as appropriate. Reject improper actions with
     `VerifyError::InvalidMessage`.

7. **Message-specific invariants**  
   - **Shuffle**: enforce shuffler order, deck continuity.
   - **Blinding share**: card destination must be the actor’s hole card; prevent
     duplicates; validate Chaum-Pedersen proof with Poseidon.
   - **Partial unblinding**: duplicate `member_index` disallowed; card mapping
     must exist.
   - **Betting action**: consult `EngineNL::legal_actions`.
   - **Showdown**: hole ciphertext must match stored data; proofs must verify;
     card positions must align with `card_plan`.

8. **Optional state hash preview**  
   - Optionally pre-compute `hash_envelope` and ensure deterministic chaining
     before queue insertion (can be deferred to worker).

## Edge Cases

- Unknown actor (seat unoccupied, shuffler missing).
- Hand already complete.
- Replay/future nonce.
- Card plan mismatch (attempting to reveal burn/board card as hole).
- Crypto mismatch (proof/ciphertext tampering).
- Out-of-turn actions or folded/all-in players acting illegally.

## Implementation Notes

- Verifier should be pure/read-only; no mutations beyond reading ledger state
  and nonce cache.
- Factor helpers for actor lookup, phase gating, and card-plan resolution to
  keep `verify` readable.
- Return precise `VerifyError` variants for API translation.
- Provide metric hooks (`counter!`) for rejection reasons if desired.

## Testing Strategy

Unit tests will live alongside the verifier (`src/ledger/verifier.rs`) and use a
lightweight snapshot builder to fabricate table states.

### 1. rejects invalid signatures
- Create a valid envelope via signing helper.
- Flip signature bytes.
- Call `verify` and expect `Err(VerifyError::BadSignature)`.

### 2. rejects unauthorized actors
- Construct snapshot without actor registration (missing seat or mismatched key).
- Build envelope for that actor.
- Expect `Err(VerifyError::Unauthorized)`.

### 3. rejects phase/turn mismatches
- Tip snapshot in `AnyTableSnapshot::Shuffling`.
- Submit a `GamePlayerMessage`.
- Expect `Err(VerifyError::PhaseMismatch)`.

### 4. rejects stale/future nonces
- Seed nonce cache with `last_nonce`.
- Verify envelope with the same nonce and `last_nonce + 2`.
- Both should return `Err(VerifyError::NonceConflict)`.

### 5. catches malformed payloads
- Produce `GameBlindingDecryptionMessage` whose `card_in_deck_position`
  corresponds to a burn/board card.
- Expect `Err(VerifyError::InvalidMessage)`.

### 6. accepts valid envelopes
- Build consistent snapshot (phase, seating, card plan, stacks).
- Construct properly signed and authorized envelope for that phase.
- Expect `Ok(_)` from `verify`.

### 7. rejects out-of-turn betting
- Snapshot in `PhaseBetting<Street>` with `to_act` set to seat A.
- Submit action from seat B not in `pending_to_match`.
- Expect `Err(VerifyError::InvalidMessage)`.

### 8. rejects shuffler order violations
- Snapshot in `PhaseShuffling` with first shuffler already recorded.
- Resubmit another shuffle from the same shuffler.
- Expect `Err(VerifyError::InvalidMessage)`.

### 9. showdown proof/ciphertext mismatches
- Snapshot in `PhaseShowdown` with stored hole ciphertexts/proofs.
- Modify Chaum-Pedersen proof or ciphertext field in envelope.
- Expect `Err(VerifyError::InvalidMessage)`.

### 10. aggregation duplicates
- During `PhaseDealing`, capture existing blinding/unblinding share set.
- Submit envelope duplicating a shuffler/member index.
- Expect `Err(VerifyError::InvalidMessage)`.

Supplementary tests (optional):
- Property test for nonce monotonicity.
- Integration smoke test with `LedgerOperator` queue to ensure valid envelope
  flows end-to-end.

