# Verify API Type Compatibility

Compare the Zod schemas in `zk_poker_frontend/src/lib/schemas/` with the Rust types used in the server API endpoints defined in `src/server/routes.rs`.

## Your Task

1. **Identify all API endpoints** in `src/server/routes.rs` and extract their request/response types
2. **Recursively trace all type definitions** in a depth-first manner:
   - Start with the top-level request/response types
   - For each struct field, find its type definition using Grep
   - Continue recursively until all primitive types are reached
   - Track visited types to avoid infinite recursion on circular references
3. **Build a complete type graph** for each endpoint showing all nested structures
4. **Read all Zod schemas** from `zk_poker_frontend/src/lib/schemas/`
5. **Compare the complete type hierarchies** field-by-field with the Zod schemas

## Type Discovery Strategy

For each type encountered:
- Use **Grep** to search for `pub struct TypeName` or `pub enum TypeName` across the codebase
- Read the file containing the definition
- Extract all fields and their types
- Recursively process each field type
- Pay attention to generic type parameters (e.g., `<C>`)
- Note `serde` annotations that affect JSON serialization:
  - `#[serde(rename = "...")]` - field name changes
  - `#[serde(flatten)]` - nested fields are flattened
  - `#[serde(skip)]` - field not serialized
  - `#[serde(skip_serializing_if = "...")]` - conditionally serialized
  - `#[serde(tag = "...")]` - enum tagging strategy
  - `#[serde(untagged)]` - untagged enum serialization

## Common Type Locations

- `src/server/dto.rs` - Top-level DTOs
- `src/ledger/snapshot.rs` - Snapshot types
- `src/ledger/messages.rs` - Message envelope types
- `src/ledger/types.rs` - Core domain types (GameId, HandId, etc.)
- `src/game/` - Game-related types
- Use Grep to find others as needed

## Compatibility Rules

- Rust `Option<T>` → Zod `.optional()` or `.nullable()`
- Rust `Vec<T>` → Zod `z.array(T)`
- Rust `String` → Zod `z.string()`
- Rust numeric types (u32, u64, i64, usize) → Zod `z.number()`
- Rust `bool` → Zod `z.boolean()`
- Rust struct → Zod `z.object({ ... })`
- Rust enum → Zod `z.union([...])` or `z.enum([...])` or discriminated union
- Rust type alias (e.g., `type GameId = i64`) → trace to underlying type
- Generic types like `<C: CurveGroup>` → check how they serialize (often custom)

## Output Format

For each endpoint, provide:

### 1. Endpoint Summary
```
Endpoint: GET /games/:game_id/hands/:hand_id/snapshot
Request: Path params (game_id, hand_id), Query params (include_messages)
Response Type: LatestSnapshotResponse<C>
Corresponding Zod Schema: tableSnapshotSchema (if exists)
```

### 2. Complete Type Hierarchy
```
LatestSnapshotResponse<C>
├── snapshot: AnyTableSnapshot<C>
│   ├── sequence: u32
│   ├── phase: GamePhase
│   │   └── (enum variants: PreFlop | Flop | Turn | River)
│   ├── deck: Vec<Card>
│   │   └── Card
│   │       ├── rank: Rank (enum)
│   │       └── suit: Suit (enum)
│   └── ...
└── messages: Option<Vec<FinalizedAnyMessageEnvelope<C>>>
    └── FinalizedAnyMessageEnvelope<C>
        ├── envelope: MessageEnvelope
        │   ├── game_id: GameId (type alias for i64)
        │   ├── hand_id: HandId (type alias for i64)
        │   └── sequence: u32
        └── ...
```

### 3. Comparison Result
```
Status: ✅ Compatible | ⚠️ Issues Found | ❌ Missing Schema

Issues Found:
- Field `snapshot.sequence` is `u32` in Rust but Zod expects `z.string()`
- Field `messages[].envelope.game_id` is `i64` (GameId) in Rust but missing in Zod
- Enum `GamePhase` has variant `PreFlop` in Rust but Zod has `pre_flop` (casing mismatch)
- Missing nested type `Card` in Zod schema
- Field `messages` uses `skip_serializing_if` in Rust (conditional) but required in Zod
```

## Process Steps

1. **Read** `src/server/routes.rs` to identify all endpoints
2. For each endpoint handler, extract the response type
3. **Grep** for the type definition (e.g., `"pub struct LatestSnapshotResponse"`)
4. **Read** the file containing the definition
5. Parse out all fields and their types
6. For each non-primitive field type, **Grep** and repeat from step 3
7. Keep a visited set to avoid circular references
8. **Read** all Zod schemas from `zk_poker_frontend/src/lib/schemas/`
9. Compare the complete Rust type tree with Zod schema structure
10. Report mismatches with full field paths

## Important Notes

- Pay special attention to serde annotations as they change the JSON shape
- Type aliases should be resolved to their underlying types
- Generic parameters like `<C>` often have custom serialization
- Enum serialization depends on serde attributes (tagged, untagged, etc.)
- Check both field names AND types for compatibility

## Success Criteria

The command should produce a comprehensive report showing:
- All endpoints analyzed
- Complete type hierarchies for each
- Specific mismatches between Rust and Zod types
- Recommended fixes for any incompatibilities found
