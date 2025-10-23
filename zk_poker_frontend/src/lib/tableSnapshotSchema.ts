import { z } from 'zod';

import { hexString, playerBetActionSchema, snapshotStatusSchema } from './finalizedEnvelopeSchema';

const seatIdSchema = z.number().int().min(0).max(255);
const cardIndexSchema = z.number().int().min(0).max(51);
const chipAmountSchema = z.number().int().nonnegative();
const gameIdSchema = z.number().int();
const handIdSchema = z.number().int();
const stateHashSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/, 'expected 32-byte state hash hex');

const canonicalKeySchema = hexString;
const curvePointSchema = hexString;
const scalarHexSchema = hexString;

const playerStatusSchema = z.enum(['active', 'folded', 'all_in', 'sitting_out']);

const handCategorySchema = z.enum([
  'high_card',
  'one_pair',
  'two_pair',
  'three_of_a_kind',
  'straight',
  'flush',
  'full_house',
  'four_of_a_kind',
  'straight_flush',
]);

const normalizedActionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('fold') }),
  z.object({ type: z.literal('check') }),
  z.object({
    type: z.literal('call'),
    call_amount: chipAmountSchema,
    full_call: z.boolean(),
  }),
  z.object({
    type: z.literal('bet'),
    to: chipAmountSchema,
  }),
  z.object({
    type: z.literal('raise'),
    to: chipAmountSchema,
    raise_amount: chipAmountSchema,
    full_raise: z.boolean(),
  }),
  z.object({
    type: z.literal('all_in_as_call'),
    call_amount: chipAmountSchema,
    full_call: z.boolean(),
  }),
  z.object({
    type: z.literal('all_in_as_bet'),
    to: chipAmountSchema,
  }),
  z.object({
    type: z.literal('all_in_as_raise'),
    to: chipAmountSchema,
    raise_amount: chipAmountSchema,
    full_raise: z.boolean(),
  }),
]);

const actionLogEntrySchema = z.object({
  street: z.enum(['preflop', 'flop', 'turn', 'river']),
  seat: seatIdSchema,
  action: normalizedActionSchema,
  price_to_call_before: chipAmountSchema,
  current_bet_to_match_after: chipAmountSchema,
});

const handConfigSchema = z.object({
  stakes: z.object({
    small_blind: chipAmountSchema,
    big_blind: chipAmountSchema,
    ante: chipAmountSchema,
  }),
  button: seatIdSchema,
  small_blind_seat: seatIdSchema,
  big_blind_seat: seatIdSchema,
  check_raise_allowed: z.boolean(),
});

const playerStateSchema = z.object({
  seat: seatIdSchema,
  player_id: z.number().int().nonnegative().nullable(),
  stack: chipAmountSchema,
  committed_this_round: chipAmountSchema,
  committed_total: chipAmountSchema,
  status: playerStatusSchema,
  has_acted_this_round: z.boolean(),
});

const potSchema = z.object({
  amount: chipAmountSchema,
  eligible: z.array(seatIdSchema),
});

const potsSchema = z.object({
  main: potSchema,
  sides: z.array(potSchema),
});

const bettingStateSchema = z.object({
  street: z.enum(['preflop', 'flop', 'turn', 'river']),
  button: seatIdSchema,
  first_to_act: seatIdSchema,
  to_act: seatIdSchema,
  current_bet_to_match: chipAmountSchema,
  last_full_raise_amount: chipAmountSchema,
  last_aggressor: seatIdSchema.nullable(),
  voluntary_bet_opened: z.boolean(),
  players: z.array(playerStateSchema),
  pots: potsSchema,
  cfg: handConfigSchema,
  pending_to_match: z.array(seatIdSchema),
  betting_locked_all_in: z.boolean(),
  action_log: z.array(actionLogEntrySchema),
});

const bettingHistoryEntrySchema = z.object({
  street: z.enum(['preflop', 'flop', 'turn', 'river']),
  action: playerBetActionSchema,
});

const playerIdentitySchema = z.object({
  public_key: curvePointSchema,
  player_key: canonicalKeySchema,
  player_id: z.number().int().nonnegative(),
  nonce: z.number().int().nonnegative(),
  seat: seatIdSchema,
});

const shufflerIdentitySchema = z.object({
  public_key: curvePointSchema,
  shuffler_key: canonicalKeySchema,
  shuffler_id: z.number().int(),
  aggregated_public_key: curvePointSchema,
});

const playerStackInfoSchema = z.object({
  seat: seatIdSchema,
  player_key: canonicalKeySchema.nullable(),
  starting_stack: chipAmountSchema,
  committed_blind: chipAmountSchema,
  status: playerStatusSchema,
});

const chaumPedersenProofSchema = z.object({
  t_g: curvePointSchema,
  t_h: curvePointSchema,
  z: scalarHexSchema,
});

const elGamalCiphertextSchema = z.object({
  c1: curvePointSchema,
  c2: curvePointSchema,
});

const shuffleProofSchema = z.object({
  input_deck: z.array(elGamalCiphertextSchema),
  sorted_deck: z.array(
    z.object({
      ciphertext: elGamalCiphertextSchema,
      randomizer: scalarHexSchema,
    })
  ),
  rerandomization_values: z.array(scalarHexSchema),
});

const shufflingStepSchema = z.object({
  shuffler_public_key: curvePointSchema,
  proof: shuffleProofSchema,
});

const shufflingSnapshotSchema = z.object({
  initial_deck: z.array(elGamalCiphertextSchema).length(52),
  steps: z.array(shufflingStepSchema),
  final_deck: z.array(elGamalCiphertextSchema).length(52),
  expected_order: z.array(canonicalKeySchema),
});

const playerTargetedBlindingContributionSchema = z.object({
  blinding_base_contribution: curvePointSchema,
  blinding_combined_contribution: curvePointSchema,
  proof: chaumPedersenProofSchema,
});

const playerAccessibleCiphertextSchema = z.object({
  blinded_base: curvePointSchema,
  blinded_message_with_player_key: curvePointSchema,
  player_unblinding_helper: curvePointSchema,
  shuffler_proofs: z.array(chaumPedersenProofSchema),
});

const partialUnblindingShareSchema = z.object({
  share: curvePointSchema,
  member_key: canonicalKeySchema,
});

const communityDecryptionShareSchema = z.object({
  share: curvePointSchema,
  proof: chaumPedersenProofSchema,
  member_key: canonicalKeySchema,
});

const dealtCardSchema = z.object({
  cipher: elGamalCiphertextSchema,
  source_index: z.number().int().min(0).max(51).nullable(),
});

const cardDestinationSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('hole'),
    seat: seatIdSchema,
    hole_index: z.number().int().min(0).max(1),
  }),
  z.object({
    type: z.literal('board'),
    board_index: z.number().int().min(0).max(4),
  }),
  z.object({ type: z.literal('burn') }),
  z.object({ type: z.literal('unused') }),
]);

const dealingSnapshotSchema = z.object({
  assignments: z.array(
    z.object({
      key: z.number().int().min(0).max(255),
      value: dealtCardSchema,
    })
  ),
  player_ciphertexts: z.array(
    z.object({
      k1: seatIdSchema,
      k2: z.number().int().min(0).max(1),
      value: playerAccessibleCiphertextSchema,
    })
  ),
  player_blinding_contribs: z.array(
    z.object({
      k1: canonicalKeySchema,
      k2: seatIdSchema,
      k3: z.number().int().min(0).max(1),
      value: playerTargetedBlindingContributionSchema,
    })
  ),
  player_unblinding_shares: z.array(
    z.object({
      k1: seatIdSchema,
      k2: z.number().int().min(0).max(1),
      value: z.record(partialUnblindingShareSchema),
    })
  ),
  player_unblinding_combined: z.array(
    z.object({
      key: z.tuple([seatIdSchema, z.number().int().min(0).max(1)]),
      value: curvePointSchema,
    })
  ),
  community_decryption_shares: z.array(
    z.object({
      k1: canonicalKeySchema,
      k2: z.number().int().min(0).max(4),
      value: communityDecryptionShareSchema,
    })
  ),
  community_cards: z.array(
    z.object({
      key: z.number().int().min(0).max(4),
      value: cardIndexSchema,
    })
  ),
  card_plan: z.array(
    z.object({
      key: z.number().int().min(0).max(255),
      value: cardDestinationSchema,
    })
  ),
});

const bettingSnapshotSchema = z.object({
  state: bettingStateSchema,
  last_events: z.array(bettingHistoryEntrySchema),
});

const revealedHandSchema = z.object({
  hole: z.array(cardIndexSchema).length(2),
  hole_ciphertexts: z.array(playerAccessibleCiphertextSchema).length(2),
  best_five: z.array(cardIndexSchema).length(5),
  best_category: handCategorySchema,
  best_tiebreak: z.array(z.number().int().min(0).max(255)).length(5),
  best_score: z.number().int().nonnegative(),
});

const revealsSnapshotSchema = z.object({
  board: z.array(cardIndexSchema),
  revealed_holes: z.record(revealedHandSchema),
});

export const baseTableSnapshotSchema = z.object({
  game_id: gameIdSchema,
  hand_id: handIdSchema.nullable(),
  sequence: z.number().int().nonnegative(),
  cfg: handConfigSchema,
  shufflers: z.record(z.string(), shufflerIdentitySchema),
  players: z.record(z.string(), playerIdentitySchema),
  seating: z.record(z.string(), canonicalKeySchema.nullable()),
  stacks: z.record(z.string(), playerStackInfoSchema),
  previous_hash: stateHashSchema.nullable(),
  state_hash: stateHashSchema,
  status: snapshotStatusSchema,
});

export type BaseTableSnapshot = z.infer<typeof baseTableSnapshotSchema>;

export const tableSnapshotShufflingSchema = baseTableSnapshotSchema.extend({
  shuffling: shufflingSnapshotSchema,
  dealing: z.null(),
  betting: z.null(),
  reveals: z.null(),
});

export const tableSnapshotDealingSchema = baseTableSnapshotSchema.extend({
  shuffling: shufflingSnapshotSchema,
  dealing: dealingSnapshotSchema,
  betting: z.null(),
  reveals: z.null(),
});

export const tableSnapshotBettingSchema = baseTableSnapshotSchema.extend({
  shuffling: shufflingSnapshotSchema,
  dealing: dealingSnapshotSchema,
  betting: bettingSnapshotSchema,
  reveals: revealsSnapshotSchema,
});

export const tableSnapshotShowdownSchema = tableSnapshotBettingSchema;
export const tableSnapshotCompleteSchema = tableSnapshotBettingSchema;

const tableAtShufflingSchema = tableSnapshotShufflingSchema.extend({
  kind: z.literal('shuffling'),
});

const tableAtDealingSchema = tableSnapshotDealingSchema.extend({
  kind: z.literal('dealing'),
});

const tableAtPreflopSchema = tableSnapshotBettingSchema.extend({
  kind: z.literal('preflop'),
});

const tableAtFlopSchema = tableSnapshotBettingSchema.extend({
  kind: z.literal('flop'),
});

const tableAtTurnSchema = tableSnapshotBettingSchema.extend({
  kind: z.literal('turn'),
});

const tableAtRiverSchema = tableSnapshotBettingSchema.extend({
  kind: z.literal('river'),
});

const tableAtShowdownSchema = tableSnapshotShowdownSchema.extend({
  kind: z.literal('showdown'),
});

const tableAtCompleteSchema = tableSnapshotCompleteSchema.extend({
  kind: z.literal('complete'),
});

export const anyTableSnapshotSchema = z.discriminatedUnion('kind', [
  tableAtShufflingSchema,
  tableAtDealingSchema,
  tableAtPreflopSchema,
  tableAtFlopSchema,
  tableAtTurnSchema,
  tableAtRiverSchema,
  tableAtShowdownSchema,
  tableAtCompleteSchema,
]);

type AnyTableSnapshot = z.infer<typeof anyTableSnapshotSchema>;

const rawTableAtShufflingSchema = tableSnapshotShufflingSchema.omit({ kind: true });
const rawTableAtDealingSchema = tableSnapshotDealingSchema.omit({ kind: true });
const rawTablePostDealSchema = tableSnapshotBettingSchema.omit({ kind: true });

export const rawAnyTableSnapshotSchema = z.union([
  z.object({ shuffling: rawTableAtShufflingSchema }),
  z.object({ dealing: rawTableAtDealingSchema }),
  z.object({ preflop: rawTablePostDealSchema }),
  z.object({ flop: rawTablePostDealSchema }),
  z.object({ turn: rawTablePostDealSchema }),
  z.object({ river: rawTablePostDealSchema }),
  z.object({ showdown: rawTablePostDealSchema }),
  z.object({ complete: rawTablePostDealSchema }),
]);

export type RawAnyTableSnapshot = z.infer<typeof rawAnyTableSnapshotSchema>;

export const latestSnapshotResponseSchema = z.object({
  snapshot: anyTableSnapshotSchema,
});

const rawLatestSnapshotResponseSchema = z.object({
  snapshot: rawAnyTableSnapshotSchema,
});

export type LatestSnapshotResponse = z.infer<typeof latestSnapshotResponseSchema>;
export type RawLatestSnapshotResponse = z.infer<typeof rawLatestSnapshotResponseSchema>;

export function normalizeAnyTableSnapshot(raw: RawAnyTableSnapshot): AnyTableSnapshot {
  if ('shuffling' in raw) {
    return { kind: 'shuffling', ...raw.shuffling };
  }
  if ('dealing' in raw) {
    return { kind: 'dealing', ...raw.dealing };
  }
  if ('preflop' in raw) {
    return { kind: 'preflop', ...raw.preflop };
  }
  if ('flop' in raw) {
    return { kind: 'flop', ...raw.flop };
  }
  if ('turn' in raw) {
    return { kind: 'turn', ...raw.turn };
  }
  if ('river' in raw) {
    return { kind: 'river', ...raw.river };
  }
  if ('showdown' in raw) {
    return { kind: 'showdown', ...raw.showdown };
  }
  if ('complete' in raw) {
    return { kind: 'complete', ...raw.complete };
  }
  // runtime safeguard – should be unreachable if schema validated
  throw new Error('unrecognized snapshot variant');
}

export function parseLatestSnapshotResponse(input: unknown): LatestSnapshotResponse {
  const raw = rawLatestSnapshotResponseSchema.parse(input);
  const snapshot = normalizeAnyTableSnapshot(raw.snapshot);
  return latestSnapshotResponseSchema.parse({ snapshot });
}
