import { z } from 'zod';

/**
 * Helpers
 */
const HEX_STRING = /^(?:0x|\\x)?[0-9a-fA-F]+$/;
export const hexString = z.string().regex(HEX_STRING, 'expected hex-encoded string');
const byteVector = z
  .array(z.number().int().min(0).max(255))
  .optional()
  .default([]);
const chips = z.union([
  z.string().regex(/^\d+$/), // keep large integers safe if they exceed JS precision
  z.number().int().nonnegative(),
]);

/**
 * Event phase mirrors `EventPhase` in Rust.
 * Rust serializes these as snake_case variants.
 */
export const eventPhaseSchema = z.enum([
  'pending',
  'shuffling',
  'dealing',
  'betting',
  'reveals',
  'showdown',
  'complete',
  'cancelled',
]);
export type EventPhase = z.infer<typeof eventPhaseSchema>;

/**
 * Snapshot status mirrors `SnapshotStatus`.
 * Rust serializes as: "success" or {"failure": "reason"}
 */
export const snapshotStatusSchema = z.union([
  z.literal('success'),
  z.object({
    failure: z.string().min(1),
  }),
]);
export type SnapshotStatus = z.infer<typeof snapshotStatusSchema>;

/**
 * Player betting actions (`PlayerBetAction`).
 */
export const playerBetActionSchema = z.union([
  z.literal('fold'),
  z.literal('check'),
  z.literal('call'),
  z.literal('all_in'),
  z.object({
    bet_to: z.object({
      to: chips,
    }),
  }),
  z.object({
    raise_to: z.object({
      to: chips,
    }),
  }),
]);
export type PlayerBetAction = z.infer<typeof playerBetActionSchema>;

/**
 * Actor union for `AnyActor`.
 * Backend uses tagged enum format: {"player": {...}}, {"shuffler": {...}}, or "none"
 */
export const anyActorSchema = z.union([
  z.literal('none'),
  z.object({
    player: z.object({
      seat_id: z.number().int().min(0).max(255),
      player_id: z.number().int().nonnegative(),
    }),
  }),
  z.object({
    shuffler: z.object({
      shuffler_id: z.number().int(),
      shuffler_key: hexString,
    }),
  }),
]);
export type AnyActor = z.infer<typeof anyActorSchema>;

/**
 * Individual game message variants (serde-backed `AnyGameMessage`).
 * Hex-encoded fields correspond to serialized curve points/ciphertexts/proofs.
 */
const DECK_SIZE = 52 as const;

const elGamalCiphertextSchema = z.object({
  c1: hexString,
  c2: hexString,
});

const sortedCiphertextSchema = z.object({
  ciphertext: elGamalCiphertextSchema,
  randomizer: hexString,
});

const shuffleProofSchema = z.object({
  input_deck: z.array(elGamalCiphertextSchema).length(DECK_SIZE),
  sorted_deck: z.array(sortedCiphertextSchema).length(DECK_SIZE),
  rerandomization_values: z.array(hexString).length(DECK_SIZE),
});

const shuffleMessageSchema = z.object({
  type: z.literal('shuffle'),
  turn_index: z.number().int().min(0).max(0xffff),
  deck_in: z.array(elGamalCiphertextSchema).length(DECK_SIZE),
  deck_out: z.array(elGamalCiphertextSchema).length(DECK_SIZE),
  proof: shuffleProofSchema,
  _curve: z.null().optional(),
});

const blindingMessageSchema = z.object({
  type: z.literal('blinding'),
  card_in_deck_position: z.number().int().min(0).max(255),
  share: z.object({
    blinding_base_contribution: hexString,
    blinding_combined_contribution: hexString,
    proof: z.object({
      t_g: hexString,
      t_h: hexString,
      z: hexString,
    }),
  }),
  target_player_public_key: hexString,
  _curve: z.null().optional(),
});

const partialUnblindingMessageSchema = z.object({
  type: z.literal('partial_unblinding'),
  card_in_deck_position: z.number().int().min(0).max(255),
  share: hexString,
  target_player_public_key: hexString,
});

const playerPreflopMessageSchema = z.object({
  type: z.literal('player_preflop'),
  action: playerBetActionSchema,
});

const playerFlopMessageSchema = z.object({
  type: z.literal('player_flop'),
  action: playerBetActionSchema,
});

const playerTurnMessageSchema = z.object({
  type: z.literal('player_turn'),
  action: playerBetActionSchema,
});

const playerRiverMessageSchema = z.object({
  type: z.literal('player_river'),
  action: playerBetActionSchema,
});

const showdownMessageSchema = z.object({
  type: z.literal('showdown'),
  chaum_pedersen_proofs: z.array(hexString).length(2),
  card_in_deck_position: z.array(z.number().int().min(0).max(255)).length(2),
  hole_ciphertexts: z.array(hexString).length(2),
});

export const anyGameMessageSchema = z.discriminatedUnion('type', [
  shuffleMessageSchema,
  blindingMessageSchema,
  partialUnblindingMessageSchema,
  playerPreflopMessageSchema,
  playerFlopMessageSchema,
  playerTurnMessageSchema,
  playerRiverMessageSchema,
  showdownMessageSchema,
]);
export type AnyGameMessage = z.infer<typeof anyGameMessageSchema>;

/**
 * Signed payload wrapper (`WithSignature`).
 */
export const withSignatureSchema = z.object({
  value: anyGameMessageSchema,
  signature: hexString,
  transcript: byteVector,
});
export type WithSignature = z.infer<typeof withSignatureSchema>;

/**
 * Core envelope (`AnyMessageEnvelope`).
 */
export const anyMessageEnvelopeSchema = z.object({
  hand_id: z.number().int().nonnegative(),
  game_id: z.number().int().nonnegative(),
  actor: anyActorSchema,
  nonce: z.number().int().nonnegative(),
  public_key: hexString,
  message: withSignatureSchema,
});
export type AnyMessageEnvelope = z.infer<typeof anyMessageEnvelopeSchema>;

/**
 * Finalized envelope – mirrors `FinalizedAnyMessageEnvelope<C>` in Rust.
 */
export const finalizedEnvelopeSchema = z.object({
  hand_id: z.number().int().nonnegative(),
  game_id: z.number().int().nonnegative(),
  actor: anyActorSchema,
  nonce: z.number().int().nonnegative(),
  public_key: hexString,
  message: withSignatureSchema,
  snapshot_status: snapshotStatusSchema,
  applied_phase: eventPhaseSchema,
  snapshot_sequence_id: z.number().int().nonnegative(),
  created_timestamp: z.number().int().nonnegative(),
});
export type FinalizedAnyMessageEnvelope = z.infer<typeof finalizedEnvelopeSchema>;
