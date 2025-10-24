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
  z.literal('Fold'),
  z.literal('Check'),
  z.literal('Call'),
  z.literal('AllIn'),
  z.object({
    BetTo: z.object({
      to: chips,
    }),
  }),
  z.object({
    RaiseTo: z.object({
      to: chips,
    }),
  }),
]);
export type PlayerBetAction = z.infer<typeof playerBetActionSchema>;

/**
 * Actor union for `AnyActor`.
 */
export const anyActorSchema = z.union([
  z.object({
    kind: z.literal('none'),
  }),
  z.object({
    kind: z.literal('player'),
    seatId: z.number().int().min(0).max(255),
    playerId: z.number().int().nonnegative(),
  }),
  z.object({
    kind: z.literal('shuffler'),
    shufflerId: z.number().int(),
  }),
]);
export type AnyActor = z.infer<typeof anyActorSchema>;

/**
 * Individual game message variants (serde-backed `AnyGameMessage`).
 * Hex-encoded fields correspond to serialized curve points/ciphertexts/proofs.
 */
const DECK_SIZE = 52 as const;

const shuffleMessageSchema = z.object({
  type: z.literal('shuffle'),
  turn_index: z.number().int().min(0).max(0xffff),
  deck_in: z.array(hexString).length(DECK_SIZE),
  deck_out: z.array(hexString).length(DECK_SIZE),
  proof: hexString,
});

const blindingMessageSchema = z.object({
  type: z.literal('blinding'),
  card_in_deck_position: z.number().int().min(0).max(255),
  share: hexString,
  target_player_public_key: hexString,
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
  handId: z.number().int().nonnegative(),
  gameId: z.number().int().nonnegative(),
  actor: anyActorSchema,
  nonce: z.number().int().nonnegative(),
  publicKey: hexString,
  message: withSignatureSchema,
});
export type AnyMessageEnvelope = z.infer<typeof anyMessageEnvelopeSchema>;

/**
 * Finalized envelope – mirrors `FinalizedAnyMessageEnvelope<C>` in Rust.
 */
export const finalizedEnvelopeSchema = z.object({
  envelope: anyMessageEnvelopeSchema,
  snapshotStatus: snapshotStatusSchema,
  appliedPhase: eventPhaseSchema,
  snapshotSequenceId: z.number().int().nonnegative(),
});
export type FinalizedAnyMessageEnvelope = z.infer<typeof finalizedEnvelopeSchema>;
