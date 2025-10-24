// lib/console/schemas.ts

import { z } from "zod";

// ============================================================================
// Enums
// ============================================================================

export const EventPhaseSchema = z.enum([
  "Pending",
  "Shuffling",
  "Dealing",
  "Betting",
  "Reveals",
  "Showdown",
  "Complete",
  "Cancelled",
]);

export const SnapshotStatusSchema = z.union([
  z.literal("success"),
  z.object({ failure: z.string() }),
]);

export const HandStatusSchema = z.enum([
  "Pending",
  "Shuffling",
  "Dealing",
  "Betting",
  "Showdown",
  "Complete",
  "Cancelled",
]);

// ============================================================================
// Actor Schemas
// ============================================================================

export const PlayerActorSchema = z.object({
  Player: z.object({
    seat_id: z.number(),
    player_id: z.number(),
    player_key: z.string(),
  }),
});

export const ShufflerActorSchema = z.object({
  Shuffler: z.object({
    shuffler_id: z.number(),
    shuffler_key: z.string(),
  }),
});

export const NoneActorSchema = z.object({
  None: z.null(),
});

export const AnyActorSchema = z.union([
  PlayerActorSchema,
  ShufflerActorSchema,
  NoneActorSchema,
]);

// ============================================================================
// Message Type Schemas
// ============================================================================

export const GameShuffleMessageSchema = z.object({
  Shuffle: z.object({
    turn_index: z.number(),
    deck_in: z.array(z.unknown()),
    deck_out: z.array(z.unknown()),
    proof: z.unknown(),
  }),
});

export const GameBlindingDecryptionMessageSchema = z.object({
  Blinding: z.object({
    card_in_deck_position: z.number(),
    share: z.unknown(),
    target_player_public_key: z.string(),
  }),
});

export const GamePartialUnblindingShareMessageSchema = z.object({
  PartialUnblinding: z.object({
    card_in_deck_position: z.number(),
    share: z.unknown(),
    target_player_public_key: z.string(),
  }),
});

export const GamePlayerPreflopMessageSchema = z.object({
  PlayerPreflop: z.object({
    action: z.unknown(),
  }),
});

export const GamePlayerFlopMessageSchema = z.object({
  PlayerFlop: z.object({
    action: z.unknown(),
  }),
});

export const GamePlayerTurnMessageSchema = z.object({
  PlayerTurn: z.object({
    action: z.unknown(),
  }),
});

export const GamePlayerRiverMessageSchema = z.object({
  PlayerRiver: z.object({
    action: z.unknown(),
  }),
});

export const GameShowdownMessageSchema = z.object({
  Showdown: z.object({
    hole_cards: z.array(z.unknown()),
  }),
});

export const AnyGameMessageSchema = z.union([
  GameShuffleMessageSchema,
  GameBlindingDecryptionMessageSchema,
  GamePartialUnblindingShareMessageSchema,
  GamePlayerPreflopMessageSchema,
  GamePlayerFlopMessageSchema,
  GamePlayerTurnMessageSchema,
  GamePlayerRiverMessageSchema,
  GameShowdownMessageSchema,
]);

// ============================================================================
// Envelope Schemas
// ============================================================================

export const AnyMessageEnvelopeSchema = z.object({
  hand_id: z.number(),
  game_id: z.number(),
  message: z.object({
    value: AnyGameMessageSchema,
    signature: z.string().regex(/^0x[0-9a-fA-F]+$/, "Signature must be a hex string with 0x prefix"),
  }),
  actor: AnyActorSchema,
  nonce: z.number(),
  public_key: z.string(),
});

export const FinalizedAnyMessageEnvelopeSchema = z.object({
  envelope: AnyMessageEnvelopeSchema,
  snapshot_status: SnapshotStatusSchema,
  applied_phase: EventPhaseSchema,
  snapshot_sequence_id: z.number(),
  created_timestamp: z.number(), // Milliseconds since Unix epoch
});

// ============================================================================
// API Response Schema
// ============================================================================

export const HandMessagesResponseSchema = z.object({
  messages: z.array(FinalizedAnyMessageEnvelopeSchema),
  hand_id: z.number(),
  game_id: z.number(),
});

// ============================================================================
// Inferred TypeScript Types
// ============================================================================

export type EventPhase = z.infer<typeof EventPhaseSchema>;
export type SnapshotStatus = z.infer<typeof SnapshotStatusSchema>;
export type HandStatus = z.infer<typeof HandStatusSchema>;
export type AnyActor = z.infer<typeof AnyActorSchema>;
export type AnyGameMessage = z.infer<typeof AnyGameMessageSchema>;
export type AnyMessageEnvelope = z.infer<typeof AnyMessageEnvelopeSchema>;
export type FinalizedAnyMessageEnvelope = z.infer<
  typeof FinalizedAnyMessageEnvelopeSchema
>;
export type HandMessagesResponse = z.infer<typeof HandMessagesResponseSchema>;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Safely parse and validate API response
 */
export function parseHandMessagesResponse(
  data: unknown,
): HandMessagesResponse {
  return HandMessagesResponseSchema.parse(data);
}

/**
 * Safely parse and validate a single message envelope
 */
export function parseFinalizedMessageEnvelope(
  data: unknown,
): FinalizedAnyMessageEnvelope {
  return FinalizedAnyMessageEnvelopeSchema.parse(data);
}

/**
 * Type guard to check if actor is a Player
 */
export function isPlayerActor(
  actor: AnyActor,
): actor is z.infer<typeof PlayerActorSchema> {
  return "Player" in actor;
}

/**
 * Type guard to check if actor is a Shuffler
 */
export function isShufflerActor(
  actor: AnyActor,
): actor is z.infer<typeof ShufflerActorSchema> {
  return "Shuffler" in actor;
}

/**
 * Type guard to check if message is a Shuffle message
 */
export function isShuffleMessage(
  message: AnyGameMessage,
): message is z.infer<typeof GameShuffleMessageSchema> {
  return "Shuffle" in message;
}

/**
 * Type guard to check if message is a Blinding message
 */
export function isBlindingMessage(
  message: AnyGameMessage,
): message is z.infer<typeof GameBlindingDecryptionMessageSchema> {
  return "Blinding" in message;
}

/**
 * Type guard to check if message is a PartialUnblinding message
 */
export function isPartialUnblindingMessage(
  message: AnyGameMessage,
): message is z.infer<typeof GamePartialUnblindingShareMessageSchema> {
  return "PartialUnblinding" in message;
}
