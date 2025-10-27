import { z } from 'zod';

import {
  anyMessageEnvelopeSchema,
  eventPhaseSchema,
  snapshotStatusSchema,
  hexString,
} from './finalizedEnvelopeSchema';
import { tableSnapshotShufflingSchema } from './tableSnapshotSchema';

const gameIdSchema = z.number().int().nonnegative();
const handIdSchema = z.number().int().nonnegative();
const seatIdSchema = z.number().int().min(0).max(255);
const cardSchema = z.object({
  rank: z.number().int().min(2).max(14),
  suit: z.enum(['clubs', 'diamonds', 'hearts', 'spades']),
});

export const demoStreamEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('player_created'),
    game_id: gameIdSchema,
    seat: seatIdSchema,
    display_name: z.string().min(1),
    public_key: hexString,
  }),
  z.object({
    type: z.literal('hand_created'),
    game_id: gameIdSchema,
    hand_id: handIdSchema,
    player_count: z.number().int().min(1),
    shuffler_count: z.number().int().min(1),
    snapshot: tableSnapshotShufflingSchema,
  }),
  z.object({
    type: z.literal('game_event'),
    // Note: Rust uses #[serde(flatten)] on FinalizedAnyMessageEnvelope
    // This flattens the finalized fields to top level while envelope stays nested
    envelope: anyMessageEnvelopeSchema,
    snapshot_status: snapshotStatusSchema,
    applied_phase: eventPhaseSchema,
    snapshot_sequence_id: z.number().int().nonnegative(),
    created_timestamp: z.number().int().nonnegative(),
  }),
  z.object({
    type: z.literal('community_decrypted'),
    game_id: gameIdSchema,
    hand_id: handIdSchema,
    cards: z.array(cardSchema),
  }),
  z.object({
    type: z.literal('card_decryptable'),
    game_id: gameIdSchema,
    hand_id: handIdSchema,
    seat: seatIdSchema,
    card_position: z.number().int().min(0).max(1),
  }),
  z.object({
    type: z.literal('hole_cards_decrypted'),
    game_id: gameIdSchema,
    hand_id: handIdSchema,
    seat: seatIdSchema,
    card_position: z.number().int().min(0).max(1),
    card: cardSchema,
  }),
  z.object({
    type: z.literal('hand_completed'),
    game_id: gameIdSchema,
    hand_id: handIdSchema,
  }),
]);

export type DemoStreamEvent = z.infer<typeof demoStreamEventSchema>;
