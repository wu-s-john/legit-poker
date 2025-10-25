import { z } from 'zod';

import { finalizedEnvelopeSchema, hexString } from './finalizedEnvelopeSchema';
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
    snapshot: tableSnapshotShufflingSchema,
  }),
  finalizedEnvelopeSchema.extend({
    type: z.literal('game_event'),
  }),
  z.object({
    type: z.literal('community_decrypted'),
    game_id: gameIdSchema,
    hand_id: handIdSchema,
    cards: z.array(cardSchema),
  }),
  z.object({
    type: z.literal('hole_cards_decrypted'),
    game_id: gameIdSchema,
    hand_id: handIdSchema,
    seat: seatIdSchema,
    cards: z.tuple([cardSchema, cardSchema]),
  }),
  z.object({
    type: z.literal('hand_completed'),
    game_id: gameIdSchema,
    hand_id: handIdSchema,
  }),
]);

export type DemoStreamEvent = z.infer<typeof demoStreamEventSchema>;
