import { z } from 'zod';

import { finalizedEnvelopeSchema, hexString } from './finalizedEnvelopeSchema';

const cardIndexSchema = z.number().int().min(0).max(51);
const gameIdSchema = z.number().int().nonnegative();
const handIdSchema = z.number().int().nonnegative();
const seatIdSchema = z.number().int().min(0).max(255);

export const demoStreamEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('player_created'),
    gameId: gameIdSchema,
    seat: seatIdSchema,
    displayName: z.string().min(1),
    publicKey: hexString,
  }),
  z.object({
    type: z.literal('hand_created'),
    gameId: gameIdSchema,
    handId: handIdSchema,
    playerCount: z.number().int().min(1),
  }),
  finalizedEnvelopeSchema.extend({
    type: z.literal('game_event'),
  }),
  z.object({
    type: z.literal('community_decrypted'),
    gameId: gameIdSchema,
    handId: handIdSchema,
    cards: z.array(cardIndexSchema),
  }),
  z.object({
    type: z.literal('hole_cards_decrypted'),
    gameId: gameIdSchema,
    handId: handIdSchema,
    seat: seatIdSchema,
    cards: z.tuple([cardIndexSchema, cardIndexSchema]),
  }),
]);

export type DemoStreamEvent = z.infer<typeof demoStreamEventSchema>;
