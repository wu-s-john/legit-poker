import { z } from 'zod';
import { finalizedEnvelopeSchema } from './finalizedEnvelopeSchema';

export const handMessagesResponseSchema = z.object({
  game_id: z.number().int(),
  hand_id: z.number().int(),
  messages: z.array(finalizedEnvelopeSchema),
});

export type HandMessagesResponse = z.infer<typeof handMessagesResponseSchema>;
