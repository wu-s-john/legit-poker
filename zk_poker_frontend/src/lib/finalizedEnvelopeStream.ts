import { Subject, type Observable } from 'rxjs';
import type { RealtimeChannel, RealtimeChannelState } from '@supabase/supabase-js';

import { finalizedEnvelopeSchema, type FinalizedAnyMessageEnvelope } from './finalizedEnvelopeSchema';
import { getSupabaseClient } from './supabaseClient';
import { mapRealtimeRowToFinalizedEnvelope } from './finalizedEnvelopeMapper';

export interface ListenHandlers {
  onStatusChange?: (status: RealtimeChannelState) => void;
  onError?: (error: unknown) => void;
}

export interface FinalizedEnvelopeStream {
  stream: Observable<FinalizedAnyMessageEnvelope>;
  unsubscribe: () => Promise<void>;
}

export function listenToGameFinalizedEnvelopes(
  gameId: number | string,
  handId: number | string,
  handlers: ListenHandlers = {}
): FinalizedEnvelopeStream {
  const supabase = getSupabaseClient();
  const subject = new Subject<FinalizedAnyMessageEnvelope>();

  const channel = supabase
    .channel(`events:game:${gameId}:hand:${handId}`)
    .on(
      'postgres_changes',
      { event: '*', schema: 'public', table: 'events', filter: `game_id=eq.${gameId},hand_id=eq.${handId}` },
      (payload) => {
        const record = payload.new ?? payload.old;
        if (!record) {
          return;
        }

        try {
          const candidate = mapRealtimeRowToFinalizedEnvelope(record);
          const parsed = finalizedEnvelopeSchema.safeParse(candidate);
          if (parsed.success) {
            subject.next(parsed.data);
          } else {
            handlers.onError?.(parsed.error);
            console.error('Failed to validate finalized envelope', parsed.error);
          }
        } catch (error) {
          handlers.onError?.(error);
          console.error('Failed to map finalized envelope', error);
        }
      }
    )
    .subscribe((status) => {
      handlers.onStatusChange?.(status);
      if (status === 'CHANNEL_ERROR') {
        subject.error(new Error('Supabase channel error'));
        return;
      }
      if (status === 'CLOSED') {
        subject.complete();
      }
    }) as RealtimeChannel;

  const unsubscribe = async () => {
    await supabase.removeChannel(channel);
    subject.complete();
  };

  return {
    stream: subject.asObservable(),
    unsubscribe,
  };
}
