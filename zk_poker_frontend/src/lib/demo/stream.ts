/**
 * Demo SSE stream connection
 */

import type { DemoStreamEvent, SSEMessage } from './events';
import { parseDemoEvent } from './events';

const API_BASE = process.env.NEXT_PUBLIC_BACKEND_SERVER_API_URL ?? 'http://localhost:4000';

export interface DemoStreamOptions {
  onEvent: (event: DemoStreamEvent) => void;
  onError?: (error: Error) => void;
  onComplete?: () => void;
}

/**
 * Connect to the demo SSE stream
 */
export function connectDemoStream(options: DemoStreamOptions): () => void {
  const { onEvent, onError, onComplete } = options;

  const eventSource = new EventSource(`${API_BASE}/games/demo/stream`);
  let isCompleted = false;

  // Handle all event types from the backend
  const eventTypes = [
    'player_created',
    'hand_created',
    'game_event',
    'community_decrypted',
    'card_decryptable',
    'hole_cards_decrypted',
    'hand_completed',
  ];

  eventTypes.forEach((eventType) => {
    eventSource.addEventListener(eventType, (e) => {
      const message: SSEMessage = {
        event: eventType,
        data: e.data,
      };

      console.log('[Demo Stream] Received event:', eventType);
      console.log('[Demo Stream] Raw data:', e.data);

      const event = parseDemoEvent(message);
      if (event) {
        console.log('[Demo Stream] Parsed event:', event);
        onEvent(event);

        // Close connection after hand_completed event
        if (event.type === 'hand_completed') {
          isCompleted = true;
          console.log('[Demo Stream] Demo hand completed, closing stream');
          eventSource.close();
          if (onComplete) {
            onComplete();
          }
        }
      } else {
        console.warn('[Demo Stream] Failed to parse event:', eventType, e.data);
      }
    });
  });

  eventSource.addEventListener('error', (e) => {
    // Don't log error if we already completed successfully
    if (!isCompleted) {
      console.error('[Demo Stream] Connection error:', e);
      if (onError) {
        onError(new Error('Stream connection error'));
      }
    }
  });

  // Connection opened
  eventSource.addEventListener('open', () => {
    console.log('[Demo Stream] Connection established successfully');
  });

  // Cleanup function
  return () => {
    eventSource.close();
    if (onComplete && !isCompleted) {
      onComplete();
    }
  };
}
