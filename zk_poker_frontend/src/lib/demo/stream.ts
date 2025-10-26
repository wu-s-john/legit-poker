/**
 * Demo SSE stream connection
 */

import type { DemoStreamEvent, SSEMessage } from './events';
import { parseDemoEvent } from './events';

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

  const eventSource = new EventSource('/api/demo/stream');

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

      const event = parseDemoEvent(message);
      if (event) {
        onEvent(event);
      }
    });
  });

  eventSource.addEventListener('error', (e) => {
    console.error('Demo stream error:', e);
    if (onError) {
      onError(new Error('Stream connection error'));
    }
  });

  // Connection opened
  eventSource.addEventListener('open', () => {
    console.log('Demo stream connected');
  });

  // Cleanup function
  return () => {
    eventSource.close();
    if (onComplete) {
      onComplete();
    }
  };
}
