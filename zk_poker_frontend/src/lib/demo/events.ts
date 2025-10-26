/**
 * Demo stream event types matching Rust backend DemoStreamEvent
 */

import type { Card } from '~/types/poker';

export interface DemoStreamEventBase {
  game_id: number;
  hand_id: number;
}

export interface PlayerCreatedEvent extends DemoStreamEventBase {
  type: 'player_created';
  seat: number;
  display_name: string;
  public_key: string;
}

export interface HandCreatedEvent extends DemoStreamEventBase {
  type: 'hand_created';
  player_count: number;
  snapshot: unknown; // TableAtShuffling - we don't need full typing for demo
}

export interface GameEvent extends DemoStreamEventBase {
  type: 'game_event';
  envelope: {
    hand_id: number;
    game_id: number;
    snapshot_sequence_id: number;
    applied_phase: string;
    snapshot_status: string;
    message: {
      type: string;
      value: unknown;
    };
  };
}

export interface CommunityDecryptedEvent extends DemoStreamEventBase {
  type: 'community_decrypted';
  cards: Card[];
}

export interface CardDecryptableEvent extends DemoStreamEventBase {
  type: 'card_decryptable';
  seat: number;
  card_position: number;
}

export interface HoleCardsDecryptedEvent extends DemoStreamEventBase {
  type: 'hole_cards_decrypted';
  seat: number;
  card_position: number;
  card: Card;
}

export interface HandCompletedEvent extends DemoStreamEventBase {
  type: 'hand_completed';
}

export type DemoStreamEvent =
  | PlayerCreatedEvent
  | HandCreatedEvent
  | GameEvent
  | CommunityDecryptedEvent
  | CardDecryptableEvent
  | HoleCardsDecryptedEvent
  | HandCompletedEvent;

/**
 * SSE message wrapper
 */
export interface SSEMessage {
  event: string;
  data: string;
}

/**
 * Parse SSE event data to DemoStreamEvent
 */
export function parseDemoEvent(message: SSEMessage): DemoStreamEvent | null {
  try {
    const event = JSON.parse(message.data) as DemoStreamEvent;
    return event;
  } catch (error) {
    console.error('Failed to parse demo event:', error);
    return null;
  }
}
