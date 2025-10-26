/**
 * Demo State Management - Reducer pattern for demo orchestration
 */

import type { Card } from '~/types/poker';
import type { PlayerPosition } from './positioning';
import type { CardDecryptionState } from './cardState';
import type { FinalizedAnyMessageEnvelope } from '../schemas/finalizedEnvelopeSchema';

export interface DemoState {
  // Connection
  gameId: number | null;
  handId: number | null;
  viewerPublicKey: string | null;
  viewerSeat: number; // Always 0 for demo

  // Game Setup
  playerCount: number;
  playerPositions: PlayerPosition[];

  // Protocol Phase Tracking
  currentPhase: 'idle' | 'shuffling' | 'dealing' | 'complete';

  // Shuffle Progress (Phase 1)
  totalShuffleSteps: number;
  currentShuffleStep: number;

  // Card State (Phase 2)
  clientDeck: Card[]; // Fisher-Yates shuffled deck for display
  cards: Map<string, CardDecryptionState>; // Key: "seat_cardIndex"

  // Dealing Animation Queue
  dealQueue: Array<{
    seat: number;
    cardIndex: number;
    deckPosition: number;
  }>;

  // Gap Detection
  lastSeqId: number;
  pendingEvents: FinalizedAnyMessageEnvelope[];

  // UI State
  statusMessage: string;
  errorMessage: string | null;
}

export type DemoAction =
  | { type: 'INIT_GAME'; gameId: number; handId: number; publicKey: string | null; playerCount: number }
  | { type: 'SET_VIEWER_PUBLIC_KEY'; publicKey: string }
  | { type: 'START_SHUFFLE' }
  | { type: 'SHUFFLE_PROGRESS'; currentStep: number; totalSteps: number }
  | { type: 'SHUFFLE_COMPLETE' }
  | { type: 'START_DEALING'; clientDeck: Card[] }
  | { type: 'CARD_DEALT'; seat: number; cardIndex: number }
  | { type: 'BLINDING_SHARE_RECEIVED'; seat: number; cardIndex: number; fromSeat: number }
  | {
      type: 'PARTIAL_UNBLINDING_SHARE_RECEIVED';
      seat: number;
      cardIndex: number;
      fromSeat: number;
    }
  | { type: 'CARD_DECRYPTABLE'; seat: number; cardIndex: number }
  | { type: 'CARD_REVEALED'; seat: number; cardIndex: number; card: Card }
  | { type: 'HAND_COMPLETE' }
  | { type: 'UPDATE_STATUS'; message: string }
  | { type: 'SET_ERROR'; error: string | null }
  | { type: 'EVENT_PROCESSED'; seqId: number };

/**
 * Helper: Generate card key for Map lookup
 */
export function getCardKey(seat: number, cardIndex: number): string {
  return `${seat}_${cardIndex}`;
}

/**
 * Helper: Parse card key into seat and cardIndex
 */
export function parseCardKey(key: string): { seat: number; cardIndex: number } {
  const [seat, cardIndex] = key.split('_').map(Number);
  return { seat, cardIndex };
}

/**
 * Helper: Calculate shuffle progress percentage
 */
export function getShuffleProgress(state: DemoState): number {
  if (state.totalShuffleSteps === 0) return 0;
  return Math.round((state.currentShuffleStep / state.totalShuffleSteps) * 100);
}

/**
 * Helper: Get all cards for a specific seat
 */
export function getCardsForSeat(state: DemoState, seat: number): CardDecryptionState[] {
  const cards: CardDecryptionState[] = [];
  const entries = Array.from(state.cards.entries());
  for (const [key, cardState] of entries) {
    const parsed = parseCardKey(key);
    if (parsed.seat === seat) {
      cards.push(cardState);
    }
  }
  return cards.sort((a, b) => a.position - b.position);
}

/**
 * Helper: Check if all cards for viewer are revealed
 */
export function areViewerCardsRevealed(state: DemoState): boolean {
  const viewerCards = getCardsForSeat(state, state.viewerSeat);
  return viewerCards.length === 2 && viewerCards.every((c) => c.revealed);
}

/**
 * Initial state
 */
export const initialDemoState: DemoState = {
  gameId: null,
  handId: null,
  viewerPublicKey: null,
  viewerSeat: 0,

  playerCount: 7,
  playerPositions: [],

  currentPhase: 'idle',

  totalShuffleSteps: 0,
  currentShuffleStep: 0,

  clientDeck: [],
  cards: new Map(),

  dealQueue: [],

  lastSeqId: -1,
  pendingEvents: [],

  statusMessage: 'Initializing...',
  errorMessage: null,
};

/**
 * Demo state reducer
 */
export function demoReducer(state: DemoState, action: DemoAction): DemoState {
  switch (action.type) {
    case 'INIT_GAME':
      return {
        ...state,
        gameId: action.gameId,
        handId: action.handId,
        viewerPublicKey: action.publicKey,
        playerCount: action.playerCount,
        statusMessage: `Game ${action.gameId} initialized with ${action.playerCount} players`,
      };

    case 'SET_VIEWER_PUBLIC_KEY':
      return {
        ...state,
        viewerPublicKey: action.publicKey,
      };

    case 'START_SHUFFLE':
      return {
        ...state,
        currentPhase: 'shuffling',
        currentShuffleStep: 0,
        statusMessage: 'Starting shuffle protocol...',
      };

    case 'SHUFFLE_PROGRESS':
      return {
        ...state,
        currentShuffleStep: action.currentStep,
        totalShuffleSteps: action.totalSteps,
        statusMessage: `Shuffling deck: ${action.currentStep}/${action.totalSteps}`,
      };

    case 'SHUFFLE_COMPLETE':
      return {
        ...state,
        currentPhase: 'dealing',
        statusMessage: 'Shuffle complete! Preparing to deal cards...',
      };

    case 'START_DEALING': {
      // Initialize card state for all players (2 cards each)
      const newCards = new Map<string, CardDecryptionState>();
      for (let seat = 0; seat < state.playerCount; seat++) {
        for (let cardIndex = 0; cardIndex < 2; cardIndex++) {
          const key = getCardKey(seat, cardIndex);
          newCards.set(key, {
            position: cardIndex,
            targetPlayerPublicKey: state.viewerPublicKey ?? '', // Will be updated with actual keys
            targetPlayerSeat: seat,
            blindingShares: new Map(),
            partialUnblindingShares: new Map(),
            requiredSharesPerType: state.playerCount,
            revealed: false,
            isFlying: false,
            hasArrived: false,
          });
        }
      }

      return {
        ...state,
        clientDeck: action.clientDeck,
        cards: newCards,
        statusMessage: 'Dealing hole cards...',
      };
    }

    case 'CARD_DEALT': {
      const key = getCardKey(action.seat, action.cardIndex);
      const cardState = state.cards.get(key);

      if (!cardState) {
        return state;
      }

      return {
        ...state,
        statusMessage:
          action.seat === state.viewerSeat
            ? `Card ${action.cardIndex + 1} dealt to you`
            : `Card ${action.cardIndex + 1} dealt to Player ${action.seat}`,
      };
    }

    case 'BLINDING_SHARE_RECEIVED': {
      const key = getCardKey(action.seat, action.cardIndex);
      const cardState = state.cards.get(key);

      if (!cardState) {
        return state;
      }

      const newBlindingShares = new Map(cardState.blindingShares);
      newBlindingShares.set(action.fromSeat, `share_from_${action.fromSeat}`);

      const newCards = new Map(state.cards);
      newCards.set(key, {
        ...cardState,
        blindingShares: newBlindingShares,
      });

      return {
        ...state,
        cards: newCards,
        statusMessage:
          action.seat === state.viewerSeat
            ? `Collecting shares for your card ${action.cardIndex + 1}... (${newBlindingShares.size}/${cardState.requiredSharesPerType})`
            : state.statusMessage,
      };
    }

    case 'PARTIAL_UNBLINDING_SHARE_RECEIVED': {
      const key = getCardKey(action.seat, action.cardIndex);
      const cardState = state.cards.get(key);

      if (!cardState) {
        return state;
      }

      const newUnblindingShares = new Map(cardState.partialUnblindingShares);
      newUnblindingShares.set(action.fromSeat, `unblinding_share_from_${action.fromSeat}`);

      const newCards = new Map(state.cards);
      newCards.set(key, {
        ...cardState,
        partialUnblindingShares: newUnblindingShares,
      });

      return {
        ...state,
        cards: newCards,
        statusMessage:
          action.seat === state.viewerSeat
            ? `Collecting unblinding shares for card ${action.cardIndex + 1}... (${newUnblindingShares.size}/${cardState.requiredSharesPerType})`
            : state.statusMessage,
      };
    }

    case 'CARD_DECRYPTABLE': {
      const key = getCardKey(action.seat, action.cardIndex);
      const cardState = state.cards.get(key);

      if (!cardState) {
        return state;
      }

      return {
        ...state,
        statusMessage:
          action.seat === state.viewerSeat
            ? `Your card ${action.cardIndex + 1} is ready to reveal!`
            : state.statusMessage,
      };
    }

    case 'CARD_REVEALED': {
      const key = getCardKey(action.seat, action.cardIndex);
      const cardState = state.cards.get(key);

      if (!cardState) {
        return state;
      }

      const newCards = new Map(state.cards);
      newCards.set(key, {
        ...cardState,
        revealed: true,
        displayCard: action.card,
      });

      return {
        ...state,
        cards: newCards,
        statusMessage:
          action.seat === state.viewerSeat
            ? `Your card ${action.cardIndex + 1} revealed!`
            : state.statusMessage,
      };
    }

    case 'HAND_COMPLETE':
      return {
        ...state,
        currentPhase: 'complete',
        statusMessage: 'Hand complete!',
      };

    case 'UPDATE_STATUS':
      return {
        ...state,
        statusMessage: action.message,
      };

    case 'SET_ERROR':
      return {
        ...state,
        errorMessage: action.error,
      };

    case 'EVENT_PROCESSED':
      return {
        ...state,
        lastSeqId: Math.max(state.lastSeqId, action.seqId),
      };

    default:
      return state;
  }
}
