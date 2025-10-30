/**
 * Client-Side Deck Generation
 *
 * Generates a shuffled 52-card deck for demo display purposes.
 * Each demo session creates a new random shuffle.
 */

import type { Card, Suit, Rank } from '~/types/poker';

const SUITS: Suit[] = ['spades', 'hearts', 'diamonds', 'clubs'];
const RANKS: Rank[] = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];

/**
 * Generate ordered 52-card deck
 */
export function generateOrderedDeck(): Card[] {
  return SUITS.flatMap((suit) =>
    RANKS.map((rank) => ({ rank, suit }))
  );
}

/**
 * Fisher-Yates shuffle (for client display, not cryptographically secure)
 */
export function shuffleDeck(deck: Card[]): Card[] {
  const shuffled = [...deck];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

/**
 * Seeded PRNG for reproducible shuffles (testing only)
 */
class SeededRandom {
  private seed: number;

  constructor(seed: number = Date.now()) {
    this.seed = seed;
  }

  next(): number {
    // Linear congruential generator
    this.seed = (this.seed * 1664525 + 1013904223) % 2 ** 32;
    return this.seed / 2 ** 32;
  }

  nextInt(min: number, max: number): number {
    return Math.floor(this.next() * (max - min)) + min;
  }
}

/**
 * Seeded shuffle for testing
 */
export function shuffleDeckSeeded(seed: number): Card[] {
  const rng = new SeededRandom(seed);
  const deck = [...generateOrderedDeck()];

  for (let i = deck.length - 1; i > 0; i--) {
    const j = rng.nextInt(0, i + 1);
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }

  return deck;
}

/**
 * Get card at specific position in shuffled deck
 */
export function getCardAtPosition(position: number, shuffledDeck: Card[]): Card | undefined {
  if (position < 0 || position >= shuffledDeck.length) {
    return undefined;
  }
  return shuffledDeck[position];
}

/**
 * Card encoding (for reference)
 * Spades: 0-12, Hearts: 13-25, Diamonds: 26-38, Clubs: 39-51
 */
export function encodeCard(card: Card): number {
  const suitIndex = SUITS.indexOf(card.suit);
  const rankIndex = RANKS.indexOf(card.rank);
  return suitIndex * 13 + rankIndex;
}

/**
 * Decode card value to Card object
 */
export function decodeCard(value: number): Card | undefined {
  if (value < 0 || value >= 52) {
    return undefined;
  }
  const suitIndex = Math.floor(value / 13);
  const rankIndex = value % 13;
  return {
    suit: SUITS[suitIndex],
    rank: RANKS[rankIndex],
  };
}

/**
 * Convert numeric rank (2-14) to string rank ('2'-'A')
 * Backend sends ranks as numbers where 11=J, 12=Q, 13=K, 14=A
 */
export function rankToString(rank: number | string): Rank {
  // If already a string, return as-is
  if (typeof rank === 'string') {
    return rank as Rank;
  }

  // Convert numeric rank (2-14) to string
  if (rank < 2 || rank > 14) {
    throw new Error(`Invalid rank: ${rank}. Must be between 2 and 14.`);
  }

  return RANKS[rank - 2];
}
