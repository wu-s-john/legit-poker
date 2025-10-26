/**
 * Hand Labeling - Poker hand quality descriptions
 */

import type { Card, Rank, Suit } from '~/types/poker';

const RANK_ORDER: Rank[] = ['A', 'K', 'Q', 'J', '10', '9', '8', '7', '6', '5', '4', '3', '2'];

const SUIT_SYMBOLS: Record<Suit, string> = {
  spades: '♠',
  hearts: '♥',
  diamonds: '♦',
  clubs: '♣',
};

export interface HandLabel {
  label: string;
  emoji: string;
  tier: 'premium' | 'strong' | 'playable' | 'marginal';
}

export function labelHand(card1: Card, card2: Card): HandLabel {
  // Sort by rank (higher first)
  const [high, low] = [card1, card2].sort(
    (a, b) => RANK_ORDER.indexOf(a.rank) - RANK_ORDER.indexOf(b.rank)
  );

  const suited = high.suit === low.suit;
  const pair = high.rank === low.rank;

  // Premium hands
  if (pair && high.rank === 'A') {
    return {
      label: '🚀 Pocket Aces - Best starting hand!',
      emoji: '🚀',
      tier: 'premium',
    };
  }

  if (pair && high.rank === 'K') {
    return {
      label: '👑 Pocket Kings - Premium hand!',
      emoji: '👑',
      tier: 'premium',
    };
  }

  if (high.rank === 'A' && low.rank === 'K' && suited) {
    return {
      label: '✨ Ace-King suited - Premium hand!',
      emoji: '✨',
      tier: 'premium',
    };
  }

  // Strong hands
  if (pair && high.rank === 'Q') {
    return {
      label: '💎 Pocket Queens - Strong hand!',
      emoji: '💎',
      tier: 'strong',
    };
  }

  if (high.rank === 'A' && low.rank === 'K') {
    return {
      label: '🎯 Ace-King - Strong hand!',
      emoji: '🎯',
      tier: 'strong',
    };
  }

  if (pair && ['J', '10'].includes(high.rank)) {
    return {
      label: `🎲 Pocket ${high.rank}s`,
      emoji: '🎲',
      tier: 'strong',
    };
  }

  // Pairs
  if (pair) {
    return {
      label: `🎲 Pocket ${high.rank}s`,
      emoji: '🎲',
      tier: 'playable',
    };
  }

  // Suited
  if (suited) {
    return {
      label: `${high.rank}${SUIT_SYMBOLS[high.suit]} ${low.rank}${SUIT_SYMBOLS[low.suit]} suited`,
      emoji: '♠',
      tier: 'playable',
    };
  }

  // Offsuit
  return {
    label: `${high.rank}${SUIT_SYMBOLS[high.suit]} ${low.rank}${SUIT_SYMBOLS[low.suit]} offsuit`,
    emoji: '🃏',
    tier: 'marginal',
  };
}
