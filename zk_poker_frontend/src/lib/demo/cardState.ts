/**
 * Card Decryption State Management
 *
 * Tracks share collection and decryption readiness for each card being dealt.
 */

import type { Card } from '~/types/poker';

export interface CardDecryptionState {
  position: number; // 0-51 in shuffled deck
  targetPlayerPublicKey: string; // Public key
  targetPlayerSeat: number; // Seat number (0-N)
  blindingShares: Map<number, string>; // shuffler_id → share
  partialUnblindingShares: Map<number, string>; // shuffler_id → share
  requiredSharesPerType: number; // = player count
  revealed: boolean;
  displayCard?: Card;
  decryptable: boolean; // Card has all shares and is ready to decrypt
  isFlying: boolean; // Card is currently animating
  hasArrived: boolean; // Card has landed at player position
}

/**
 * Create new card state
 */
export function createCardState(
  position: number,
  targetPlayerPublicKey: string,
  targetPlayerSeat: number,
  requiredSharesPerType: number
): CardDecryptionState {
  return {
    position,
    targetPlayerPublicKey,
    targetPlayerSeat,
    blindingShares: new Map(),
    partialUnblindingShares: new Map(),
    requiredSharesPerType,
    revealed: false,
    decryptable: false,
    isFlying: false,
    hasArrived: false,
  };
}

/**
 * Add blinding share to card
 */
export function addBlindingShare(
  card: CardDecryptionState,
  shufflerId: number,
  share: string
): CardDecryptionState {
  const newShares = new Map(card.blindingShares);
  newShares.set(shufflerId, share);

  return {
    ...card,
    blindingShares: newShares,
  };
}

/**
 * Add partial unblinding share to card
 */
export function addPartialUnblindingShare(
  card: CardDecryptionState,
  shufflerId: number,
  share: string
): CardDecryptionState {
  const newShares = new Map(card.partialUnblindingShares);
  newShares.set(shufflerId, share);

  return {
    ...card,
    partialUnblindingShares: newShares,
  };
}

/**
 * Check if card has all shares needed for decryption
 */
export function hasAllShares(card: CardDecryptionState): boolean {
  const hasAllBlinding = card.blindingShares.size === card.requiredSharesPerType;
  const hasAllUnblinding =
    card.partialUnblindingShares.size === card.requiredSharesPerType;

  return hasAllBlinding && hasAllUnblinding;
}

/**
 * Mark card as revealed with display card
 */
export function revealCard(
  card: CardDecryptionState,
  displayCard: Card
): CardDecryptionState {
  return {
    ...card,
    revealed: true,
    displayCard,
  };
}

/**
 * Mark card as flying (animation started)
 */
export function markCardFlying(card: CardDecryptionState): CardDecryptionState {
  return {
    ...card,
    isFlying: true,
  };
}

/**
 * Mark card as arrived (animation complete)
 */
export function markCardArrived(card: CardDecryptionState): CardDecryptionState {
  return {
    ...card,
    isFlying: false,
    hasArrived: true,
  };
}

/**
 * Get share collection progress (0-1)
 */
export function getShareProgress(card: CardDecryptionState): number {
  const totalRequired = card.requiredSharesPerType * 2; // blinding + unblinding
  const totalCollected = card.blindingShares.size + card.partialUnblindingShares.size;
  return totalCollected / totalRequired;
}

/**
 * Get share collection status text
 */
export function getShareStatusText(card: CardDecryptionState): string {
  if (card.revealed) {
    return `${card.displayCard?.rank}${card.displayCard?.suit}`;
  }

  if (hasAllShares(card)) {
    return '✓ All shares collected';
  }

  const totalRequired = card.requiredSharesPerType * 2;
  const totalCollected = card.blindingShares.size + card.partialUnblindingShares.size;

  if (totalCollected === 0) {
    return 'Waiting for shares...';
  }

  return `Collecting shares (${totalCollected}/${totalRequired})...`;
}
