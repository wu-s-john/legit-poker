/**
 * Event Handlers - Process demo events and dispatch state actions
 */

import type { DemoStreamEvent } from "./events";
import type { AnyActor } from "../schemas/finalizedEnvelopeSchema";
import type { DemoAction } from "./demoState";
import type { Card } from "~/types/poker";
import { generateOrderedDeck, shuffleDeck } from "./deck";

export interface EventHandlerCallbacks {
  onShuffleProgress?: (current: number, total: number) => void;
  onCardDealt?: (seat: number, cardIndex: number, deckPosition: number) => void;
  onCardReveal?: (seat: number, cardIndex: number) => void;
  onPhaseChange?: (phase: "shuffling" | "dealing" | "complete") => void;
}

/**
 * Handles all demo events and dispatches appropriate actions
 */
export class DemoEventHandler {
  private shuffleEventCount = 0;
  private totalShuffleEvents = 0;
  private dealingStarted = false;
  private viewerPublicKey: string | null = null;
  private playerCount = 7; // Default, will be updated from hand_created event
  private static readonly VIEWER_SEAT = 0;

  constructor(
    private dispatch: (action: DemoAction) => void,
    private callbacks: EventHandlerCallbacks = {},
  ) {}

  /**
   * Main entry point for handling demo SSE events
   */
  handleDemoEvent(event: DemoStreamEvent): void {
    switch (event.type) {
      case "player_created":
        this.handlePlayerCreated(event);
        break;

      case "hand_created":
        this.handleHandCreated(event);
        break;

      case "game_event":
        this.handleGameEvent(event);
        break;

      case "card_decryptable":
        this.handleCardDecryptable(event);
        break;

      case "hole_cards_decrypted":
        this.handleHoleCardsDecrypted(event);
        break;

      case "hand_completed":
        this.handleHandCompleted(event);
        break;
    }
  }

  /**
   * Handle player_created event
   */
  private handlePlayerCreated(
    event: Extract<DemoStreamEvent, { type: "player_created" }>,
  ): void {
    // Viewer is always seated at seat 0
    if (event.seat === DemoEventHandler.VIEWER_SEAT) {
      this.viewerPublicKey = event.public_key;
      console.log(
        "[EventHandler] Viewer public key captured:",
        this.viewerPublicKey,
      );
      this.dispatch({
        type: "SET_VIEWER_PUBLIC_KEY",
        publicKey: event.public_key,
      });
    }

    this.dispatch({
      type: "UPDATE_STATUS",
      message: `Player ${event.seat + 1} joined`,
    });
  }

  /**
   * Handle hand_created event - start shuffle phase
   */
  private handleHandCreated(
    event: Extract<DemoStreamEvent, { type: "hand_created" }>,
  ): void {
    this.shuffleEventCount = 0;
    this.totalShuffleEvents = event.shuffler_count;
    this.dealingStarted = false;

    // Store player count from event
    this.playerCount = event.player_count;

    // Resolve viewer public key (may arrive after hand_created)
    const snapshotViewerPublicKey = this.resolveViewerPublicKeyFromSnapshot(
      event.snapshot?.players,
    );
    if (!this.viewerPublicKey && snapshotViewerPublicKey) {
      this.viewerPublicKey = snapshotViewerPublicKey;
    }
    const resolvedViewerPublicKey =
      this.viewerPublicKey ?? snapshotViewerPublicKey ?? null;

    // Initialize game state with metadata from backend
    this.dispatch({
      type: "INIT_GAME",
      gameId: event.game_id,
      handId: event.hand_id,
      publicKey: resolvedViewerPublicKey,
      playerCount: event.player_count,
    });

    this.dispatch({ type: "START_SHUFFLE" });
    this.callbacks.onPhaseChange?.("shuffling");

    // Initialize shuffle progress with total shuffler count
    this.dispatch({
      type: "SHUFFLE_PROGRESS",
      currentStep: 0,
      totalSteps: event.shuffler_count,
    });

    this.dispatch({
      type: "UPDATE_STATUS",
      message: "Hand started - shuffling deck...",
    });
  }

  /**
   * Handle game_event - protocol messages
   */
  private handleGameEvent(
    event: Extract<DemoStreamEvent, { type: "game_event" }>,
  ): void {
    // Note: Due to Rust's #[serde(flatten)], finalized fields are at event top-level
    // while basic envelope fields are nested under event.envelope
    const message = event.envelope.message.value; // Access the actual message from WithSignature wrapper

    // Track sequence ID
    this.dispatch({
      type: "EVENT_PROCESSED",
      seqId: event.snapshot_sequence_id,
    });

    // Determine message type and handle accordingly
    if (message.type === "shuffle") {
      this.handleShuffleMessage(event);
    } else if (message.type === "blinding") {
      this.handleBlindingMessage(event);
    } else if (message.type === "partial_unblinding") {
      this.handlePartialUnblindingMessage(event);
    }
  }

  /**
   * Handle shuffle message - track progress
   */
  private handleShuffleMessage(
    _event: Extract<DemoStreamEvent, { type: "game_event" }>,
  ): void {
    this.shuffleEventCount++;

    // Estimate total shuffle events (N players × shuffle rounds)
    // For demo, assume ~20-30 shuffle events total
    if (this.totalShuffleEvents === 0) {
      this.totalShuffleEvents = 25; // Rough estimate
    }

    this.dispatch({
      type: "SHUFFLE_PROGRESS",
      currentStep: this.shuffleEventCount,
      totalSteps: this.totalShuffleEvents,
    });

    this.callbacks.onShuffleProgress?.(
      this.shuffleEventCount,
      this.totalShuffleEvents,
    );

    // Check if shuffle is complete (heuristic: when we see blinding events)
    if (this.shuffleEventCount >= this.totalShuffleEvents) {
      this.dispatch({ type: "SHUFFLE_COMPLETE" });
    }
  }

  /**
   * Handle blinding message - marks start of dealing phase
   */
  private handleBlindingMessage(
    event: Extract<DemoStreamEvent, { type: "game_event" }>,
  ): void {
    // First blinding event triggers dealing phase
    if (!this.dealingStarted) {
      this.dealingStarted = true;

      // Complete shuffle phase
      this.dispatch({ type: "SHUFFLE_COMPLETE" });

      // Generate client-side shuffled deck for display
      const clientDeck = shuffleDeck(generateOrderedDeck());

      this.dispatch({ type: "START_DEALING", clientDeck });
      this.callbacks.onPhaseChange?.("dealing");

      // Trigger initial card dealing animations
      this.startCardDealingAnimations();
    }

    // Extract card position from message
    const message = event.envelope.message.value;
    const actor = event.envelope.actor;

    // Blinding messages contain shares for specific cards
    if (message.type === "blinding") {
      const cardPosition = message.card_in_deck_position;
      const fromSeat = this.extractSeatFromActor(actor);

      // For now, we'll map card_in_deck_position to seat/cardIndex
      // Assuming first 14 cards go to 7 players (2 each)
      const targetSeat = Math.floor(cardPosition / 2);
      const cardIndex = cardPosition % 2;

      this.dispatch({
        type: "BLINDING_SHARE_RECEIVED",
        seat: targetSeat,
        cardIndex,
        fromSeat,
      });
    }
  }

  /**
   * Handle partial unblinding message
   */
  private handlePartialUnblindingMessage(
    event: Extract<DemoStreamEvent, { type: "game_event" }>,
  ): void {
    const message = event.envelope.message.value;
    const actor = event.envelope.actor;

    if (message.type === "partial_unblinding") {
      const cardPosition = message.card_in_deck_position;
      const fromSeat = this.extractSeatFromActor(actor);

      // Map card_in_deck_position to seat/cardIndex
      const targetSeat = Math.floor(cardPosition / 2);
      const cardIndex = cardPosition % 2;

      this.dispatch({
        type: "PARTIAL_UNBLINDING_SHARE_RECEIVED",
        seat: targetSeat,
        cardIndex,
        fromSeat,
      });
    }
  }

  /**
   * Handle card_decryptable event
   */
  private handleCardDecryptable(
    event: Extract<DemoStreamEvent, { type: "card_decryptable" }>,
  ): void {
    this.dispatch({
      type: "CARD_DECRYPTABLE",
      seat: event.seat,
      cardIndex: event.card_position,
    });

    this.dispatch({
      type: "UPDATE_STATUS",
      message:
        event.seat === 0
          ? `Your card ${event.card_position + 1} is ready to reveal!`
          : `Player ${event.seat}'s card ready`,
    });
  }

  /**
   * Handle hole_cards_decrypted event
   */
  private handleHoleCardsDecrypted(
    event: Extract<DemoStreamEvent, { type: "hole_cards_decrypted" }>,
  ): void {
    this.dispatch({
      type: "CARD_REVEALED",
      seat: event.seat,
      cardIndex: event.card_position,
      card: event.card,
    });

    this.callbacks.onCardReveal?.(event.seat, event.card_position);

    this.dispatch({
      type: "UPDATE_STATUS",
      message:
        event.seat === 0
          ? `Your ${event.card.rank}${this.getSuitSymbol(event.card.suit)} revealed!`
          : `Player ${event.seat} card revealed`,
    });
  }

  /**
   * Handle hand_completed event
   */
  private handleHandCompleted(
    _event: Extract<DemoStreamEvent, { type: "hand_completed" }>,
  ): void {
    this.dispatch({ type: "HAND_COMPLETE" });
    this.callbacks.onPhaseChange?.("complete");

    this.dispatch({
      type: "UPDATE_STATUS",
      message: "Hand complete!",
    });
  }

  /**
   * Trigger card dealing animations (called once at start of dealing phase)
   */
  private startCardDealingAnimations(): void {
    // Trigger animations for all players' cards (2 cards each)
    // Animation order: round-robin (card 1 to all players, then card 2 to all players)
    let deckPosition = 0;

    // First card to each player
    for (let seat = 0; seat < this.playerCount; seat++) {
      setTimeout(() => {
        this.dispatch({ type: "CARD_DEALT", seat, cardIndex: 0 });
        this.callbacks.onCardDealt?.(seat, 0, deckPosition);
      }, seat * 200); // Stagger by 200ms
      deckPosition++;
    }

    // Second card to each player
    for (let seat = 0; seat < this.playerCount; seat++) {
      setTimeout(
        () => {
          this.dispatch({ type: "CARD_DEALT", seat, cardIndex: 1 });
          this.callbacks.onCardDealt?.(seat, 1, deckPosition);
        },
        1400 + seat * 200,
      ); // Start after first round (playerCount × 200ms) + delay
      deckPosition++;
    }
  }

  /**
   * Extract seat number from actor
   */
  private extractSeatFromActor(actor: AnyActor): number {
    // Actor is either "none", {player: {...}}, or {shuffler: {...}}
    if (typeof actor === "object" && "player" in actor && actor.player) {
      return actor.player.seat_id;
    }
    return -1; // Unknown/server actor
  }

  /**
   * Get suit symbol for display
   */
  private getSuitSymbol(suit: Card["suit"]): string {
    const symbols: Record<Card["suit"], string> = {
      spades: "♠",
      hearts: "♥",
      diamonds: "♦",
      clubs: "♣",
    };
    return symbols[suit];
  }

  /**
   * Reset handler state (for new hand)
   */
  reset(): void {
    this.shuffleEventCount = 0;
    this.totalShuffleEvents = 0;
    this.dealingStarted = false;
    this.viewerPublicKey = null;
    this.playerCount = 7; // Reset to default
  }

  /**
   * Attempt to recover the viewer's public key from snapshot data
   */
  private resolveViewerPublicKeyFromSnapshot(
    players:
      | Record<
          string,
          {
            seat: number;
            public_key: string;
            player_key: string;
          }
        >
      | undefined,
  ): string | null {
    if (this.viewerPublicKey) {
      return this.viewerPublicKey;
    }

    if (!players) {
      return null;
    }

    const viewerEntry = Object.values(players).find(
      (player) => player.seat === DemoEventHandler.VIEWER_SEAT,
    );

    if (!viewerEntry) {
      return null;
    }

    return viewerEntry.public_key ?? null;
  }
}
