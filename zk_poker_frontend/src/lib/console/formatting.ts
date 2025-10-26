// lib/console/formatting.ts

import type {
  AnyActor,
  AnyGameMessage,
  EventPhase,
} from "../schemas/finalizedEnvelopeSchema";
import {
  isBlindingMessage,
  isPartialUnblindingMessage,
  isPlayerActor,
  isShufflerActor,
  isShuffleMessage,
} from "../schemas/finalizedEnvelopeSchema";

// Re-export type guards for convenience
export {
  isBlindingMessage,
  isPartialUnblindingMessage,
  isPlayerActor,
  isShufflerActor,
  isShuffleMessage,
};

/**
 * Format actor name for display
 */
export function formatActor(actor: AnyActor, viewerPublicKey: string): string {
  if (isShufflerActor(actor)) {
    return `Shuffler ${actor.shuffler.shuffler_id + 1}`;
  }

  if (isPlayerActor(actor)) {
    // Note: player_key is not in the schema, using player_id for comparison
    if (actor.player.player_id.toString() === viewerPublicKey) {
      return "You";
    }
    return `Player ${actor.player.seat_id + 1}`;
  }

  return "System";
}

/**
 * Check if actor is the viewer
 */
export function isViewerActor(
  actor: AnyActor,
  viewerPublicKey: string,
): boolean {
  return isPlayerActor(actor) && actor.player.player_id.toString() === viewerPublicKey;
}

/**
 * Format timestamp to human-readable format
 */
export function formatTimestamp(isoString: string): string {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }).format(new Date(isoString));
}

/**
 * Format message summary for display in table (without actor context)
 */
export function formatMessageSummary(message: AnyGameMessage): string {
  if (isShuffleMessage(message)) {
    const count = message.deck_out.length;
    return `Shuffled ${count} cards`;
  }

  if (isBlindingMessage(message)) {
    return `Blinding card #${message.card_in_deck_position}`;
  }

  if (isPartialUnblindingMessage(message)) {
    return `Share for card #${message.card_in_deck_position}`;
  }

  if (message.type === "player_preflop") {
    return formatPlayerAction(message.action);
  }

  if (message.type === "player_flop") {
    return formatPlayerAction(message.action);
  }

  if (message.type === "player_turn") {
    return formatPlayerAction(message.action);
  }

  if (message.type === "player_river") {
    return formatPlayerAction(message.action);
  }

  if (message.type === "showdown") {
    return "Revealed hand";
  }

  return "Unknown message";
}

/**
 * Get message summary parts for rich formatting with actor names
 */
export interface MessageSummaryParts {
  prefix?: string; // Text before actor name (e.g., "")
  hasActor: boolean;
  suffix: string; // Text after actor name or full message if no actor
}

export function getMessageSummaryParts(
  message: AnyGameMessage,
  playerMapping: Map<string, { seat: number; player_key: string }>,
): MessageSummaryParts {
  if (isShuffleMessage(message)) {
    return {
      hasActor: true,
      suffix: ` created a shuffle proof`,
    };
  }

  if (isBlindingMessage(message)) {
    // Look up target player's seat from playerMapping
    const targetPlayerInfo = playerMapping.get(
      message.target_player_public_key,
    );
    const targetPlayerLabel = targetPlayerInfo
      ? `Player ${targetPlayerInfo.seat + 1}`
      : "unknown player";

    return {
      hasActor: true,
      suffix: ` sent partial blinding decryption share of card #${message.card_in_deck_position} to ${targetPlayerLabel}`,
    };
  }

  if (isPartialUnblindingMessage(message)) {
    return {
      hasActor: true,
      suffix: ` sent unblinding share for card #${message.card_in_deck_position}`,
    };
  }

  if (
    message.type === "player_preflop" ||
    message.type === "player_flop" ||
    message.type === "player_turn" ||
    message.type === "player_river"
  ) {
    const action = formatPlayerAction(message.action).toLowerCase();
    return {
      hasActor: true,
      suffix: ` ${action}`,
    };
  }

  if (message.type === "showdown") {
    return {
      hasActor: true,
      suffix: " revealed hand",
    };
  }

  return {
    hasActor: false,
    suffix: "Unknown message",
  };
}

/**
 * Format player action (helper)
 */
function formatPlayerAction(action: unknown): string {
  if (typeof action !== "object" || action === null) {
    return "Action";
  }

  if ("Bet" in action) {
    return `Bet $${(action as { Bet: { amount: number } }).Bet.amount}`;
  }

  if ("Call" in action) {
    return "Call";
  }

  if ("Fold" in action) {
    return "Fold";
  }

  if ("Check" in action) {
    return "Check";
  }

  if ("Raise" in action) {
    return `Raise to $${(action as { Raise: { to_amount: number } }).Raise.to_amount}`;
  }

  return "Action";
}

/**
 * Phase configuration for badges
 */
export interface PhaseConfig {
  label: string;
  color: string;
  icon: string;
  bgColor: string;
  borderColor: string;
}

/**
 * Get phase configuration based on phase and message type
 */
export function getPhaseConfig(
  phase: EventPhase,
  messageType: AnyGameMessage,
): PhaseConfig {
  // Use discriminator to determine message type directly
  switch (messageType.type) {
    case "shuffle":
      return {
        label: "Shuffle",
        color: "var(--color-phase-shuffle)",
        icon: "",
        bgColor: "oklch(from var(--color-phase-shuffle) l c h / 0.1)",
        borderColor: "oklch(from var(--color-phase-shuffle) l c h / 0.2)",
      };

    case "blinding":
      return {
        label: "Blinding Share",
        color: "var(--color-phase-blind)",
        icon: "",
        bgColor: "oklch(from var(--color-phase-blind) l c h / 0.1)",
        borderColor: "oklch(from var(--color-phase-blind) l c h / 0.2)",
      };

    case "partial_unblinding":
      return {
        label: "Unblinding Share",
        color: "var(--color-phase-unblind)",
        icon: "",
        bgColor: "oklch(from var(--color-phase-unblind) l c h / 0.1)",
        borderColor: "oklch(from var(--color-phase-unblind) l c h / 0.2)",
      };

    case "player_preflop":
    case "player_flop":
    case "player_turn":
    case "player_river":
      return {
        label: "Bet",
        color: "var(--color-phase-bet)",
        icon: "",
        bgColor: "oklch(from var(--color-phase-bet) l c h / 0.1)",
        borderColor: "oklch(from var(--color-phase-bet) l c h / 0.2)",
      };

    case "showdown":
      return {
        label: "Showdown",
        color: "var(--color-phase-showdown)",
        icon: "",
        bgColor: "oklch(from var(--color-phase-showdown) l c h / 0.1)",
        borderColor: "oklch(from var(--color-phase-showdown) l c h / 0.2)",
      };

    default:
      return {
        label: "Unknown",
        color: "var(--color-text-muted)",
        icon: "",
        bgColor: "oklch(from var(--color-text-muted) l c h / 0.1)",
        borderColor: "oklch(from var(--color-text-muted) l c h / 0.2)",
      };
  }
}
