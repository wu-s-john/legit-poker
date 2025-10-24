// lib/console/formatting.ts

import type {
  AnyActor,
  AnyGameMessage,
  EventPhase,
} from "./schemas";
import {
  isBlindingMessage,
  isPartialUnblindingMessage,
  isPlayerActor,
  isShufflerActor,
  isShuffleMessage,
} from "./schemas";

/**
 * Format actor name for display
 */
export function formatActor(actor: AnyActor, viewerPublicKey: string): string {
  if (isShufflerActor(actor)) {
    return `Shuffler ${actor.Shuffler.shuffler_id + 1}`;
  }

  if (isPlayerActor(actor)) {
    if (actor.Player.player_key === viewerPublicKey) {
      return "You";
    }
    return `Player ${actor.Player.seat_id + 1}`;
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
  return (
    isPlayerActor(actor) && actor.Player.player_key === viewerPublicKey
  );
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
 * Format message summary for display in table
 */
export function formatMessageSummary(message: AnyGameMessage): string {
  if (isShuffleMessage(message)) {
    const count = message.Shuffle.deck_out.length;
    return `Shuffled ${count} cards`;
  }

  if (isBlindingMessage(message)) {
    return `Blinding card #${message.Blinding.card_in_deck_position}`;
  }

  if (isPartialUnblindingMessage(message)) {
    return `Share for card #${message.PartialUnblinding.card_in_deck_position}`;
  }

  if ("PlayerPreflop" in message) {
    const action = message.PlayerPreflop.action;
    return formatPlayerAction(action);
  }

  if ("PlayerFlop" in message) {
    const action = message.PlayerFlop.action;
    return formatPlayerAction(action);
  }

  if ("PlayerTurn" in message) {
    const action = message.PlayerTurn.action;
    return formatPlayerAction(action);
  }

  if ("PlayerRiver" in message) {
    const action = message.PlayerRiver.action;
    return formatPlayerAction(action);
  }

  if ("Showdown" in message) {
    return "Revealed hand";
  }

  return "Unknown message";
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
  // Differentiate Blinding vs Unblinding by message type
  if (phase === "Dealing") {
    if (isBlindingMessage(messageType)) {
      return {
        label: "Blinding Decryption Share",
        color: "var(--color-phase-blind)",
        icon: "🟢",
        bgColor: "oklch(from var(--color-phase-blind) l c h / 0.1)",
        borderColor: "oklch(from var(--color-phase-blind) l c h / 0.2)",
      };
    }
  }

  if (phase === "Reveals") {
    if (isPartialUnblindingMessage(messageType)) {
      return {
        label: "Unblinding Decryption Share",
        color: "var(--color-phase-unblind)",
        icon: "🟣",
        bgColor: "oklch(from var(--color-phase-unblind) l c h / 0.1)",
        borderColor: "oklch(from var(--color-phase-unblind) l c h / 0.2)",
      };
    }
  }

  const configs: Record<EventPhase, PhaseConfig> = {
    Shuffling: {
      label: "Shuffle",
      color: "var(--color-phase-shuffle)",
      icon: "🔵",
      bgColor: "oklch(from var(--color-phase-shuffle) l c h / 0.1)",
      borderColor: "oklch(from var(--color-phase-shuffle) l c h / 0.2)",
    },
    Betting: {
      label: "Bet",
      color: "var(--color-phase-bet)",
      icon: "🟡",
      bgColor: "oklch(from var(--color-phase-bet) l c h / 0.1)",
      borderColor: "oklch(from var(--color-phase-bet) l c h / 0.2)",
    },
    Showdown: {
      label: "Showdown",
      color: "var(--color-phase-showdown)",
      icon: "🔴",
      bgColor: "oklch(from var(--color-phase-showdown) l c h / 0.1)",
      borderColor: "oklch(from var(--color-phase-showdown) l c h / 0.2)",
    },
    // Fallbacks
    Pending: {
      label: "Pending",
      color: "var(--color-text-muted)",
      icon: "⏳",
      bgColor: "oklch(from var(--color-text-muted) l c h / 0.1)",
      borderColor: "oklch(from var(--color-text-muted) l c h / 0.2)",
    },
    Dealing: {
      label: "Dealing",
      color: "var(--color-phase-blind)",
      icon: "🟢",
      bgColor: "oklch(from var(--color-phase-blind) l c h / 0.1)",
      borderColor: "oklch(from var(--color-phase-blind) l c h / 0.2)",
    },
    Reveals: {
      label: "Reveals",
      color: "var(--color-phase-unblind)",
      icon: "🟣",
      bgColor: "oklch(from var(--color-phase-unblind) l c h / 0.1)",
      borderColor: "oklch(from var(--color-phase-unblind) l c h / 0.2)",
    },
    Complete: {
      label: "Complete",
      color: "var(--color-accent-green)",
      icon: "✅",
      bgColor: "oklch(from var(--color-accent-green) l c h / 0.1)",
      borderColor: "oklch(from var(--color-accent-green) l c h / 0.2)",
    },
    Cancelled: {
      label: "Cancelled",
      color: "var(--color-accent-red)",
      icon: "❌",
      bgColor: "oklch(from var(--color-accent-red) l c h / 0.1)",
      borderColor: "oklch(from var(--color-accent-red) l c h / 0.2)",
    },
  };

  return configs[phase];
}
