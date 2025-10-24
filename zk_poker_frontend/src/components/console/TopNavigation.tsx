// components/console/TopNavigation.tsx

"use client";

import Link from "next/link";
import type { EventPhase } from "~/lib/console/schemas";

interface TopNavigationProps {
  gameId: string;
  handId: string;
  handStatus: EventPhase;
  totalMessages: number;
}

export function TopNavigation({
  gameId,
  handId,
  handStatus,
  totalMessages,
}: TopNavigationProps) {
  const getStatusColor = (status: EventPhase): string => {
    switch (status) {
      case "Complete":
        return "var(--color-accent-green)";
      case "Cancelled":
        return "var(--color-accent-red)";
      case "Pending":
        return "var(--color-text-muted)";
      case "Shuffling":
        return "var(--color-phase-shuffle)";
      case "Dealing":
        return "var(--color-phase-deal)";
      case "Betting":
        return "var(--color-phase-bet)";
      case "Reveals":
        return "var(--color-phase-reveal)";
      case "Showdown":
        return "var(--color-phase-showdown)";
      default:
        return "var(--color-accent-teal)";
    }
  };

  return (
    <nav
      className="sticky top-0 z-50 backdrop-blur-lg border-b"
      style={{
        backgroundColor: "var(--color-bg-nav)",
        borderColor: "var(--color-border-primary)",
        boxShadow: "var(--shadow-nav)",
      }}
    >
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Left side - Breadcrumb */}
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="text-sm font-medium transition-colors"
              style={{ color: "var(--color-text-secondary)" }}
            >
              ← Home
            </Link>

            <span style={{ color: "var(--color-text-muted)" }}>/</span>

            <Link
              href={`/debug/games/${gameId}`}
              className="text-sm font-medium transition-colors"
              style={{ color: "var(--color-text-secondary)" }}
            >
              Game {gameId}
            </Link>

            <span style={{ color: "var(--color-text-muted)" }}>/</span>

            <span
              className="text-sm font-semibold"
              style={{ color: "var(--color-text-primary)" }}
            >
              Hand {handId}
            </span>
          </div>

          {/* Right side - Status and message count */}
          <div className="flex items-center gap-6">
            {/* Message count */}
            <div className="flex items-center gap-2">
              <span
                className="text-sm"
                style={{ color: "var(--color-text-muted)" }}
              >
                Messages:
              </span>
              <span
                className="text-lg font-bold font-mono"
                style={{ color: "var(--color-accent-teal)" }}
              >
                {totalMessages}
              </span>
            </div>

            {/* Status badge */}
            <div
              className="px-4 py-1.5 rounded-full text-sm font-semibold border"
              style={{
                color: getStatusColor(handStatus),
                backgroundColor: `oklch(from ${getStatusColor(handStatus)} l c h / 0.1)`,
                borderColor: `oklch(from ${getStatusColor(handStatus)} l c h / 0.3)`,
              }}
            >
              {handStatus}
            </div>
          </div>
        </div>

        {/* Title */}
        <h1
          className="mt-3 text-2xl font-bold"
          style={{ color: "var(--color-text-primary)" }}
        >
          Console Logs
        </h1>
      </div>
    </nav>
  );
}
