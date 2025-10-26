// components/protocol-logs/CompactMessageRow.tsx

"use client";

import { useState } from "react";
import { ChevronRight } from "lucide-react";
import type { FinalizedAnyMessageEnvelope } from "~/lib/schemas/finalizedEnvelopeSchema";
import {
  getMessageSummaryParts,
  getPhaseConfig,
} from "~/lib/console/formatting";
import { ActorName } from "~/components/console/ActorName";
import { PhaseBadgeCompact } from "./PhaseBadgeCompact";
import { StatusBadge } from "./StatusBadge";
import { ExpandedMessageSection } from "./ExpandedMessageSection";

interface CompactMessageRowProps {
  message: FinalizedAnyMessageEnvelope;
  viewerPublicKey: string;
  playerMapping: Map<string, { seat: number; player_key: string }>;
}

/**
 * Format timestamp to full format: "Apr 25, 2025 at 3:10:56 PM"
 */
function formatTimestampFull(timestamp: string | number): string {
  const date = new Date(timestamp);
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }).format(date);
}

/**
 * Format timestamp to short format for mobile: "3:10 PM"
 */
function formatTimestampShort(timestamp: string | number): string {
  const date = new Date(timestamp);
  return new Intl.DateTimeFormat("en-US", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  }).format(date);
}

/**
 * Multi-line card component for protocol logs
 * Collapsed: 3 lines (timestamp + phase, message, metadata)
 * Expanded: Shows full JSON payload with verification tools
 */
export function CompactMessageRow({
  message,
  viewerPublicKey,
  playerMapping,
}: CompactMessageRowProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const summaryParts = getMessageSummaryParts(
    message.envelope.message.value,
    playerMapping,
  );
  const phaseConfig = getPhaseConfig(
    message.applied_phase,
    message.envelope.message.value,
  );

  return (
    <div
      className="cursor-pointer border-b transition-colors"
      style={{
        borderColor: "var(--color-border-subtle)",
        backgroundColor: isExpanded
          ? "var(--color-bg-expanded)"
          : "transparent",
      }}
      onMouseEnter={(e) => {
        if (!isExpanded) {
          e.currentTarget.style.backgroundColor = "var(--color-bg-row-hover)";
        }
      }}
      onMouseLeave={(e) => {
        if (!isExpanded) {
          e.currentTarget.style.backgroundColor = "transparent";
        }
      }}
    >
      {/* Collapsed Card - 3 Lines */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full space-y-1 px-4 py-3 text-left"
      >
        {/* Line 1: Timestamp (left) + Phase Badge + Chevron (right) */}
        <div className="flex items-center justify-between">
          {/* Desktop: Full timestamp */}
          <span
            className="hidden font-mono text-xs sm:block"
            style={{ color: "var(--color-text-secondary)" }}
          >
            {formatTimestampFull(message.created_timestamp)}
          </span>
          {/* Mobile: Short timestamp */}
          <span
            className="font-mono text-xs sm:hidden"
            style={{ color: "var(--color-text-secondary)" }}
          >
            {formatTimestampShort(message.created_timestamp)}
          </span>

          <div className="flex items-center gap-2">
            <PhaseBadgeCompact config={phaseConfig} />
            <ChevronRight
              size={14}
              className="transition-transform"
              style={{
                color: "var(--color-text-muted)",
                transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)",
              }}
            />
          </div>
        </div>

        {/* Line 2: Actor + Message Summary */}
        <div
          className="text-sm leading-snug"
          style={{ color: "var(--color-text-primary)" }}
        >
          {summaryParts.hasActor && (
            <ActorName
              actor={message.envelope.actor}
              viewerPublicKey={viewerPublicKey}
            />
          )}
          <span>{summaryParts.suffix}</span>
        </div>

        {/* Line 3: Metadata (Nonce + Status) */}
        <div className="flex items-center gap-2 text-xs">
          {/* Desktop: Full labels */}
          <span
            className="hidden sm:inline"
            style={{ color: "var(--color-text-muted)" }}
          >
            Nonce: {message.envelope.nonce}
          </span>
          {/* Mobile: Short labels */}
          <span
            className="sm:hidden"
            style={{ color: "var(--color-text-muted)" }}
          >
            #{message.envelope.nonce}
          </span>

          <span style={{ color: "var(--color-text-muted)" }}>•</span>
          <StatusBadge status={message.snapshot_status} />
        </div>
      </button>

      {/* Expanded Section */}
      {isExpanded && (
        <div
          className="px-4 pb-4"
          style={{
            backgroundColor: "var(--color-bg-expanded)",
            borderTop: "1px solid var(--color-border-payload)",
          }}
        >
          <ExpandedMessageSection message={message} />
        </div>
      )}
    </div>
  );
}
