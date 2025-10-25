// components/protocol-logs/CompactTableRow.tsx

"use client";

import { useState } from "react";
import { ChevronRight } from "lucide-react";
import type { FinalizedAnyMessageEnvelope } from "~/lib/console/schemas";
import {
  getMessageSummaryParts,
  getPhaseConfig,
} from "~/lib/console/formatting";
import { ActorName } from "~/components/console/ActorName";
import { ExpandedMessageSection } from "./ExpandedMessageSection";

interface CompactTableRowProps {
  message: FinalizedAnyMessageEnvelope;
  sequenceNumber: number;
  viewerPublicKey: string;
  playerMapping: Map<string, { seat: number; player_key: string }>;
}

/**
 * Format timestamp to short format: "3:10 PM"
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
 * Get phase badge emoji and color
 */
function getPhaseStyle(label: string): { emoji: string; color: string } {
  const styles: Record<string, { emoji: string; color: string }> = {
    "Shuffle": { emoji: "🔵", color: "#3b82f6" },
    "Blinding Share": { emoji: "🟢", color: "#10b981" },
    "Unblinding Share": { emoji: "🟣", color: "#8b5cf6" },
    "Bet": { emoji: "🟡", color: "#f59e0b" },
    "Showdown": { emoji: "🔴", color: "#ef4444" },
  };
  return styles[label] || { emoji: "⚪", color: "#94a3b8" };
}

/**
 * Hybrid table row component
 * Grid layout: SEQ | TIME | TYPE + MESSAGE (multi-line)
 * Expands to show full JSON payload
 */
export function CompactTableRow({
  message,
  sequenceNumber,
  viewerPublicKey,
  playerMapping,
}: CompactTableRowProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const summaryParts = getMessageSummaryParts(
    message.envelope.message.value,
    playerMapping
  );
  const phaseConfig = getPhaseConfig(
    message.applied_phase,
    message.envelope.message.value
  );
  const phaseStyle = getPhaseStyle(phaseConfig.label);

  return (
    <div
      className="border-b transition-colors cursor-pointer"
      style={{
        borderColor: "rgba(45, 55, 72, 0.3)",
        backgroundColor: isExpanded ? "#0a0e14" : "transparent",
      }}
      onMouseEnter={(e) => {
        if (!isExpanded) {
          e.currentTarget.style.backgroundColor = "rgba(26, 31, 46, 0.25)";
        }
      }}
      onMouseLeave={(e) => {
        if (!isExpanded) {
          e.currentTarget.style.backgroundColor = "transparent";
        }
      }}
    >
      {/* Collapsed: Grid layout with multi-line content */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full text-left px-4 py-2 grid grid-cols-[40px_60px_1fr] gap-2 items-start"
      >
        {/* Column 1: Sequence Number */}
        <div
          className="text-xs font-mono pt-1"
          style={{ color: "#94a3b8" }}
        >
          {sequenceNumber}
        </div>

        {/* Column 2: Timestamp */}
        <div
          className="text-xs font-mono pt-1"
          style={{ color: "#94a3b8" }}
        >
          {formatTimestampShort(message.created_timestamp)}
        </div>

        {/* Column 3: Type + Message (multi-line) */}
        <div className="space-y-1">
          {/* Line 1: Phase Badge + Chevron */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs font-medium">
              <span>{phaseStyle.emoji}</span>
              <span style={{ color: phaseStyle.color }}>
                {phaseConfig.label}
              </span>
            </div>
            <ChevronRight
              size={12}
              className="transition-transform flex-shrink-0"
              style={{
                color: "#64748b",
                transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)",
              }}
            />
          </div>

          {/* Line 2: Message Summary */}
          <div className="text-sm pr-4" style={{ color: "#e2e8f0" }}>
            {summaryParts.hasActor && (
              <ActorName
                actor={message.envelope.actor}
                viewerPublicKey={viewerPublicKey}
              />
            )}
            <span>{summaryParts.suffix}</span>
          </div>
        </div>
      </button>

      {/* Expanded: Full payload */}
      {isExpanded && (
        <div
          className="px-4 pb-4 border-t"
          style={{ borderColor: "#2d3748" }}
        >
          <ExpandedMessageSection message={message} />
        </div>
      )}
    </div>
  );
}
