// components/protocol-logs/CompactTableRow.tsx

"use client";

import { useState } from "react";
import { ChevronRight } from "lucide-react";
import type {
  FinalizedAnyMessageEnvelope,
  SnapshotStatus,
} from "~/lib/schemas/finalizedEnvelopeSchema";
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
 * Format timestamp with milliseconds: "9:30:247 AM"
 */
function formatTimestampWithMilliseconds(timestamp: string | number): string {
  const date = new Date(timestamp);
  const hours = date.getHours();
  const minutes = date.getMinutes();
  const seconds = date.getSeconds();
  const milliseconds = date.getMilliseconds();
  const ampm = hours >= 12 ? "PM" : "AM";
  const displayHours = hours % 12 || 12;

  return `${displayHours}:${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}.${milliseconds.toString().padStart(3, "0")} ${ampm}`;
}

/**
 * Get phase badge emoji, color, and background
 */
function getPhaseStyle(label: string): {
  emoji: string;
  color: string;
  background: string;
} {
  const styles: Record<string, { emoji: string; color: string; background: string }> = {
    "Shuffle": {
      emoji: "🔵",
      color: "#3b82f6",
      background: "rgba(59, 130, 246, 0.05)"
    },
    "Blinding Share": {
      emoji: "🟢",
      color: "#10b981",
      background: "rgba(16, 185, 129, 0.05)"
    },
    "Unblinding Share": {
      emoji: "🟣",
      color: "#8b5cf6",
      background: "rgba(139, 92, 246, 0.05)"
    },
    "Bet": {
      emoji: "🟡",
      color: "#f59e0b",
      background: "rgba(245, 158, 11, 0.05)"
    },
    "Showdown": {
      emoji: "🔴",
      color: "#ef4444",
      background: "rgba(239, 68, 68, 0.05)"
    },
  };
  return styles[label] ?? {
    emoji: "⚪",
    color: "#94a3b8",
    background: "rgba(148, 163, 184, 0.05)"
  };
}

/**
 * Get status badge display properties
 */
function getStatusDisplay(status: SnapshotStatus): {
  icon: string;
  label: string;
  color: string;
  background: string;
} {
  if (status === "success") {
    return {
      icon: "✓",
      label: "Success",
      color: "#10b981",
      background: "rgba(16, 185, 129, 0.1)"
    };
  } else {
    return {
      icon: "✗",
      label: "Failed",
      color: "#ef4444",
      background: "rgba(239, 68, 68, 0.1)"
    };
  }
}

/**
 * Card-based protocol log row component
 * Layout: Top row (time + phase badge + chevron), sequence number, full-width message
 * Expands to show full JSON payload
 */
export function CompactTableRow({
  message,
  sequenceNumber: _sequenceNumber,
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
  const statusDisplay = getStatusDisplay(message.snapshot_status);

  return (
    <div
      className="border-b transition-colors cursor-pointer"
      style={{
        borderColor: "rgba(124, 145, 255, 0.2)", // Blue-tinted border for better separation
        backgroundColor: isExpanded ? "#0a0a2f" : phaseStyle.background,
      }}
      onMouseEnter={(e) => {
        if (!isExpanded) {
          e.currentTarget.style.backgroundColor = "rgba(124, 145, 255, 0.1)"; // More visible blue tint on hover
        }
      }}
      onMouseLeave={(e) => {
        if (!isExpanded) {
          e.currentTarget.style.backgroundColor = phaseStyle.background;
        }
      }}
    >
      {/* Card layout */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full text-left px-4 py-3"
      >
        {/* Top row: Phase badge (left) + Chevron (right) */}
        <div className="flex items-center justify-between mb-2">
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

        {/* Second row: Timestamp (left) + Status badge (right) */}
        <div className="flex items-center justify-between mb-2">
          <div
            className="text-xs font-mono"
            style={{ color: "#94a3b8" }}
          >
            {formatTimestampWithMilliseconds(message.created_timestamp)}
          </div>
          <div
            className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
            style={{
              color: statusDisplay.color,
              backgroundColor: statusDisplay.background,
            }}
          >
            <span>{statusDisplay.icon}</span>
            <span>{statusDisplay.label}</span>
          </div>
        </div>

        {/* Third row: Full-width message summary */}
        <div className="text-sm" style={{ color: "#e2e8f0" }}>
          {summaryParts.hasActor && (
            <ActorName
              actor={message.envelope.actor}
              viewerPublicKey={viewerPublicKey}
            />
          )}
          <span>{summaryParts.suffix}</span>
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
