// components/protocol-logs/CompactTableLogsPanel.tsx

"use client";

import { useRef, useEffect } from "react";
import type { FinalizedAnyMessageEnvelope } from "~/lib/finalizedEnvelopeSchema";
import { CompactTableRow } from "./CompactTableRow";

interface CompactTableLogsPanelProps {
  messages: FinalizedAnyMessageEnvelope[];
  playerMapping: Map<string, { seat: number; player_key: string }>;
  isOpen: boolean;
  onClose: () => void;
  variant?: "overlay" | "embedded";
}

/**
 * Card-based protocol logs panel component
 * Clean, scannable layout with developer console aesthetic
 *
 * Features:
 * - Card-based rows (no table columns)
 * - Dark blue background matching landing page (primary-950)
 * - Primary blue accent border (#7c91ff)
 * - LIVE indicator with pulsing dot
 * - Expandable cards with full JSON payload
 * - Phase-based subtle background colors
 */
export function CompactTableLogsPanel({
  messages,
  playerMapping,
  isOpen,
  onClose,
  variant = "overlay",
}: CompactTableLogsPanelProps) {
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to top when new message arrives (newest first)
  useEffect(() => {
    if (scrollContainerRef.current && messages.length > 0) {
      scrollContainerRef.current.scrollTop = 0;
    }
  }, [messages.length]);

  // Container classes based on variant
  const containerClasses =
    variant === "overlay"
      ? "fixed right-0 top-0 h-screen lg:w-[425px] md:w-[250px] w-full z-[999]"
      : "relative h-[600px] w-full";

  return (
    <div
      className={`${containerClasses} flex flex-col rounded-xl overflow-hidden`}
      style={{
        backgroundColor: "#0a0a2f", // Match landing page primary-950
        borderLeft: "2px solid #7c91ff", // Primary blue accent
        borderTop: "1px solid #2d3748",
        borderRight: "1px solid #2d3748",
        borderBottom: "1px solid #2d3748",
        boxShadow: `
          inset 4px 0 12px rgba(124, 145, 255, 0.08),
          0 20px 50px rgba(0, 0, 0, 0.6)
        `,
      }}
    >
      {/* Header */}
      <header
        className="px-4 py-3 flex items-center justify-between shrink-0 border-b"
        style={{
          backgroundColor: "#1a1a4f", // Match landing page primary-900
          borderColor: "#2d3748",
        }}
      >
        <div className="flex items-center gap-3">
          <h3
            className="text-sm font-semibold"
            style={{ color: "#e2e8f0" }}
          >
            Protocol Logs
          </h3>
          <span
            className="text-xs font-medium"
            style={{ color: "#7c91ff" }} // Primary blue
          >
            ({messages.length})
          </span>
          {/* LIVE indicator */}
          <div
            className="flex items-center gap-1 text-xs"
            style={{ color: "#7c91ff" }} // Primary blue
          >
            <span
              className="w-2 h-2 rounded-full animate-pulse"
              style={{ backgroundColor: "#7c91ff" }} // Primary blue
            />
            LIVE
          </div>
        </div>

        {/* Close button */}
        <button
          onClick={onClose}
          className="p-1 rounded-lg transition-colors hover:bg-opacity-80"
          style={{ color: "#94a3b8" }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = "rgba(45, 55, 72, 0.3)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = "transparent";
          }}
        >
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      </header>

      {/* Scrollable Card List */}
      <div
        ref={scrollContainerRef}
        className="flex-1 overflow-y-auto"
        style={{
          scrollbarWidth: "thin",
          scrollbarColor: "#2d3748 transparent",
        }}
      >
        {messages.length === 0 ? (
          <div
            className="px-4 py-12 text-center text-sm"
            style={{ color: "#94a3b8" }}
          >
            <div className="mb-2">⏳</div>
            <div>Waiting for protocol messages...</div>
            <div
              className="text-xs mt-2"
              style={{ color: "#64748b" }}
            >
              Messages will appear here as they stream in
            </div>
          </div>
        ) : (
          messages.map((msg, idx) => (
            <CompactTableRow
              key={`${msg.hand_id}-${msg.snapshot_sequence_id ?? idx}`}
              message={msg}
              sequenceNumber={idx}
              viewerPublicKey="placeholder_viewer_key"
              playerMapping={playerMapping}
            />
          ))
        )}
      </div>
    </div>
  );
}
