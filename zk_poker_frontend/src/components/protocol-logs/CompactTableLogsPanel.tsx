// components/protocol-logs/CompactTableLogsPanel.tsx

"use client";

import { useRef, useEffect } from "react";
import type { FinalizedAnyMessageEnvelope } from "~/lib/console/schemas";
import { CompactTableRow } from "./CompactTableRow";

interface CompactTableLogsPanelProps {
  messages: FinalizedAnyMessageEnvelope[];
  playerMapping: Map<string, { seat: number; player_key: string }>;
  isOpen: boolean;
  onClose: () => void;
  variant?: "overlay" | "embedded";
}

/**
 * Hybrid table logs panel component
 * Combines debug page's table structure with developer console aesthetic
 *
 * Features:
 * - Table headers: SEQ | TIME | TYPE
 * - Solid dark background (#0a0e14)
 * - Cyan accent border (#00d9ff)
 * - LIVE indicator with pulsing dot
 * - Multi-line rows with expandable JSON
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
        backgroundColor: "#0a0e14",
        borderLeft: "2px solid #00d9ff", // Cyan accent
        borderTop: "1px solid #2d3748",
        borderRight: "1px solid #2d3748",
        borderBottom: "1px solid #2d3748",
        boxShadow: `
          inset 4px 0 12px rgba(0, 217, 255, 0.08),
          0 20px 50px rgba(0, 0, 0, 0.6)
        `,
      }}
    >
      {/* Header */}
      <header
        className="px-4 py-3 flex items-center justify-between shrink-0 border-b"
        style={{
          backgroundColor: "#0f1419",
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
            style={{ color: "#00d9ff" }}
          >
            ({messages.length})
          </span>
          {/* LIVE indicator */}
          <div
            className="flex items-center gap-1 text-xs"
            style={{ color: "#00d9ff" }}
          >
            <span
              className="w-2 h-2 rounded-full animate-pulse"
              style={{ backgroundColor: "#00d9ff" }}
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

      {/* Column Headers */}
      <div
        className="px-4 py-2 grid grid-cols-[40px_60px_1fr] gap-2 border-b text-xs font-semibold uppercase tracking-wider shrink-0"
        style={{
          backgroundColor: "#0f1419",
          borderColor: "#2d3748",
          color: "#64748b",
        }}
      >
        <div>SEQ</div>
        <div>TIME</div>
        <div>TYPE</div>
      </div>

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
              key={msg.snapshot_sequence_id}
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
