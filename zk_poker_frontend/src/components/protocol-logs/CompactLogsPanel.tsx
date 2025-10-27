// components/protocol-logs/CompactLogsPanel.tsx

"use client";

import { useRef, useEffect } from "react";
import type { FinalizedAnyMessageEnvelope } from "~/lib/schemas/finalizedEnvelopeSchema";
import { CompactMessageRow } from "./CompactMessageRow";

interface CompactLogsPanelProps {
  messages: FinalizedAnyMessageEnvelope[];
  playerMapping: Map<string, { seat: number; player_key: string }>;
  isOpen: boolean;
  onClose: () => void;
}

/**
 * Panel component that displays protocol logs as a scrollable list of cards
 * Designed for side panel overlay layout (25-33% width)
 */
export function CompactLogsPanel({
  messages,
  playerMapping,
  isOpen: _isOpen,
  onClose,
}: CompactLogsPanelProps) {
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to top when new message arrives (newest first)
  useEffect(() => {
    if (scrollContainerRef.current && messages.length > 0) {
      scrollContainerRef.current.scrollTop = 0;
    }
  }, [messages.length]);

  return (
    <div
      className="fixed top-0 right-0 z-[999] flex h-screen w-full flex-col md:w-[250px] lg:w-[425px]"
      style={{
        backgroundColor: "var(--color-bg-card)",
        borderLeft: "1px solid var(--color-border-primary)",
        boxShadow: "var(--shadow-card)",
        backdropFilter: "blur(24px)",
      }}
    >
      {/* Header */}
      <header
        className="flex shrink-0 items-center justify-between px-4 py-3"
        style={{
          backgroundColor: "var(--color-bg-card-header)",
          borderBottom: "1px solid var(--color-border-primary)",
        }}
      >
        <h2
          className="text-sm font-semibold"
          style={{ color: "var(--color-text-primary)" }}
        >
          Protocol Logs
          <span className="ml-2" style={{ color: "var(--color-accent-cyan)" }}>
            ({messages.length})
          </span>
        </h2>
        <button
          onClick={onClose}
          className="hover:bg-opacity-80 rounded-lg p-1 transition-colors"
          style={{
            color: "var(--color-text-secondary)",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor =
              "var(--color-bg-button-hover)";
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
          scrollbarColor: "var(--color-border-primary) transparent",
        }}
      >
        {messages.length === 0 ? (
          <div
            className="px-4 py-12 text-center text-sm"
            style={{ color: "var(--color-text-secondary)" }}
          >
            <div className="mb-2">⏳</div>
            <div>Waiting for protocol messages...</div>
            <div
              className="mt-2 text-xs"
              style={{ color: "var(--color-text-muted)" }}
            >
              Messages will appear here as they stream in
            </div>
          </div>
        ) : (
          messages
            .slice()
            .reverse()
            .map((msg) => (
              <CompactMessageRow
                key={`${msg.envelope.hand_id}-${msg.snapshot_sequence_id}`}
                message={msg}
                viewerPublicKey="placeholder_viewer_key"
                playerMapping={playerMapping}
              />
            ))
        )}
      </div>
    </div>
  );
}
