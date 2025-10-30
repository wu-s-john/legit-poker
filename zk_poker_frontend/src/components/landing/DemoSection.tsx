// components/landing/DemoSection.tsx

"use client";

import { useState, useMemo, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CompactTableLogsPanel } from "~/components/protocol-logs/CompactTableLogsPanel";
import { PokerTableSection } from "./PokerTableSection";
import type { DemoStreamEvent } from "~/lib/demo/events";
import type { FinalizedAnyMessageEnvelope } from "~/lib/schemas/finalizedEnvelopeSchema";

interface DemoSectionProps {
  isVisible: boolean;
}

/**
 * Interactive demo section for landing page
 * Shows poker table visualization + protocol logs side-by-side
 *
 * Layouts:
 * - Desktop (≥1280px): Side-by-side 920px table + 340px logs
 * - Tablet (768-1279px): Side-by-side 67% table + 33% logs
 * - Mobile (<768px): Stacked with floating "View Logs" button + modal
 */
export function DemoSection({ isVisible }: DemoSectionProps) {
  const [isDemoActive, setIsDemoActive] = useState(false);
  const [showLogModal, setShowLogModal] = useState(false);
  const [demoEvents, setDemoEvents] = useState<DemoStreamEvent[]>([]);

  const handleStartDemo = () => {
    setDemoEvents([]); // Clear previous events
    setIsDemoActive(true);
  };

  const handleDemoEvent = useCallback((event: DemoStreamEvent) => {
    console.log("[DemoSection] Received demo event:", event.type, event);
    setDemoEvents((prev) => [...prev, event]);
  }, []);

  // Convert demo events to format expected by CompactTableLogsPanel
  const messages: FinalizedAnyMessageEnvelope[] = useMemo(() => {
    return demoEvents
      .filter((e): e is Extract<DemoStreamEvent, { type: "game_event" }> => e.type === "game_event")
      .map((e) => ({
        envelope: e.envelope,
        snapshot_status: e.snapshot_status,
        applied_phase: e.applied_phase,
        snapshot_sequence_id: e.snapshot_sequence_id,
        created_timestamp: e.created_timestamp,
      }));
  }, [demoEvents]);

  // Extract player mapping from player_created events
  // Map: public_key -> { seat, player_key }
  const playerMapping = useMemo(() => {
    const map = new Map<string, { seat: number; player_key: string }>();
    demoEvents
      .filter((e): e is Extract<DemoStreamEvent, { type: "player_created" }> => e.type === "player_created")
      .forEach((e) => {
        map.set(e.public_key, {
          seat: e.seat,
          player_key: e.public_key,
        });
      });
    return map;
  }, [demoEvents]);

  // Track SSE status based on demo state
  const status = isDemoActive ? "connected" : "idle";
  const error = null; // EmbeddedDemoScene handles errors internally

  return (
    <div
      className={`mx-auto max-w-[1600px] px-4 transition-all duration-1000 sm:px-6 ${
        isVisible ? "translate-y-0 opacity-100" : "translate-y-10 opacity-0"
      }`}
    >
      <h2 className="mb-8 text-center text-2xl font-bold text-white sm:text-3xl md:mb-12 md:text-4xl">
        PLAY A HAND, WATCH IT PROVE ITSELF
      </h2>

      {/* Desktop/Tablet: Side-by-side layout */}
      <div className="flex flex-col gap-6 lg:flex-row">
        {/* Left: Poker Table - 2/3 width on desktop */}
        <div className="w-full lg:w-2/3">
          <PokerTableSection
            isDemoActive={isDemoActive}
            onStartDemo={handleStartDemo}
            sseStatus={status}
            onEvent={handleDemoEvent}
          />
        </div>

        {/* Right: Protocol Logs - 1/3 width on desktop */}
        {/* Hidden on mobile */}
        <div className="hidden md:block w-full lg:w-1/3">
          {isDemoActive ? (
            <CompactTableLogsPanel
              variant="embedded"
              messages={messages}
              playerMapping={playerMapping}
              isOpen={true}
              onClose={() => setIsDemoActive(false)}
            />
          ) : (
            /* Placeholder when demo not active */
            <div
              className="flex h-[600px] items-center justify-center rounded-xl border-2 p-8"
              style={{
                backgroundColor: "#0a0e14",
                borderColor: "#2d3748",
              }}
            >
              <div className="text-center">
                <p className="text-sm" style={{ color: "#94a3b8" }}>
                  Protocol logs will appear here
                </p>
                <p className="mt-2 text-xs" style={{ color: "#64748b" }}>
                  Click &quot;Start Demo&quot; to begin
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Mobile: Floating "View Logs" Button */}
      {isDemoActive && (
        <button
          onClick={() => setShowLogModal(true)}
          className="fixed right-6 bottom-6 z-50 flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium text-white shadow-lg md:hidden"
          style={{
            backgroundColor: "#3b82f6",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = "#2563eb";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = "#3b82f6";
          }}
        >
          <span>📋</span>
          <span>Logs ({messages.length})</span>
        </button>
      )}

      {/* Mobile: Logs Modal */}
      <AnimatePresence>
        {showLogModal && (
          <motion.div
            initial={{ y: "100%" }}
            animate={{ y: 0 }}
            exit={{ y: "100%" }}
            transition={{
              type: "spring",
              damping: 30,
              stiffness: 300,
            }}
            className="fixed inset-0 z-[999] md:hidden"
          >
            <CompactTableLogsPanel
              variant="overlay"
              messages={messages}
              playerMapping={playerMapping}
              isOpen={true}
              onClose={() => setShowLogModal(false)}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Subtitle */}
      <p className="text-primary-200 mt-6 text-center text-base md:mt-8 md:text-lg">
        Real poker. Real opponents. Mathematically guaranteed fairness.
      </p>

      {/* Error Display */}
      {error && (
        <div
          className="mt-4 rounded-lg border p-4 text-center"
          style={{
            backgroundColor: "rgba(239, 68, 68, 0.1)",
            borderColor: "#ef4444",
          }}
        >
          <p className="text-sm" style={{ color: "#ef4444" }}>
            {error}
          </p>
        </div>
      )}
    </div>
  );
}
