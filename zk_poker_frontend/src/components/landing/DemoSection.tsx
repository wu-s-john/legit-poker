// components/landing/DemoSection.tsx

"use client";

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CompactTableLogsPanel } from "~/components/protocol-logs/CompactTableLogsPanel";
import { PokerTableSection } from "./PokerTableSection";
import type { DemoStreamEvent } from "~/lib/demo/events";
import type { FinalizedAnyMessageEnvelope } from "~/lib/finalizedEnvelopeSchema";

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

  const handleDemoEvent = (event: DemoStreamEvent) => {
    setDemoEvents((prev) => [...prev, event]);
  };

  // Convert demo events to format expected by CompactTableLogsPanel
  const messages: FinalizedAnyMessageEnvelope[] = useMemo(() => {
    return demoEvents
      .filter((e) => e.type === 'game_event')
      .map((e) => e.envelope);
  }, [demoEvents]);

  // Extract player mapping from player_created events
  const playerMapping: Record<number, string> = useMemo(() => {
    return demoEvents
      .filter((e) => e.type === 'player_created')
      .reduce((acc, e) => {
        acc[e.seat] = e.display_name;
        return acc;
      }, {} as Record<number, string>);
  }, [demoEvents]);

  // Track SSE status based on demo state
  const status = isDemoActive ? 'connected' : 'idle';
  const error = null; // EmbeddedDemoScene handles errors internally

  return (
    <div
      className={`mx-auto max-w-6xl px-4 sm:px-6 transition-all duration-1000 ${
        isVisible ? "translate-y-0 opacity-100" : "translate-y-10 opacity-0"
      }`}
    >
      <h2 className="mb-8 text-center text-2xl font-bold text-white sm:text-3xl md:mb-12 md:text-4xl">
        PLAY A HAND, WATCH IT PROVE ITSELF
      </h2>

      {/* Desktop/Tablet: Side-by-side layout */}
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Left: Poker Table - 1600px desktop, 67% tablet */}
        <div className="flex-1 lg:max-w-[1600px]">
          <PokerTableSection
            isDemoActive={isDemoActive}
            onStartDemo={handleStartDemo}
            sseStatus={status}
            onEvent={handleDemoEvent}
          />
        </div>

        {/* Right: Protocol Logs - 340px desktop (26%), 33% tablet */}
        {/* Hidden on mobile */}
        <div className="hidden md:block lg:w-[340px] md:w-1/3">
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
              className="h-[600px] flex items-center justify-center rounded-xl border-2 p-8"
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
                  Click "Start Demo" to begin
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
          className="md:hidden fixed bottom-6 right-6 z-50 px-4 py-2 rounded-lg shadow-lg font-medium text-sm text-white flex items-center gap-2"
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
            className="md:hidden fixed inset-0 z-[999]"
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
        <div className="mt-4 rounded-lg border p-4 text-center" style={{
          backgroundColor: "rgba(239, 68, 68, 0.1)",
          borderColor: "#ef4444",
        }}>
          <p className="text-sm" style={{ color: "#ef4444" }}>
            {error}
          </p>
        </div>
      )}
    </div>
  );
}
