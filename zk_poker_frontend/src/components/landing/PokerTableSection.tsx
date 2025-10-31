// components/landing/PokerTableSection.tsx

"use client";

import { Spade, Play } from "lucide-react";
import { InteractiveDemoScene } from "~/components/demo/InteractiveDemoScene";
import type { DemoStreamEvent } from "~/lib/demo/events";

interface PokerTableSectionProps {
  isDemoActive: boolean;
  onStartDemo: () => void;
  sseStatus: "idle" | "connecting" | "connected" | "error" | "completed";
  onEvent?: (event: DemoStreamEvent) => void;
}

/**
 * Poker table section for landing page demo
 *
 * States:
 * - Before demo: Green felt with "Start Demo" button
 * - After demo: Placeholder visualization with SSE status
 */
export function PokerTableSection({
  isDemoActive,
  onStartDemo,
  sseStatus,
  onEvent,
}: PokerTableSectionProps) {
  // Determine button state based on SSE status
  const isConnecting = sseStatus === "connecting";
  const isActive = isDemoActive && (sseStatus === "connected" || sseStatus === "completed");
  const hasError = sseStatus === "error";
  const canStartDemo = !isDemoActive && sseStatus === "idle";

  return (
    <div
      className="rounded-xl md:rounded-2xl border-2 md:border-4 p-4 md:p-8 flex items-center justify-center overflow-hidden"
      style={{
        background: "linear-gradient(135deg, #0a4d3c 0%, #084a38 50%, #063d2f 100%)",
        borderColor: "var(--color-table-border)", // #1e3a5f
        height: '600px', // Fixed height to match logs panel
        position: 'relative', // Positioning context for absolute overlays
      }}
    >
      {!isDemoActive ? (
        /* Initial State: Start Demo Button */
        <div className="text-center">
          <Spade className="mx-auto mb-6 h-12 w-12 md:h-16 md:w-16 text-white/80" />
          <h3 className="mb-4 text-xl md:text-2xl font-semibold text-white">
            Interactive Poker Table
          </h3>
          <p className="mb-8 text-xs md:text-sm text-white/70">
            Watch cryptographic shuffling in real-time
          </p>

          {/* Button with loading state */}
          <button
            onClick={onStartDemo}
            disabled={!canStartDemo || isConnecting}
            className="flex items-center gap-2 mx-auto px-6 md:px-8 py-2 md:py-3 text-sm md:text-base font-semibold text-white rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed hover:scale-105 active:scale-95 disabled:hover:scale-100"
            style={{
              backgroundColor: isConnecting ? "#94a3b8" : "#3b82f6",
            }}
            onMouseEnter={(e) => {
              if (!isConnecting) {
                e.currentTarget.style.backgroundColor = "#2563eb";
              }
            }}
            onMouseLeave={(e) => {
              if (!isConnecting) {
                e.currentTarget.style.backgroundColor = "#3b82f6";
              }
            }}
          >
            {isConnecting ? (
              <>
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Connecting...
              </>
            ) : (
              <>
                <Play size={20} />
                Start Demo
              </>
            )}
          </button>

          {/* Error message */}
          {hasError && (
            <p className="mt-4 text-xs text-red-400">
              Failed to connect. Please check backend server.
            </p>
          )}
        </div>
      ) : (
        /* Active State: Live Demo Scene */
        <InteractiveDemoScene
          isActive={isDemoActive}
          onEvent={onEvent}
          showBackground={false}
          containerStyle={{
            width: '100%',
            // Fill the entire felt area (including padding) for overlays
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
          }}
        />
      )}
    </div>
  );
}
