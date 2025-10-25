// components/protocol-logs/LogsToggle.tsx

"use client";

import { ChevronLeft } from "lucide-react";

interface LogsToggleProps {
  onClick: () => void;
  messageCount: number;
}

/**
 * Vertical tab button that appears on the right edge when logs panel is closed
 * Shows message count badge and expands on hover
 */
export function LogsToggle({ onClick, messageCount }: LogsToggleProps) {
  return (
    <button
      onClick={onClick}
      className="fixed right-0 z-[998]
                 lg:top-20 md:top-16 top-12
                 lg:w-16 lg:h-40 md:w-14 md:h-32 w-12 h-28
                 hover:lg:w-20 hover:md:w-16
                 rounded-l-lg shadow-xl transition-all duration-300
                 flex flex-col items-center justify-center gap-2 py-3"
      style={{
        backgroundColor: "var(--color-bg-card)",
        borderLeft: "1px solid var(--color-border-primary)",
        borderTop: "1px solid var(--color-border-primary)",
        borderBottom: "1px solid var(--color-border-primary)",
        color: "var(--color-text-primary)",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.boxShadow = "var(--shadow-card-hover)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.boxShadow = "var(--shadow-card)";
      }}
      aria-label="Open Protocol Logs"
    >
      {/* Vertical Text */}
      <div className="flex flex-col items-center gap-1">
        <span
          className="lg:text-sm md:text-xs text-xs font-medium whitespace-nowrap"
          style={{
            writingMode: "vertical-rl",
            textOrientation: "mixed",
          }}
        >
          Logs
        </span>

        {/* Message Count Badge */}
        {messageCount > 0 && (
          <span
            className="lg:text-xs text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center"
            style={{
              backgroundColor: "var(--color-accent-cyan)",
              color: "var(--color-bg-page)",
            }}
          >
            {messageCount > 99 ? "99+" : messageCount}
          </span>
        )}
      </div>

      {/* Chevron Icon */}
      <ChevronLeft
        className="lg:w-4 lg:h-4 md:w-3.5 md:h-3.5 w-3 h-3"
        style={{ color: "var(--color-accent-cyan)" }}
      />
    </button>
  );
}
