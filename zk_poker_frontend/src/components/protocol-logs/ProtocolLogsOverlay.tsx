// components/protocol-logs/ProtocolLogsOverlay.tsx

"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useDemoStream } from "~/hooks/useDemoStream";
import { CompactLogsPanel } from "./CompactLogsPanel";
import { LogsToggle } from "./LogsToggle";

/**
 * Main overlay orchestrator component
 * Manages SSE connection, panel visibility, and animations
 */
export function ProtocolLogsOverlay() {
  const [isOpen, setIsOpen] = useState(false);
  const { messages, playerMapping, status, error } = useDemoStream();

  return (
    <>
      {/* Toggle Button (only when closed) */}
      {!isOpen && (
        <LogsToggle
          onClick={() => setIsOpen(true)}
          messageCount={messages.length}
        />
      )}

      {/* Panel with Backdrop */}
      <AnimatePresence>
        {isOpen && (
          <>
            {/* Backdrop (desktop/tablet only - hidden on mobile) */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              onClick={() => setIsOpen(false)}
              className="hidden lg:block fixed inset-0 z-[998]"
              style={{
                backgroundColor: "rgba(0, 0, 0, 0.6)",
                backdropFilter: "blur(4px)",
              }}
            />

            {/* Side Panel - Desktop/Tablet (slide from right) */}
            <motion.div
              initial={{ x: "100%" }}
              animate={{ x: 0 }}
              exit={{ x: "100%" }}
              transition={{
                type: "spring",
                damping: 30,
                stiffness: 300,
              }}
              className="hidden md:block"
            >
              <CompactLogsPanel
                messages={messages}
                playerMapping={playerMapping}
                isOpen={isOpen}
                onClose={() => setIsOpen(false)}
              />
            </motion.div>

            {/* Full Screen Overlay - Mobile (slide from bottom) */}
            <motion.div
              initial={{ y: "100%" }}
              animate={{ y: 0 }}
              exit={{ y: "100%" }}
              transition={{
                type: "spring",
                damping: 30,
                stiffness: 300,
              }}
              className="md:hidden"
            >
              <CompactLogsPanel
                messages={messages}
                playerMapping={playerMapping}
                isOpen={isOpen}
                onClose={() => setIsOpen(false)}
              />
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Connection Status Indicator (optional - for debugging) */}
      {status === "error" && error && (
        <div
          className="fixed bottom-4 right-4 z-[1000] px-4 py-2 rounded-lg shadow-lg text-sm"
          style={{
            backgroundColor: "var(--color-accent-red)",
            color: "white",
          }}
        >
          {error}
        </div>
      )}
    </>
  );
}
