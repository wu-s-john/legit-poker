// components/protocol-logs/ExpandedMessageSection.tsx

"use client";

import { useState } from "react";
import type { FinalizedAnyMessageEnvelope, AnyGameMessage } from "~/lib/console/schemas";
import {
  isShuffleMessage,
  isBlindingMessage,
  isPartialUnblindingMessage,
} from "~/lib/console/formatting";
import { CopyButton } from "~/components/console/CopyButton";
import JsonView from "react18-json-view";
import "react18-json-view/src/style.css";
import { StatusBadge } from "./StatusBadge";

interface ExpandedMessageSectionProps {
  message: FinalizedAnyMessageEnvelope;
}

type VerificationState =
  | { status: "idle" }
  | { status: "verifying"; startTime: number }
  | { status: "success"; duration: number }
  | { status: "failed"; duration: number; error: string };

type VerificationResult =
  | { success: true; duration: number }
  | { success: false; duration: number; error: string };

// Helper: Check if message has verifiable proof
function hasVerifiableProof(message: AnyGameMessage): boolean {
  return (
    isShuffleMessage(message) ||
    isBlindingMessage(message) ||
    isPartialUnblindingMessage(message)
  );
}

// Helper: Format duration for display
function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  } else if (ms < 60000) {
    return `${(ms / 1000).toFixed(2)}s`;
  } else {
    const minutes = Math.floor(ms / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  }
}

// Stub verification function (0-150ms random delay)
async function verifyProof(message: AnyGameMessage): Promise<VerificationResult> {
  const delay = Math.floor(Math.random() * 151);
  const startTime = performance.now();

  await new Promise((resolve) => setTimeout(resolve, delay));

  const duration = Math.round(performance.now() - startTime);

  // Stub: always succeed for now
  return { success: true, duration };
}

// VerifyProofButton component
function VerifyProofButton({ message }: { message: AnyGameMessage }) {
  const [state, setState] = useState<VerificationState>({ status: "idle" });

  const handleVerify = async () => {
    if (state.status !== "idle") return;

    const verifyStartTime = performance.now();
    setState({ status: "verifying", startTime: verifyStartTime });

    try {
      const result = await verifyProof(message);

      if (result.success) {
        setState({ status: "success", duration: result.duration });
      } else {
        setState({
          status: "failed",
          duration: result.duration,
          error: result.error,
        });
      }
    } catch (error) {
      const duration = Math.round(performance.now() - verifyStartTime);
      setState({
        status: "failed",
        duration,
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  };

  // Idle state - button
  if (state.status === "idle") {
    return (
      <button
        onClick={handleVerify}
        className="px-3 py-1 text-xs rounded-md transition-colors hover:bg-opacity-80"
        style={{
          backgroundColor: "var(--color-bg-button)",
          color: "var(--color-text-secondary)",
          border: "1px solid var(--color-border-subtle)",
        }}
      >
        Verify Proof
      </button>
    );
  }

  // Verifying state - button with spinner
  if (state.status === "verifying") {
    return (
      <div
        className="px-3 py-1 text-xs rounded-md flex items-center gap-1.5"
        style={{
          backgroundColor: "oklch(from cyan l c h / 0.15)",
          color: "var(--color-accent-cyan)",
          border: "1px solid var(--color-accent-cyan)",
        }}
      >
        <span className="animate-spin">⏳</span>
        <span>Verifying...</span>
      </div>
    );
  }

  // Success state - badge
  if (state.status === "success") {
    return (
      <div
        className="px-3 py-1 text-xs rounded-md font-medium"
        style={{
          backgroundColor: "oklch(from green l c h / 0.15)",
          color: "var(--color-accent-green)",
          border: "1px solid var(--color-accent-green)",
        }}
      >
        ✓ Verified in {formatDuration(state.duration)}
      </div>
    );
  }

  // Failed state - badge with hover tooltip
  return (
    <div
      className="px-3 py-1 text-xs rounded-md font-medium cursor-help"
      style={{
        backgroundColor: "oklch(from red l c h / 0.15)",
        color: "var(--color-accent-red)",
        border: "1px solid var(--color-accent-red)",
      }}
      title={state.error}
    >
      ✗ Failed in {formatDuration(state.duration)}
    </div>
  );
}

function SignatureDisplay({ signature }: { signature: string }) {
  const [isExpanded, setIsExpanded] = useState(false);

  // Truncate: show first 10 chars (including 0x) and last 6 chars
  const truncated =
    signature.length > 18
      ? `${signature.slice(0, 10)}...${signature.slice(-6)}`
      : signature;

  return (
    <div className="flex items-center gap-2">
      <span className="text-xs" style={{ color: "var(--color-text-muted)" }}>
        Signature:{" "}
      </span>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="text-xs font-mono hover:underline transition-colors"
        style={{ color: "var(--color-text-secondary)" }}
      >
        {isExpanded ? signature : truncated}
      </button>
      <CopyButton text={signature} label="" />
    </div>
  );
}

/**
 * Reusable expanded message section (extracted from MessageRow.tsx)
 * Shows metadata, JSON payload, and signature
 */
export function ExpandedMessageSection({ message }: ExpandedMessageSectionProps) {
  return (
    <div className="pt-4 space-y-4">
      {/* Row 1: Metadata + Actions */}
      <div
        className="flex items-center justify-between text-xs pb-3"
        style={{ borderBottom: "1px solid var(--color-border-subtle)" }}
      >
        {/* Left: Metadata */}
        <div className="flex items-center gap-4">
          <div>
            <span style={{ color: "var(--color-text-muted)" }}>Nonce: </span>
            <span
              className="font-mono"
              style={{ color: "var(--color-text-secondary)" }}
            >
              {message.envelope.nonce}
            </span>
          </div>
          <span style={{ color: "var(--color-text-muted)" }}>•</span>
          <div>
            <span style={{ color: "var(--color-text-muted)" }}>Status: </span>
            <StatusBadge status={message.snapshot_status} />
          </div>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-2">
          {hasVerifiableProof(message.envelope.message.value) && (
            <VerifyProofButton message={message.envelope.message.value} />
          )}
          <CopyButton
            text={JSON.stringify(message.envelope.message, null, 2)}
            label="Copy Payload"
          />
        </div>
      </div>

      {/* Row 2: Payload (dominant) */}
      <div
        className="rounded-lg overflow-auto"
        style={{
          backgroundColor: "#0a0e14",
          border: "1px solid var(--color-border-payload)",
          maxHeight: "400px",
          boxShadow: "inset 0 2px 8px rgba(0, 0, 0, 0.4)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <JsonView
          src={message.envelope.message.value as any}
          dark={true}
          collapsed={2}
          enableClipboard={true}
          displayDataTypes={false}
          displayArrayIndex={false}
          collapseStringsAfterLength={60}
          matchesURL={true}
          style={{
            padding: "16px",
            fontSize: "12px",
            fontFamily: "ui-monospace, monospace",
            backgroundColor: "transparent",
            lineHeight: "1.6",
            color: "#FFD700", // Gold for brackets/punctuation
            "--json-property": "#9CDCFE", // Cyan for keys
            "--json-string": "#CE9178", // Peach for strings
            "--json-number": "#B5CEA8", // Green for numbers
            "--json-boolean": "#569CD6", // Blue for booleans
            "--json-null": "#808080", // Gray for null
            "--json-index": "#FFD700", // Gold for array indices
            "--json-ellipsis": "#94a3b8", // Gray for collapsed ellipsis {...}
          } as React.CSSProperties}
        />
      </div>

      {/* Row 3: Signature (footer) */}
      <div
        className="pt-3"
        style={{ borderTop: "1px solid var(--color-border-subtle)" }}
      >
        <SignatureDisplay signature={message.envelope.message.signature} />
      </div>
    </div>
  );
}
