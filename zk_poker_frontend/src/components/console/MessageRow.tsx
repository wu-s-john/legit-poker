// components/console/MessageRow.tsx

"use client";

import { useState } from "react";
import type { FinalizedAnyMessageEnvelope } from "~/lib/console/schemas";
import {
  formatActor,
  formatMessageSummary,
  getPhaseConfig,
  isViewerActor,
} from "~/lib/console/formatting";
import { PhaseBadge } from "./PhaseBadge";
import { CopyButton } from "./CopyButton";
import JsonView from "react18-json-view";
import "react18-json-view/src/style.css";

interface MessageRowProps {
  message: FinalizedAnyMessageEnvelope;
  sequenceNumber: number;
  viewerPublicKey: string;
}

export function MessageRow({
  message,
  sequenceNumber,
  viewerPublicKey,
}: MessageRowProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const summary = formatMessageSummary(message.envelope.message.value);
  const phaseConfig = getPhaseConfig(
    message.applied_phase,
    message.envelope.message.value,
  );

  // Format timestamp to user's locale
  const formattedTimestamp = new Date(message.created_timestamp).toLocaleString(
    undefined,
    {
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    }
  );

  return (
    <div
      className="border-b transition-colors"
      style={{
        borderColor: "var(--color-border-subtle)",
        backgroundColor: isExpanded
          ? "var(--color-bg-expanded)"
          : "transparent",
      }}
      onMouseEnter={(e) => {
        if (!isExpanded) {
          e.currentTarget.style.backgroundColor = "var(--color-bg-row-hover)";
        }
      }}
      onMouseLeave={(e) => {
        if (!isExpanded) {
          e.currentTarget.style.backgroundColor = "transparent";
        }
      }}
    >
      {/* Main row */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-6 py-3 text-left grid grid-cols-[24px_60px_180px_200px_1fr] gap-4 items-center"
      >
        {/* Expand indicator */}
        <div
          className="flex items-center justify-center text-sm transition-transform"
          style={{
            color: "var(--color-text-muted)",
            transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)",
          }}
        >
          ▶
        </div>

        {/* Sequence ID */}
        <div
          className="text-sm font-mono"
          style={{ color: "var(--color-text-muted)" }}
        >
          #{sequenceNumber}
        </div>

        {/* Timestamp */}
        <div
          className="text-xs font-mono"
          style={{ color: "var(--color-text-secondary)" }}
        >
          {formattedTimestamp}
        </div>

        {/* Phase Badge */}
        <div className="flex justify-start">
          <PhaseBadge config={phaseConfig} />
        </div>

        {/* Summary */}
        <div
          className="text-sm"
          style={{ color: "var(--color-text-primary)" }}
        >
          {summary}
        </div>
      </button>

      {/* Expanded payload section */}
      {isExpanded && (
        <div
          className="px-6 pb-4 border-t"
          style={{
            borderColor: "var(--color-border-payload)",
            backgroundColor: "var(--color-bg-expanded)",
            boxShadow: "var(--shadow-inset-payload)",
          }}
        >
          <div className="pt-4 space-y-3">
            {/* Metadata row */}
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-6">
                <div>
                  <span style={{ color: "var(--color-text-muted)" }}>
                    Nonce:{" "}
                  </span>
                  <span
                    className="font-mono"
                    style={{ color: "var(--color-text-secondary)" }}
                  >
                    {message.envelope.nonce}
                  </span>
                </div>
                <div>
                  <span style={{ color: "var(--color-text-muted)" }}>
                    Status:{" "}
                  </span>
                  <span
                    className="font-medium"
                    style={{
                      color:
                        message.snapshot_status === "success"
                          ? "var(--color-accent-green)"
                          : typeof message.snapshot_status === "object" && "failure" in message.snapshot_status
                            ? "var(--color-accent-red)"
                            : "var(--color-accent-gold)",
                    }}
                  >
                    {message.snapshot_status === "success"
                      ? "Success"
                      : typeof message.snapshot_status === "object" && "failure" in message.snapshot_status
                        ? `Failed: ${message.snapshot_status.failure}`
                        : message.snapshot_status}
                  </span>
                </div>
              </div>

              <CopyButton
                text={JSON.stringify(message.envelope.message, null, 2)}
                label="Copy Payload"
              />
            </div>

            {/* JSON payload */}
            <div
              className="rounded-lg overflow-auto"
              style={{
                backgroundColor: "oklch(from black l c h / 0.3)",
                border: "1px solid var(--color-border-payload)",
                maxHeight: "400px",
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <JsonView
                src={message.envelope.message.value}
                theme="vscode"
                collapsed={2}
                enableClipboard={true}
                displayDataTypes={false}
                collapseStringsAfterLength={60}
                matchesURL={true}
                style={{
                  padding: "16px",
                  fontSize: "12px",
                  fontFamily: "ui-monospace, monospace",
                  backgroundColor: "transparent",
                }}
              />
            </div>

            {/* Signature row */}
            <div>
              <span
                className="text-xs"
                style={{ color: "var(--color-text-muted)" }}
              >
                Signature:{" "}
              </span>
              <code
                className="text-xs font-mono break-all"
                style={{ color: "var(--color-text-secondary)" }}
              >
                {message.envelope.signature}
              </code>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

