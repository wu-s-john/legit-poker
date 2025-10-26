// components/protocol-logs/StatusBadge.tsx

import type { SnapshotStatus } from "~/lib/schemas/finalizedEnvelopeSchema";

interface StatusBadgeProps {
  status: SnapshotStatus;
}

/**
 * Compact status indicator for multi-line card metadata
 */
export function StatusBadge({ status }: StatusBadgeProps) {
  // Success status
  if (status === "success") {
    return (
      <span
        className="font-medium"
        style={{ color: "var(--color-accent-green)" }}
      >
        ✓ Success
      </span>
    );
  }

  // Failure status with error message in title tooltip
  if (typeof status === "object" && "failure" in status) {
    return (
      <span
        className="cursor-help font-medium"
        style={{ color: "var(--color-accent-red)" }}
        title={status.failure}
      >
        ✗ Failed
      </span>
    );
  }

  // Unknown status
  return (
    <span className="font-medium" style={{ color: "var(--color-accent-gold)" }}>
      {status}
    </span>
  );
}
