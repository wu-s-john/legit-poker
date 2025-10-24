// components/console/PhaseBadge.tsx

import type { PhaseConfig } from "~/lib/console/formatting";

interface PhaseBadgeProps {
  config: PhaseConfig;
}

export function PhaseBadge({ config }: PhaseBadgeProps) {
  return (
    <div
      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border"
      style={{
        color: config.color,
        backgroundColor: config.bgColor,
        borderColor: config.borderColor,
      }}
    >
      <span>{config.icon}</span>
      <span>{config.label}</span>
    </div>
  );
}
