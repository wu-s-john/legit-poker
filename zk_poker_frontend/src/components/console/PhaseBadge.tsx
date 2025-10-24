// components/console/PhaseBadge.tsx

import type { PhaseConfig } from "~/lib/console/formatting";

interface PhaseBadgeProps {
  config: PhaseConfig;
}

export function PhaseBadge({ config }: PhaseBadgeProps) {
  return (
    <div
      className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium border whitespace-nowrap"
      style={{
        color: config.color,
        backgroundColor: config.bgColor,
        borderColor: config.borderColor,
      }}
    >
      <span>{config.label}</span>
    </div>
  );
}
