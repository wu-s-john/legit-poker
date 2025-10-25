// components/protocol-logs/PhaseBadgeCompact.tsx

import type { PhaseConfig } from "~/lib/console/formatting";

interface PhaseBadgeCompactProps {
  config: PhaseConfig;
}

/**
 * Get emoji for phase label
 */
function getPhaseEmoji(label: string): string {
  const emojiMap: Record<string, string> = {
    "Shuffle": "🔵",
    "Blinding Share": "🟢",
    "Unblinding Share": "🟣",
    "Bet": "🟡",
    "Showdown": "🔴",
  };
  return emojiMap[label] || "⚪";
}

/**
 * Compact phase badge with emoji for multi-line card layouts
 */
export function PhaseBadgeCompact({ config }: PhaseBadgeCompactProps) {
  return (
    <div
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium whitespace-nowrap"
      style={{
        color: config.color,
        backgroundColor: config.bgColor,
        borderColor: config.borderColor,
      }}
    >
      <span>{getPhaseEmoji(config.label)}</span>
      <span>{config.label}</span>
    </div>
  );
}
