import { Check } from 'lucide-react';

interface DecryptableBadgeProps {
  visible: boolean;
  isViewer: boolean;
  size: 'small' | 'medium' | 'large';
  className?: string;
}

/**
 * Badge indicating a card is decryptable/verified
 *
 * Shows a checkmark icon with color coding:
 * - Gold for viewer's cards
 * - Green for other players' cards
 *
 * Scales proportionally with card size for visual hierarchy.
 */
export function DecryptableBadge({
  visible,
  isViewer,
  size,
  className = '',
}: DecryptableBadgeProps) {
  if (!visible) return null;

  // Proportional sizing based on card size
  const dimensions = {
    small: { badge: 16, icon: 12 },
    medium: { badge: 20, icon: 14 },
    large: { badge: 24, icon: 16 },
  }[size];

  // Color scheme: gold for viewer, green for others
  const colors = isViewer
    ? {
        background: 'rgba(251, 191, 36, 0.9)', // amber-400
        glow: 'rgba(251, 191, 36, 0.6)',
      }
    : {
        background: 'rgba(16, 185, 129, 0.9)', // emerald-500
        glow: 'rgba(16, 185, 129, 0.6)',
      };

  return (
    <div
      className={`decryptable-badge ${className}`}
      style={{
        position: 'absolute',
        top: '4px',
        right: '4px',
        width: `${dimensions.badge}px`,
        height: `${dimensions.badge}px`,
        borderRadius: '50%',
        background: colors.background,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 10,
        animation: 'fadeIn 0.3s ease-out',
        boxShadow: `0 0 8px ${colors.glow}`,
      }}
      role="status"
      aria-label="Card verified and decryptable"
    >
      <Check size={dimensions.icon} color="white" strokeWidth={3} />
    </div>
  );
}
