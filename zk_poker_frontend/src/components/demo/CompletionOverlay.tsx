/**
 * Completion Overlay - Shows hand results and quality label
 */

'use client';

import React from 'react';
import type { Card as CardType } from '~/types/poker';
import { labelHand } from '~/lib/demo/handLabels';
import { Card } from './Card';

interface CompletionOverlayProps {
  isVisible: boolean;
  viewerCards: CardType[];
  onNewHand?: () => void;
}

const TIER_COLORS = {
  premium: '#10b981', // Green
  strong: '#3b82f6', // Blue
  playable: '#8b5cf6', // Purple
  marginal: '#64748b', // Gray
};

const TIER_BACKGROUNDS = {
  premium: 'rgba(16, 185, 129, 0.1)',
  strong: 'rgba(59, 130, 246, 0.1)',
  playable: 'rgba(139, 92, 246, 0.1)',
  marginal: 'rgba(100, 116, 139, 0.1)',
};

export function CompletionOverlay({ isVisible, viewerCards, onNewHand }: CompletionOverlayProps) {
  const [isAnimated, setIsAnimated] = React.useState(false);

  React.useEffect(() => {
    if (isVisible) {
      const timer = setTimeout(() => setIsAnimated(true), 100);
      return () => clearTimeout(timer);
    } else {
      setIsAnimated(false);
    }
  }, [isVisible]);

  if (!isVisible) return null;

  // Get hand label if we have both cards
  const handLabel = viewerCards.length === 2 ? labelHand(viewerCards[0], viewerCards[1]) : null;

  return (
    <div
      className="completion-overlay"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(0, 0, 0, 0.85)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 100,
        backdropFilter: 'blur(8px)',
        opacity: isAnimated ? 1 : 0,
        transition: 'opacity 400ms ease-out',
      }}
    >
      <div
        className="completion-card"
        style={{
          background: 'linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 35, 0.95))',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          borderRadius: '24px',
          padding: '48px',
          maxWidth: '600px',
          textAlign: 'center',
          transform: isAnimated ? 'scale(1) translateY(0)' : 'scale(0.9) translateY(20px)',
          transition: 'all 400ms cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      >
        {/* Chapter header */}
        <div
          className="chapter-badge"
          style={{
            display: 'inline-flex',
            padding: '6px 14px',
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            borderRadius: '8px',
            marginBottom: '24px',
          }}
        >
          <span
            style={{
              fontSize: '11px',
              fontWeight: 600,
              color: '#10b981',
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
            }}
          >
            HAND COMPLETE
          </span>
        </div>

        {/* Title */}
        <h2
          style={{
            fontSize: '36px',
            fontWeight: 700,
            color: 'rgba(255, 255, 255, 0.95)',
            marginBottom: '32px',
            letterSpacing: '-0.02em',
          }}
        >
          Your Hand
        </h2>

        {/* Cards Display */}
        <div
          style={{
            display: 'flex',
            gap: '24px',
            justifyContent: 'center',
            marginBottom: '32px',
          }}
        >
          {viewerCards.map((card, idx) => (
            <div
              key={idx}
              style={{
                transform: isAnimated ? 'scale(1)' : 'scale(0.8)',
                opacity: isAnimated ? 1 : 0,
                transition: `all 400ms cubic-bezier(0.4, 0, 0.2, 1) ${idx * 100}ms`,
              }}
            >
              <Card card={card} revealed={true} size="large" />
            </div>
          ))}
        </div>

        {/* Hand Label */}
        {handLabel && (
          <div
            className="hand-quality"
            style={{
              padding: '20px 32px',
              background: TIER_BACKGROUNDS[handLabel.tier],
              border: `1px solid ${TIER_COLORS[handLabel.tier]}33`,
              borderRadius: '12px',
              marginBottom: '32px',
            }}
          >
            <div
              style={{
                fontSize: '18px',
                fontWeight: 600,
                color: TIER_COLORS[handLabel.tier],
                marginBottom: '4px',
              }}
            >
              {handLabel.label}
            </div>
            <div
              style={{
                fontSize: '12px',
                color: 'rgba(255, 255, 255, 0.5)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              {handLabel.tier} hand
            </div>
          </div>
        )}

        {/* Action Button */}
        {onNewHand && (
          <button
            onClick={onNewHand}
            style={{
              padding: '14px 32px',
              background: 'linear-gradient(135deg, #10b981, #059669)',
              border: 'none',
              borderRadius: '10px',
              color: 'white',
              fontSize: '15px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 200ms ease',
              boxShadow: '0 4px 12px rgba(16, 185, 129, 0.3)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 6px 16px rgba(16, 185, 129, 0.4)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 4px 12px rgba(16, 185, 129, 0.3)';
            }}
          >
            Start New Hand
          </button>
        )}

        {/* Footer Message */}
        <p
          style={{
            marginTop: '24px',
            fontSize: '13px',
            color: 'rgba(255, 255, 255, 0.4)',
            lineHeight: '1.6',
          }}
        >
          All cards were dealt using zero-knowledge mental poker.
          <br />
          No central dealer. Provably fair.
        </p>
      </div>
    </div>
  );
}
