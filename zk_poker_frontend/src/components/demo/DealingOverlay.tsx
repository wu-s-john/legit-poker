/**
 * Dealing Overlay - Phase 2 overlay showing card dealing progress
 */

import React from 'react';

interface DealingOverlayProps {
  isVisible: boolean;
  currentPlayer?: number;
  playerName?: string;
}

export function DealingOverlay({ isVisible, currentPlayer, playerName }: DealingOverlayProps) {
  if (!isVisible) return null;

  return (
    <div className="dealing-overlay" style={{ position: 'absolute', top: 0, left: 0, right: 0, zIndex: 50 }}>
      {/* Chapter header */}
      <div
        className="chapter-header"
        style={{
          textAlign: 'center',
          padding: '32px 0 16px',
          animation: 'slideInFromTop 600ms ease-out',
        }}
      >
        <div
          className="chapter-badge"
          style={{
            display: 'inline-flex',
            padding: '4px 12px',
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            borderRadius: '6px',
            marginBottom: '16px',
          }}
        >
          <span
            style={{
              fontSize: '10px',
              fontWeight: 600,
              color: '#10b981',
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
            }}
          >
            CHAPTER 2
          </span>
        </div>

        <h2
          className="phase-title"
          style={{
            fontSize: '32px',
            fontWeight: 700,
            color: 'rgba(255, 255, 255, 0.95)',
            marginBottom: '12px',
            letterSpacing: '-0.02em',
          }}
        >
          DEALING HOLE CARDS
        </h2>

        {currentPlayer !== undefined && playerName && (
          <p
            className="dealing-status"
            style={{
              fontSize: '16px',
              color: 'rgba(255, 255, 255, 0.7)',
            }}
          >
            Dealing to {playerName}...
          </p>
        )}
      </div>
    </div>
  );
}
