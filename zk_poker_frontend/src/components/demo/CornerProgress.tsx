/**
 * Corner Progress - Persistent progress indicator in top-right corner
 */

import React from 'react';

interface CornerProgressProps {
  totalCards: number; // Total cards to be dealt (e.g., 12 for 6 players × 2 cards)
  cardsDealt: number; // Cards dealt so far
}

export function CornerProgress({ totalCards, cardsDealt }: CornerProgressProps) {
  const progress = totalCards > 0 ? (cardsDealt / totalCards) * 100 : 0;

  return (
    <div className="corner-progress">
      {/* Glass card */}
      <div className="corner-progress-card">
        {/* Icon */}
        <div className="corner-progress-icon">
          <span>🃏</span>
        </div>

        {/* Stats */}
        <div className="corner-progress-stats">
          <div className="corner-progress-label">Cards Dealt</div>
          <div className="corner-progress-count">
            {cardsDealt} / {totalCards}
          </div>
        </div>

        {/* Mini progress bar */}
        <div className="corner-progress-bar">
          <div className="corner-progress-track">
            <div
              className="corner-progress-fill"
              style={{
                width: `${progress}%`,
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
