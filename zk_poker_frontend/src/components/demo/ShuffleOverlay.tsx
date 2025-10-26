/**
 * Shuffle Overlay - Phase 1 overlay showing cryptographic shuffle progress
 */

import React from 'react';
import { ProgressBar } from './ProgressBar';

interface ShuffleOverlayProps {
  progress: number; // 0-100
  isVisible: boolean;
}

export function ShuffleOverlay({ progress, isVisible }: ShuffleOverlayProps) {
  if (!isVisible) return null;

  return (
    <div className="phase-overlay shuffle-overlay">
      {/* Glassmorphic card */}
      <div className="phase-card">
        {/* Chapter badge */}
        <div className="chapter-badge">
          <span className="chapter-number">CHAPTER 1</span>
        </div>

        {/* Phase title */}
        <h2 className="phase-title">CRYPTOGRAPHIC SHUFFLE</h2>

        {/* Subtitle */}
        <p className="phase-subtitle">
          Each player shuffles the deck using zero-knowledge proofs
        </p>

        {/* Progress bar */}
        <div className="phase-progress">
          <ProgressBar
            progress={progress}
            label="Shuffle Progress"
            showPercentage={true}
            variant="primary"
          />
        </div>

        {/* Deck animation container */}
        <div className="deck-animation-container">
          <div className="deck-stack">
            {/* Animated deck cards (4 layers for visual depth) */}
            {[0, 1, 2, 3].map((i) => (
              <div
                key={i}
                className="deck-card-layer"
                style={{
                  animationDelay: `${i * 0.1}s`,
                }}
              />
            ))}
          </div>
        </div>

        {/* Technical detail */}
        <div className="phase-detail">
          <span className="detail-icon">🔐</span>
          <span className="detail-text">
            Generating mental poker proofs...
          </span>
        </div>
      </div>
    </div>
  );
}
