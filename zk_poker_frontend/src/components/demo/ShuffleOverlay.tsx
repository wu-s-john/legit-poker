/**
 * Shuffle Overlay - Phase 1 overlay showing cryptographic shuffle progress
 */

import React from 'react';
import { ProgressBar } from './ProgressBar';

interface ShuffleOverlayProps {
  progress: number; // 0-100
  isVisible: boolean;
  currentShuffler?: number; // 0-6 (current shuffler index)
  totalShufflers?: number; // 7 (total number of shufflers)
  isComplete?: boolean; // When true, shows completion state with button
  onStartDeal?: () => void; // Called when user clicks "Start Dealing"
}

export function ShuffleOverlay({
  progress,
  isVisible,
  currentShuffler,
  totalShufflers,
  isComplete = false,
  onStartDeal,
}: ShuffleOverlayProps) {
  if (!isVisible) return null;

  // Completion state - show "Shuffle Complete" with button
  if (isComplete) {
    return (
      <div className="absolute inset-0 flex items-center justify-center bg-black/40 backdrop-blur-sm z-50">
        <div className="phase-card">
          <h2 className="phase-title">SHUFFLE COMPLETE</h2>

          <p className="phase-subtitle">
            The deck has been successfully shuffled by all {totalShufflers ?? 5} shufflers using
            zero-knowledge proofs. The cards are now ready to be dealt to players.
          </p>

          <div className="flex justify-center py-6">
            <button
              onClick={onStartDeal}
              className="bg-gradient-to-r from-green-600 to-emerald-600 px-8 py-3 rounded-lg text-base font-semibold text-white shadow-lg transition-all hover:from-green-700 hover:to-emerald-700 hover:shadow-xl active:scale-95"
            >
              Start Dealing
            </button>
          </div>

          <div className="phase-detail">
            <span className="detail-icon">✅</span>
            <span className="detail-text">All cryptographic proofs verified</span>
          </div>
        </div>
      </div>
    );
  }

  // Progress state - show shuffle progress
  return (
    <div className="absolute inset-0 flex items-center justify-center bg-black/40 backdrop-blur-sm z-50">
      {/* Glassmorphic card */}
      <div className="phase-card">
        {/* Phase title */}
        <h2 className="phase-title">CRYPTOGRAPHIC SHUFFLE</h2>

        {/* Subtitle */}
        <p className="phase-subtitle">
          {currentShuffler !== undefined && totalShufflers !== undefined
            ? `Shuffler ${currentShuffler + 1} of ${totalShufflers} performing cryptographic shuffle`
            : 'Shufflers performing cryptographic shuffle using zero-knowledge proofs'}
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
            {currentShuffler !== undefined && totalShufflers !== undefined
              ? `Shuffler ${currentShuffler + 1} generating zero-knowledge proof...`
              : 'Generating mental poker proofs...'}
          </span>
        </div>
      </div>
    </div>
  );
}
