/**
 * Progress Bar - Reusable animated progress indicator
 */

import React from 'react';

interface ProgressBarProps {
  progress: number; // 0-100
  label?: string;
  showPercentage?: boolean;
  variant?: 'primary' | 'success' | 'warning';
}

export function ProgressBar({
  progress,
  label,
  showPercentage = false,
  variant = 'primary',
}: ProgressBarProps) {
  const clampedProgress = Math.min(100, Math.max(0, progress));

  const variantColors = {
    primary: 'bg-blue-500',
    success: 'bg-green-500',
    warning: 'bg-yellow-500',
  };

  return (
    <div className="progress-bar-container">
      {/* Label row */}
      {(label || showPercentage) && (
        <div className="progress-label-row">
          {label && <span className="progress-label">{label}</span>}
          {showPercentage && (
            <span className="progress-percentage">{Math.round(clampedProgress)}%</span>
          )}
        </div>
      )}

      {/* Track */}
      <div className="progress-track">
        {/* Fill */}
        <div
          className={`progress-fill ${variantColors[variant]}`}
          style={{
            width: `${clampedProgress}%`,
          }}
        >
          {/* Glow effect */}
          <div className="progress-glow" />
        </div>
      </div>
    </div>
  );
}
