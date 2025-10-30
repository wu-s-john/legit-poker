/**
 * Player Seat - Individual player position around the table
 */

import React from 'react';
import type { Position } from '~/lib/demo/positioning';

interface PlayerSeatProps {
  seat: number;
  position: Position;
  isViewer: boolean;
  name: string;
  isActive?: boolean;
}

export function PlayerSeat({ seat: _seat, position, isViewer, name, isActive }: PlayerSeatProps) {
  // Avatar sizes using viewport width (vw) for consistent scaling
  // Min/max bounds prevent too small or too large avatars
  const avatarVw = isViewer ? 5 : 4; // ~96px viewer, ~77px others at 1920px viewport
  const minSize = isViewer ? 70 : 60; // Minimum pixel size
  const maxSize = isViewer ? 110 : 90; // Maximum pixel size

  return (
    <div
      className="player-seat"
      style={{
        position: 'absolute',
        left: `${position.x}%`,
        top: `${position.y}%`,
        transform: 'translate(-50%, -50%)',
      }}
    >
      {/* Avatar */}
      <div
        className={`player-avatar ${isViewer ? 'you' : ''} ${isActive ? 'active' : ''}`}
        style={{
          width: `${avatarVw}vw`,
          minWidth: `${minSize}px`,
          maxWidth: `${maxSize}px`,
          aspectRatio: '1', // Square avatar
        }}
      >
        <div className="avatar-placeholder">
          <span>👤</span>
        </div>
      </div>

      {/* Name badge */}
      <div className={`player-name-badge ${isViewer ? 'viewer-badge' : ''}`}>
        {isViewer && <span className="viewer-star">⭐ </span>}
        {name}
      </div>
    </div>
  );
}
