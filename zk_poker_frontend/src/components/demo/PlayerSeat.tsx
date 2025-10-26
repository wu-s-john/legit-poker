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
  const avatarSize = isViewer ? 100 : 80;

  return (
    <div
      className="player-seat"
      style={{
        position: 'absolute',
        left: `${position.x}px`,
        top: `${position.y}px`,
        transform: 'translate(-50%, -50%)',
      }}
    >
      {/* Avatar */}
      <div
        className={`player-avatar ${isViewer ? 'you' : ''} ${isActive ? 'active' : ''}`}
        style={{
          width: `${avatarSize}px`,
          height: `${avatarSize}px`,
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

      {/* Card slots (rendered by parent) */}
      <div className="card-slots">
        <div className="card-placeholder" />
        <div className="card-placeholder" />
      </div>
    </div>
  );
}
