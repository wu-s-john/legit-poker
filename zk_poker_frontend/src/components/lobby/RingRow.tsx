'use client';

import type { LobbyTable } from '~/types/poker';
import { ChevronRight, Users } from 'lucide-react';
import Link from 'next/link';
import { SeatMapDots } from './SeatMapDots';

interface RingRowProps {
  room: LobbyTable;
}

export function RingRow({ room }: RingRowProps) {
  const formatStakes = (stakes: LobbyTable['stakes']) => {
    const parts = [`$${stakes.sb}/${stakes.bb}`];
    if (stakes.ante) parts.push(`$${stakes.ante} ante`);
    if (stakes.straddle) parts.push(`$${stakes.straddle} straddle`);
    return parts.join(', ');
  };

  const getStatusColor = (status: LobbyTable['status']) => {
    switch (status) {
      case 'waiting':
        return 'text-yellow-400';
      case 'playing':
        return 'text-green-400';
      case 'full':
        return 'text-red-400';
      default:
        return 'text-primary-300';
    }
  };

  const getStatusText = (status: LobbyTable['status']) => {
    switch (status) {
      case 'waiting':
        return 'Waiting for players';
      case 'playing':
        return 'In progress';
      case 'full':
        return 'Full';
      default:
        return status;
    }
  };

  return (
    <Link
      href={`/room/${room.id}`}
      className="block bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700 hover:border-primary-600 hover:bg-primary-800/70 transition-all duration-200"
    >
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-4 mb-3">
            <h3 className="text-lg font-semibold text-white">{room.name}</h3>
            <span className={`text-sm font-medium ${getStatusColor(room.status)}`}>
              {getStatusText(room.status)}
            </span>
          </div>
          
          <div className="flex items-center gap-6 text-sm text-primary-300">
            <div className="flex items-center gap-2">
              <span className="font-medium">{room.gameType}</span>
            </div>
            <div className="flex items-center gap-2">
              <span>Stakes:</span>
              <span className="font-medium text-primary-200">
                {formatStakes(room.stakes)}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4" />
              <span>
                {room.playerCount}/{room.maxPlayers} players
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span>Buy-in:</span>
              <span className="font-medium text-primary-200">
                ${room.buyIn.min}-${room.buyIn.max}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <SeatMapDots 
            playerCount={room.playerCount} 
            maxPlayers={room.maxPlayers} 
          />
          <ChevronRight className="w-5 h-5 text-primary-400" />
        </div>
      </div>
    </Link>
  );
}
