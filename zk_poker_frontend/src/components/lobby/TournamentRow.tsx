'use client';

import type { Tournament } from '~/types/poker';
import { ChevronRight, Users, Trophy } from 'lucide-react';
import Link from 'next/link';
import { CountdownBadge } from './CountdownBadge';

interface TournamentRowProps {
  tournament: Tournament;
}

export function TournamentRow({ tournament }: TournamentRowProps) {
  const getStatusColor = (status: Tournament['status']) => {
    switch (status) {
      case 'registering':
        return 'text-green-400';
      case 'late_reg':
        return 'text-yellow-400';
      case 'running':
        return 'text-blue-400';
      case 'finished':
        return 'text-gray-400';
      default:
        return 'text-primary-300';
    }
  };

  const getStatusText = (status: Tournament['status']) => {
    switch (status) {
      case 'registering':
        return 'Registration Open';
      case 'late_reg':
        return 'Late Registration';
      case 'running':
        return 'In Progress';
      case 'finished':
        return 'Finished';
      default:
        return status;
    }
  };

  const formatPrizePool = (amount: number) => {
    if (amount >= 1000000) {
      return `$${(amount / 1000000).toFixed(1)}M`;
    }
    if (amount >= 1000) {
      return `$${(amount / 1000).toFixed(0)}K`;
    }
    return `$${amount.toLocaleString()}`;
  };

  return (
    <Link
      href={`/tournament/${tournament.id}`}
      className="block bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700 hover:border-primary-600 hover:bg-primary-800/70 transition-all duration-200"
    >
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-4 mb-3">
            <h3 className="text-lg font-semibold text-white">{tournament.name}</h3>
            <span className={`text-sm font-medium ${getStatusColor(tournament.status)}`}>
              {getStatusText(tournament.status)}
            </span>
          </div>
          
          <div className="flex items-center gap-6 text-sm text-primary-300">
            <div className="flex items-center gap-2">
              <span>Buy-in:</span>
              <span className="font-medium text-primary-200">
                ${tournament.buyIn.toLocaleString()}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4" />
              <span>
                {tournament.entries}/{tournament.maxEntries} entries
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Trophy className="w-4 h-4" />
              <span>
                Prize Pool: {formatPrizePool(tournament.prizePool)}
              </span>
            </div>
            {tournament.guaranteed > 0 && (
              <div className="flex items-center gap-2">
                <span>GTD:</span>
                <span className="font-medium text-primary-200">
                  {formatPrizePool(tournament.guaranteed)}
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
          <CountdownBadge 
            status={tournament.status}
            startsAt={tournament.startsAt}
            endsAt={tournament.endsAt}
          />
          <ChevronRight className="w-5 h-5 text-primary-400" />
        </div>
      </div>
    </Link>
  );
}
