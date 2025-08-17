'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { lobby } from '~/lib/api';
import { FilterBar } from '~/components/lobby/FilterBar';
import { RingRow } from '~/components/lobby/RingRow';
import { TournamentRow } from '~/components/lobby/TournamentRow';
import { RightRailPromo } from '~/components/lobby/RightRailPromo';
import { Loader2 } from 'lucide-react';

function LobbyContent() {
  const searchParams = useSearchParams();
  const currentTab = searchParams.get('tab') ?? 'ring';

  const { data: rooms, isLoading: roomsLoading } = useQuery({
    queryKey: ['lobby', 'rooms'],
    queryFn: lobby.listRooms,
    staleTime: 10000, // 10 seconds
  });

  const { data: tournaments, isLoading: tournamentsLoading } = useQuery({
    queryKey: ['lobby', 'tournaments'],
    queryFn: lobby.listTournaments,
    staleTime: 10000, // 10 seconds
  });

  // Mock data for development
  const mockRooms = [
    {
      id: '1',
      name: 'High Stakes NLHE',
      stakes: { sb: 50, bb: 100 },
      gameType: 'NLHE' as const,
      playerCount: 6,
      maxPlayers: 9,
      status: 'playing' as const,
      buyIn: { min: 2000, max: 10000 },
    },
    {
      id: '2',
      name: 'Micro Stakes PLO',
      stakes: { sb: 1, bb: 2 },
      gameType: 'PLO' as const,
      playerCount: 3,
      maxPlayers: 6,
      status: 'waiting' as const,
      buyIn: { min: 40, max: 200 },
    },
  ];

  const mockTournaments = [
    {
      id: '1',
      name: 'Sunday Million',
      buyIn: 1000,
      entries: 150,
      maxEntries: 1000,
      prizePool: 1000000,
      guaranteed: 1000000,
      status: 'registering' as const,
      startsAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
    },
    {
      id: '2',
      name: 'Daily Deep Stack',
      buyIn: 100,
      entries: 45,
      maxEntries: 100,
      prizePool: 9000,
      guaranteed: 5000,
      status: 'late_reg' as const,
      startsAt: new Date(Date.now() - 1800000).toISOString(), // 30 minutes ago
      endsAt: new Date(Date.now() + 7200000).toISOString(), // 2 hours from now
    },
  ];

  const displayRooms = rooms ?? mockRooms;
  const displayTournaments = tournaments ?? mockTournaments;

  if (roomsLoading || tournamentsLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-8 h-8 animate-spin text-primary-400" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Main Content */}
        <div className="lg:col-span-3 space-y-6">
          <FilterBar />
          
          {currentTab === 'ring' ? (
            <div className="space-y-4">
              {displayRooms.map((room) => (
                <RingRow key={room.id} room={room} />
              ))}
            </div>
          ) : (
            <div className="space-y-4">
              {displayTournaments.map((tournament) => (
                <TournamentRow key={tournament.id} tournament={tournament} />
              ))}
            </div>
          )}
        </div>

        {/* Right Rail */}
        <div className="lg:col-span-1">
          <RightRailPromo />
        </div>
      </div>
    </div>
  );
}

export default function LobbyPage() {
  return (
    <Suspense fallback={<div className="flex items-center justify-center min-h-[400px]"><Loader2 className="w-8 h-8 animate-spin text-primary-400" /></div>}>
      <LobbyContent />
    </Suspense>
  );
}
