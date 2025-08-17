'use client';

import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { rooms } from '~/lib/api';
import { Loader2 } from 'lucide-react';

export default function RoomPage() {
  const params = useParams();
  const roomId = params.id as string;

  const { data: room, isLoading, error } = useQuery({
    queryKey: ['room', roomId],
    queryFn: () => rooms.get(roomId),
    enabled: !!roomId,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-8 h-8 animate-spin text-primary-400" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-6">
          <h2 className="text-xl font-semibold text-red-400 mb-2">Error Loading Room</h2>
          <p className="text-red-300">
            {error instanceof Error ? error.message : 'Failed to load room data'}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-6 py-8">
      <div className="bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700">
        <h1 className="text-2xl font-bold text-white mb-4">
          Room: {room?.id ?? roomId}
        </h1>
        <p className="text-primary-300">
          This is a placeholder for the poker table interface. The full table UI will be implemented here.
        </p>
        <div className="mt-4 p-4 bg-primary-700/50 rounded-lg">
          <h3 className="text-lg font-semibold text-white mb-2">Room Status</h3>
          <p className="text-primary-300">
            Status: {room?.status ?? 'Unknown'}
          </p>
          <p className="text-primary-300">
            Players: {room?.players?.length ?? 0}
          </p>
        </div>
      </div>
    </div>
  );
}
