import type { LobbyTable, Tournament, RoomSnapshot, TableStakes } from '~/types/poker';
import type { HandMessagesResponse } from './console/schemas';
import { parseHandMessagesResponse } from './console/schemas';

const API_BASE = process.env.NEXT_PUBLIC_BACKEND_SERVER_API_URL ?? 'http://localhost:4000';

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    throw new ApiError(response.status, `API Error: ${response.statusText}`);
  }

  return response.json() as Promise<T>;
}

// Auth endpoints
export const auth = {
  guest: () => fetchApi<{ token: string; userId: string }>('/auth/guest', {
    method: 'POST',
  }),
};

// Lobby endpoints
export const lobby = {
  listRooms: () => fetchApi<LobbyTable[]>('/rooms'),
  listTournaments: () => fetchApi<Tournament[]>('/tournaments'),
};

// Room endpoints
export const rooms = {
  get: (id: string) => fetchApi<RoomSnapshot>(`/rooms/${id}`),
  create: (data: { name: string; stakes: TableStakes; gameType: 'NLHE' | 'PLO' }) =>
    fetchApi<{ id: string }>('/rooms', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  join: (id: string, data: { role: 'player' | 'spectator'; pk_player?: string }) =>
    fetchApi<{ ok: boolean }>(`/rooms/${id}/join`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  start: (id: string) => fetchApi<{ ok: boolean }>(`/rooms/${id}/start`, {
    method: 'POST',
  }),
  transcript: (id: string, fromSeq: number, limit = 100) =>
    fetchApi<{ items: unknown[] }>(`/rooms/${id}/transcript?from_seq=${fromSeq}&limit=${limit}`),
};

// Action endpoints
export const actions = {
  post: (roomId: string, data: { idempotency_key: string; action: string; amount?: number }) =>
    fetchApi<{ action_id: string }>(`/rooms/${roomId}/action`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
};

// Table management
export const tables = {
  buyIn: (tableId: string, amount: number) =>
    fetchApi<{ ok: boolean; newStack: number }>(`/tables/${tableId}/buyin`, {
      method: 'POST',
      body: JSON.stringify({ amount }),
    }),
  shuffle: (tableId: string) =>
    fetchApi<{ ok: boolean }>(`/tables/${tableId}/shuffle`, {
      method: 'POST',
    }),
  deal: (tableId: string) =>
    fetchApi<{ ok: boolean }>(`/tables/${tableId}/deal`, {
      method: 'POST',
    }),
  showdown: (tableId: string) =>
    fetchApi<{ ok: boolean }>(`/tables/${tableId}/showdown`, {
      method: 'POST',
    }),
};

// React Query hooks
export const useLobbyRooms = () => ({
  queryKey: ['lobby', 'rooms'],
  queryFn: lobby.listRooms,
});

export const useLobbyTournaments = () => ({
  queryKey: ['lobby', 'tournaments'],
  queryFn: lobby.listTournaments,
});

export const useRoom = (id: string) => ({
  queryKey: ['room', id],
  queryFn: () => rooms.get(id),
  enabled: !!id,
});

export const useRoomTranscript = (id: string, fromSeq: number) => ({
  queryKey: ['room', id, 'transcript', fromSeq],
  queryFn: () => rooms.transcript(id, fromSeq),
  enabled: !!id && fromSeq >= 0,
});

// Console logs endpoints
export const console = {
  getHandMessages: async (gameId: string, handId: string): Promise<HandMessagesResponse> => {
    const data = await fetchApi<unknown>(`/games/${gameId}/hands/${handId}/messages`);
    return parseHandMessagesResponse(data);
  },
};

export const useHandMessages = (gameId: string, handId: string) => ({
  queryKey: ['console', 'game', gameId, 'hand', handId, 'messages'],
  queryFn: () => console.getHandMessages(gameId, handId),
  enabled: !!gameId && !!handId,
});
