/**
 * Demo API Client
 *
 * API functions for initializing and controlling the poker demo.
 */

import { z } from 'zod';
import { tableSnapshotShufflingSchema } from '../schemas/tableSnapshotSchema';
import type { FinalizedAnyMessageEnvelope } from '../schemas/finalizedEnvelopeSchema';

const API_BASE = process.env.NEXT_PUBLIC_BACKEND_SERVER_API_URL ?? 'http://localhost:4000';

export interface DemoGameInfo {
  game_id: number;
  hand_id: number;
  player_count: number;
}

/**
 * Generate random 32-byte hex public key for viewer
 */
export function generateViewerPublicKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return (
    '0x' +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  );
}

/**
 * @deprecated This function is deprecated. Use `createInteractiveDemo()` instead.
 *
 * The old endpoints have been removed. Use the new interactive demo API:
 * - `createInteractiveDemo()` - Create demo session
 * - `connectShuffleStream(demoId)` - Connect to shuffle phase
 * - `connectDealStream(demoId)` - Connect to deal phase
 */
export async function createDemoGame(publicKey: string): Promise<DemoGameInfo> {
  const response = await fetch(`${API_BASE}/game/demo/?public_key=${publicKey}`, {
    method: 'POST',
  });

  if (!response.ok) {
    throw new Error(`Failed to create demo game: ${response.statusText}`);
  }

  return response.json() as Promise<DemoGameInfo>;
}

/**
 * @deprecated This function is deprecated. Use the new interactive demo API instead.
 *
 * The old endpoints have been removed. Use:
 * - `createInteractiveDemo()` - Create demo session
 * - `connectShuffleStream(demoId)` - Connect to shuffle phase
 * - `connectDealStream(demoId)` - Connect to deal phase
 */
export async function startDemo(gameId: number, handId: number): Promise<void> {
  const response = await fetch(`${API_BASE}/game/demo/${gameId}/hand/${handId}`, {
    method: 'POST',
  });

  if (!response.ok) {
    throw new Error(`Failed to start demo: ${response.statusText}`);
  }
}

/**
 * Interactive Demo API - Create a new demo session
 */
export const createDemoResponseSchema = z.object({
  demo_id: z.string().uuid(),
  game_id: z.number().int(),
  hand_id: z.number().int(),
  viewer_public_key: z.string(),
  initial_snapshot: tableSnapshotShufflingSchema,
});

export type CreateDemoResponse = z.infer<typeof createDemoResponseSchema>;

export async function createInteractiveDemo(): Promise<CreateDemoResponse> {
  const response = await fetch(`${API_BASE}/games/demo`, {
    method: 'POST',
  });

  if (!response.ok) {
    throw new Error(`Failed to create demo: ${response.statusText}`);
  }

  const json: unknown = await response.json();
  return createDemoResponseSchema.parse(json);
}

/**
 * Interactive Demo API - Connect to shuffle phase SSE stream
 */
export function connectShuffleStream(demoId: string): EventSource {
  const url = `${API_BASE}/games/demo/${demoId}/shuffle`;
  return new EventSource(url);
}

/**
 * Interactive Demo API - Connect to deal phase SSE stream
 */
export function connectDealStream(demoId: string): EventSource {
  const url = `${API_BASE}/games/demo/${demoId}/deal`;
  return new EventSource(url);
}

/**
 * Fetch events for gap recovery
 */
export async function fetchDemoEvents(
  gameId: number,
  handId: number,
  options?: {
    sinceSeqId?: number;
    seqIds?: number[];
  }
): Promise<FinalizedAnyMessageEnvelope[]> {
  let url = `${API_BASE}/games/${gameId}/hands/${handId}/messages`;

  // Backend uses from_sequence/to_sequence query params
  const params = new URLSearchParams();

  if (options?.seqIds && options.seqIds.length > 0) {
    // Fetch range from min to max of requested sequence IDs
    const minSeq = Math.min(...options.seqIds);
    const maxSeq = Math.max(...options.seqIds);
    params.append('from_sequence', minSeq.toString());
    params.append('to_sequence', maxSeq.toString());
  } else if (options?.sinceSeqId !== undefined) {
    params.append('from_sequence', options.sinceSeqId.toString());
  }

  if (params.toString()) {
    url += `?${params.toString()}`;
  }

  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch events: ${response.statusText}`);
  }

  const json = await response.json() as { events: FinalizedAnyMessageEnvelope[] };
  return json.events;
}
