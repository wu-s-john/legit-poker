/**
 * Demo API Client
 *
 * API functions for initializing and controlling the poker demo.
 */

import type { FinalizedAnyMessageEnvelope } from '../finalizedEnvelopeSchema';

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
 * @deprecated DO NOT USE - Use /games/demo/stream instead
 * Create demo game (viewer is always seat 0)
 *
 * This endpoint should not be called directly.
 * The streaming endpoint /games/demo/stream handles game creation automatically.
 */
export async function createDemoGame(publicKey: string): Promise<DemoGameInfo> {
  const response = await fetch(`${API_BASE}/game/demo/?public_key=${publicKey}`, {
    method: 'POST',
  });

  if (!response.ok) {
    throw new Error(`Failed to create demo game: ${response.statusText}`);
  }

  return response.json();
}

/**
 * @deprecated DO NOT USE - Use /games/demo/stream instead
 * Start demo protocol execution
 *
 * This endpoint should not be called directly.
 * The streaming endpoint /games/demo/stream handles game initialization automatically.
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
  let url = `${API_BASE}/game/${gameId}/hand/${handId}/events`;

  if (options?.seqIds && options.seqIds.length > 0) {
    url += `?seq_ids=${options.seqIds.join(',')}`;
  } else if (options?.sinceSeqId !== undefined) {
    url += `?since_seq_id=${options.sinceSeqId}`;
  }

  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch events: ${response.statusText}`);
  }

  const { events } = await response.json();
  return events;
}
