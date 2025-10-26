import { z } from 'zod';
import {
  anyGameMessageSchema,
  eventPhaseSchema,
} from './schemas/finalizedEnvelopeSchema';

const ENTITY_PLAYER = 0;
const ENTITY_SHUFFLER = 1;

const ACTOR_NONE = 0;
const ACTOR_PLAYER = 1;
const ACTOR_SHUFFLER = 2;

const rawEventRowSchema = z.object({
  hand_id: z.union([z.number(), z.string()]),
  game_id: z.union([z.number(), z.string()]),
  entity_kind: z.union([z.number(), z.string()]),
  entity_id: z.union([z.number(), z.string()]),
  actor_kind: z.union([z.number(), z.string()]),
  seat_id: z.union([z.number(), z.string(), z.null()]).optional(),
  shuffler_id: z.union([z.number(), z.string(), z.null()]).optional(),
  public_key: z.string(),
  nonce: z.union([z.number(), z.string()]),
  snapshot_number: z.union([z.number(), z.string()]),
  is_successful: z.union([z.boolean(), z.number(), z.string()]),
  failure_message: z.union([z.string(), z.null()]).optional(),
  resulting_phase: z.string(),
  payload: z.unknown(),
  signature: z.string(),
});

type RawEventRow = z.infer<typeof rawEventRowSchema>;

// Define actor type explicitly to avoid type inference issues
type ActorType =
  | 'none'
  | { player: { seat_id: number; player_id: number } }
  | { shuffler: { shuffler_id: number; shuffler_key: string } };

// Define the wrapped envelope structure that this mapper produces
// Note: This doesn't match the current finalizedEnvelopeSchema which has a flat structure
// and uses different field names (e.g., snake_case vs camelCase)
interface MappedEnvelope {
  envelope: {
    handId: number;
    gameId: number;
    actor: ActorType;
    nonce: number;
    publicKey: string;
    message: {
      value: z.infer<typeof anyGameMessageSchema>;
      signature: string;
      transcript: unknown[];
    };
  };
  snapshotStatus: { status: 'success' } | { status: 'failure'; reason: string };
  appliedPhase: z.input<typeof eventPhaseSchema>;
  snapshotSequenceId: number;
}

type EventPhaseInput = z.input<typeof eventPhaseSchema>;

function toNumeric(value: number | string | null | undefined, field: string): number {
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  throw new Error(`Expected numeric value for ${field}`);
}

function toBoolean(value: RawEventRow['is_successful']): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }
  if (typeof value === 'string') {
    const normalized = value.toLowerCase();
    return normalized === 'true' || normalized === 't' || normalized === '1';
  }
  return false;
}

function normalizeHex(value: string): string {
  if (value.startsWith('\\x')) {
    return `0x${value.slice(2)}`;
  }
  if (value.startsWith('0x')) {
    return value;
  }
  return `0x${value}`;
}

function mapSnapshotStatus(isSuccessful: boolean, failureMessage?: string | null): MappedEnvelope['snapshotStatus'] {
  if (isSuccessful) {
    return { status: 'success' } as const;
  }

  return {
    status: 'failure',
    reason: failureMessage ?? 'unknown failure',
  } as const;
}

function mapPhase(phase: string): EventPhaseInput {
  return eventPhaseSchema.parse(phase);
}

function mapActor(row: RawEventRow): MappedEnvelope['envelope']['actor'] {
  const actorKind = toNumeric(row.actor_kind, 'actor_kind');
  switch (actorKind) {
    case ACTOR_NONE:
      return 'none' as const;
    case ACTOR_PLAYER: {
      const seat = row.seat_id;
      if (seat === null || seat === undefined) {
        throw new Error('player actor missing seat_id');
      }
      const seatId = toNumeric(seat, 'seat_id');
      const playerId = toNumeric(row.entity_id, 'entity_id');
      if (toNumeric(row.entity_kind, 'entity_kind') !== ENTITY_PLAYER) {
        throw new Error('player actor stored with mismatched entity_kind');
      }
      return { player: { seat_id: seatId, player_id: playerId } } as const;
    }
    case ACTOR_SHUFFLER: {
      const shufflerSource = row.shuffler_id ?? row.entity_id;
      const shufflerId = toNumeric(shufflerSource, 'shuffler_id');
      if (toNumeric(row.entity_kind, 'entity_kind') !== ENTITY_SHUFFLER) {
        throw new Error('shuffler actor stored with mismatched entity_kind');
      }
      const shufflerKey = normalizeHex(row.public_key);
      return { shuffler: { shuffler_id: shufflerId, shuffler_key: shufflerKey } } as const;
    }
    default:
      throw new Error(`unknown actor_kind value ${actorKind}`);
  }
}

export function mapRealtimeRowToFinalizedEnvelope(row: unknown): MappedEnvelope {
  const parsedRow = rawEventRowSchema.parse(row);
  const messagePayload = anyGameMessageSchema.parse(parsedRow.payload);

  const handId = toNumeric(parsedRow.hand_id, 'hand_id');
  const gameId = toNumeric(parsedRow.game_id, 'game_id');
  const nonce = toNumeric(parsedRow.nonce, 'nonce');
  const snapshotSequenceId = toNumeric(parsedRow.snapshot_number, 'snapshot_number');
  const snapshotStatus: MappedEnvelope['snapshotStatus'] = mapSnapshotStatus(toBoolean(parsedRow.is_successful), parsedRow.failure_message ?? null);
  const appliedPhase: EventPhaseInput = mapPhase(parsedRow.resulting_phase);
  const actor = mapActor(parsedRow);

  return {
    envelope: {
      handId,
      gameId,
      actor,
      nonce,
      publicKey: normalizeHex(parsedRow.public_key),
      message: {
        value: messagePayload,
        signature: normalizeHex(parsedRow.signature),
        transcript: [],
      },
    },
    snapshotStatus,
    appliedPhase,
    snapshotSequenceId,
  } as MappedEnvelope;
}
