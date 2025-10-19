import { z } from 'zod';
import {
  anyGameMessageSchema,
  finalizedEnvelopeSchema,
  snapshotStatusSchema,
  eventPhaseSchema,
} from './finalizedEnvelopeSchema';

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

const storedEnvelopePayloadSchema = z.object({
  game_id: z.union([z.number(), z.string()]),
  message: anyGameMessageSchema,
});

type StoredEnvelopePayload = z.infer<typeof storedEnvelopePayloadSchema>;

type FinalizedEnvelopeInput = z.input<typeof finalizedEnvelopeSchema>;

type SnapshotStatusInput = z.input<typeof snapshotStatusSchema>;

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

function mapSnapshotStatus(isSuccessful: boolean, failureMessage?: string | null): SnapshotStatusInput {
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

function mapActor(row: RawEventRow): FinalizedEnvelopeInput['envelope']['actor'] {
  const actorKind = toNumeric(row.actor_kind as RawEventRow['actor_kind'], 'actor_kind');
  switch (actorKind) {
    case ACTOR_NONE:
      return { kind: 'none' };
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
      return { kind: 'player', seatId, playerId };
    }
    case ACTOR_SHUFFLER: {
      const shufflerSource = row.shuffler_id ?? row.entity_id;
      const shufflerId = toNumeric(shufflerSource, 'shuffler_id');
      if (toNumeric(row.entity_kind, 'entity_kind') !== ENTITY_SHUFFLER) {
        throw new Error('shuffler actor stored with mismatched entity_kind');
      }
      return { kind: 'shuffler', shufflerId };
    }
    default:
      throw new Error(`unknown actor_kind value ${actorKind}`);
  }
}

export function mapRealtimeRowToFinalizedEnvelope(row: unknown): FinalizedEnvelopeInput {
  const parsedRow = rawEventRowSchema.parse(row);
  const payload = storedEnvelopePayloadSchema.parse(parsedRow.payload) as StoredEnvelopePayload;

  const handId = toNumeric(parsedRow.hand_id, 'hand_id');
  const gameId = toNumeric(parsedRow.game_id, 'game_id');
  const nonce = toNumeric(parsedRow.nonce, 'nonce');
  const snapshotSequenceId = toNumeric(parsedRow.snapshot_number, 'snapshot_number');
  const snapshotStatus = mapSnapshotStatus(toBoolean(parsedRow.is_successful), parsedRow.failure_message ?? null);
  const appliedPhase = mapPhase(parsedRow.resulting_phase);
  const actor = mapActor(parsedRow);

  if (toNumeric(payload.game_id, 'payload.game_id') !== gameId) {
    console.warn('Payload game_id mismatch with row game_id', payload.game_id, gameId);
  }

  return {
    envelope: {
      handId,
      gameId,
      actor,
      nonce,
      publicKey: normalizeHex(parsedRow.public_key),
      message: {
        value: payload.message,
        signature: normalizeHex(parsedRow.signature),
        transcript: [],
      },
    },
    snapshotStatus,
    appliedPhase,
    snapshotSequenceId,
  };
}
