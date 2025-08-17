import { io } from 'socket.io-client';
import type { Socket } from 'socket.io-client';
import type { TranscriptEnvelope } from '~/types/poker';

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL ?? 'ws://localhost:3001';

class RoomSocket {
  private socket: Socket | null = null;
  private roomId: string | null = null;
  private lastSeq = 0;
  private onVerified?: (actionId: string, proverMs: number) => void;

  connect(token: string, roomId: string, lastSeq = 0, onVerified?: (actionId: string, proverMs: number) => void) {
    this.roomId = roomId;
    this.lastSeq = lastSeq;
    this.onVerified = onVerified;

    this.socket = io(`${WS_BASE}/rooms`, {
      auth: { token },
      transports: ['websocket'] as const,
    });

    this.socket.on('connect', () => {
      console.log('Connected to room socket');
      this.socket?.emit('room:join', { room_id: roomId, last_seq: lastSeq });
    });

    this.socket.on('transcript.append', (envelope: TranscriptEnvelope) => {
      console.log('Received transcript envelope:', envelope);
      
      // Handle action.verified events for toast notifications
      if (envelope.event.kind === 'action.verified' && this.onVerified) {
        const data = envelope.event.data as { action_id: string; prover_ms: number };
        this.onVerified(data.action_id, data.prover_ms);
      }
    });

    this.socket.on('disconnect', () => {
      console.log('Disconnected from room socket');
    });

    this.socket.on('error', (error: unknown) => {
      console.error('Socket error:', error);
    });
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.roomId = null;
    this.lastSeq = 0;
    this.onVerified = undefined;
  }

  isConnected(): boolean {
    return this.socket?.connected ?? false;
  }

  getRoomId(): string | null {
    return this.roomId;
  }

  getLastSeq() {
    return this.lastSeq;
  }
}

// Singleton instance
export const roomSocket = new RoomSocket();

// Hook for using the socket
export function useRoomSocket() {
  return {
    connect: roomSocket.connect.bind(roomSocket),
    disconnect: roomSocket.disconnect.bind(roomSocket),
    isConnected: roomSocket.isConnected.bind(roomSocket),
    getRoomId: roomSocket.getRoomId.bind(roomSocket),
    getLastSeq: roomSocket.getLastSeq.bind(roomSocket),
  };
}
