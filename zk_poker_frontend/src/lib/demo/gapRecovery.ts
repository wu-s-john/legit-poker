/**
 * Gap Recovery - Handles detection and recovery from missing/out-of-order events
 */

import type { FinalizedAnyMessageEnvelope } from '../finalizedEnvelopeSchema';

export interface GapDetectionResult {
  hasGap: boolean;
  missingSeqIds: number[];
  readyEvents: FinalizedAnyMessageEnvelope[];
}

/**
 * Detects gaps in event sequence and manages out-of-order events
 */
export class GapDetector {
  private expectedSeqId: number = 0;
  private pendingEvents: Map<number, FinalizedAnyMessageEnvelope> = new Map();

  /**
   * Process incoming event and detect gaps
   * Returns:
   * - hasGap: true if there are missing events before this one
   * - missingSeqIds: array of missing sequence IDs to fetch
   * - readyEvents: array of events that can be processed in order
   */
  detectGaps(event: FinalizedAnyMessageEnvelope): GapDetectionResult {
    const seqId = event.snapshot_sequence_id;

    // Store event in pending buffer
    this.pendingEvents.set(seqId, event);

    // Check if this event is ahead of expected sequence
    if (seqId > this.expectedSeqId) {
      const missingSeqIds: number[] = [];

      // Find all missing sequence IDs between expected and received
      for (let i = this.expectedSeqId; i < seqId; i++) {
        if (!this.pendingEvents.has(i)) {
          missingSeqIds.push(i);
        }
      }

      return {
        hasGap: true,
        missingSeqIds,
        readyEvents: [],
      };
    }

    // No gap detected - collect all consecutive ready events
    const readyEvents: FinalizedAnyMessageEnvelope[] = [];

    while (this.pendingEvents.has(this.expectedSeqId)) {
      const readyEvent = this.pendingEvents.get(this.expectedSeqId)!;
      readyEvents.push(readyEvent);
      this.pendingEvents.delete(this.expectedSeqId);
      this.expectedSeqId++;
    }

    return {
      hasGap: false,
      missingSeqIds: [],
      readyEvents,
    };
  }

  /**
   * Process fetched events to fill gaps
   * Returns events that are now ready to process in order
   */
  processFetchedEvents(events: FinalizedAnyMessageEnvelope[]): FinalizedAnyMessageEnvelope[] {
    // Add all fetched events to pending buffer
    for (const event of events) {
      this.pendingEvents.set(event.snapshot_sequence_id, event);
    }

    // Collect all consecutive ready events
    const readyEvents: FinalizedAnyMessageEnvelope[] = [];

    while (this.pendingEvents.has(this.expectedSeqId)) {
      const readyEvent = this.pendingEvents.get(this.expectedSeqId)!;
      readyEvents.push(readyEvent);
      this.pendingEvents.delete(this.expectedSeqId);
      this.expectedSeqId++;
    }

    return readyEvents;
  }

  /**
   * Check if there are still pending events waiting for gaps to be filled
   */
  hasPendingEvents(): boolean {
    return this.pendingEvents.size > 0;
  }

  /**
   * Get count of pending events
   */
  getPendingCount(): number {
    return this.pendingEvents.size;
  }

  /**
   * Get the next expected sequence ID
   */
  getExpectedSeqId(): number {
    return this.expectedSeqId;
  }

  /**
   * Get all pending sequence IDs (sorted)
   */
  getPendingSeqIds(): number[] {
    return Array.from(this.pendingEvents.keys()).sort((a, b) => a - b);
  }

  /**
   * Reset detector state (useful for new hand or reconnection)
   */
  reset(startingSeqId: number = 0): void {
    this.expectedSeqId = startingSeqId;
    this.pendingEvents.clear();
  }

  /**
   * Get diagnostic info for debugging
   */
  getDebugInfo(): {
    expectedSeqId: number;
    pendingCount: number;
    pendingSeqIds: number[];
    oldestPending: number | null;
    newestPending: number | null;
  } {
    const pendingSeqIds = this.getPendingSeqIds();

    return {
      expectedSeqId: this.expectedSeqId,
      pendingCount: this.pendingEvents.size,
      pendingSeqIds,
      oldestPending: pendingSeqIds.length > 0 ? pendingSeqIds[0] : null,
      newestPending: pendingSeqIds.length > 0 ? pendingSeqIds[pendingSeqIds.length - 1] : null,
    };
  }
}
