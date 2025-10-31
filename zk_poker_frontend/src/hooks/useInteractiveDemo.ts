/**
 * useInteractiveDemo Hook
 *
 * Manages interactive demo state and phase transitions for user-controlled poker demo.
 *
 * Phase flow:
 * idle → loading → ready → shuffling → shuffle_complete → dealing → complete
 *
 * Note: shuffle_complete and complete phases are triggered by SSE stream closure,
 * not by explicit events from the backend.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createInteractiveDemo, connectShuffleStream, connectDealStream } from '~/lib/api/demoApi';

export type DemoPhase = 'idle' | 'loading' | 'ready' | 'shuffling' | 'shuffle_complete' | 'dealing' | 'complete';

export interface InteractiveDemoState {
  phase: DemoPhase;
  demoId: string | null;
  gameId: number | null;
  handId: number | null;
  error: string | null;
  shuffleStartTime: number | null;
  shuffleDuration: number | null;
  dealStartTime: number | null;
  dealDuration: number | null;
}

export interface InteractiveDemoActions {
  startDemo: () => Promise<void>;
  startShuffle: (onEvent: (eventType: string, data: unknown) => void) => void;
  startDeal: (onEvent: (eventType: string, data: unknown) => void) => void;
  reset: () => void;
}

export type UseInteractiveDemoReturn = [InteractiveDemoState, InteractiveDemoActions];

export function useInteractiveDemo(): UseInteractiveDemoReturn {
  const [state, setState] = useState<InteractiveDemoState>({
    phase: 'idle',
    demoId: null,
    gameId: null,
    handId: null,
    error: null,
    shuffleStartTime: null,
    shuffleDuration: null,
    dealStartTime: null,
    dealDuration: null,
  });

  // Store EventSource refs to allow cleanup
  const shuffleStreamRef = useRef<EventSource | null>(null);
  const dealStreamRef = useRef<EventSource | null>(null);

  // Store demoId in ref to avoid circular dependencies in callbacks
  const demoIdRef = useRef<string | null>(null);

  // Guard to prevent concurrent startDemo calls (React StrictMode double-mounting)
  const isStartingRef = useRef<boolean>(false);

  // Update ref whenever demoId changes
  useEffect(() => {
    demoIdRef.current = state.demoId;
  }, [state.demoId]);

  /**
   * Step 1: Create demo session
   * Transitions: idle → loading → ready
   */
  const startDemo = useCallback(async () => {
    // Guard against concurrent calls (React StrictMode double-mounting)
    if (isStartingRef.current) {
      console.log('[useInteractiveDemo] startDemo already in progress, skipping');
      return;
    }

    try {
      isStartingRef.current = true; // Set guard
      // Set to 'loading' to prevent double calls
      setState((prev) => ({ ...prev, phase: 'loading', error: null }));

      const response = await createInteractiveDemo();

      setState({
        phase: 'ready',
        demoId: response.demo_id,
        gameId: response.game_id,
        handId: response.hand_id,
        error: null,
        shuffleStartTime: null,
        shuffleDuration: null,
        dealStartTime: null,
        dealDuration: null,
      });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to create demo';
      setState((prev) => ({
        ...prev,
        phase: 'idle', // Reset to idle on error so user can retry
        error: errorMessage,
      }));
    } finally {
      isStartingRef.current = false; // Reset guard
    }
  }, []);

  /**
   * Step 2: Start shuffle phase
   * Transitions: ready → shuffling → shuffle_complete
   */
  const startShuffle = useCallback(
    (onEvent: (eventType: string, data: unknown) => void) => {
      if (!demoIdRef.current) {
        setState((prev) => ({ ...prev, error: 'No demo ID available' }));
        return;
      }

      // Close any existing shuffle stream
      if (shuffleStreamRef.current) {
        shuffleStreamRef.current.close();
      }

      const shuffleStartTime = Date.now();
      setState((prev) => ({ ...prev, phase: 'shuffling', error: null, shuffleStartTime }));

      const eventSource = connectShuffleStream(demoIdRef.current);
      shuffleStreamRef.current = eventSource;

      // Listen for game_event SSE messages (backend sends events with event: game_event)
      eventSource.addEventListener('game_event', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data as string) as { type?: string };
          const eventType = data.type ?? 'unknown';
          onEvent(eventType, data);
        } catch (error: unknown) {
          console.error('Failed to parse SSE event:', error);
        }
      });

      // Also listen for generic message events (backward compatibility)
      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data as string) as { type?: string };
          const eventType = event.type ?? data.type ?? 'unknown';
          onEvent(eventType, data);
        } catch (error: unknown) {
          console.error('Failed to parse SSE event:', error);
        }
      };

      eventSource.onerror = (err) => {
        console.error('Shuffle stream closed:', err);

        // Stream closure indicates shuffle phase completed successfully
        // Backend closes stream after transitioning to ShuffleComplete phase
        setState((prev) => {
          const shuffleDuration = prev.shuffleStartTime ? Date.now() - prev.shuffleStartTime : null;
          return { ...prev, phase: 'shuffle_complete', shuffleDuration };
        });

        eventSource.close();
        shuffleStreamRef.current = null;
      };
    },
    []
  );

  /**
   * Step 3: Start deal phase
   * Transitions: shuffle_complete → dealing → complete
   */
  const startDeal = useCallback(
    (onEvent: (eventType: string, data: unknown) => void) => {
      if (!demoIdRef.current) {
        setState((prev) => ({ ...prev, error: 'No demo ID available' }));
        return;
      }

      // Close any existing deal stream
      if (dealStreamRef.current) {
        dealStreamRef.current.close();
      }

      const dealStartTime = Date.now();
      setState((prev) => ({ ...prev, phase: 'dealing', error: null, dealStartTime }));

      const eventSource = connectDealStream(demoIdRef.current);
      dealStreamRef.current = eventSource;

      // Listen for all SSE event types the backend sends
      eventSource.addEventListener('game_event', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data as string) as { type?: string };
          onEvent('game_event', data);
        } catch (error: unknown) {
          console.error('Failed to parse game_event:', error);
        }
      });

      eventSource.addEventListener('card_decryptable', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data as string);
          onEvent('card_decryptable', data);
        } catch (error: unknown) {
          console.error('Failed to parse card_decryptable:', error);
        }
      });

      eventSource.addEventListener('hole_cards_decrypted', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data as string);
          onEvent('hole_cards_decrypted', data);
        } catch (error: unknown) {
          console.error('Failed to parse hole_cards_decrypted:', error);
        }
      });

      eventSource.addEventListener('hand_completed', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data as string);
          onEvent('hand_completed', data);
        } catch (error: unknown) {
          console.error('Failed to parse hand_completed:', error);
        }
      });

      // Also listen for generic message events (backward compatibility)
      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data as string) as { type?: string };
          const eventType = event.type ?? data.type ?? 'unknown';
          onEvent(eventType, data);
        } catch (error: unknown) {
          console.error('Failed to parse SSE event:', error);
        }
      };

      eventSource.onerror = (err) => {
        console.error('Deal stream closed:', err);

        // Stream closure indicates dealing phase completed successfully
        // Backend closes stream after all events have been sent
        setState((prev) => {
          const dealDuration = prev.dealStartTime ? Date.now() - prev.dealStartTime : null;
          return { ...prev, phase: 'complete', dealDuration };
        });

        eventSource.close();
        dealStreamRef.current = null;
      };
    },
    []
  );

  /**
   * Reset demo to initial state
   */
  const reset = useCallback(() => {
    // Cleanup any active streams
    if (shuffleStreamRef.current) {
      shuffleStreamRef.current.close();
      shuffleStreamRef.current = null;
    }
    if (dealStreamRef.current) {
      dealStreamRef.current.close();
      dealStreamRef.current = null;
    }

    // Reset refs
    demoIdRef.current = null;
    isStartingRef.current = false; // Reset guard

    setState({
      phase: 'idle',
      demoId: null,
      gameId: null,
      handId: null,
      error: null,
      shuffleStartTime: null,
      shuffleDuration: null,
      dealStartTime: null,
      dealDuration: null,
    });
  }, []);

  // Memoize actions object to prevent infinite re-renders
  const actions = useMemo(
    () => ({ startDemo, startShuffle, startDeal, reset }),
    [startDemo, startShuffle, startDeal, reset]
  );

  return [state, actions];
}
