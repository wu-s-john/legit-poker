/**
 * Interactive Demo Scene - User-controlled multi-phase poker demo
 *
 * Replaces the auto-playing EmbeddedDemoScene with a three-phase interactive flow:
 * 1. Preparation: "Ready to shuffle?" overlay with button
 * 2. Shuffling: Progress overlay → completion state with "Start Dealing" button
 * 3. Dealing: Card animations and final completion overlay
 */

'use client';

import React, { useEffect, useReducer, useRef, useState, type CSSProperties } from 'react';
import { useInteractiveDemo } from '~/hooks/useInteractiveDemo';
import {
  demoReducer,
  initialDemoState,
  getCardsForSeat,
  getShuffleProgress,
  areAllCardsDealt,
  areAllCardsDecryptable,
  areViewerCardsDecryptable,
} from '~/lib/demo/demoState';
import { DemoEventHandler } from '~/lib/demo/eventHandlers';
import { GapDetector } from '~/lib/demo/gapRecovery';
import { fetchDemoEvents } from '~/lib/api/demoApi';
import type { DemoStreamEvent } from '~/lib/demo/events';
import PixiDemo, { type PixiDemoAPI } from '~/lib/pixi/PixiDemo';
import { PreparationOverlay } from './PreparationOverlay';
import { ShuffleOverlay } from './ShuffleOverlay';
import { CompletionOverlay } from './CompletionOverlay';
import './demo.css';

export interface InteractiveDemoSceneProps {
  /** Control when demo initializes and starts */
  isActive: boolean;

  /** Callback to emit events to parent (for protocol logs sync) */
  onEvent?: (event: DemoStreamEvent) => void;

  /** Custom container styles (e.g., height, width) */
  containerStyle?: CSSProperties;

  /** Show dark background (false = transparent for green felt) */
  showBackground?: boolean;
}

export function InteractiveDemoScene({
  isActive,
  onEvent,
  containerStyle,
  showBackground = false,
}: InteractiveDemoSceneProps) {
  // Interactive demo state management
  const [demoState, demoActions] = useInteractiveDemo();

  // Poker game state management
  const [gameState, dispatch] = useReducer(demoReducer, initialDemoState);

  // PixiJS initialization tracking
  const [isPixiReady, setIsPixiReady] = useState(false);

  // Pixi demo ref
  const pixiDemoRef = useRef<PixiDemoAPI | null>(null);

  // Gap detection
  const gapDetectorRef = useRef(new GapDetector());

  // Event handler
  const eventHandlerRef = useRef<DemoEventHandler | null>(null);

  // Sync game state with Pixi whenever state changes
  useEffect(() => {
    if (pixiDemoRef.current && isActive) {
      pixiDemoRef.current.updateState(gameState);
    }
  }, [gameState, isActive]);

  // Initialize event handler
  useEffect(() => {
    if (eventHandlerRef.current) return;

    eventHandlerRef.current = new DemoEventHandler(dispatch, {
      onShuffleProgress: (_current, _total) => {
        // Already handled in reducer
      },
      onCardDealt: (_seat, _cardIndex, _deckPosition) => {
        // Card animation now handled by Pixi
      },
      onCardReveal: (_seat, _cardIndex) => {
        // Card revealed - handled by Pixi
      },
      onPhaseChange: (phase) => {
        console.log('Phase changed:', phase);
      },
    });
  }, []);

  // Step 1: Create demo session when isActive becomes true
  useEffect(() => {
    if (isActive && demoState.phase === 'idle') {
      void demoActions.startDemo();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isActive, demoState.phase]); // demoActions omitted - stable reference, prevents double calls

  // Update game state when demo session is created
  useEffect(() => {
    if (demoState.gameId && demoState.handId) {
      dispatch({
        type: 'INIT_GAME',
        gameId: demoState.gameId,
        handId: demoState.handId,
        publicKey: null,
        playerCount: 7,
      });
    }
  }, [demoState.gameId, demoState.handId]);

  // Reset when isActive becomes false
  useEffect(() => {
    if (!isActive) {
      demoActions.reset();
      gapDetectorRef.current.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isActive]); // demoActions omitted - stable reference, prevents unnecessary resets

  // Handle shuffle start
  const handleStartShuffle = () => {
    demoActions.startShuffle((eventType, data) => {
      const event = data as DemoStreamEvent;

      console.log('[InteractiveDemoScene] Received shuffle event:', event.type);

      // Emit to parent
      onEvent?.(event);

      // Handle event through game state
      if (event.type === 'game_event') {
        const result = gapDetectorRef.current.detectGaps(event);

        if (result.hasGap) {
          console.warn('Gap detected, fetching missing events:', result.missingSeqIds);
          void handleGapRecovery(result.missingSeqIds);
        }

        result.readyEvents.forEach((gameEvent) => {
          eventHandlerRef.current?.handleDemoEvent(gameEvent);
        });
      } else {
        eventHandlerRef.current?.handleDemoEvent(event);
      }
    });
  };

  // Handle deal start
  const handleStartDeal = () => {
    demoActions.startDeal((eventType, data) => {
      const event = data as DemoStreamEvent;

      // Emit to parent
      onEvent?.(event);

      // Handle event through game state
      if (event.type === 'game_event') {
        const result = gapDetectorRef.current.detectGaps(event);

        if (result.hasGap) {
          console.warn('Gap detected, fetching missing events:', result.missingSeqIds);
          void handleGapRecovery(result.missingSeqIds);
        }

        result.readyEvents.forEach((gameEvent) => {
          eventHandlerRef.current?.handleDemoEvent(gameEvent);
        });
      } else {
        eventHandlerRef.current?.handleDemoEvent(event);
      }
    });
  };

  // Gap recovery function
  async function handleGapRecovery(missingSeqIds: number[]): Promise<void> {
    if (!demoState.gameId || !demoState.handId) return;

    try {
      const envelopes = await fetchDemoEvents(demoState.gameId, demoState.handId, {
        seqIds: missingSeqIds,
      });

      const events = envelopes.map((env) => ({
        type: 'game_event' as const,
        envelope: env.envelope,
        snapshot_status: env.snapshot_status,
        applied_phase: env.applied_phase,
        snapshot_sequence_id: env.snapshot_sequence_id,
        created_timestamp: env.created_timestamp,
      }));

      const readyEvents = gapDetectorRef.current.processFetchedEvents(events);

      readyEvents.forEach((event) => {
        eventHandlerRef.current?.handleDemoEvent(event);
      });
    } catch (error) {
      console.error('Gap recovery failed:', error);
    }
  }

  // After all cards dealt, wait 500ms before allowing completion overlay
  useEffect(() => {
    const allCardsDealt = areAllCardsDealt(gameState);
    if (allCardsDealt && !gameState.canShowCompletionOverlay) {
      const timer = setTimeout(() => {
        dispatch({ type: 'ENABLE_COMPLETION_OVERLAY' });
      }, 500);

      return () => clearTimeout(timer);
    }
  }, [gameState.cards, gameState.canShowCompletionOverlay]);

  // After viewer's cards are decryptable, wait 300ms before enabling final overlay condition
  useEffect(() => {
    const viewerCardsDecryptable = areViewerCardsDecryptable(gameState);
    if (viewerCardsDecryptable && !gameState.canShowOverlayAfterViewerCardsDecryptable) {
      const timer = setTimeout(() => {
        dispatch({ type: 'ENABLE_VIEWER_CARDS_OVERLAY_TIMER' });
      }, 300);

      return () => clearTimeout(timer);
    }
  }, [gameState.cards, gameState.viewerSeat, gameState.canShowOverlayAfterViewerCardsDecryptable]);

  // Handle new hand request
  async function handleNewHand(): Promise<void> {
    try {
      gapDetectorRef.current.reset();
      eventHandlerRef.current?.reset();
      demoActions.reset();
      window.location.reload();
    } catch (error) {
      console.error('Failed to start new hand:', error);
    }
  }

  // Handle subscribe button click
  function handleSubscribe(): void {
    const subscribeUrl = process.env.NEXT_PUBLIC_SUBSCRIBE_URL ?? '/launch-updates';
    window.open(subscribeUrl, '_blank', 'noopener,noreferrer');
  }

  // Get viewer cards
  const viewerCards = getCardsForSeat(gameState, gameState.viewerSeat);
  const viewerRevealedCards = viewerCards
    .filter((c) => c.revealed && c.displayCard)
    .map((c) => c.displayCard!);

  // Calculate progress
  const shuffleProgress = getShuffleProgress(gameState);

  // Container styles
  const finalContainerStyle: CSSProperties = {
    background: showBackground ? '#0a0e14' : 'transparent',
    height: '100%',
    position: 'relative',
    ...containerStyle,
  };

  // Show table after demo session is created (not during idle or loading)
  const shouldShowTable = isActive && demoState.phase !== 'idle' && demoState.phase !== 'loading';

  return (
    <div className="demo-scene embedded" style={finalContainerStyle}>
      {/* Loading state - Wait for both demo session AND PixiJS initialization */}
      {isActive && (demoState.phase === 'idle' || demoState.phase === 'loading' || (demoState.phase === 'ready' && !isPixiReady)) && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'rgba(0, 0, 0, 0.3)',
            zIndex: 100,
          }}
        >
          <div style={{ textAlign: 'center' }}>
            <div
              style={{
                width: '48px',
                height: '48px',
                border: '4px solid rgba(255, 255, 255, 0.1)',
                borderTop: '4px solid #10b981',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite',
                margin: '0 auto 16px',
              }}
            />
            <p style={{ color: 'rgba(255, 255, 255, 0.7)', fontSize: '14px' }}>
              {demoState.phase === 'ready' && !isPixiReady
                ? 'Loading poker table...'
                : 'Creating demo session...'}
            </p>
          </div>
        </div>
      )}

      {/* Pixi Demo Canvas - Always rendered for preinitialization */}
      {isActive && (
        <div style={{ opacity: shouldShowTable ? 1 : 0, transition: 'opacity 300ms ease-in-out' }}>
          <PixiDemo
            ref={pixiDemoRef}
            playerCount={gameState.playerCount}
            onCardClick={(seatIndex, cardIndex) => {
              console.log('Card clicked:', seatIndex, cardIndex);
            }}
            onCardAnimationComplete={(seat, cardIndex) => {
              dispatch({ type: 'CARD_DEALT', seat, cardIndex });
            }}
            onInitialized={() => {
              console.log('[InteractiveDemoScene] PixiJS initialization complete');
              setIsPixiReady(true);
            }}
          />
        </div>
      )}

      {/* Phase Overlays */}
      {isActive && (
        <>
          {/* Preparation Overlay - "Ready to shuffle?" */}
          {demoState.phase === 'ready' && isPixiReady && <PreparationOverlay onStartShuffle={handleStartShuffle} />}

          {/* Shuffle Overlay - Progress and completion */}
          <ShuffleOverlay
            progress={shuffleProgress}
            isVisible={demoState.phase === 'shuffling' || demoState.phase === 'shuffle_complete'}
            currentShuffler={gameState.currentShuffleStep > 0 ? gameState.currentShuffleStep - 1 : undefined}
            totalShufflers={gameState.totalShuffleSteps > 0 ? gameState.totalShuffleSteps : undefined}
            isComplete={demoState.phase === 'shuffle_complete'}
            onStartDeal={handleStartDeal}
          />

          {/* Completion Overlay - Show dealt cards */}
          {(() => {
            const phaseComplete = demoState.phase === 'complete';
            const allCardsDealt = areAllCardsDealt(gameState);
            const allCardsDecryptable = areAllCardsDecryptable(gameState);
            const canShowOverlay = gameState.canShowCompletionOverlay;
            const canShowAfterViewerCards = gameState.canShowOverlayAfterViewerCardsDecryptable;

            console.log('[InteractiveDemoScene] Completion overlay visibility check:', {
              phaseComplete,
              allCardsDealt,
              allCardsDecryptable,
              canShowOverlay,
              canShowAfterViewerCards,
              totalCards: gameState.cards.size,
            });

            return null;
          })()}
          <CompletionOverlay
            isVisible={
              demoState.phase === 'complete' &&
              areAllCardsDealt(gameState) &&
              areAllCardsDecryptable(gameState) &&
              gameState.canShowCompletionOverlay &&
              gameState.canShowOverlayAfterViewerCardsDecryptable
            }
            viewerCards={viewerRevealedCards}
            onNewHand={handleNewHand}
            onSubscribe={handleSubscribe}
          />
        </>
      )}

      {/* Error display */}
      {demoState.error && (
        <div
          style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: 'rgba(239, 68, 68, 0.9)',
            color: 'white',
            padding: '12px 20px',
            borderRadius: '8px',
            zIndex: 200,
          }}
        >
          {demoState.error}
        </div>
      )}

      {gameState.errorMessage && (
        <div
          style={{
            position: 'absolute',
            top: '60px',
            right: '20px',
            background: 'rgba(239, 68, 68, 0.9)',
            color: 'white',
            padding: '12px 20px',
            borderRadius: '8px',
            zIndex: 200,
          }}
        >
          {gameState.errorMessage}
        </div>
      )}
    </div>
  );
}
