/**
 * Embedded Demo Scene - Embeddable variant for landing page integration
 *
 * Key differences from DemoScene:
 * - Controlled initialization via isActive prop
 * - Exposes events to parent via onEvent callback
 * - Customizable sizing and background
 * - Designed for constrained containers (920px × 600px)
 */

'use client';

import React, { useEffect, useReducer, useRef, useState, type CSSProperties } from 'react';
import { connectDemoStream } from '~/lib/demo/stream';
import { calculatePlayerPositions, getDeckPosition, getCardPosition, type Position } from '~/lib/demo/positioning';
import { demoReducer, initialDemoState, getCardsForSeat, getShuffleProgress } from '~/lib/demo/demoState';
import { DemoEventHandler } from '~/lib/demo/eventHandlers';
import { GapDetector } from '~/lib/demo/gapRecovery';
import { fetchDemoEvents } from '~/lib/api/demoApi';
import type { DemoStreamEvent } from '~/lib/demo/events';
import { PokerTable } from './PokerTable';
import { PlayerSeat } from './PlayerSeat';
import { ShuffleOverlay } from './ShuffleOverlay';
import { CompletionOverlay } from './CompletionOverlay';
import { FlyingCard } from './FlyingCard';
import './demo.css';

interface FlyingCardAnimation {
  id: string;
  seat: number;
  cardIndex: number;
  startPosition: Position;
  endPosition: Position;
}

export interface EmbeddedDemoSceneProps {
  /** Control when demo initializes and starts */
  isActive: boolean;

  /** Callback to emit events to parent (for protocol logs sync) */
  onEvent?: (event: DemoStreamEvent) => void;

  /** Custom container styles (e.g., height, width) */
  containerStyle?: CSSProperties;

  /** Show dark background (false = transparent for green felt) */
  showBackground?: boolean;

  /** Auto-scale to fit container (default: true) */
  autoScale?: boolean;
}

export function EmbeddedDemoScene({
  isActive,
  onEvent,
  containerStyle,
  showBackground = false,
  autoScale: _autoScale = true, // Reserved for future use
}: EmbeddedDemoSceneProps) {
  // State management
  const [state, dispatch] = useReducer(demoReducer, initialDemoState);

  // Flying card animations
  const [flyingCards, setFlyingCards] = useState<FlyingCardAnimation[]>([]);

  // Gap detection
  const gapDetectorRef = useRef(new GapDetector());

  // Event handler
  const eventHandlerRef = useRef<DemoEventHandler | null>(null);

  // Track initialization
  const [hasInitialized, setHasInitialized] = useState(false);

  // Initialize event handler
  useEffect(() => {
    // Guard: prevent recreation on Strict Mode remounts
    if (eventHandlerRef.current) return;

    eventHandlerRef.current = new DemoEventHandler(dispatch, {
      onShuffleProgress: (_current, _total) => {
        // Already handled in reducer
      },
      onCardDealt: (seat, cardIndex, _deckPosition) => {
        triggerCardAnimation(seat, cardIndex);
      },
      onCardReveal: (_seat, _cardIndex) => {
        // Card revealed - animation handled by Card component
      },
      onPhaseChange: (phase) => {
        console.log('Phase changed:', phase);
      },
    });
  }, []);

  // Conditional initialization - only when isActive becomes true
  useEffect(() => {
    if (!isActive || hasInitialized) return;

    // Stream will handle game creation automatically
    dispatch({
      type: 'UPDATE_STATUS',
      message: 'Connecting to demo stream...',
    });

    setHasInitialized(true);
  }, [isActive, hasInitialized]);

  // Reset when isActive becomes false
  useEffect(() => {
    if (!isActive) {
      setHasInitialized(false);
      gapDetectorRef.current.reset();
    }
  }, [isActive]);

  // Connect to SSE stream (only when active)
  useEffect(() => {
    if (!isActive || !eventHandlerRef.current) return;

    const cleanup = connectDemoStream({
      onEvent: (event) => {
        // Emit to parent
        onEvent?.(event);

        // Handle demo event through event handler
        if (event.type === 'game_event') {
          // Check for gaps in protocol messages
          const result = gapDetectorRef.current.detectGaps(event);

          console.log('[EmbeddedDemoScene] Gap detection result:', {
            seqId: event.snapshot_sequence_id,
            hasGap: result.hasGap,
            missingSeqIds: result.missingSeqIds,
            readyEventsCount: result.readyEvents.length,
          });

          if (result.hasGap) {
            console.warn('Gap detected, fetching missing events:', result.missingSeqIds);
            void handleGapRecovery(result.missingSeqIds);
          }

          // Process all ready events (they're already full game_event objects)
          result.readyEvents.forEach((gameEvent) => {
            console.log('[EmbeddedDemoScene] Processing ready event:', gameEvent.snapshot_sequence_id);
            eventHandlerRef.current?.handleDemoEvent(gameEvent);
          });
        } else {
          // Non-protocol events don't need gap detection
          eventHandlerRef.current.handleDemoEvent(event);
        }
      },
      onError: (error) => {
        console.error('Demo stream error:', error);
        dispatch({ type: 'SET_ERROR', error: 'Stream connection error' });
      },
      onComplete: () => {
        console.log('Demo stream completed');
      },
    });

    return cleanup;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isActive, onEvent]);

  // Gap recovery function
  async function handleGapRecovery(missingSeqIds: number[]): Promise<void> {
    if (!state.gameId || !state.handId) return;

    try {
      const envelopes = await fetchDemoEvents(state.gameId, state.handId, {
        seqIds: missingSeqIds,
      });

      // Convert FinalizedAnyMessageEnvelope to GameEvent format
      const events = envelopes.map(env => ({
        type: 'game_event' as const,
        envelope: env.envelope,
        snapshot_status: env.snapshot_status,
        applied_phase: env.applied_phase,
        snapshot_sequence_id: env.snapshot_sequence_id,
        created_timestamp: env.created_timestamp,
      }));

      const readyEvents = gapDetectorRef.current.processFetchedEvents(events);

      // Process recovered events
      readyEvents.forEach((event) => {
        eventHandlerRef.current?.handleDemoEvent(event);
      });
    } catch (error) {
      console.error('Gap recovery failed:', error);
    }
  }

  // Trigger card dealing animation
  function triggerCardAnimation(seat: number, cardIndex: number): void {
    const deckPos = getDeckPosition();
    const playerPositions = calculatePlayerPositions(state.playerCount);
    const playerPos = playerPositions.find((p) => p.seat === seat);

    if (!playerPos) return;

    // Calculate the specific card position (left or right card slot)
    const isViewer = seat === state.viewerSeat;
    const cardPosition = getCardPosition(playerPos.position, cardIndex, isViewer);

    const animation: FlyingCardAnimation = {
      id: `card_${seat}_${cardIndex}_${Date.now()}`,
      seat,
      cardIndex,
      startPosition: deckPos,
      endPosition: cardPosition,
    };

    setFlyingCards((prev) => [...prev, animation]);

    // FlyingCard now stays permanent after animation completes
  }

  // Handle new hand request
  async function handleNewHand(): Promise<void> {
    try {
      // Reset gap detector
      gapDetectorRef.current.reset();

      // Reset event handler
      eventHandlerRef.current?.reset();

      // For embedded version, trigger parent refresh or reload
      window.location.reload();
    } catch (error) {
      console.error('Failed to start new hand:', error);
    }
  }

  // Calculate positions
  const playerPositions = calculatePlayerPositions(state.playerCount);
  const deckPosition = getDeckPosition();

  // Get viewer cards
  const viewerCards = getCardsForSeat(state, state.viewerSeat);
  const viewerRevealedCards = viewerCards
    .filter((c) => c.revealed && c.displayCard)
    .map((c) => c.displayCard!);

  // Calculate progress
  const shuffleProgress = getShuffleProgress(state);

  // Container class names
  const containerClasses = ['demo-scene', 'embedded'].filter(Boolean).join(' ');

  // Container styles
  const finalContainerStyle: CSSProperties = {
    background: showBackground ? '#0a0e14' : 'transparent',
    height: '100%',
    position: 'relative',
    ...containerStyle,
  };

  // Show loading state while initializing
  const isLoading = isActive && !hasInitialized && !state.errorMessage;

  // Only show table elements after demo has initialized
  const shouldShowTable = isActive && hasInitialized;

  return (
    <div className={containerClasses} style={finalContainerStyle}>
      {/* Loading state */}
      {isLoading && (
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
              Initializing demo...
            </p>
          </div>
        </div>
      )}

      {/* Only render table when demo is active and initialized */}
      {shouldShowTable && (
        <PokerTable>
        {/* Deck visualization */}
        <div
          className="deck-indicator"
          style={{
            position: 'absolute',
            left: `${deckPosition.x}%`,
            top: `${deckPosition.y}%`,
            transform: 'translate(-50%, -50%)',
          }}
        >
          <div
            className="deck-icon"
            style={{
              background: 'linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%)',
              borderRadius: '8px',
              border: '2px solid rgba(255, 255, 255, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <span className="deck-emoji">🃏</span>
          </div>
        </div>

        {/* Players */}
        {playerPositions.map((playerPos) => {
          const isViewer = playerPos.seat === state.viewerSeat;

          return (
            <PlayerSeat
              key={playerPos.seat}
              seat={playerPos.seat}
              position={playerPos.position}
              isViewer={isViewer}
              name={`Player ${playerPos.seat + 1}`}
              isActive={false}
            >
              {/* Cards are now shown via FlyingCard components */}
            </PlayerSeat>
          );
        })}

        {/* Flying card animations */}
        {flyingCards.map((anim) => {
          // Get card state for this flying card
          const playerCards = getCardsForSeat(state, anim.seat);
          const cardState = playerCards.find((c) => c.position === anim.cardIndex);

          return (
            <FlyingCard
              key={anim.id}
              startPosition={anim.startPosition}
              endPosition={anim.endPosition}
              isForYou={anim.seat === state.viewerSeat}
              duration={400}
              cardState={
                cardState
                  ? {
                      revealed: cardState.revealed,
                      displayCard: cardState.displayCard,
                      decryptable: cardState.decryptable,
                    }
                  : undefined
              }
              onComplete={() => {
                // Animation complete
              }}
            />
          );
        })}
      </PokerTable>
      )}

      {/* Phase Overlays - always render if active to show loading/error states */}
      {isActive && (
        <>
      <ShuffleOverlay
        progress={shuffleProgress}
        isVisible={state.currentPhase === 'shuffling'}
        currentShuffler={state.currentShuffleStep > 0 ? state.currentShuffleStep - 1 : undefined}
        totalShufflers={state.totalShuffleSteps > 0 ? state.totalShuffleSteps : undefined}
      />

      {/* DealingOverlay removed to allow unobstructed view of card animations */}

      <CompletionOverlay
        isVisible={state.currentPhase === 'complete'}
        viewerCards={viewerRevealedCards}
        onNewHand={handleNewHand}
      />
        </>
      )}

      {/* Error display */}
      {state.errorMessage && (
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
          {state.errorMessage}
        </div>
      )}
    </div>
  );
}
