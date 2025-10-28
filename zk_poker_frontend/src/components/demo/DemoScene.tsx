/**
 * Demo Scene - Main orchestrator for the poker demo visualization
 */

'use client';

import React, { useEffect, useReducer, useRef, useState } from 'react';
import { connectDemoStream } from '~/lib/demo/stream';
import { calculatePlayerPositions, getDeckPosition, getCardPosition, type Position } from '~/lib/demo/positioning';
import { demoReducer, initialDemoState, getCardsForSeat, getShuffleProgress } from '~/lib/demo/demoState';
import { DemoEventHandler } from '~/lib/demo/eventHandlers';
import { GapDetector } from '~/lib/demo/gapRecovery';
import { fetchDemoEvents } from '~/lib/api/demoApi';
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

export function DemoScene() {
  // State management
  const [state, dispatch] = useReducer(demoReducer, initialDemoState);

  // Flying card animations
  const [flyingCards, setFlyingCards] = useState<FlyingCardAnimation[]>([]);

  // Gap detection
  const gapDetectorRef = useRef(new GapDetector());

  // Event handler
  const eventHandlerRef = useRef<DemoEventHandler | null>(null);

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

  // Initialize demo - stream will handle game creation automatically
  useEffect(() => {
    // Stream connection will handle everything
    dispatch({
      type: 'UPDATE_STATUS',
      message: 'Connecting to demo stream...',
    });
  }, []);

  // Connect to SSE stream
  useEffect(() => {
    if (!eventHandlerRef.current) return;

    const cleanup = connectDemoStream({
      onEvent: (event) => {
        // Handle demo event through event handler
        if (event.type === 'game_event') {
          // Check for gaps in protocol messages
          const result = gapDetectorRef.current.detectGaps(event);

          if (result.hasGap) {
            console.warn('Gap detected, fetching missing events:', result.missingSeqIds);
            void handleGapRecovery(result.missingSeqIds);
          }

          // Process all ready events (they're already full game_event objects)
          result.readyEvents.forEach((gameEvent) => {
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
  }, []);

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

      // Reload page to restart stream
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

  return (
    <div className="demo-scene" style={{ background: '#0a0e14', minHeight: '100vh' }}>
      <PokerTable>
        {/* Deck visualization */}
        <div
          className="deck-indicator"
          style={{
            position: 'absolute',
            left: `${deckPosition.x}px`,
            top: `${deckPosition.y}px`,
            transform: 'translate(-50%, -50%)',
          }}
        >
          <div
            className="deck-icon"
            style={{
              width: '80px',
              height: '112px',
              background: 'linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%)',
              borderRadius: '8px',
              border: '2px solid rgba(255, 255, 255, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '32px',
            }}
          >
            🃏
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

      {/* Phase Overlays */}
      <ShuffleOverlay progress={shuffleProgress} isVisible={state.currentPhase === 'shuffling'} />

      {/* DealingOverlay removed to allow unobstructed view of card animations */}

      <CompletionOverlay
        isVisible={state.currentPhase === 'complete'}
        viewerCards={viewerRevealedCards}
        onNewHand={handleNewHand}
      />

      {/* Error display */}
      {state.errorMessage && (
        <div
          style={{
            position: 'fixed',
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
