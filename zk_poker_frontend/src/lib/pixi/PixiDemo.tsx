'use client';

import React, { useEffect, useRef, useImperativeHandle, forwardRef } from 'react';
import { Application, Container } from 'pixi.js';
import { DESIGN_W, DESIGN_H, calculatePlayerPositions, getDeckPosition, getCardPosition } from './utils';
import { PixiTable } from './PixiTable';
import { PixiPlayerSeat } from './PixiPlayerSeat';
import { PixiCard, type Suit, type Rank } from './PixiCard';
import { AnimationManager } from './AnimationManager';
import { PhysicsManager } from './PhysicsManager';
import { InputManager } from './InputManager';
import type { DemoState } from '../demo/demoState';

export interface PixiDemoProps {
  onCardClick?: (seatIndex: number, cardIndex: number) => void;
  playerCount?: number;
}

export interface PixiDemoAPI {
  updateState: (state: DemoState) => void;
  destroy: () => void;
}

const PixiDemo = forwardRef<PixiDemoAPI, PixiDemoProps>(({ onCardClick, playerCount = 7 }, ref) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const appRef = useRef<Application | null>(null);
  const worldRef = useRef<Container | null>(null);
  const isInitializedRef = useRef(false);

  // Game object refs
  const tableRef = useRef<PixiTable | null>(null);
  const seatsRef = useRef<PixiPlayerSeat[]>([]);
  const cardsRef = useRef<Map<string, PixiCard>>(new Map());
  const animationManagerRef = useRef<AnimationManager | null>(null);
  const physicsManagerRef = useRef<PhysicsManager | null>(null);
  const inputManagerRef = useRef<InputManager | null>(null);
  const previousStateRef = useRef<DemoState | null>(null);

  // Cleanup function ref
  const cleanupRef = useRef<(() => void) | null>(null);

  // Initialize Pixi Application
  useEffect(() => {
    if (!containerRef.current) return;

    // Enhanced logging for debugging
    console.log('[PixiDemo] useEffect triggered', {
      hasContainer: !!containerRef.current,
      isInitialized: isInitializedRef.current,
      hasApp: !!appRef.current,
    });

    // Prevent double initialization (React Strict Mode protection)
    // Check isInitializedRef instead of appRef because it's set synchronously
    if (isInitializedRef.current) {
      console.log('[PixiDemo] Already initialized, skipping');
      return;
    }

    console.log('[PixiDemo] Starting initialization');
    isInitializedRef.current = true;

    const initPixi = async () => {
      // Cleanup flag to prevent stale closures
      let cancelled = false;

      const host = containerRef.current!;

      // Create Pixi application
      const app = new Application();
      await app.init({
        resizeTo: host,
        autoDensity: true,
        resolution: Math.min(window.devicePixelRatio || 1, 2),
        backgroundAlpha: 0, // Transparent background
        antialias: true,
        preference: 'webgl', // Prefer WebGL over WebGPU for compatibility
      });

      // Check if component unmounted during async init
      if (cancelled) {
        console.log('[PixiDemo] Initialization cancelled (unmounted during init)');
        app.destroy(true, { children: true, texture: true });
        // Return no-op cleanup function
        return () => {
          // No cleanup needed - already destroyed
        };
      }

      host.appendChild(app.canvas);
      appRef.current = app;

      // Create world container for all game objects
      const world = new Container();
      app.stage.addChild(world);
      worldRef.current = world;

      // Make stage interactive
      app.stage.eventMode = 'static';
      app.stage.hitArea = app.screen;

      // Letterbox scaling function
      const fitWorld = () => {
        const w = app.screen.width;
        const h = app.screen.height;

        // FIT: scale to fit without cropping
        const scale = Math.min(w / DESIGN_W, h / DESIGN_H);

        world.scale.set(scale);
        world.position.set((w - DESIGN_W * scale) / 2, (h - DESIGN_H * scale) / 2);
      };

      fitWorld();

      // Re-fit on resize
      const resizeObserver = new ResizeObserver(fitWorld);
      resizeObserver.observe(host);

      // Pause rendering when tab is hidden (save battery)
      const handleVisibilityChange = () => {
        if (document.hidden) {
          app.ticker.stop();
        } else {
          app.ticker.start();
        }
      };
      document.addEventListener('visibilitychange', handleVisibilityChange);

      // Initialize managers
      animationManagerRef.current = new AnimationManager();
      physicsManagerRef.current = new PhysicsManager({ enabled: false });
      inputManagerRef.current = new InputManager({
        onCardClick: (seatIndex, cardIndex) => {
          onCardClick?.(seatIndex, cardIndex);
        },
      });

      // Initialize table
      tableRef.current = new PixiTable();
      world.addChild(tableRef.current.getContainer());

      // Initialize player seats with dynamic player count
      const playerPositions = calculatePlayerPositions(playerCount);
      seatsRef.current = playerPositions.map((position, index) => {
        const seat = new PixiPlayerSeat({
          position,
          seatIndex: index,
          isViewer: index === 0, // First seat is always the viewer
        });
        world.addChild(seat.getContainer());
        return seat;
      });

      // Add physics update to ticker
      app.ticker.add((ticker) => {
        physicsManagerRef.current?.update(ticker.deltaMS);
      });

      // Cleanup function
      return () => {
        cancelled = true; // Mark as cancelled for future checks
        resizeObserver.disconnect();
        document.removeEventListener('visibilitychange', handleVisibilityChange);
        app.destroy(true, { children: true, texture: true });
      };
    };

    void initPixi().then((cleanup) => {
      cleanupRef.current = cleanup;
    });

    return () => {
      // Only cleanup if we have an app (prevents Strict Mode double-cleanup)
      if (cleanupRef.current) {
        console.log('[PixiDemo] Running cleanup');
        cleanupRef.current();
        cleanupRef.current = null;
      }

      // Reset refs
      appRef.current = null;
      worldRef.current = null;
      // Don't reset isInitializedRef - keep it true to prevent remount from re-initializing
      // Once we've started initialization, we should never initialize again
    };
  }, []);

  // Expose API to parent component
  useImperativeHandle(ref, () => ({
    updateState: (state: DemoState) => {
      if (!worldRef.current || !isInitializedRef.current) {
        console.warn('[PixiDemo] updateState called but not initialized', {
          hasWorld: !!worldRef.current,
          isInitialized: isInitializedRef.current,
        });
        return;
      }

      const world = worldRef.current;
      const previousState = previousStateRef.current;

      console.log('[PixiDemo] updateState called', {
        currentDealQueue: state.dealQueue.length,
        previousDealQueue: previousState?.dealQueue.length ?? 0,
        currentPhase: state.currentPhase,
      });

      // Handle dealing phase
      if (state.dealQueue.length > 0 && (previousState?.dealQueue.length ?? 0) === 0) {
        console.log('[PixiDemo] Triggering deal animation');
        handleDealAnimation(state, world);
      }

      // Update card states (decryptable, revealed)
      state.cards.forEach((cardState, key) => {
        const card = cardsRef.current.get(key);
        if (!card) return;

        // Update decryptable state
        if (cardState.decryptable) {
          card.setState('decryptable');
        }

        // Handle reveal
        if (cardState.revealed && !previousState?.cards.get(key)?.revealed) {
          const { displayCard } = cardState;
          if (displayCard?.suit && displayCard?.rank) {
            // Type assertion is safe here because suit and rank come from validated backend data
            card.setCard(displayCard.suit as Suit, displayCard.rank as Rank);
            void card.flip(500);
          }
        }
      });

      previousStateRef.current = state;
    },
    destroy: () => {
      // Clean up all game objects
      tableRef.current?.destroy();
      seatsRef.current.forEach((seat) => seat.destroy());
      cardsRef.current.forEach((card) => card.destroy());
      animationManagerRef.current?.stopAll();
      physicsManagerRef.current?.destroy();
      inputManagerRef.current?.destroy();

      if (appRef.current) {
        appRef.current.destroy(true);
        appRef.current = null;
        worldRef.current = null;
        isInitializedRef.current = false;
      }
    },
  }));

  // Handle dealing animation
  const handleDealAnimation = (state: DemoState, world: Container) => {
    console.log('[PixiDemo] handleDealAnimation called', {
      dealQueueLength: state.dealQueue.length,
      playerCount: state.playerCount,
    });

    if (state.dealQueue.length === 0) {
      console.warn('[PixiDemo] Deal queue is empty, skipping animation');
      return;
    }

    const deckPosition = getDeckPosition();
    const playerPositions = calculatePlayerPositions(state.playerCount);

    state.dealQueue.forEach((dealItem, index) => {
      const seatIndex = dealItem.seat;
      const cardIndex = dealItem.cardIndex;

      if (seatIndex < 0 || seatIndex >= playerPositions.length) {
        console.error('Invalid seat index:', seatIndex);
        return;
      }

      const seatPosition = playerPositions[seatIndex];
      if (!seatPosition) {
        console.error('Seat position not found for index:', seatIndex);
        return;
      }

      const cardPosition = getCardPosition(seatPosition, cardIndex, 80, 10, seatIndex === 0);

      // Create card
      const cardKey = `${seatIndex}_${cardIndex}`;
      const card = new PixiCard({
        width: 80,
        height: 112,
        position: deckPosition,
        seatIndex,
        cardIndex,
      });

      world.addChild(card.getContainer());
      cardsRef.current.set(cardKey, card);

      // Make card interactive
      inputManagerRef.current?.makeCardInteractive(card);

      // Animate card from deck to player
      const delay = index * 200; // 200ms stagger
      void animationManagerRef.current?.dealCard({
        card,
        start: deckPosition,
        end: cardPosition,
        duration: 400,
        delay,
      });
    });
  };

  return (
    <div
      ref={containerRef}
      style={{
        width: '100%',
        height: '100%',
        display: 'grid',
        placeItems: 'center',
        overflow: 'hidden',
        touchAction: 'none',
        WebkitUserSelect: 'none',
        userSelect: 'none',
      }}
    />
  );
});

PixiDemo.displayName = 'PixiDemo';

export default PixiDemo;
