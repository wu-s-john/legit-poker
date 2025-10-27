/**
 * Flying Card - Animated card that flies from deck to player position
 * Now stays permanent and reveals when cardState updates
 */

'use client';

import React, { useEffect, useRef, useState } from 'react';
import type { Position } from '~/lib/demo/positioning';
import type { Card as CardType } from '~/types/poker';
import { Card } from './Card';

interface FlyingCardProps {
  startPosition: Position;
  endPosition: Position;
  isForYou: boolean;
  duration?: number;
  delay?: number;
  onComplete?: () => void;
  // New: card state for revealing
  cardState?: {
    revealed: boolean;
    displayCard?: CardType;
  };
}

export function FlyingCard({
  startPosition,
  endPosition,
  isForYou,
  duration = 400,
  delay = 0,
  onComplete,
  cardState,
}: FlyingCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const [isAnimating, setIsAnimating] = useState(false);
  const [hasLanded, setHasLanded] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      // Check if ref is still valid when timer fires
      if (!cardRef.current) return;

      setIsAnimating(true);

      const glowColor = isForYou
        ? 'rgba(251, 191, 36, 0.6)'
        : 'rgba(0, 217, 255, 0.6)';

      const animation = cardRef.current.animate(
        [
          {
            left: `${startPosition.x}px`,
            top: `${startPosition.y}px`,
            transform: 'translate(-50%, -50%) rotate(0deg) scale(0.8)',
            boxShadow: `0 0 20px ${glowColor}`,
            opacity: 1,
          },
          {
            left: `${startPosition.x + (endPosition.x - startPosition.x) * 0.3}px`,
            top: `${startPosition.y + (endPosition.y - startPosition.y) * 0.3}px`,
            transform: 'translate(-50%, -50%) rotate(120deg) scale(1.1)',
            boxShadow: `0 0 30px ${glowColor}`,
            opacity: 1,
          },
          {
            left: `${endPosition.x}px`,
            top: `${endPosition.y}px`,
            transform: 'translate(-50%, -50%) rotate(360deg) scale(1)',
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.5)',
            opacity: 1,
          },
        ],
        {
          duration: isForYou ? duration + 100 : duration,
          easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
          fill: 'forwards',
        }
      );

      animation.onfinish = () => {
        setIsAnimating(false);
        setHasLanded(true);
        onComplete?.();
      };
    }, delay);

    return () => clearTimeout(timer);
  }, [startPosition, endPosition, isForYou, duration, delay, onComplete]);

  // After landing, use Card component for revealing
  if (hasLanded && cardState) {
    return (
      <div
        style={{
          position: 'absolute',
          left: `${endPosition.x}px`,
          top: `${endPosition.y}px`,
          transform: 'translate(-50%, -50%)',
          pointerEvents: 'none',
          zIndex: 10,
        }}
      >
        <Card
          card={cardState.displayCard}
          revealed={cardState.revealed}
          size={isForYou ? 'medium' : 'small'}
        />
      </div>
    );
  }

  // During animation: show card back emoji
  return (
    <div
      ref={cardRef}
      className="flying-card"
      style={{
        position: 'absolute',
        left: `${startPosition.x}px`,
        top: `${startPosition.y}px`,
        transform: 'translate(-50%, -50%)',
        width: isForYou ? '56px' : '48px',
        height: isForYou ? '80px' : '64px',
        background: 'linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%)',
        border: '2px solid rgba(255, 255, 255, 0.1)',
        borderRadius: '8px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: isForYou ? '28px' : '24px',
        pointerEvents: 'none',
        zIndex: isAnimating ? 100 : 10,
      }}
    >
      <span style={{ opacity: 0.7 }}>🃏</span>
    </div>
  );
}
