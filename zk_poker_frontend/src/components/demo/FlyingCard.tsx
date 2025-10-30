/**
 * Flying Card - Animated card that flies from deck to player position using Framer Motion
 * Now stays permanent and reveals when cardState updates
 */

'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
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
    decryptable?: boolean;
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
  const [hasLanded, setHasLanded] = useState(false);

  const glowColor = isForYou
    ? 'rgba(251, 191, 36, 0.6)'
    : 'rgba(0, 217, 255, 0.6)';

  // Calculate midpoint for curved animation
  const midX = startPosition.x + (endPosition.x - startPosition.x) * 0.3;
  const midY = startPosition.y + (endPosition.y - startPosition.y) * 0.3;

  // After landing, use Card component for revealing
  if (hasLanded && cardState) {
    return (
      <div
        style={{
          position: 'absolute',
          left: `${endPosition.x}%`,
          top: `${endPosition.y}%`,
          transform: 'translate(-50%, -50%)',
          pointerEvents: 'none',
          zIndex: 10,
        }}
      >
        <Card
          card={cardState.displayCard}
          revealed={cardState.revealed}
          decryptable={cardState.decryptable}
          isViewer={isForYou}
          size={isForYou ? 'medium' : 'small'}
        />
      </div>
    );
  }

  // Card sizes using viewport width (vw) matching Card component
  const cardVw = isForYou ? 2.8 : 2.3; // Slightly smaller during flight
  const minWidth = isForYou ? 42 : 35;

  // During animation: show card back emoji with Framer Motion
  // Note: Framer Motion animates left/top as percentages when positions are percentages
  return (
    <motion.div
      className="flying-card"
      initial={{
        left: `${startPosition.x}%`,
        top: `${startPosition.y}%`,
        rotate: 0,
        scale: 0.8,
        opacity: 1,
      }}
      animate={{
        left: [`${startPosition.x}%`, `${midX}%`, `${endPosition.x}%`],
        top: [`${startPosition.y}%`, `${midY}%`, `${endPosition.y}%`],
        rotate: [0, 120, 360],
        scale: [0.8, 1.1, 1],
        opacity: 1,
      }}
      transition={{
        duration: (isForYou ? duration + 100 : duration) / 1000,
        delay: delay / 1000,
        ease: [0.4, 0, 0.2, 1],
        times: [0, 0.3, 1],
      }}
      onAnimationComplete={() => {
        setHasLanded(true);
        onComplete?.();
      }}
      style={{
        position: 'absolute',
        x: '-50%',
        y: '-50%',
        width: `${cardVw}vw`,
        minWidth: `${minWidth}px`,
        aspectRatio: '5 / 7', // Standard playing card ratio
        background: 'linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%)',
        border: '2px solid rgba(255, 255, 255, 0.1)',
        borderRadius: '8px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        pointerEvents: 'none',
        zIndex: hasLanded ? 10 : 100,
        boxShadow: `0 0 20px ${glowColor}`,
      }}
    >
      <span className={isForYou ? 'flying-card-emoji-viewer' : 'flying-card-emoji'}>🃏</span>
    </motion.div>
  );
}
