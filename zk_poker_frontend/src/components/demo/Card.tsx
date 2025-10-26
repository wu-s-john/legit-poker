/**
 * Card - Playing card with 3D flip animation
 */

import React from 'react';
import type { Card as CardType, Suit } from '~/types/poker';

interface CardProps {
  card?: CardType;
  revealed: boolean;
  size?: 'small' | 'medium' | 'large' | 'xlarge';
  className?: string;
  onFlipComplete?: () => void;
}

const CARD_SIZES = {
  small: { width: 40, height: 56 },
  medium: { width: 60, height: 84 },
  large: { width: 65, height: 91 },
  xlarge: { width: 70, height: 98 },
};

const SUIT_SYMBOLS: Record<Suit, string> = {
  spades: '♠',
  hearts: '♥',
  diamonds: '♦',
  clubs: '♣',
};

const SUIT_COLORS: Record<Suit, string> = {
  spades: '#000000',
  hearts: '#c41e3a',
  diamonds: '#c41e3a',
  clubs: '#000000',
};

export function Card({
  card,
  revealed,
  size = 'medium',
  className = '',
  onFlipComplete,
}: CardProps) {
  const dimensions = CARD_SIZES[size];
  const [isFlipping, setIsFlipping] = React.useState(false);

  React.useEffect(() => {
    if (revealed && !isFlipping) {
      setIsFlipping(true);
      const timer = setTimeout(() => {
        setIsFlipping(false);
        onFlipComplete?.();
      }, 500);
      return () => clearTimeout(timer);
    }
  }, [revealed, isFlipping, onFlipComplete]);

  return (
    <div
      className={`card-container ${className}`}
      style={{
        width: `${dimensions.width}px`,
        height: `${dimensions.height}px`,
        perspective: '1000px',
      }}
    >
      <div
        className={`card-inner ${revealed ? 'flipped' : ''} ${isFlipping ? 'flipping' : ''}`}
        style={{
          position: 'relative',
          width: '100%',
          height: '100%',
          transformStyle: 'preserve-3d',
          transition: 'transform 500ms cubic-bezier(0.4, 0, 0.2, 1)',
          transform: revealed ? 'rotateY(180deg)' : 'rotateY(0deg)',
        }}
      >
        {/* Card Back */}
        <div
          className="card-face card-back"
          style={{
            position: 'absolute',
            width: '100%',
            height: '100%',
            backfaceVisibility: 'hidden',
            background: 'linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%)',
            border: '2px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: `${dimensions.width * 0.5}px`,
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.5)',
          }}
        >
          <span style={{ opacity: 0.7 }}>🃏</span>
        </div>

        {/* Card Front */}
        {card && (
          <div
            className="card-face card-front"
            style={{
              position: 'absolute',
              width: '100%',
              height: '100%',
              backfaceVisibility: 'hidden',
              transform: 'rotateY(180deg)',
              background: '#ffffff',
              border: '2px solid #d1d5db',
              borderRadius: '8px',
              boxShadow: '0 8px 16px rgba(0, 0, 0, 0.5)',
              color: SUIT_COLORS[card.suit],
              fontFamily: 'serif',
              fontWeight: 'bold',
            }}
          >
            {/* Top-left corner */}
            <div
              className="card-corner"
              style={{
                position: 'absolute',
                top: '6px',
                left: '6px',
                fontSize: `${dimensions.width * 0.25}px`,
                lineHeight: 1,
                textAlign: 'center',
              }}
            >
              <div>{card.rank}</div>
              <div style={{ fontSize: `${dimensions.width * 0.25}px` }}>
                {SUIT_SYMBOLS[card.suit]}
              </div>
            </div>

            {/* Center suit */}
            <div
              className="card-center"
              style={{
                position: 'absolute',
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                fontSize: `${dimensions.width * 0.7}px`,
                lineHeight: 1,
              }}
            >
              {SUIT_SYMBOLS[card.suit]}
            </div>

            {/* Bottom-right corner (rotated 180°) */}
            <div
              className="card-corner"
              style={{
                position: 'absolute',
                bottom: '6px',
                right: '6px',
                fontSize: `${dimensions.width * 0.25}px`,
                lineHeight: 1,
                textAlign: 'center',
                transform: 'rotate(180deg)',
              }}
            >
              <div>{card.rank}</div>
              <div style={{ fontSize: `${dimensions.width * 0.25}px` }}>
                {SUIT_SYMBOLS[card.suit]}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
