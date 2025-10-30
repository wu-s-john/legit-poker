/**
 * Card - Playing card with 3D flip animation
 */

import React from 'react';
import type { Card as CardType, Suit } from '~/types/poker';
import { DecryptableBadge } from './DecryptableBadge';

interface CardProps {
  card?: CardType;
  revealed: boolean;
  decryptable?: boolean;
  isViewer?: boolean;
  size?: 'small' | 'medium' | 'large' | 'xlarge';
  className?: string;
  onFlipComplete?: () => void;
}

// Card sizes using viewport width (vw) for consistent scaling
// Min-width ensures cards don't get too small on mobile devices
const CARD_SIZES = {
  small: { vw: 2.5, minWidth: 35 }, // ~48px at 1920px, min 35px
  medium: { vw: 3, minWidth: 45 }, // ~58px at 1920px, min 45px
  large: { vw: 3.3, minWidth: 50 }, // ~63px at 1920px, min 50px
  xlarge: { vw: 3.5, minWidth: 55 }, // ~67px at 1920px, min 55px
};

// Map suit names to SVG file naming convention
const getSuitFileName = (suit: Suit): string => {
  const suitMap: Record<Suit, string> = {
    hearts: 'Heart',
    diamonds: 'Diamond',
    clubs: 'Club',
    spades: 'Spade',
  };
  return suitMap[suit];
};

export function Card({
  card,
  revealed,
  decryptable = false,
  isViewer = false,
  size = 'medium',
  className = '',
  onFlipComplete,
}: CardProps) {
  const { vw, minWidth } = CARD_SIZES[size];
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
        width: `${vw}vw`,
        minWidth: `${minWidth}px`,
        aspectRatio: '5 / 7', // Standard playing card ratio
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
            border: decryptable
              ? isViewer
                ? '2px solid rgba(251, 191, 36, 0.4)' // Gold for viewer
                : '2px solid rgba(16, 185, 129, 0.4)' // Green for others
              : 'none',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: decryptable
              ? isViewer
                ? '0 0 16px rgba(251, 191, 36, 0.6), 0 0 24px rgba(251, 191, 36, 0.3), 0 4px 6px rgba(0, 0, 0, 0.5)'
                : '0 0 16px rgba(16, 185, 129, 0.6), 0 0 24px rgba(16, 185, 129, 0.3), 0 4px 6px rgba(0, 0, 0, 0.5)'
              : '0 4px 6px rgba(0, 0, 0, 0.5)',
            transition: 'all 0.3s ease-out',
            overflow: 'hidden',
          }}
        >
          {/* SVG Card Back Image */}
          <img
            src="/cards/card_back.svg"
            alt="Card back"
            style={{
              width: '100%',
              height: '100%',
              objectFit: 'cover',
              display: 'block',
            }}
          />
          <DecryptableBadge
            visible={decryptable && !revealed}
            isViewer={isViewer}
            size={size === 'xlarge' ? 'large' : size}
          />
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
              borderRadius: '8px',
              boxShadow: '0 8px 16px rgba(0, 0, 0, 0.5)',
              overflow: 'hidden',
            }}
          >
            {/* SVG Card Image */}
            <img
              src={`/cards/${getSuitFileName(card.suit)}_${card.rank}.svg`}
              alt={`${card.rank} of ${card.suit}`}
              style={{
                width: '100%',
                height: '100%',
                objectFit: 'cover',
                display: 'block',
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
