/**
 * Status Text - Shows card decryption status below YOUR cards
 */

'use client';

import React from 'react';

interface StatusTextProps {
  text: string;
  type?: 'waiting' | 'collecting' | 'complete' | 'decrypting' | 'revealed';
}

const STATUS_COLORS = {
  waiting: '#64748b',     // Gray
  collecting: '#00d9ff',  // Cyan
  complete: '#22c55e',    // Green
  decrypting: '#00d9ff',  // Cyan
  revealed: '#fbbf24',    // Gold
};

export function StatusText({ text, type = 'waiting' }: StatusTextProps) {
  const [isVisible, setIsVisible] = React.useState(false);

  React.useEffect(() => {
    // Fade in animation
    const timer = setTimeout(() => setIsVisible(true), 50);
    return () => clearTimeout(timer);
  }, [text]);

  return (
    <div
      className="status-text"
      style={{
        fontSize: '11px',
        color: STATUS_COLORS[type],
        textAlign: 'center',
        marginTop: '8px',
        fontWeight: 500,
        opacity: isVisible ? 1 : 0,
        transform: isVisible ? 'translateY(0)' : 'translateY(-8px)',
        transition: 'all 300ms ease-out',
      }}
    >
      {text}
    </div>
  );
}
