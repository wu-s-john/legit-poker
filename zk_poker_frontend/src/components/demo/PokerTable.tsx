/**
 * Poker Table - Main table surface with felt background
 */

import React from 'react';

interface PokerTableProps {
  children: React.ReactNode;
}

export function PokerTable({ children }: PokerTableProps) {
  return (
    <div className="poker-table-scale-wrapper">
      <div className="poker-table-container">
        {/* Table felt */}
        <div className="table-felt" />

        {/* Inner content area - positioning reference within padding safe zone */}
        <div className="poker-content">
          {/* Children (players, deck, etc.) */}
          {children}
        </div>
      </div>
    </div>
  );
}
