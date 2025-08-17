export type Suit = 'hearts' | 'diamonds' | 'clubs' | 'spades';
export type Rank = '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '10' | 'J' | 'Q' | 'K' | 'A';

export interface Card {
  suit: Suit;
  rank: Rank;
}

export interface Hand {
  cards: Card[];
  rank: string;
  value: number;
}

export type PlayerStatus = 'waiting' | 'playing' | 'folded' | 'all-in' | 'busted';

export interface Player {
  id: string;
  name: string;
  avatar?: string;
  stack: number;
  bet: number;
  status: PlayerStatus;
  position: number;
  isDealer: boolean;
  isSmallBlind: boolean;
  isBigBlind: boolean;
  isHero: boolean;
  hand?: Hand;
  isActive: boolean;
}

export type BetAction = 'fold' | 'check' | 'call' | 'bet' | 'raise' | 'all-in';

export interface Action {
  playerId: string;
  action: BetAction;
  amount?: number;
  timestamp: number;
}

export type Street = 'preflop' | 'flop' | 'turn' | 'river';

export interface Pot {
  amount: number;
  players: string[];
  isMain: boolean;
}

export interface TableStakes {
  sb: number;
  bb: number;
  ante?: number;
  straddle?: number;
  cap?: number;
}

export interface TableState {
  id: string;
  name: string;
  stakes: TableStakes;
  players: Player[];
  communityCards: Card[];
  pot: number;
  sidePots: Pot[];
  currentStreet: Street;
  currentPlayer?: string;
  dealerPosition: number;
  smallBlindPosition: number;
  bigBlindPosition: number;
  minBet: number;
  maxBet: number;
  lastAction?: Action;
  gameStatus: 'waiting' | 'playing' | 'finished';
  handHistory: Action[];
}

export interface RoomSnapshot {
  id: string;
  status: 'waiting' | 'playing' | 'finished';
  stakes?: TableStakes;
  players: Player[];
  communityCards: Card[];
  pot: number;
  currentStreet: Street;
  currentPlayer?: string;
  lastSeq: number;
}

export interface TranscriptEvent {
  kind: string;
  timestamp: number;
  data: unknown;
}

export interface TranscriptEnvelope {
  seq: number;
  event: TranscriptEvent;
}

export interface LobbyTable {
  id: string;
  name: string;
  stakes: TableStakes;
  gameType: 'NLHE' | 'PLO';
  playerCount: number;
  maxPlayers: number;
  status: 'waiting' | 'playing' | 'full';
  buyIn: {
    min: number;
    max: number;
  };
}

export interface Tournament {
  id: string;
  name: string;
  buyIn: number;
  entries: number;
  maxEntries: number;
  prizePool: number;
  guaranteed: number;
  status: 'registering' | 'late_reg' | 'running' | 'finished';
  startsAt: string;
  endsAt?: string;
}

export interface Balance {
  GC: number; // Game Coins
  SC: number; // Stake Coins
}

export interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  actionId?: string;
  duration?: number;
}
