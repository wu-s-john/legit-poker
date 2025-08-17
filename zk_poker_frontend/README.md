# ProofPlay - ZK Poker Frontend

A real-time zero-knowledge poker client built with Next.js, TypeScript, and Tailwind CSS.

## Features

- **Zero-Knowledge Proofs**: Mathematical guarantees for fair play without revealing strategy
- **Real-Time Gaming**: Lightning-fast gameplay with instant verification
- **Modern UI**: Beautiful, responsive interface with deep navy theme
- **Type Safety**: Full TypeScript support throughout the application
- **State Management**: Zustand for client state, React Query for server state
- **Real-Time Communication**: Socket.IO for live updates

## Tech Stack

- **Framework**: Next.js 15 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS v4
- **State Management**: Zustand, React Query
- **Icons**: Lucide React
- **Real-Time**: Socket.IO Client
- **Build Tool**: Vite (via Next.js)

## Getting Started

### Prerequisites

- Node.js 18+ (LTS recommended)
- npm or yarn

### Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set up environment variables:
   ```bash
   cp .env.example .env.local
   ```
   
   Update the values in `.env.local`:
   ```
   NEXT_PUBLIC_API_URL=http://localhost:3001
   NEXT_PUBLIC_WS_URL=ws://localhost:3001
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

4. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Project Structure

```
src/
├── app/                    # Next.js App Router pages
│   ├── layout.tsx         # Root layout with providers
│   ├── page.tsx           # Landing page
│   ├── lobby/             # Lobby pages
│   ├── room/              # Room/poker table pages
│   └── profile/           # User profile pages
├── components/            # React components
│   ├── common/            # Shared components (ToastHost, etc.)
│   ├── layout/            # Layout components (TopBar, AppShell, etc.)
│   ├── lobby/             # Lobby-specific components
│   ├── modals/            # Modal components
│   └── room/              # Poker table components
├── lib/                   # Utility libraries
│   ├── api.ts            # API client and endpoints
│   ├── socket.ts         # Socket.IO client
│   ├── toasts.ts         # Toast notification system
│   ├── balances.tsx      # Balance management context
│   └── query.ts          # React Query configuration
├── types/                 # TypeScript type definitions
│   └── poker.ts          # Poker game types
└── styles/               # Global styles
    └── globals.css       # Tailwind CSS configuration
```

## Key Components

### Core Features

- **Landing Page**: Hero section with feature highlights
- **Lobby**: Ring games and tournaments with filtering
- **TopBar**: Navigation with balance display and tabs
- **Toast System**: Real-time notifications for game events
- **Balance Management**: GC (Game Coins) and SC (Stake Coins)

### Poker Types

The application includes comprehensive TypeScript types for:
- Cards, hands, and game state
- Players and actions
- Room and tournament data
- Real-time events and transcripts

### Real-Time Features

- **Socket.IO Integration**: Live updates for game state
- **Action Verification**: Toast notifications for ZK proof verification
- **Transcript System**: Append-only event log for game history

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint
- `npm run typecheck` - Run TypeScript type checking

### Styling

The application uses Tailwind CSS v4 with a custom deep navy theme:
- Primary colors: Deep navy palette (ClubWPT vibe)
- Component styles: Toast animations, active seat rings
- Utility classes: Responsive design and accessibility

### State Management

- **Zustand**: Client-side state (toasts, balances, UI state)
- **React Query**: Server state (rooms, tournaments, game data)
- **Context**: Balance management across the app

## API Integration

The frontend is designed to work with a ZK Poker backend that provides:
- REST API for room management and actions
- WebSocket connections for real-time updates
- Zero-knowledge proof verification
- Transcript-based game state management

## Next Steps

This is a foundation for the ZK Poker frontend. Future development includes:
- Complete poker table UI with cards and chips
- Real-time betting controls
- Player avatars and chat
- Tournament bracket visualization
- Mobile-responsive design
- Accessibility improvements

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is part of the ProofPlay ZK Poker platform.
