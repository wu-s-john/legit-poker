# LegitPoker Demo - Engineering Specification

## Overview

This document specifies the design and implementation for the LegitPoker landing page demo, which demonstrates zero-knowledge mental poker card dealing in real-time.

### Purpose

Traditional online poker requires trusting a centralized dealer to shuffle and deal cards fairly. LegitPoker eliminates this trust requirement using cryptographic protocols:

1. **Distributed Shuffling**: Independent shufflers (number varies by player count) each apply their own random permutation to an encrypted deck. No single party knows the final card order.

2. **Provable Fairness**: Every shuffle and deal operation includes a zero-knowledge proof that can be verified by anyone.

3. **Privacy Preservation**: Players can decrypt only their own cards. Other players' cards remain hidden until showdown.

4. **True Randomness**: Each demo session generates a cryptographically random deck shuffle, ensuring viewers see different hands every time they replay the demo.

5. **Real-Time Execution**: The demo runs at actual protocol speed with no artificial slowdown. The frontend renders events as they arrive from the backend, showing the true performance of the cryptographic operations.

The demo puts the viewer in the game as "Player 0" (YOU, at bottom center), allowing them to experience receiving and decrypting their own cards while watching the cryptographic protocol execute in real-time.

### Variable Player Count Support

The demo dynamically adapts to different player counts (2-9 players):

| Players | Shufflers | Your Cards | Total Cards Dealt | Messages | Execution Time |
|---------|-----------|------------|-------------------|----------|----------------|
| 2       | 2         | 2          | 4 hole cards      | 11       | ~2.0s          |
| 3       | 3         | 2          | 6 hole cards      | 21       | ~2.5s          |
| 4       | 4         | 2          | 8 hole cards      | 33       | ~3.0s          |
| 5       | 5         | 2          | 10 hole cards     | 47       | ~3.3s          |
| 6       | 6         | 2          | 12 hole cards     | 63       | ~3.5s          |
| 7       | 7         | 2          | 14 hole cards     | 81       | ~3.8s          |
| 8       | 8         | 2          | 16 hole cards     | 101      | ~4.0s          |
| 9       | 9         | 2          | 18 hole cards     | 123      | ~4.0s          |

**Default Configuration**: 7 players (most visually balanced for demonstrations)

**Performance Profile**:
- Shuffling: ~0.5s
- Card dealing (all players, parallel): ~2.0s
- Your card decryption: ~0.3s per card
- Completion: ~0.5s

**Note**: Cards are dealt **in parallel** (multiple cards flying simultaneously, like a real dealer). The frontend renders events as they arrive from the backend with coordinated animations.

---

## Demo Flow

**Total Duration: ~4 seconds** (actual real-time protocol execution)

### Phase 1: Shuffling (~0.5s)
- **Collapsed view**: Show overall progress rather than individual shufflers
- **Display**: Progress bar fills rapidly as shufflers complete
- **Duration**: ~1.0s
- **Expandable**: User can click to see detailed shuffle log

### Phase 2: Dealing Hole Cards (~2.0s, parallel)
- **Parallel dealing**: Multiple cards fly simultaneously from center deck (like a real dealer)
- **Round 1**: First card to each player
  - Cards launched with 50ms stagger for visual clarity
  - Multiple cards in flight at once
  - Other players receive face-down cards (🃏)
  - When YOUR card arrives:
    - All unblinding shares collected **instantly** (no progressive counter). They are face down private
    - **Auto-decrypt**: Card flips to reveal (~0.3s total)
- **Round 2**: Second card to each player (same parallel process)
  - YOUR second card revealed when decryption completes (~0.3s)

### Phase 3: Demo Complete
- All hole cards dealt (varies by player count)
- Your cards visible (random cards each session - see Client-Side Random Deck section)
- Other players' cards remain hidden (🃏 🃏)
- Stats summary displayed
- Call-to-action buttons: View Log, Play Live

**Total Messages** (varies by player count):
See the "Variable Player Count Support" table in the Overview section for exact counts.

**Example (7 players)**:
- 7 shuffle events (one per shuffler, ~0.1s apart)
- 98 blinding share messages (14 cards × 7 shufflers)
- 98 partial unblinding share messages (14 cards × 7 shufflers)
- **Total**: 203 messages

**Total Execution Time**: ~2-10 seconds depending on player count (see Variable Player Count Support table)

**Frontend Rendering**: Events are rendered as they arrive from the backend. Animations are coordinated with event timing to provide smooth visual feedback without artificial delays.

---

## Animation & Sound Design

### Animation System Overview

The demo uses an **event-driven animation system** built on the Web Animations API with CSS transforms. Animations are triggered by protocol events as they arrive from the backend in real-time.

**Performance Constraint**: Demo completes in **~4 seconds max** (actual protocol execution time). All animations are tuned to fit this window while maintaining smooth 60fps performance.

**Core Principles**:
- **Event-Driven**: Animations triggered by actual protocol events, not timers
- **Real-Time Rendering**: Frontend renders events as they arrive with no artificial delays
- **Parallel Execution**: Multiple cards animate simultaneously (non-blocking)
- **Smooth Performance**: Uses transforms (translate, scale, rotate, opacity) for 60fps
- **Fast & Smooth**: Animation durations shortened (300-400ms card flights) without sacrificing visual quality
- **Accessibility**: All animations support `prefers-reduced-motion`

### Animation Library

#### 1. Card Dealing Flight Animation

**Purpose**: Cards flying from center deck to player positions (parallel dealing, like a real dealer)

**Specifications**:
```typescript
{
  duration: 400,  // Fast animation for 4-second demo
  easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
  keyframes: [
    {
      offset: 0,
      transform: 'translate(-50%, -50%) rotate(0deg) scale(0.8)',
      boxShadow: '0 0 20px rgba(0, 217, 255, 0.6)',
      opacity: 1
    },
    {
      offset: 0.3,
      transform: 'translate(-50%, -50%) rotate(120deg) scale(1.1)',
      boxShadow: '0 0 30px rgba(0, 217, 255, 0.8)',
      opacity: 1
    },
    {
      offset: 1,
      transform: 'translate(-50%, -50%) rotate(360deg) scale(1)',
      boxShadow: '0 4px 6px rgba(0, 0, 0, 0.5)',
      opacity: 1
    }
  ]
}
```

**Variants**:
- **To Other Players** (48×64px cards): Duration 300ms, final scale(1)
- **To You** (56×80px cards): Duration 400ms, golden glow (`rgba(251, 191, 36, 0.6)`)

**Parallel Dealing**: Multiple cards fly simultaneously with slight stagger (50ms) for visual clarity. In a 2-second dealing phase with 14 cards, cards overlap in flight.

#### 2. Card Flip Reveal Animation

**Purpose**: Flipping card from back to face when decrypted

**Specifications**:
```typescript
{
  duration: 500,
  easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
  keyframes: [
    {
      offset: 0,
      transform: 'perspective(1000px) rotateY(0deg)',
      backfaceVisibility: 'hidden'
    },
    {
      offset: 0.5,
      transform: 'perspective(1000px) rotateY(90deg)',
      boxShadow: '0 8px 16px rgba(0, 0, 0, 0.6)'
    },
    {
      offset: 1,
      transform: 'perspective(1000px) rotateY(180deg)',
      boxShadow: '0 8px 16px rgba(0, 0, 0, 0.5)'
    }
  ]
}
```

**3D Setup**:
- Parent container: `transform-style: preserve-3d`
- Card faces: `backface-visibility: hidden`
- Back face: `transform: rotateY(0deg)`
- Front face: `transform: rotateY(180deg)`

#### 3. Progress Bar Fill Animation

**Purpose**: Smooth progress bar updates as protocol advances

**Specifications**:
```typescript
{
  duration: 400,
  easing: 'cubic-bezier(0.4, 0, 0.6, 1)',
  keyframes: [
    {
      offset: 0,
      width: '${prevPercent}%',
      boxShadow: '0 0 10px rgba(0, 217, 255, 0.5)'
    },
    {
      offset: 1,
      width: '${newPercent}%',
      boxShadow: '0 0 15px rgba(0, 217, 255, 0.6)'
    }
  ]
}
```

**Pulse on Completion**:
```typescript
{
  duration: 800,
  easing: 'ease-in-out',
  iterations: 2,
  keyframes: [
    { offset: 0, boxShadow: '0 0 15px rgba(0, 217, 255, 0.6)' },
    { offset: 0.5, boxShadow: '0 0 25px rgba(0, 217, 255, 0.9)' },
    { offset: 1, boxShadow: '0 0 15px rgba(0, 217, 255, 0.6)' }
  ]
}
```

#### 4. Player Avatar Pulse Animation

**Purpose**: Indicate active player receiving card

**Specifications**:
```typescript
{
  duration: 1200,
  easing: 'ease-in-out',
  iterations: Infinity,
  keyframes: [
    {
      offset: 0,
      transform: 'translate(-50%, -50%) scale(1)',
      boxShadow: '0 0 0 0 rgba(0, 217, 255, 0.7)'
    },
    {
      offset: 0.5,
      transform: 'translate(-50%, -50%) scale(1.05)',
      boxShadow: '0 0 0 10px rgba(0, 217, 255, 0)'
    },
    {
      offset: 1,
      transform: 'translate(-50%, -50%) scale(1)',
      boxShadow: '0 0 0 0 rgba(0, 217, 255, 0)'
    }
  ]
}
```

**Your Avatar Glow** (Golden):
```typescript
{
  duration: 1500,
  easing: 'ease-in-out',
  iterations: Infinity,
  keyframes: [
    { offset: 0, boxShadow: '0 0 20px rgba(251, 191, 36, 0.5)' },
    { offset: 0.5, boxShadow: '0 0 30px rgba(251, 191, 36, 0.8)' },
    { offset: 1, boxShadow: '0 0 20px rgba(251, 191, 36, 0.5)' }
  ]
}
```

#### 5. Status Text Fade Transitions

**Purpose**: Smooth transitions for status messages

**Fade In**:
```typescript
{
  duration: 300,
  easing: 'ease-out',
  keyframes: [
    { offset: 0, opacity: 0, transform: 'translateY(-8px)' },
    { offset: 1, opacity: 1, transform: 'translateY(0)' }
  ]
}
```

**Fade Out**:
```typescript
{
  duration: 200,
  easing: 'ease-in',
  keyframes: [
    { offset: 0, opacity: 1, transform: 'translateY(0)' },
    { offset: 1, opacity: 0, transform: 'translateY(8px)' }
  ]
}
```

#### 6. Share Collection Animation (Instant)

**Purpose**: Visual feedback when all unblinding shares arrive simultaneously

**Shares Arrive Instantly**: All shares collected at once (no progressive counter). Display immediate success animation.

**Complete Checkmark** (appears instantly):
```typescript
{
  duration: 200,  // Fast bounce-in
  easing: 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
  keyframes: [
    { offset: 0, transform: 'scale(0) rotate(-45deg)', opacity: 0 },
    { offset: 0.7, transform: 'scale(1.2) rotate(5deg)', opacity: 1 },
    { offset: 1, transform: 'scale(1) rotate(0deg)', opacity: 1 }
  ]
}
```

**Status Text**:
- Shows "Collecting shares..." briefly
- Immediately updates to "✓ All shares collected" with checkmark animation
- No progressive counter (1/7, 2/7, etc.) due to instant arrival

#### 7. Button Interaction Animations

**Hover**:
```typescript
{
  duration: 200,
  easing: 'ease-out',
  keyframes: [
    { offset: 0, transform: 'scale(1)' },
    { offset: 1, transform: 'scale(1.05)' }
  ]
}
```

**Active Press**:
```typescript
{
  duration: 100,
  easing: 'ease-in',
  keyframes: [
    { offset: 0, transform: 'scale(1.05)' },
    { offset: 1, transform: 'scale(0.95)' }
  ]
}
```

**Primary Button Glow**:
```typescript
{
  duration: 2000,
  easing: 'ease-in-out',
  iterations: Infinity,
  keyframes: [
    { offset: 0, boxShadow: '0 0 20px rgba(16, 185, 129, 0.4)' },
    { offset: 0.5, boxShadow: '0 0 30px rgba(16, 185, 129, 0.6)' },
    { offset: 1, boxShadow: '0 0 20px rgba(16, 185, 129, 0.4)' }
  ]
}
```

#### 8. Chapter Transition Animation

**Purpose**: Smooth transitions between Shuffling → Dealing → Complete

**Fade Out Old**:
```typescript
{
  duration: 400,
  easing: 'ease-in',
  keyframes: [
    { offset: 0, opacity: 1, transform: 'translateY(0)' },
    { offset: 1, opacity: 0, transform: 'translateY(-20px)' }
  ]
}
```

**Fade In New**:
```typescript
{
  duration: 600,
  easing: 'ease-out',
  keyframes: [
    { offset: 0, opacity: 0, transform: 'translateY(20px)' },
    { offset: 1, opacity: 1, transform: 'translateY(0)' }
  ]
}
```

#### 9. Log Panel Slide Animation (Mobile)

**Slide Up**:
```typescript
{
  duration: 300,
  easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
  keyframes: [
    {
      offset: 0,
      transform: 'translateY(100%)',
      opacity: 0
    },
    {
      offset: 1,
      transform: 'translateY(0)',
      opacity: 1
    }
  ]
}
```

**Backdrop Blur In**:
```typescript
{
  duration: 300,
  easing: 'ease-out',
  keyframes: [
    { offset: 0, backdropFilter: 'blur(0px)', background: 'rgba(10, 14, 20, 0)' },
    { offset: 1, backdropFilter: 'blur(4px)', background: 'rgba(10, 14, 20, 0.8)' }
  ]
}
```

#### 10. Deck Shuffle Animation (Initial)

**Purpose**: Visual shuffle effect during Phase 1

**Specifications**:
```typescript
{
  duration: 2000,
  easing: 'ease-in-out',
  iterations: 3,
  keyframes: [
    {
      offset: 0,
      transform: 'translateX(0) rotate(0deg)',
      filter: 'brightness(1)'
    },
    {
      offset: 0.25,
      transform: 'translateX(-8px) rotate(-5deg)',
      filter: 'brightness(1.2)'
    },
    {
      offset: 0.5,
      transform: 'translateX(0) rotate(0deg)',
      filter: 'brightness(1)'
    },
    {
      offset: 0.75,
      transform: 'translateX(8px) rotate(5deg)',
      filter: 'brightness(1.2)'
    },
    {
      offset: 1,
      transform: 'translateX(0) rotate(0deg)',
      filter: 'brightness(1)'
    }
  ]
}
```

---

### Sound Design Specifications

**Audio System**: Web Audio API with fallback to HTML5 Audio
**Format**: OGG Vorbis (primary), MP3 (fallback), WebM Opus (modern browsers)
**Compression**: -q 4 for OGG (balanced quality/size)
**Sample Rate**: 44.1kHz
**Channels**: Stereo for ambient, Mono for effects

#### Sound Categories

##### 1. Card Sounds

**Card Deal Whoosh**
- **Trigger**: Card leaves center deck
- **Duration**: 800ms
- **Volume**: -18dB
- **Characteristics**: Subtle whoosh with slight pitch variation per card
- **Variation**: 4 variants to avoid repetition
- **Pan**: Stereo pan based on target player position (left/center/right)
- **Files**: `card_deal_01.ogg` through `card_deal_04.ogg`

**Card Land Soft**
- **Trigger**: Card arrives at player position (other players)
- **Duration**: 150ms
- **Volume**: -24dB
- **Characteristics**: Soft card-on-felt sound
- **Files**: `card_land_soft.ogg`

**Card Land Your**
- **Trigger**: Card arrives at YOUR position
- **Duration**: 200ms
- **Volume**: -20dB
- **Characteristics**: Slightly more prominent, with subtle golden shimmer tail
- **Files**: `card_land_yours.ogg`

**Card Flip Mechanical**
- **Trigger**: Card begins flip animation
- **Duration**: 500ms
- **Volume**: -16dB
- **Characteristics**: Clean flip with slight paper friction
- **Pitch**: +10% for Ace/King (premium cards)
- **Files**: `card_flip_01.ogg`, `card_flip_02.ogg`

**Card Reveal Success**
- **Trigger**: Card face fully visible
- **Duration**: 400ms
- **Volume**: -18dB
- **Characteristics**: Subtle magical sparkle/chime
- **Files**: `card_reveal.ogg`

##### 2. Shuffle Phase Sounds

**Shuffle Progress Ambient**
- **Trigger**: Shuffle phase begins
- **Duration**: 2500ms (loops until complete)
- **Volume**: -22dB
- **Characteristics**: Low rumble with cryptographic "data processing" texture
- **Files**: `shuffle_ambient_loop.ogg`

**Shuffle Complete**
- **Trigger**: All shufflers finished
- **Duration**: 1200ms
- **Volume**: -16dB
- **Characteristics**: Rising tone with satisfying resolution
- **Files**: `shuffle_complete.ogg`

**Progress Bar Fill**
- **Trigger**: Progress bar updates
- **Duration**: 400ms
- **Volume**: -26dB
- **Characteristics**: Subtle digital bleep
- **Files**: `progress_tick.ogg`

##### 3. Share Collection Sounds

**Shares Complete** (Instant)
- **Trigger**: All shares collected simultaneously (no progressive pings)
- **Duration**: 400ms
- **Volume**: -18dB
- **Characteristics**: Single satisfying success tone (no ascending arpeggio, arrives too fast)
- **Files**: `shares_complete.ogg`
- **Note**: No individual share ping sounds - shares arrive instantly in <100ms

**Decrypting Process**
- **Trigger**: Decryption starts immediately after shares complete
- **Duration**: 200ms (shortened for 0.3s decryption time)
- **Volume**: -20dB
- **Characteristics**: Quick processing sound
- **Files**: `decrypt_process.ogg`

##### 4. UI Interaction Sounds

**Button Hover**
- **Trigger**: Mouse enters button
- **Duration**: 80ms
- **Volume**: -28dB
- **Characteristics**: Subtle soft click
- **Files**: `button_hover.ogg`

**Button Click**
- **Trigger**: Button pressed
- **Duration**: 120ms
- **Volume**: -22dB
- **Characteristics**: Satisfying click with slight depth
- **Files**: `button_click.ogg`

**Primary Button Click** (Play Live)
- **Trigger**: Primary CTA clicked
- **Duration**: 200ms
- **Volume**: -20dB
- **Characteristics**: More prominent, uplifting tone
- **Files**: `button_primary_click.ogg`

**Log Toggle Open**
- **Trigger**: Log panel slides up
- **Duration**: 300ms
- **Volume**: -24dB
- **Characteristics**: Panel whoosh
- **Files**: `log_open.ogg`

**Log Toggle Close**
- **Trigger**: Log panel slides down
- **Duration**: 300ms
- **Volume**: -24dB
- **Characteristics**: Panel whoosh (reverse)
- **Files**: `log_close.ogg`

**Log Entry Expand**
- **Trigger**: Log entry expanded
- **Duration**: 150ms
- **Volume**: -26dB
- **Characteristics**: Quick unfold sound
- **Files**: `log_expand.ogg`

##### 5. Ambient & Background

**Background Music** (Optional, User Controlled)
- **Trigger**: Demo start (with mute option)
- **Duration**: 40s loop
- **Volume**: -30dB (very subtle)
- **Characteristics**: Minimal electronic ambient, non-distracting
- **Fade**: 2s fade in/out
- **Files**: `ambient_bg_loop.ogg`

**Player Attention Pulse** (Your Turn)
- **Trigger**: Card flying to YOU
- **Duration**: 1200ms
- **Volume**: -20dB
- **Characteristics**: Gentle golden bell tone
- **Files**: `your_turn_pulse.ogg`

##### 6. Demo Completion Sounds

**Demo Complete Fanfare**
- **Trigger**: All cards dealt, completion screen
- **Duration**: 2000ms
- **Volume**: -16dB
- **Characteristics**: Celebratory but sophisticated, not cheesy
- **Files**: `demo_complete.ogg`

**Premium Hand Bonus** (Ace-King suited)
- **Trigger**: Second card revealed (if premium hand)
- **Duration**: 1500ms
- **Volume**: -18dB
- **Characteristics**: Extra sparkle/chime layer
- **Files**: `premium_hand.ogg`

---

### Audio Mixing Guidelines

**Master Volume**: Adjustable via user preference (default: 70%)
**Dynamic Range**: -12dB to -30dB (avoid loudness fatigue)
**Ducking**: Background ambient drops -6dB during card dealing
**Fade Out**: All loops fade out over 1s when transitioning phases

**Spatial Audio** (Stereo Panning):
- Cards to left players: 30% left pan
- Cards to right players: 30% right pan
- Cards to YOU: Center
- Ambient: Center

**Audio Preloading**:
```typescript
const audioAssets = [
  'card_deal_01.ogg',
  'card_deal_02.ogg',
  'card_flip_01.ogg',
  'card_reveal.ogg',
  'shuffle_complete.ogg',
  'share_ping.ogg',
  'shares_complete.ogg',
  // ... all critical sounds
];

// Preload on page load
preloadAudio(audioAssets);
```

**Audio Sprite Sheet** (Performance Optimization):
For frequently used sounds, combine into single sprite:
```typescript
const audioSprite = {
  'share_ping': { start: 0, duration: 100 },
  'button_hover': { start: 150, duration: 80 },
  'button_click': { start: 280, duration: 120 },
  'progress_tick': { start: 450, duration: 400 }
};
```

---

### Accessibility & User Preferences

**Reduced Motion**:
```css
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

**Reduced Motion Sound**: Replace whooshes with simple clicks

**Mute Option**:
- Toggle button in corner: 🔊 / 🔇
- Persists via localStorage
- Keyboard shortcut: M key

**Volume Control**:
- Slider: 0% to 100%
- Default: 70%
- Saved to localStorage

---

### Event-Driven Animation Timeline

**Architecture**: Animations are triggered by WebSocket/SSE events from the backend. The frontend maintains an event queue and renders animations as messages arrive.

**Total Demo Time: ~4 seconds max**

**Shuffling Phase** (~0.5s)
```
EVENT: ShuffleStarted (t=0ms)
  → Shuffle ambient loop starts
  → Deck shuffle animation begins
  → Progress bar initialized at 0%

EVENT: ShufflerCompleted (per shuffler, rapid succession)
  → Progress bar increments (+14% for 7 players)
  → Progress tick sound (subtle)

EVENT: ShuffleComplete (t=~500ms)
  → Progress bar fill to 100% (animation: 200ms)
  → Shuffle complete sound (600ms)
  → Shuffle ambient fade out (300ms)
  → Chapter transition animation (400ms)
```

**Dealing Phase** (~2.0s with parallel card dealing)
```
EVENT: CardDealt { player, cardIndex } (MULTIPLE IN PARALLEL)
  → Card deal whoosh sound (variant based on position)
  → Card flight animation starts (300-400ms depending on target)
  → Target player avatar pulse starts (if visible)
  → Progress bar increment
  → 50ms stagger between card launches for visual clarity

EVENT: CardArrived { player, cardIndex }
  → Card land sound (soft for others, yours for player 0)
  → Avatar pulse stops
  → Card settles in position

IF player === 0 (YOUR card):
  EVENT: AllSharesCollected (INSTANT - no progressive events)
    → Status text: "Collecting shares..." (brief flash)
    → Status text: "✓ All shares collected" (immediate)
    → Shares complete sound (400ms)
    → Checkmark bounce animation (200ms)

  EVENT: DecryptionStarted
    → Decrypt process sound (200ms)
    → Status text: "Decrypting..."

  EVENT: CardDecrypted { card: { rank, suit } } (~0.3s after shares)
    → Card flip animation (500ms 3D transform)
    → Card flip sound
    → Card reveal sound (400ms) at flip completion
    → Status text: Card rank/suit displayed
```

**Completion Phase** (~0.5s)
```
EVENT: DealingComplete (t=~3.5s)
  → Demo complete fanfare (1500ms, truncated version)
  → IF premium hand: Premium hand bonus sound (1000ms, overlaps)
  → Final stats panel fade in (300ms)
  → Call-to-action buttons fade in with stagger (100ms each)
  → Primary button glow animation starts (infinite loop)
```

**Key Timing Constraints**:
- **Parallel card dealing**: Multiple cards fly simultaneously (up to 14 cards in ~2s)
- **Instant share collection**: No progressive counter, all shares arrive at once
- **Fast decryption**: 0.3s per card including flip animation
- **Overlapping animations**: Card flights overlap, sounds layer appropriately
- Animation durations shortened to fit 4-second window while maintaining smoothness

---

### Implementation Example

```typescript
class DemoEventHandler {
  private audioContext: AudioContext;
  private soundLibrary: Map<string, AudioBuffer>;
  private eventQueue: ProtocolEvent[] = [];
  private isProcessing: boolean = false;

  constructor() {
    // Connect to backend event stream
    this.connectEventStream();
  }

  private connectEventStream() {
    const eventSource = new EventSource('/api/demo/events');

    eventSource.addEventListener('shuffle-started', (e) => {
      this.handleEvent(JSON.parse(e.data));
    });

    eventSource.addEventListener('card-dealt', (e) => {
      this.handleEvent(JSON.parse(e.data));
    });

    eventSource.addEventListener('card-decrypted', (e) => {
      this.handleEvent(JSON.parse(e.data));
    });

    // ... other event listeners
  }

  private async handleEvent(event: ProtocolEvent) {
    this.eventQueue.push(event);
    if (!this.isProcessing) {
      await this.processQueue();
    }
  }

  private async processQueue() {
    this.isProcessing = true;

    while (this.eventQueue.length > 0) {
      const event = this.eventQueue.shift()!;

      switch (event.type) {
        case 'CardDealt':
          // Don't await - allow parallel card animations
          this.handleCardDealt(event.data);
          break;
        case 'CardDecrypted':
          await this.handleCardDecrypted(event.data);
          break;
        case 'AllSharesCollected':
          await this.handleAllSharesCollected(event.data);
          break;
        // ... other cases
      }
    }

    this.isProcessing = false;
  }

  private async handleCardDealt(data: CardDealtEvent) {
    const { player, cardIndex } = data;
    const targetPosition = this.getPlayerPosition(player);
    const isYourCard = player === 0;

    // Play sound with spatial audio (non-blocking)
    this.playCardDeal(targetPosition);

    // Animate card flight (parallel with other cards)
    const cardElement = this.createCardElement();

    // Fire and forget - don't block for parallel dealing
    this.animateCardFlight(cardElement, targetPosition, isYourCard).then(() => {
      // Card has arrived - play land sound
      this.playSound(isYourCard ? 'card_land_yours' : 'card_land_soft');
    });
  }

  private async handleAllSharesCollected(data: SharesCollectedEvent) {
    // All shares arrived instantly - show immediate success
    const statusElement = document.querySelector('.status-text');

    // Brief flash of "Collecting shares..."
    statusElement.textContent = 'Collecting shares...';

    // Immediately update to success
    await new Promise(resolve => setTimeout(resolve, 50));
    statusElement.textContent = '✓ All shares collected';

    // Play success sound
    await this.playSound('shares_complete');

    // Animate checkmark
    await this.animateCheckmark();
  }

  private async handleCardDecrypted(data: CardDecryptedEvent) {
    const { card } = data;

    // Play flip sound
    await this.playSound('card_flip_01');

    // Animate 3D flip
    const cardElement = document.querySelector(`[data-card-index="${data.cardIndex}"]`);
    await this.flipCard(cardElement!, card);

    // Play reveal sound at completion
    await this.playSound('card_reveal');
  }

  private async playCardDeal(targetPosition: Position) {
    const variant = Math.floor(Math.random() * 4) + 1;
    const sound = this.soundLibrary.get(`card_deal_0${variant}`);
    const source = this.audioContext.createBufferSource();
    source.buffer = sound;

    // Spatial panning based on target position
    const panner = this.audioContext.createStereoPanner();
    panner.pan.value = this.calculatePan(targetPosition);

    source.connect(panner).connect(this.audioContext.destination);
    source.start();
  }

  private animateCardFlight(
    cardElement: HTMLElement,
    targetPosition: Position,
    isYourCard: boolean
  ): Promise<void> {
    return new Promise((resolve) => {
      const glowColor = isYourCard
        ? 'rgba(251, 191, 36, 0.6)'
        : 'rgba(0, 217, 255, 0.6)';

      const animation = cardElement.animate([
        {
          offset: 0,
          transform: 'translate(-50%, -50%) rotate(0deg) scale(0.8)',
          boxShadow: `0 0 20px ${glowColor}`,
        },
        {
          offset: 0.3,
          transform: 'translate(-50%, -50%) rotate(120deg) scale(1.1)',
          boxShadow: `0 0 30px ${glowColor}`,
        },
        {
          offset: 1,
          transform: `translate(${targetPosition.x}, ${targetPosition.y}) rotate(360deg) scale(1)`,
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.5)',
        }
      ], {
        duration: isYourCard ? 400 : 300,  // Fast animations for 4-second demo
        easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
        fill: 'forwards'
      });

      animation.onfinish = () => resolve();
    });
  }
}
```

**Key Architectural Points**:
- **WebSocket or SSE**: Real-time event stream from backend
- **Non-blocking card animations**: Don't await CardDealt events to allow parallel dealing
- **Event queue**: Handles rapid succession of events
- **Instant share collection**: No progressive updates, all shares arrive simultaneously
- **4-second constraint**: All animation durations tuned for fast protocol execution
- **Backend controls pacing**: Frontend renders as fast as events arrive (typically ~4s total)

---

**Total Animation Assets**: ~30 unique animations (tuned for 4-second demo)
**Total Sound Assets**: ~22 unique sounds (35-40 files with variants)
**Estimated Audio Size**: ~700KB compressed (OGG + MP3 fallbacks)
**Animation Performance Target**: 60fps on iPhone 12 / Android equivalent
**Total Demo Duration**: ~4 seconds max (real protocol execution time)

---

## Demo Initialization

### Overview

The demo is triggered by the user clicking "Start Demo". The frontend creates a game, subscribes to events, then starts the protocol execution.

### API Endpoints

**1. Create Demo Game**
```typescript
POST /game/demo/?public_key={public_key}

Query Parameters:
  - public_key: string (hex-encoded, randomly generated by viewer)

Response: {
  game_id: number;
  hand_id: number;
  player_count: number;  // e.g., 7
}
```

**State**: Game and hand created with initial snapshot, but **not started yet**.

**2. Start Shuffling**
```typescript
POST /game/demo/{game_id}/hand/{hand_id}

Path Parameters:
  - game_id: number
  - hand_id: number

Response: 200 OK (triggers protocol execution)
```

**Triggers**: Backend starts emitting shuffle events → dealing events.

**3. Realtime Event Stream (Supabase)**
```typescript
// Subscribe to events for specific game AND hand
// Uses: zk_poker_frontend/src/lib/finalizedEnvelopeStream.ts
listenToGameFinalizedEnvelopes(game_id, hand_id)

Receives: FinalizedAnyMessageEnvelope (real-time stream)
  - envelope.message.value: AnyGameMessage
  - snapshotSequenceId: number (sequential event ID)
  - appliedPhase: EventPhase
  - snapshotStatus: SnapshotStatus
```

**Note**: Must subscribe to events using **both** `game_id` and `hand_id` to filter correctly.

**4. Fetch Events**
```typescript
// Fetch all events for a hand
GET /game/{game_id}/hand/{hand_id}/events

Response: {
  events: FinalizedAnyMessageEnvelope[]  // All events, sorted by snapshotSequenceId
}

// Fetch events since a specific sequence number (reconnection/catch-up)
GET /game/{game_id}/hand/{hand_id}/events?since_seq_id=42

Query Parameters:
  - since_seq_id: number (return all events with snapshotSequenceId > since_seq_id)

Response: {
  events: FinalizedAnyMessageEnvelope[]  // All events after the specified sequence ID
}

// Fetch specific events (gap recovery)
GET /game/{game_id}/hand/{hand_id}/events?seq_ids=5,7,8

Query Parameters:
  - seq_ids: string (comma-separated sequence IDs)

Response: {
  events: FinalizedAnyMessageEnvelope[]  // Requested events only
}
```

### Initialization Flow

```typescript
// 1. Generate viewer's public key (random for demo)
function generateRandomPublicKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return '0x' + Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

const viewerPublicKey = generateRandomPublicKey();

// 2. Create demo game (viewer is always seat 0)
const { game_id, hand_id, player_count } = await fetch(
  `/game/demo/?public_key=${viewerPublicKey}`,
  { method: 'POST' }
).then(r => r.json());

// 3. Subscribe to realtime events BEFORE starting
const { stream, unsubscribe } = listenToGameFinalizedEnvelopes(
  game_id,
  hand_id  // ← Filter by both game_id AND hand_id
);

let lastSequenceId = 0;

stream.subscribe({
  next: (envelope) => handleEvent(envelope),
  error: (err) => console.error('Event stream error:', err),
  complete: () => console.log('Stream complete')
});

// 4. Start the protocol (triggers shuffling)
await fetch(`/game/demo/${game_id}/hand/${hand_id}`, {
  method: 'POST'
});

// 5. Events start arriving via Supabase...
// - Shuffle events (N events, one per shuffler)
// - Blinding events (cards × shufflers)
// - Partial unblinding events (cards × shufflers)
```

### Player Roles

**Viewer (YOU)**:
- Always assigned **seat_id = 0** (bottom center position)
- Identified by `public_key` provided in initial POST request
- Only player whose cards are revealed in the demo

**Other Players (Seats 1-6)**:
- Placeholder players created automatically by backend
- Do not perform any actions
- Their cards remain face-down throughout the demo
- Used to demonstrate multi-player card dealing protocol

**Identifying YOUR cards**:
```typescript
const YOUR_PUBLIC_KEY = viewerPublicKey;  // From step 1
const YOUR_SEAT = 0;  // Always seat 0 for viewer

function isYourCard(targetPlayerPublicKey: string): boolean {
  return targetPlayerPublicKey === YOUR_PUBLIC_KEY;
}
```

### Event Sequencing & Gap Detection

Every event has `snapshotSequenceId` - a sequential number (1, 2, 3, ...). Events may arrive **out of order** due to network conditions.

**Gap Detection**:
```typescript
const pendingEvents: Map<number, FinalizedAnyMessageEnvelope> = new Map();

function handleEvent(envelope: FinalizedAnyMessageEnvelope) {
  const seqId = envelope.snapshotSequenceId;

  // Detect gap
  if (seqId > lastSequenceId + 1) {
    // Missing events! Fetch them
    const missingIds = [];
    for (let i = lastSequenceId + 1; i < seqId; i++) {
      missingIds.push(i);
    }

    fetchMissingEvents(game_id, hand_id, missingIds);

    // Store out-of-order event
    pendingEvents.set(seqId, envelope);
    return;
  }

  // Process in-order event
  if (seqId === lastSequenceId + 1) {
    processEvent(envelope);
    lastSequenceId = seqId;

    // Process any pending events that are now in sequence
    processPendingEvents();
  } else if (seqId <= lastSequenceId) {
    // Duplicate/old event - ignore
    console.warn(`Ignoring duplicate event: ${seqId}`);
  }
}

function processPendingEvents() {
  while (pendingEvents.has(lastSequenceId + 1)) {
    const nextEvent = pendingEvents.get(lastSequenceId + 1)!;
    pendingEvents.delete(lastSequenceId + 1);
    processEvent(nextEvent);
    lastSequenceId++;
  }
}

async function fetchMissingEvents(
  gameId: number,
  handId: number,
  seqIds: number[]
) {
  const seqIdsParam = seqIds.join(',');
  const response = await fetch(
    `/game/${gameId}/hand/${handId}/events?seq_ids=${seqIdsParam}`
  );
  const { events } = await response.json();

  // Sort and process
  events.sort((a, b) => a.snapshotSequenceId - b.snapshotSequenceId);
  events.forEach(event => {
    if (event.snapshotSequenceId === lastSequenceId + 1) {
      processEvent(event);
      lastSequenceId++;
    } else {
      pendingEvents.set(event.snapshotSequenceId, event);
    }
  });

  processPendingEvents();
}
```

---

## Event-Driven Architecture

### Overview

The demo is a **real-time visualization** of the actual mental poker protocol. The frontend **listens to protocol events** streamed from the backend via Supabase Realtime (filtered by `game_id` and `hand_id`) and renders them as they arrive.

**Key Principle**: The frontend is a passive observer that renders cryptographic events in real-time. All shuffling, dealing, and card encryption happens on the backend using the actual ZK mental poker protocol.

### Card Representation

**Standard 52-Card Deck**:
```typescript
type Suit = 'spades' | 'hearts' | 'diamonds' | 'clubs';
type Rank = '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '10' | 'J' | 'Q' | 'K' | 'A';

interface Card {
  rank: Rank;
  suit: Suit;
  value: number; // 0-51 for encryption
}

const SUITS: Suit[] = ['spades', 'hearts', 'diamonds', 'clubs'];
const RANKS: Rank[] = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];

// Generate ordered deck
const orderedDeck: Card[] = SUITS.flatMap((suit, suitIdx) =>
  RANKS.map((rank, rankIdx) => ({
    rank,
    suit,
    value: suitIdx * 13 + rankIdx // 0-51
  }))
);
```

**Card Encoding**:
- Spades: 0-12 (2♠=0, 3♠=1, ..., A♠=12)
- Hearts: 13-25 (2♥=13, 3♥=14, ..., A♥=25)
- Diamonds: 26-38 (2♦=26, 3♦=27, ..., A♦=38)
- Clubs: 39-51 (2♣=39, 3♣=40, ..., A♣=51)

### Protocol Event Flow

The backend emits events via Supabase Realtime as the protocol executes. The frontend subscribes to these events and renders them in real-time.

**Phase 1: Distributed Shuffling**

Each shuffler (count = player count) applies their own random permutation. Shuffles arrive **in order** (turn_index: 0, 1, 2, ..., N-1):

```typescript
import type { FinalizedAnyMessageEnvelope } from '~/lib/finalizedEnvelopeSchema';

// Global state
let shuffleCount = 0;
const totalShufflers = playerCount;  // e.g., 7 for 7-player game

function handleShuffleEvent(envelope: FinalizedAnyMessageEnvelope) {
  const msg = envelope.envelope.message.value;

  if (msg.type !== 'shuffle') return;

  // Schema fields (from finalizedEnvelopeSchema.ts):
  // msg.turn_index: number (0 to N-1) - which shuffler (arrives in order)
  // msg.deck_in: string[] (52 hex strings) - input ciphertexts
  // msg.deck_out: string[] (52 hex strings) - output ciphertexts
  // msg.proof: string (hex) - ZK proof of correct shuffle

  // Increment counter
  shuffleCount++;

  // Update progress bar
  const progress = shuffleCount / totalShufflers;
  updateShuffleProgress(progress);
  updateStatusText(`Shuffler ${shuffleCount} of ${totalShufflers} complete`);

  // All shufflers complete?
  if (shuffleCount === totalShufflers) {
    // Pulse animation on progress bar
    animateProgressBarComplete();

    // Transition to Dealing phase
    setTimeout(() => {
      transitionToDealing();
    }, 500);
  }
}
```

**Visual State During Shuffling**:

- **Collapsed by default** (can expand to see detailed log)
- Progress bar fills as shuffles complete: `shuffleCount / totalShufflers`
- Status updates: "Shuffler 1 of 7 complete", "Shuffler 2 of 7 complete", etc.
- When complete: pulse animation, then transition to dealing

**UI Example** (collapsed):
```
┌─────────────────────────────────────┐
│ 🔀 Shuffler 3 of 7 complete         │
│ ████████▱▱▱▱▱▱▱▱▱▱▱▱  43%          │
│                         [▼ Expand]  │
└─────────────────────────────────────┘
```

**Phase 2: Card Dealing (Blinding)**

For each card dealt to a player, the backend emits `blinding` events from each shuffler:

```typescript
import type { FinalizedAnyMessageEnvelope } from '~/lib/finalizedEnvelopeSchema';

function handleBlindingEvent(envelope: FinalizedAnyMessageEnvelope) {
  const msg = envelope.envelope.message.value;

  if (msg.type !== 'blinding') return;

  // Schema fields (from finalizedEnvelopeSchema.ts):
  // msg.card_in_deck_position: number (0-51) - position in shuffled deck
  // msg.share: string (hex) - blinding share
  // msg.target_player_public_key: string (hex) - recipient public key

  const actor = envelope.envelope.actor;
  if (actor.kind !== 'shuffler') return;

  // Get or create card state
  const card = getOrCreateCard(msg.card_in_deck_position, msg.target_player_public_key);

  // Store blinding share from this shuffler
  card.blindingShares.set(actor.shufflerId, msg.share);

  // Trigger card flight animation on first share
  if (card.blindingShares.size === 1) {
    triggerCardFlightAnimation(card);
  }

  // Check if ready to decrypt
  checkCardDecryption(card);
}
```

**Phase 3: Partial Unblinding (Share Collection)**

For each card dealt, every shuffler provides a partial decryption share:

```typescript
import type { FinalizedAnyMessageEnvelope } from '~/lib/finalizedEnvelopeSchema';

function handlePartialUnblindingEvent(envelope: FinalizedAnyMessageEnvelope) {
  const msg = envelope.envelope.message.value;

  if (msg.type !== 'partial_unblinding') return;

  // Schema fields (from finalizedEnvelopeSchema.ts):
  // msg.card_in_deck_position: number (0-51) - position in shuffled deck
  // msg.share: string (hex) - partial unblinding share
  // msg.target_player_public_key: string (hex) - recipient public key

  const actor = envelope.envelope.actor;
  if (actor.kind !== 'shuffler') return;

  const card = getCardByPosition(msg.card_in_deck_position);
  if (!card) return;

  // Store partial unblinding share from this shuffler
  card.partialUnblindingShares.set(actor.shufflerId, msg.share);

  // Check if ready to decrypt
  checkCardDecryption(card);
}
```

**Card Decryption Requirements**:

A player can decrypt a card when they have received ALL shares:

- **N blinding shares** (one from each shuffler)
- **N partial unblinding shares** (one from each shuffler)
- **Total: 2N shares per card** (where N = player count)

**Example (7 players)**:
- Player 0's first card:
  - 7 blinding shares (one from each shuffler)
  - 7 partial unblinding shares (one from each shuffler)
  - **Total: 14 shares** → card can be decrypted

**Share Tracking**:
```typescript
interface CardDecryptionState {
  position: number;
  targetPlayerKey: string;
  blindingShares: Map<number, string>;          // shuffler_id → share
  partialUnblindingShares: Map<number, string>; // shuffler_id → share
  requiredSharesPerType: number;                // = player count
}

function handleBlindingEvent(event: BlindingEvent) {
  const card = getOrCreateCard(event.card_in_deck_position, event.target_player_public_key);

  // Store blinding share
  const shufflerId = event.envelope.actor.shufflerId;
  card.blindingShares.set(shufflerId, event.share);

  // Trigger card flight animation on first share
  if (card.blindingShares.size === 1) {
    triggerCardFlightAnimation(card);
  }

  // Check if ready to decrypt
  checkCardDecryption(card);
}

function handlePartialUnblindingEvent(event: PartialUnblindingEvent) {
  const card = getCardByPosition(event.card_in_deck_position);

  // Store partial unblinding share
  const shufflerId = event.envelope.actor.shufflerId;
  card.partialUnblindingShares.set(shufflerId, event.share);

  // Check if ready to decrypt
  checkCardDecryption(card);
}

function checkCardDecryption(card: CardDecryptionState) {
  const hasAllBlinding = card.blindingShares.size === card.requiredSharesPerType;
  const hasAllUnblinding = card.partialUnblindingShares.size === card.requiredSharesPerType;

  if (hasAllBlinding && hasAllUnblinding) {
    // All shares collected → trigger reveal
    revealCard(card);
  }
}
```

### Client-Side Random Deck (Demo Display)

For demo purposes, we generate a **client-side shuffled deck** to display card values when decryption completes. This is temporary until actual cryptographic decryption is implemented.

**Initialization** (on demo start):

```typescript
type Suit = 'spades' | 'hearts' | 'diamonds' | 'clubs';
type Rank = '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '10' | 'J' | 'Q' | 'K' | 'A';

interface Card {
  rank: Rank;
  suit: Suit;
}

const SUITS: Suit[] = ['spades', 'hearts', 'diamonds', 'clubs'];
const RANKS: Rank[] = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];

// Generate ordered 52-card deck
function generateOrderedDeck(): Card[] {
  return SUITS.flatMap(suit =>
    RANKS.map(rank => ({ rank, suit }))
  );
}

// Simple Fisher-Yates shuffle for client display (NOT cryptographically secure)
function shuffleDeck(deck: Card[]): Card[] {
  const shuffled = [...deck];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

// Initialize at demo start
const clientShuffledDeck: Card[] = shuffleDeck(generateOrderedDeck());
```

**Card Reveal** (when all shares collected):

```typescript
function revealCard(card: CardDecryptionState) {
  // TODO: Actual decryption using collected shares
  // For demo: map card position to client-shuffled deck
  const displayCard = clientShuffledDeck[card.position];  // 0-51

  card.revealed = true;
  card.displayCard = displayCard;

  // Trigger flip animation to reveal card
  animateCardReveal(card.position, displayCard);
}
```

**Key Points**:
- **One shuffle per demo session**: All players see the same random cards
- **Position mapping**: `card_in_deck_position` (0-51) → `clientShuffledDeck[position]`
- **Works for all cards**: Hole cards, flop, turn, river all use the same mapping
- **Each replay**: Generate new `clientShuffledDeck` for fresh random cards

**Card Encoding** (for reference):
- Position 0 could be 7♠, Position 1 could be K♦, etc.
- Each demo session shows different random cards
- Positions 0-51 map to the 52-card deck in shuffled order

### Card Display

**Rendering Cards**:
```typescript
function renderCard(card: Card, revealed: boolean): JSX.Element {
  if (!revealed) {
    return <CardBack />; // 🃏
  }

  const suitSymbols = {
    spades: '♠',
    hearts: '♥',
    diamonds: '♦',
    clubs: '♣'
  };

  const suitColors = {
    spades: '#000000',
    hearts: '#c41e3a',
    diamonds: '#c41e3a',
    clubs: '#000000'
  };

  return (
    <div className="card-face" style={{ color: suitColors[card.suit] }}>
      <div className="card-corner top-left">
        <div>{card.rank}</div>
        <div>{suitSymbols[card.suit]}</div>
      </div>
      <div className="card-center">
        {suitSymbols[card.suit]}
      </div>
      <div className="card-corner bottom-right">
        <div>{card.rank}</div>
        <div>{suitSymbols[card.suit]}</div>
      </div>
    </div>
  );
}
```

### Hand Quality Distribution

**Approximate Probabilities** (for viewer interest):

| Hand Type | Probability | Demo Occurrence |
|-----------|-------------|-----------------|
| Premium (AA, KK, QQ, AK) | 2.1% | ~1 in 50 sessions |
| Strong (JJ-TT, AQ, AJ) | 4.5% | ~1 in 22 sessions |
| Playable (99-22, suited connectors) | 35% | ~1 in 3 sessions |
| Marginal (offsuit, low pairs) | 58.4% | ~6 in 10 sessions |

**Hand Labeling** (for completion screen):
```typescript
function labelHand(card1: Card, card2: Card): string {
  const ranks = [card1.rank, card2.rank].sort((a, b) =>
    RANKS.indexOf(b) - RANKS.indexOf(a)
  );
  const suited = card1.suit === card2.suit;

  // Premium hands
  if (ranks[0] === 'A' && ranks[1] === 'A') return '🚀 Pocket Aces - Best starting hand!';
  if (ranks[0] === 'K' && ranks[1] === 'K') return '👑 Pocket Kings - Premium hand!';
  if (ranks[0] === 'A' && ranks[1] === 'K' && suited) return '✨ Ace-King suited - Premium hand!';

  // Strong hands
  if (ranks[0] === 'Q' && ranks[1] === 'Q') return '💎 Pocket Queens - Strong hand!';
  if (ranks[0] === 'A' && ranks[1] === 'K') return '🎯 Ace-King - Strong hand!';

  // Pairs
  if (ranks[0] === ranks[1]) return `🎲 Pocket ${ranks[0]}s`;

  // Suited
  if (suited) return `${ranks[0]}${ranks[1]} suited`;

  // Default
  return `${ranks[0]}${ranks[1]} offsuit`;
}
```

### Seeded Randomness (Optional for Testing)

For **reproducible demo runs** during development/testing:
```typescript
/**
 * Seeded PRNG for reproducible shuffles (testing only)
 */
class SeededRandom {
  private seed: number;

  constructor(seed: number = Date.now()) {
    this.seed = seed;
  }

  next(): number {
    // Linear congruential generator
    this.seed = (this.seed * 1664525 + 1013904223) % (2 ** 32);
    return this.seed / (2 ** 32);
  }

  nextInt(min: number, max: number): number {
    return Math.floor(this.next() * (max - min)) + min;
  }
}

function shuffleDeckSeeded(seed?: number): Card[] {
  const rng = new SeededRandom(seed);
  const deck = [...orderedDeck];

  for (let i = deck.length - 1; i > 0; i--) {
    const j = rng.nextInt(0, i + 1);
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }

  return deck;
}
```

**Usage**:
```typescript
// Production: true randomness
const prodSession = initializeDemoSession(7);

// Testing: reproducible shuffle
const testSession = initializeDemoSession(7, { seed: 12345 });
```


---

## Design Specifications

**Note**: The following ASCII diagrams show the **7-player configuration** as the default/example. The system dynamically adapts to 2-9 players using the positioning algorithm shown in the Technical Implementation Notes section.

### State 1: Shuffling Phase (7-Player Example)

```
┌────────────────────────────────────────────────────────────────────────┐
│ BG: #0a0e14 (deep dark slate)                                          │
│ Viewport: 1440×900px (desktop)                                         │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────┐     │
│ │ CHAPTER 1: CRYPTOGRAPHIC SHUFFLE                               │ ←─┐ │
│ │ Color: #e2e8f0 (light gray) • 32px bold • centered            │   │ │
│ └────────────────────────────────────────────────────────────────┘   │ │
│                                  ↑                                    │ │
│                              32px padding top                         │ │
│                                  ↓                                    │ │
│                              48px gap                                 │ │
│                                  ↓                                    │ │
│                  🎴 LEGIT POKER 🎴                                    │ │
│                  Color: #e2e8f0                                       │ │
│                  20px font size                                       │ │
│                                  ↓                                    │ │
│                              24px gap                                 │ │
│                                  ↓                                    │ │
│              ⚡ Shuffling deck...                                     │ │
│              Color: #94a3b8 (medium gray)                             │ │
│              16px font size                                           │ │
│                                  ↓                                    │ │
│                              16px gap                                 │ │
│                                  ↓                                    │ │
│         🔄 7 independent shufflers                                    │ │
│         🔒 Zero-knowledge proofs verified                             │ │
│         ⚡ Completed in 0.68 seconds                                  │ │
│         Color: #94a3b8 • 14px • line-height: 1.8                     │ │
│                                  ↓                                    │ │
│                              32px gap                                 │ │
│                                  ↓                                    │ │
│    ┌──────────────────────────────────────────────────────────┐      │ │
│    │ ████████████████████████████████████████████████████     │ ←─┐  │ │
│    │ BG: #1e293b (dark) • Fill: #00d9ff (teal)              │   │  │ │
│    │ Height: 12px • Rounded: 9999px                          │   │  │ │
│    │ Shadow: 0 0 10px rgba(0,217,255,0.5)                   │   │  │ │
│    └──────────────────────────────────────────────────────────┘   │  │ │
│                                  ↑                                │  │ │
│                          Progress bar: 100%                       │  │ │
│                      Max-width: 600px • Centered                  │  │ │
│                                  ↓                                    │ │
│                              24px gap                                 │ │
│                                  ↓                                    │ │
│              ✓ Shuffle Complete                                       │ │
│              Color: #22c55e (success green)                           │ │
│              18px font • Bold                                         │ │
│                                  ↓                                    │ │
│                              16px gap                                 │ │
│                                  ↓                                    │ │
│              [See Shuffle Details ▾]                                  │ │
│              Button: BG #1a1f2e • Border #2d3748 • 2px              │ │
│              Color: #94a3b8 • Padding: 8px 16px                      │ │
│              Hover: Border #00d9ff                                   │ │
│                                                                        │
│                              32px padding bottom                      │ │
└────────────────────────────────────────────────────────────────────────┘

Element Positioning:
- All centered horizontally (left: 50%, transform: translateX(-50%))
- Stacked vertically with specified gaps
- Chapter header: absolute top-8
- Content area: flex flex-col items-center justify-center
- Total content height: ~400px
```

---

### State 2: Dealing Phase - Before Your Cards (7-Player Example)

```
┌────────────────────────────────────────────────────────────────────────┐
│ BG: #0a0e14                                                            │
│ Viewport: 1440×900px                                                   │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────┐     │
│ │ CHAPTER 2: DEALING HOLE CARDS                                  │     │
│ │ Color: #e2e8f0 • 32px bold                                     │     │
│ └────────────────────────────────────────────────────────────────┘     │
│                                  ↓                                     │
│                              48px gap                                  │
│                                  ↓                                     │
│ Dealing to Player 2...                                                 │
│ Color: #94a3b8 • 16px • Centered                                      │
│                                  ↓                                     │
│                              24px gap                                  │
│                                                                        │
│      Player 2 (154.2°)                                                │
│      ┌────────┐                                                       │
│      │ Avatar │  64×64px • Rounded-full                               │
│      │ #0f1419│  Border: 2px #2d3748                                  │
│      └────────┘                                                       │
│       Player 2   12px • #e2e8f0                                       │
│        🃏 ●     32×44px cards • 4px gap • Dealing animation          │
│          ↑                                                            │
│      Dealing indicator (pulsing)                                      │
│                                                                        │
│  Player 3          ┌─────────────────────┐           Player 1        │
│  ┌────┐            │                     │           ┌────┐          │
│  │👤  │            │   POKER TABLE       │           │👤  │          │
│  └────┘            │                     │           └────┘          │
│  Player 3          │   900×600px         │           Player 1        │
│   ○  ○             │   rounded-[50%]     │            🃏 🃏         │
│    ↑               │                     │             ↑             │
│ Waiting            │   BG: #2d5016       │         Received          │
│                    │   (poker felt)      │                           │
│                    │   Border: 8px       │                           │
│                    │   #1a3510           │                           │
│                    │   (darker green)    │                           │
│                    │                     │                           │
│         YOU ⭐     │   ┌─────┐           │          Player 7         │
│     ┌──────────┐   │   │ 🃏  │  Deck     │          ┌────┐          │
│     │ Avatar   │   │   └─────┘           │          │👤  │          │
│     │ 80×80px  │   │   48×64px           │          └────┘          │
│     │ Border:  │   │   BG: #c41e3a       │          Player 7        │
│     │ 3px      │   │   (red back)        │           ○  ○           │
│     │ #fbbf24  │   │                     │                           │
│     │ Golden   │   │   🃏 ──────→        │ ← Card flying animation  │
│     │ Glow     │   │   To Player 2       │    Color: #00d9ff glow   │
│     └──────────┘   │                     │                           │
│   YOU (Player 3)   │                     │                           │
│   Badge BG:        └─────────────────────┘                           │
│   gradient #fbbf24/20                                                │
│   Border: 2px #fbbf24                                                │
│   Padding: 6px 16px                                                  │
│   Rounded-full                                                       │
│      ○   ○                                                           │
│   Waiting for cards                                                  │
│   12px • #94a3b8                                                     │
│                                  ↓                                    │
│                              80px from bottom                         │
│                                  ↓                                    │
│ ┌────────────────────────────────────────────────────────────────┐   │
│ │ Progress: 4/14 hole cards dealt                           29%  │   │
│ │ Color: #94a3b8 • 14px                                          │   │
│ │ ──────────────────────────────────────────────────────────     │   │
│ │ ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                    │   │
│ │ Height: 12px • Max-width: 800px • Centered                     │   │
│ └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘

Player Positioning Example (7 players):
- Center point: (50%, 50%)
- Distance from center: 48% of table size (varies by player count, see Technical Implementation)
- Rotation: 360° / 7 = 51.4° increments
- Player 0 (YOU): 0° (bottom center)
- Player 1: 51.4°
- Player 2: 102.8°
- Player 3: 154.2° (top center)
- Player 4: 205.6°
- Player 5: 257°
- Player 6: 308.4°

**For other player counts (2-9)**, see the `getPlayerPositions()` algorithm in Technical Implementation Notes.

Formula:
  x = 50% + sin(rotation) × baseDistance%
  y = 50% - cos(rotation) × baseDistance%

Card Animation:
- Start: Center deck position
- End: Player position
- Duration: 1000ms
- Easing: cubic-bezier(0.4, 0, 0.2, 1)
- Shadow: 0 0 20px rgba(0,217,255,0.6) during flight
```

---

### State 3: Dealing Phase - Your Card Arriving (7-Player Example)

```
┌────────────────────────────────────────────────────────────────────────┐
│ BG: #0a0e14                                                            │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────┐     │
│ │ 🃏 Dealing to you...                                           │     │
│ │ Color: #e2e8f0 • 24px bold                                     │     │
│ └────────────────────────────────────────────────────────────────┘     │
│                                  ↓                                     │
│                              48px gap                                  │
│                                                                        │
│      Player 2                                                         │
│      ┌────┐                                                           │
│      │👤  │ 64×64px                                                   │
│      └────┘                                                           │
│      Player 2                                                         │
│      🃏 🃏                                                            │
│                                                                        │
│                    ┌─────────────────────┐                            │
│  Player 3          │   POKER TABLE       │           Player 1        │
│  ┌────┐            │   900×600px         │           ┌────┐          │
│  │👤  │            │                     │           │👤  │          │
│  └────┘            │   ┌─────┐           │           └────┘          │
│  Player 3          │   │ 🃏  │           │           Player 1        │
│  🃏 🃏            │   └─────┘           │           🃏 🃏          │
│                    │    Deck             │                           │
│                    │      ↓              │                           │
│                    │   🃏 ──────→ ●      │ ← Card flying to YOU     │
│         YOU ⭐     │   Animation         │                           │
│     ┌──────────┐   │                     │                           │
│     │ Avatar   │   │                     │                           │
│     │ 80×80px  │   │                     │                           │
│     │ Pulsing  │   │                     │                           │
│     │ Glow     │   └─────────────────────┘                           │
│     │ #fbbf24  │                                                     │
│     └──────────┘                                                     │
│   YOU (Player 3)                                                     │
│   Border: 3px #fbbf24                                                │
│   Shadow: 0 0 20px rgba(251,191,36,0.5)                             │
│                                                                        │
│   🃏 ← ●  Collecting shares (7/7) ✓                                  │
│    ↑      Color: #00d9ff • 11px                                      │
│    │      Animated ellipsis                                          │
│   Card    "Collecting shares (5/7)..."                               │
│   flying  "Collecting shares (6/7)..."                               │
│   in      "Collecting shares (7/7) ✓"                                │
│            ↓                                                          │
│           Decrypting...                                              │
│           Color: #00d9ff • 11px                                      │
│           Fade in after shares complete                              │
│                                                                        │
│   ○  ← Second card waiting                                           │
│                                                                        │
│                              80px from bottom                         │
│                                  ↓                                    │
│ ┌────────────────────────────────────────────────────────────────┐   │
│ │ Progress: 5/14 hole cards dealt                           36%  │   │
│ │ ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                      │   │
│ └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘

Animation Sequence:
1. Card leaves deck (0ms)
   - Scale: 0.8 → 1.0
   - Position: Center → YOUR position

2. Blinding contribution (250ms)
   - Green glow pulse on card
   - Status text: "Blinding contribution received"

3. Collecting shares (250ms - 1500ms)
   - Progress counter updates: 1/7 → 7/7
   - Cyan glow (#00d9ff) on card

4. Decrypting (1500ms - 1800ms)
   - Status text: "Decrypting..."
   - Card begins flip animation

5. Card lands (2000ms)
   - Card settles in position
   - Ready for flip reveal
```

---

### State 4: Your Card Revealed (7-Player Example)

```
┌────────────────────────────────────────────────────────────────────────┐
│ BG: #0a0e14                                                            │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────┐     │
│ │ ✨ Your first card decrypted                                   │     │
│ │ Color: #e2e8f0 • 24px bold                                     │     │
│ └────────────────────────────────────────────────────────────────┘     │
│                                  ↓                                     │
│                              48px gap                                  │
│                                                                        │
│      Player 2                                                         │
│      ┌────┐                                                           │
│      │👤  │                                                           │
│      └────┘                                                           │
│      Player 2                                                         │
│      🃏 🃏                                                            │
│                                                                        │
│                    ┌─────────────────────┐                            │
│  Player 3          │   POKER TABLE       │           Player 1        │
│  ┌────┐            │                     │           ┌────┐          │
│  │👤  │            │   ┌─────┐           │           │👤  │          │
│  └────┘            │   │ 🃏  │  Deck     │           └────┘          │
│  Player 3          │   └─────┘           │           Player 1        │
│  🃏 🃏            │                     │           🃏 🃏          │
│                    │                     │                           │
│                    │                     │                           │
│         YOU ⭐     │                     │                           │
│     ┌──────────┐   │                     │                           │
│     │ Avatar   │   │                     │                           │
│     │ 80×80px  │   │                     │                           │
│     │ #fbbf24  │   └─────────────────────┘                           │
│     └──────────┘                                                     │
│   YOU (Player 3)                                                     │
│                                                                        │
│   ┌─────────────┐     ○                                              │
│   │             │                                                     │
│   │      A      │  [Waiting]                                         │
│   │      ♠      │  Color: #64748b                                    │
│   │             │  12px                                              │
│   │      ♠      │                                                    │
│   │      A      │                                                    │
│   └─────────────┘                                                    │
│   56×80px                                                            │
│   BG: #ffffff (white)                                                │
│   Border: 2px #d1d5db                                                │
│   Rounded: 12px                                                      │
│   Shadow: 0 8px 16px rgba(0,0,0,0.5)                                │
│   Suit color: #000000 (black for spades)                            │
│                                                                        │
│   Card Layout:                                                        │
│   ┌─ Top-left corner (8px, 8px)                                     │
│   │  A  14px bold                                                    │
│   │  ♠  14px                                                         │
│   │                                                                   │
│   │  Center (50%, 50%)                                               │
│   │  ♠  40px suit symbol                                             │
│   │                                                                   │
│   └─ Bottom-right (rotated 180°)                                    │
│      A  14px bold                                                    │
│      ♠  14px                                                         │
│                                                                        │
│                              80px from bottom                         │
│                                  ↓                                    │
│ ┌────────────────────────────────────────────────────────────────┐   │
│ │ Progress: 7/14 hole cards dealt                           50%  │   │
│ │ ██████████████░░░░░░░░░░░░░░░░░░░░░░░░                        │   │
│ └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘

Card Flip Animation (500ms):
- Uses 3D transform
- perspective: 1000px
- transform-style: preserve-3d
- backface-visibility: hidden

Keyframes:
  0%:   rotateY(0deg)     [Back visible]
  50%:  rotateY(90deg)    [Edge visible]
  100%: rotateY(180deg)   [Face visible]

Easing: cubic-bezier(0.4, 0, 0.2, 1)
```

---

### State 5: Both Cards Revealed - Demo Complete (7-Player Example)

```
┌────────────────────────────────────────────────────────────────────────┐
│ BG: #0a0e14                                                            │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────┐     │
│ │ ✨ [Dynamic Hand Label - see Random Card Generation section]   │     │
│ │ Examples: "Pocket Aces - Best starting hand!" or               │     │
│ │ "Ace-King suited - Premium hand!" or "7♠ 2♦ offsuit"          │     │
│ │ Color: #fbbf24 (golden) • 28px bold                            │     │
│ └────────────────────────────────────────────────────────────────┘     │
│                                  ↓                                     │
│                              48px gap                                  │
│                                                                        │
│      Player 2          ┌─────────────────────┐          Player 1     │
│      ┌────┐            │   POKER TABLE       │          ┌────┐       │
│      │👤  │            │   900×600px         │          │👤  │       │
│      └────┘            │                     │          └────┘       │
│      Player 2          │   BG: #2d5016       │          Player 1     │
│      🃏 🃏            │   Border: 8px       │          🃏 🃏       │
│                        │   #1a3510           │                       │
│                        │                     │                       │
│  Player 3              │   ┌─────┐           │          Player 7     │
│  ┌────┐                │   │ 🃏  │  Deck     │          ┌────┐       │
│  │👤  │                │   └─────┘           │          │👤  │       │
│  └────┘                │   (No more cards)   │          └────┘       │
│  Player 3              │                     │          Player 7     │
│  🃏 🃏                │                     │          🃏 🃏       │
│                        │                     │                       │
│                        └─────────────────────┘                       │
│                                                                        │
│         YOU ⭐                                                        │
│     ┌──────────┐                                                     │
│     │ Avatar   │                                                     │
│     │ 80×80px  │                                                     │
│     │ #fbbf24  │                                                     │
│     └──────────┘                                                     │
│   YOU (Player 3)                                                     │
│                                                                        │
│   ┌─────────────┐      ┌─────────────┐                               │
│   │             │      │             │                               │
│   │      A      │      │      K      │                               │
│   │      ♠      │      │      ♠      │                               │
│   │             │      │             │                               │
│   │      ♠      │      │      ♠      │                               │
│   │      A      │      │      K      │                               │
│   └─────────────┘      └─────────────┘                               │
│   56×80px              56×80px                                       │
│   Gap between: 8px                                                    │
│                                                                        │
│                              ↓                                        │
│                          60px gap                                     │
│                              ↓                                        │
│                                                                        │
│ Other players: 👤 Player 1  👤 Player 2  👤 Player 3  👤 Player 4   │
│                👤 Player 6  👤 Player 7                              │
│ Color: #64748b • 12px • Centered                                     │
│                                                                        │
│                              ↓                                        │
│                          24px gap                                     │
│                              ↓                                        │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────┐   │
│ │ ✓ All hole cards dealt (14/14)                                │   │
│ │ ✓ 63 cryptographic messages processed                         │   │
│ │ ✓ 63 zero-knowledge proofs verified                           │   │
│ │ ✓ Total protocol time: 4.8 seconds                            │   │
│ │                                                                │   │
│ │ Color: #22c55e • 14px • Line-height: 1.8                      │   │
│ │ Max-width: 600px • Centered                                   │   │
│ │ BG: #1a1f2e/50 • Backdrop-blur                                │   │
│ │ Padding: 24px • Rounded: 12px                                 │   │
│ │ Border: 1px #2d3748                                           │   │
│ └────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│                              ↓                                        │
│                          32px gap                                     │
│                              ↓                                        │
│                                                                        │
│ 🎉 Demo Complete!                                                     │
│ Color: #e2e8f0 • 24px bold • Centered                                │
│                                                                        │
│                              ↓                                        │
│                          24px gap                                     │
│                              ↓                                        │
│                                                                        │
│ ┌────────────┐  ┌────────────┐  ┌──────────────────┐                │
│ │ 📊 View    │  │ 🔄 Replay  │  │ 🎮 Play Live     │                │
│ │ Protocol   │  │ Demo       │  │ Game             │                │
│ │ Log        │  │            │  │                  │                │
│ │            │  │            │  │                  │                │
│ │ BG:        │  │ BG:        │  │ BG: Gradient     │                │
│ │ #3b82f6    │  │ #1a1f2e    │  │ #10b981→#059669  │                │
│ │ Border:    │  │ Border:    │  │ Border:          │                │
│ │ #60a5fa    │  │ #2d3748    │  │ #34d399          │                │
│ │ Shadow:    │  │            │  │ Shadow:          │                │
│ │ 0 0 20px   │  │ Hover:     │  │ 0 0 20px         │                │
│ │ blue/50%   │  │ #00d9ff    │  │ green/50%        │                │
│ │            │  │ border     │  │                  │                │
│ │ Padding:   │  │            │  │ Padding:         │                │
│ │ 16px 32px  │  │ Padding:   │  │ 16px 32px        │                │
│ │ Height:    │  │ 16px 32px  │  │ Height: 56px     │                │
│ │ 56px       │  │ Height:    │  │ Font: 16px bold  │                │
│ │ Font:      │  │ 56px       │  │ Color: #fff      │                │
│ │ 16px bold  │  │ Font:      │  │ Rounded: 12px    │                │
│ │ Color:     │  │ 16px bold  │  │                  │                │
│ │ #fff       │  │ Color:     │  │ Hover: Scale 105%│                │
│ │ Rounded:   │  │ #e2e8f0    │  │ Active: Scale 95%│                │
│ │ 12px       │  │ Rounded:   │  │ Transition: 200ms│                │
│ │            │  │ 12px       │  │                  │                │
│ │ Hover:     │  │            │  │                  │                │
│ │ #2563eb    │  │ Transition:│  │                  │                │
│ │ Scale 105% │  │ 200ms      │  │                  │                │
│ └────────────┘  └────────────┘  └──────────────────┘                │
│     ↑               ↑                   ↑                            │
│     │               └───── 16px gap ────┘                            │
│   First             Second              Third                        │
│   button            button              button                       │
│                                                                        │
│ Buttons container:                                                    │
│ - Display: flex                                                       │
│ - Gap: 16px                                                           │
│ - Justify: center                                                     │
│ - Absolute: bottom-32px, centered horizontally                        │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Mobile Layout Specifications

### Small Mobile (375px)

#### Table View (Default)

```
┌─────────────────────────────────┐
│ 375px width                     │
│ BG: #0a0e14                     │
│                                 │
│ ┌─────────────────────────────┐ │
│ │ CHAPTER 2: DEALING          │ │ ← 20px font, #e2e8f0
│ │ HOLE CARDS                  │ │   Padding: 16px
│ └─────────────────────────────┘ │
│         ↓ 16px gap              │
│ Dealing to you...               │ ← 14px, #94a3b8
│         ↓ 16px gap              │
│                                 │
│ ┌─────────────────────────────┐ │
│ │ POKER TABLE                 │ │
│ │ 343×229px                   │ │ ← Full width - 32px padding
│ │ rounded-[50%]               │ │   BG: #2d5016
│ │ Border: 4px #1a3510         │ │   Thinner border on mobile
│ │                             │ │
│ │    Player 2                 │ │
│ │    ┌────┐                   │ │
│ │    │👤  │ 48×48px           │ │ ← Smaller avatars
│ │    └────┘                   │ │
│ │    P2  (11px)               │ │
│ │    🃏🃏 (32×44px)          │ │ ← Smaller cards
│ │                             │ │
│ │👤      ┌───┐      👤        │ │
│ │P3      │🃏 │      P1        │ │
│ │🃏🃏    └───┘     🃏🃏       │ │
│ │                             │ │
│ │    YOU ⭐                   │ │
│ │  ┌──────────┐               │ │
│ │  │ Avatar   │               │ │
│ │  │ 56×56px  │               │ │ ← Smaller your avatar
│ │  └──────────┘               │ │
│ │  YOU (Player 3)             │ │   12px, #fbbf24
│ │                             │ │
│ │  Collecting shares (7/7) ✓  │ │ ← Status below name
│ │  (10px, #00d9ff)            │ │   Not in box
│ │                             │ │
│ │  ┌─────┐    ○              │ │
│ │  │ A♠  │  [Wait]            │ │
│ │  └─────┘                   │ │
│ │  40×56px                   │ │ ← Smaller your cards
│ │                             │ │
│ └─────────────────────────────┘ │
│         ↓ 12px gap              │
│                                 │
│ Other players:                  │ ← Collapsed list
│ 👤 P1 👤 P2 👤 P3 👤 P4        │   11px, #64748b
│         ↓ 16px gap              │
│                                 │
│ ┌─────────────────────────────┐ │
│ │ Progress: 5/14         36%  │ │ ← 12px font
│ │ ██████░░░░░░░░░░░░░░░░░     │ │   Height: 6px (thinner)
│ └─────────────────────────────┘ │
│         ↓ 16px gap              │
│                                 │
│ ┌─────────────────────────────┐ │ ← Log toggle (hidden)
│ │ 📊 Protocol Log (5)     ▴   │ │   Sticky at viewport bottom
│ └─────────────────────────────┘ │   44px height, #1a1f2e
│         ↓ 12px gap              │   Border-top: 2px #00d9ff
│ ┌─────────────────────────────┐ │
│ │   🔄 Replay Demo            │ │ ← Full width buttons
│ └─────────────────────────────┘ │   44px height (touch target)
│         ↓ 8px gap               │   Stacked vertically
│ ┌─────────────────────────────┐ │
│ │   🎮 Play Live Game         │ │
│ └─────────────────────────────┘ │
│         ↓ 16px padding          │
└─────────────────────────────────┘
```

#### Console Logs (Expanded)

```
┌─────────────────────────────────┐
│ 375px width                     │
│ BG: #0a0e14                     │
│                                 │
│ ┌─────────────────────────────┐ │ ← Compressed table (25vh)
│ │ CHAPTER 2: DEALING          │ │   150px height
│ └─────────────────────────────┘ │
│ ┌─────────────────────────────┐ │
│ │ Mini Table                  │ │
│ │ 🎴 YOU ⭐ A♠ K♠            │ │
│ │ Progress: 5/14 (36%)        │ │
│ └─────────────────────────────┘ │
│                                 │
│ ┌─────────────────────────────┐ │ ← Log header (sticky)
│ │ 📊 Protocol Log        [▾]  │ │   52px height
│ └─────────────────────────────┘ │   BG: #1a1f2e
│ ┌─────────────────────────────┐ │   Z-index: 10
│ │ [All ▾] [🔵] [🟢] [🟣]     │ │
│ │ Progress: 5/105             │ │
│ └─────────────────────────────┘ │
│ ╔═════════════════════════════╗ │
│ ║ SCROLLABLE AREA (60vh)      ║ │ ← ~490px scrollable
│ ║                             ║ │   Overscroll-contain
│ ║ ┌─────────────────────────┐ ║ │
│ ║ │ 🔵 SHUFFLE          ▸   │ ║ │ ← Log entry
│ ║ │ Shuffler 1              │ ║ │   Padding: 12px
│ ║ │ Shuffled 52 cards       │ ║ │   Min-height: 72px
│ ║ │ 4:09:05 PM              │ ║ │   BG: #0f1419
│ ║ └─────────────────────────┘ ║ │   Border-bottom: 1px
│ ║         ↓ 2px gap           ║ │   #2d3748
│ ║ ┌─────────────────────────┐ ║ │   12px font, #e2e8f0
│ ║ │ 🔵 SHUFFLE          ▸   │ ║ │   Secondary: #94a3b8
│ ║ │ Shuffler 2              │ ║ │
│ ║ │ Shuffled 52 cards       │ ║ │   Tap entire row to
│ ║ │ 4:08:45 PM              │ ║ │   expand
│ ║ └─────────────────────────┘ ║ │
│ ║         ↓ 2px gap           ║ │
│ ║ ┌─────────────────────────┐ ║ │
│ ║ │ 🟢 BLIND            ▾   │ ║ │ ← Expanded entry
│ ║ │ Shuffler 1 → You        │ ║ │
│ ║ │ Blinding card #5        │ ║ │
│ ║ │ 4:08:28 PM              │ ║ │
│ ║ ├─────────────────────────┤ ║ │ ← Expanded section
│ ║ │ Payload        [Copy]   │ ║ │   BG: #0a0e14
│ ║ ├─────────────────────────┤ ║ │   11px monospace
│ ║ │ ▾ BlindingDecryption    │ ║ │
│ ║ │   · card_position: 5    │ ║ │   Max 2 levels deep
│ ║ │   ▸ blinding: 0x1a2b... │ ║ │   Truncate hex (8 chars)
│ ║ │   ▸ proof: CP_Proof     │ ║ │
│ ║ │                         │ ║ │
│ ║ │ ✓ Verified (38ms)       │ ║ │
│ ║ └─────────────────────────┘ ║ │
│ ║                             ║ │
│ ║ ↓ Scroll for more...        ║ │
│ ╚═════════════════════════════╝ │
│ ┌─────────────────────────────┐ │
│ │   [Close Log ▾]             │ │ ← Close button
│ └─────────────────────────────┘ │   44px height
└─────────────────────────────────┘

Animation:
- Slide up from bottom: 300ms
- Easing: cubic-bezier(0.4, 0, 0.2, 1)
- Backdrop: blur(4px) on table
- Close: Swipe down or tap button
```

---

## Component Hierarchy

**Note**: Component structure supports 2-9 players dynamically. The `count` prop is configurable.

```
<LandingPageDemo>
  <ChapterHeader />                      ← State-dependent title

  <PokerTableContainer>
    <Table>                              ← 900×600px oval, #2d5016
      <InnerRail />                      ← Border decoration
      <CenterDeck />                     ← Card stack, 48×64px
      <FlyingCards />                    ← Animated cards in flight
    </Table>

    <PlayerSeats count={playerCount}>    ← Dynamic 2-9 players
      {players.map(player => (
        <PlayerSeat
          position={getPosition(index)}  ← Circular layout
          isYou={index === 2}            ← Special styling
        >
          <Avatar size={isYou ? 80 : 64} />
          <PlayerName highlight={isYou} />
          <Cards
            revealed={isYou}
            size={isYou ? 56×80 : 48×64}
          />
          {isYou && <StatusIndicator />}  ← Blinding shares
        </PlayerSeat>
      ))}
    </PlayerSeats>
  </PokerTableContainer>

  <ProgressBar
    current={cardsDealt}
    total={14}
  />

  <ActionButtons>
    <ViewLogButton />
    <ReplayButton />
    <PlayLiveButton />
  </ActionButtons>

  <MobileLogToggle />                    ← Mobile only

  <ConsoleLogPanel
    expanded={isLogExpanded}
    entries={protocolMessages}
  />
</LandingPageDemo>
```

---

## Technical Implementation Notes

### Event-Driven Architecture

The demo uses a **real-time event-driven architecture** where the backend emits protocol events as they occur, and the frontend renders them immediately with coordinated animations.

**Backend Event Stream**:
```typescript
// Server-Sent Events (SSE) or WebSocket
interface ProtocolEvent {
  type: 'ShuffleStarted' | 'ShufflerCompleted' | 'ShuffleComplete' |
        'CardDealt' | 'BlindingContributionReceived' |
        'PartialUnblindingShareReceived' | 'AllSharesCollected' |
        'DecryptionStarted' | 'CardDecrypted' | 'DealingComplete';
  timestamp: number;
  data: any;
}

// Example event emission from backend
function emitShufflerCompleted(shufflerId: number) {
  eventStream.emit({
    type: 'ShufflerCompleted',
    timestamp: Date.now(),
    data: { shufflerId, total: playerCount }
  });
}
```

**Frontend Event Consumer**:
- Connects to backend event stream on demo start
- Maintains event queue for sequential processing
- Triggers animations and sounds based on events
- No artificial delays - respects actual protocol timing

**Benefits**:
- Demonstrates true protocol performance
- Responsive to backend optimizations
- Realistic user experience
- Easier debugging (can replay event streams)

### Player Positioning Algorithm

```typescript
// Dynamic player positioning for 2-9 players
const getPlayerPositions = (playerCount: number) => {
  const baseDistance = {
    2: 45, 3: 45, 4: 45,
    5: 48, 6: 48, 7: 48,
    8: 48, 9: 50
  }[playerCount];

  return Array.from({ length: playerCount }, (_, i) => {
    const rotation = (360 / playerCount) * i;
    const radians = (rotation * Math.PI) / 180;

    return {
      left: `calc(50% + ${Math.sin(radians) * baseDistance}%)`,
      top: `calc(50% - ${Math.cos(radians) * baseDistance}%)`,
      transform: 'translate(-50%, -50%)',
    };
  });
};

// Player 0 (YOU) always at bottom center (0°)
// Others positioned clockwise from there
```

### Card Animation

```typescript
// Card flight animation
const animateCardToPlayer = (
  cardElement: HTMLElement,
  playerPosition: { left: string; top: string }
) => {
  cardElement.animate([
    {
      left: '50%',
      top: '50%',
      transform: 'translate(-50%, -50%) rotate(0deg) scale(0.8)',
      boxShadow: '0 0 20px rgba(0, 217, 255, 0.6)',
    },
    {
      left: playerPosition.left,
      top: playerPosition.top,
      transform: 'translate(-50%, -50%) rotate(360deg) scale(1)',
      boxShadow: '0 4px 6px rgba(0, 0, 0, 0.5)',
    }
  ], {
    duration: 1000,
    easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
    fill: 'forwards',
  });
};

// Card flip animation
const flipCard = (cardElement: HTMLElement) => {
  cardElement.animate([
    { transform: 'rotateY(0deg)' },
    { transform: 'rotateY(180deg)' },
  ], {
    duration: 500,
    easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
    fill: 'forwards',
  });
};
```

### Message Flow (Event-Driven)

The backend streams protocol events to the frontend in real-time as cryptographic operations complete.

```typescript
interface ProtocolMessage {
  timestamp: Date;
  type: 'Shuffle' | 'BlindingDecryption' | 'PartialUnblinding';
  actor: string;        // "Shuffler 1", "Shuffler 2", etc.
  payload: any;         // Actual message data
  cardPosition?: number; // For dealing messages
  targetPlayer?: number; // For dealing messages
}

// Event-driven message processing for YOUR cards
// Backend emits events as they occur; frontend renders in real-time
const processYourCard = async (
  cardPosition: number,
  messages: ProtocolMessage[]
) => {
  // 1. Blinding contribution
  const blindingMsg = messages.find(
    m => m.type === 'BlindingDecryption' &&
         m.cardPosition === cardPosition &&
         m.targetPlayer === 2 // YOU
  );

  // 2. Collect 7 partial unblinding shares
  const unbindingShares = messages.filter(
    m => m.type === 'PartialUnblinding' &&
         m.cardPosition === cardPosition
  );

  // 3. Construct PlayerAccessibleCiphertext
  const pac = constructPlayerAccessibleCiphertext(
    blindingMsg,
    unbindingShares
  );

  // 4. Decrypt to reveal card
  const cardValue = await decryptCard(pac, yourSecretKey);

  return cardValue; // e.g., { rank: 'A', suit: 'spades' }
};
```

### Responsive Breakpoints

```typescript
// Tailwind configuration
const breakpoints = {
  sm: '375px',   // Small mobile
  md: '430px',   // Large mobile
  lg: '768px',   // Tablet
  xl: '1024px',  // Desktop
  '2xl': '1440px', // Large desktop
};

// Component-specific responsive values
const responsiveValues = {
  tableSize: {
    sm: { w: 343, h: 229 },
    md: { w: 390, h: 260 },
    lg: { w: 600, h: 400 },
    xl: { w: 800, h: 533 },
    '2xl': { w: 900, h: 600 },
  },
  avatarSize: {
    sm: { regular: 48, you: 56 },
    md: { regular: 56, you: 64 },
    lg: { regular: 64, you: 72 },
    xl: { regular: 64, you: 80 },
  },
  cardSize: {
    sm: { regular: { w: 32, h: 44 }, you: { w: 40, h: 56 } },
    md: { regular: { w: 36, h: 50 }, you: { w: 48, h: 64 } },
    lg: { regular: { w: 40, h: 56 }, you: { w: 52, h: 72 } },
    xl: { regular: { w: 48, h: 64 }, you: { w: 56, h: 80 } },
  },
};
```

---

## Performance Considerations

### Animation Performance
- Use `transform` and `opacity` for animations (smoother performance)
- Avoid animating `width`, `height`, `left`, `top` directly where possible
- Keep animations simple and efficient

### Mobile Optimizations
- Reduce particle effects on mobile (or disable entirely)
- Use CSS transitions instead of JavaScript animations where possible
- Virtualize log entries (only render visible items)
- Lazy load expanded payload details
- Throttle scroll events

### State Management
- Keep demo state in a single source of truth
- Use React Context or similar for global demo state
- Memoize expensive computations (player positions, etc.)
- Debounce user interactions (expand/collapse, filters)

---

## Color Palette Reference

```css
/* Primary backgrounds */
--bg-primary: #0a0e14;       /* Page background */
--bg-secondary: #1a1f2e;     /* Cards, panels */
--bg-tertiary: #2d3748;      /* Borders, dividers */

/* Poker table */
--table-felt: #2d5016;       /* Felt green */
--table-rail: #1a3510;       /* Dark green border */
--table-highlight: #3d6b1e;  /* Light green accent */

/* Accents */
--accent-teal: #00d9ff;      /* Info, highlights */
--accent-cyan: #22d3ee;      /* Secondary highlights */
--accent-gold: #fbbf24;      /* YOUR player highlight */

/* Cards */
--card-back: #c41e3a;        /* Red card back */
--card-face: #ffffff;        /* White face */
--suit-black: #000000;       /* Spades, clubs */
--suit-red: #c41e3a;         /* Hearts, diamonds */

/* Status */
--status-shuffle: #3b82f6;   /* Blue */
--status-blind: #10b981;     /* Green */
--status-unblind: #8b5cf6;   /* Purple */
--status-complete: #22c55e;  /* Success */
--status-error: #ef4444;     /* Error */

/* Text */
--text-primary: #e2e8f0;     /* Light gray */
--text-secondary: #94a3b8;   /* Medium gray */
--text-muted: #64748b;       /* Dark gray */
```

---

## Accessibility

### Keyboard Navigation
- Tab through interactive elements
- Enter/Space to expand log entries
- Escape to close expanded logs
- Arrow keys to navigate between entries

### Screen Readers
- ARIA labels for all interactive elements
- Live regions for status updates
- Semantic HTML structure
- Alt text for card images

### Visual
- Minimum contrast ratio: 4.5:1 for text
- Focus indicators on all interactive elements
- Reduced motion support (prefers-reduced-motion)
- Large touch targets (44×44px minimum)

---

## Next Steps

1. **Implementation**: Build React components following this spec
2. **Testing**: Test on multiple devices and screen sizes
3. **Performance**: Optimize animations and transitions
4. **Accessibility**: WCAG 2.1 AA compliance audit
5. **Analytics**: Track user engagement with demo
6. **Iteration**: Gather feedback and refine UX

---

**Document Version**: 2.0
**Last Updated**: 2025-10-17
**Author**: Engineering Team
**Status**: Ready for Implementation

**Version 2.0 Changes**:
- Added variable player count support (2-9 players) with scaling tables
- Added comprehensive Animation & Sound Design specifications
- Added Random Card Generation implementation with cryptographic shuffling
- Updated all ASCII diagrams to indicate 7-player default configuration
- Added hand quality distribution and labeling system
- Added replay functionality and session management specifications
- **Clarified real-time execution**: Demo runs at actual protocol speed with event-driven frontend
- **4-second performance constraint**: Updated all timings to reflect ~4s max demo duration
  - Shuffling: ~0.5s
  - Dealing: ~2.0s (parallel card animations)
  - Decryption: ~0.3s per card
  - Completion: ~0.5s
- **Parallel card dealing**: Cards fly simultaneously with 50ms stagger
- **Instant share collection**: All shares arrive at once (no progressive counter)
- **Shortened animations**: Card flight 300-400ms (was 800-1000ms)
- Changed animation architecture from timer-based to event-driven (WebSocket/SSE)
- Removed progressive share ping sounds (shares arrive instantly)
