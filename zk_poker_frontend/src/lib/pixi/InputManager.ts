import { Rectangle } from 'pixi.js';
import type { Container, FederatedPointerEvent } from 'pixi.js';
import type { PixiCard } from './PixiCard';
import type { Point } from './utils';

export interface InputCallbacks {
  onCardClick?: (seatIndex: number, cardIndex: number) => void;
  onCardDragStart?: (card: PixiCard, position: Point) => void;
  onCardDrag?: (card: PixiCard, position: Point) => void;
  onCardDragEnd?: (card: PixiCard, position: Point, velocity: Point) => void;
}

interface DragState {
  card: PixiCard;
  startPosition: Point;
  lastPosition: Point;
  lastTime: number;
}

export class InputManager {
  private callbacks: InputCallbacks;
  private dragState: DragState | null = null;
  private isDragging = false;
  private tapThreshold = 10; // pixels
  private tapTimeThreshold = 300; // milliseconds

  constructor(callbacks: InputCallbacks) {
    this.callbacks = callbacks;
  }

  /**
   * Make a card interactive
   */
  public makeCardInteractive(card: PixiCard): void {
    const container = card.getContainer();

    container.eventMode = 'static';
    container.cursor = 'pointer';

    // Enlarge hit area for better touch targets (44px minimum)
    this.ensureMinimumTapTarget(container);

    // Pointer down (start drag or tap)
    container.on('pointerdown', (event: FederatedPointerEvent) => {
      this.onPointerDown(card, event);
    });
  }

  /**
   * Ensure minimum tap target size (44px for accessibility)
   */
  private ensureMinimumTapTarget(container: Container): void {
    const bounds = container.getBounds();
    const minSize = 44;

    const width = Math.max(bounds.width, minSize);
    const height = Math.max(bounds.height, minSize);

    // Update hit area if needed
    if (bounds.width < minSize || bounds.height < minSize) {
      const offsetX = (width - bounds.width) / 2;
      const offsetY = (height - bounds.height) / 2;

      container.hitArea = new Rectangle(
        bounds.x - offsetX,
        bounds.y - offsetY,
        width,
        height
      );
    }
  }

  /**
   * Handle pointer down event
   */
  private onPointerDown(card: PixiCard, event: FederatedPointerEvent): void {
    const position = { x: event.global.x, y: event.global.y };

    this.dragState = {
      card,
      startPosition: position,
      lastPosition: position,
      lastTime: Date.now(),
    };

    // Listen for move and up events on the stage (not just the card)
    const stage = event.currentTarget.parent;
    if (stage) {
      stage.on('pointermove', this.onPointerMove);
      stage.on('pointerup', this.onPointerUp);
      stage.on('pointerupoutside', this.onPointerUp);
    }

    this.callbacks.onCardDragStart?.(card, position);
  }

  /**
   * Handle pointer move event
   */
  private onPointerMove = (event: FederatedPointerEvent): void => {
    if (!this.dragState) return;

    const position = { x: event.global.x, y: event.global.y };
    const { startPosition } = this.dragState;

    // Calculate distance moved
    const dx = position.x - startPosition.x;
    const dy = position.y - startPosition.y;
    const distance = Math.sqrt(dx * dx + dy * dy);

    // If moved beyond threshold, start dragging
    if (distance > this.tapThreshold) {
      this.isDragging = true;
      this.callbacks.onCardDrag?.(this.dragState.card, position);
    }

    this.dragState.lastPosition = position;
    this.dragState.lastTime = Date.now();
  };

  /**
   * Handle pointer up event
   */
  private onPointerUp = (event: FederatedPointerEvent): void => {
    if (!this.dragState) return;

    const position = { x: event.global.x, y: event.global.y };
    const { card, startPosition, lastPosition, lastTime } = this.dragState;

    // Remove listeners
    const stage = event.currentTarget;
    if (stage) {
      stage.off('pointermove', this.onPointerMove);
      stage.off('pointerup', this.onPointerUp);
      stage.off('pointerupoutside', this.onPointerUp);
    }

    if (this.isDragging) {
      // Calculate velocity for physics throw
      const now = Date.now();
      const dt = now - lastTime;
      const velocity: Point = {
        x: (position.x - lastPosition.x) / (dt || 1),
        y: (position.y - lastPosition.y) / (dt || 1),
      };

      this.callbacks.onCardDragEnd?.(card, position, velocity);
    } else {
      // It's a tap/click
      const dx = position.x - startPosition.x;
      const dy = position.y - startPosition.y;
      const distance = Math.sqrt(dx * dx + dy * dy);

      if (distance <= this.tapThreshold) {
        this.callbacks.onCardClick?.(card.getSeatIndex(), card.getCardIndex());
      }
    }

    // Reset state
    this.dragState = null;
    this.isDragging = false;
  };

  /**
   * Clean up all event listeners
   */
  public destroy(): void {
    this.dragState = null;
    this.isDragging = false;
  }
}
