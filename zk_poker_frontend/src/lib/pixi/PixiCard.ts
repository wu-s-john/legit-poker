import { Graphics, Container, Text, TextStyle, BlurFilter, Rectangle } from 'pixi.js';
import type { Point } from './utils';

export type Suit = 'hearts' | 'diamonds' | 'clubs' | 'spades';
export type Rank = '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '10' | 'J' | 'Q' | 'K' | 'A';

export interface CardConfig {
  suit?: Suit;
  rank?: Rank;
  width: number;
  height: number;
  position: Point;
  seatIndex: number;
  cardIndex: number;
}

export type CardState = 'face_down' | 'decryptable' | 'revealed';

export class PixiCard {
  private container: Container;
  private frontCard: Graphics;
  private backCard: Graphics;
  private config: CardConfig;
  private state: CardState = 'face_down';
  private isFlipping = false;
  private glowFilter: BlurFilter | null = null;
  private rankText: Text | null = null;
  private suitText: Text | null = null;

  constructor(config: CardConfig) {
    this.container = new Container();
    this.config = config;

    // Create card back
    this.backCard = new Graphics();
    this.createCardBack();

    // Create card front (hidden initially)
    this.frontCard = new Graphics();
    if (config.suit && config.rank) {
      this.createCardFront(config.suit, config.rank);
    }

    // Initially show only the back
    this.backCard.visible = true;
    this.frontCard.visible = false;

    // Position card
    this.container.position.set(config.position.x, config.position.y);

    // Make interactive
    this.container.eventMode = 'static';
    this.container.cursor = 'pointer';

    // Set up hit area
    this.container.hitArea = new Rectangle(
      -config.width / 2,
      -config.height / 2,
      config.width,
      config.height
    );

    // Add hover effect
    this.container.on('pointerover', () => this.onHover(true));
    this.container.on('pointerout', () => this.onHover(false));
  }

  private createCardBack(): void {
    const { width, height } = this.config;

    this.backCard.clear();

    // Card background
    this.backCard.fill(0x4169e1); // Royal blue
    this.backCard.roundRect(-width / 2, -height / 2, width, height, 8);
    this.backCard.fill();

    // Border
    this.backCard.stroke({ color: 0x000000, width: 2 });
    this.backCard.roundRect(-width / 2, -height / 2, width, height, 8);
    this.backCard.stroke();

    // Add decorative pattern
    const patternText = new Text({
      text: '🃏',
      style: new TextStyle({
        fontSize: width * 0.5,
        align: 'center',
      }),
    });
    patternText.anchor.set(0.5);
    this.backCard.addChild(patternText);

    this.container.addChild(this.backCard);
  }

  private createCardFront(suit: Suit, rank: Rank): void {
    const { width, height } = this.config;

    this.frontCard.clear();

    // Card background (white)
    this.frontCard.fill(0xffffff);
    this.frontCard.roundRect(-width / 2, -height / 2, width, height, 8);
    this.frontCard.fill();

    // Border
    this.frontCard.stroke({ color: 0x000000, width: 2 });
    this.frontCard.roundRect(-width / 2, -height / 2, width, height, 8);
    this.frontCard.stroke();

    // Determine suit color and symbol
    const isRed = suit === 'hearts' || suit === 'diamonds';
    const color = isRed ? 0xff0000 : 0x000000;
    const suitSymbol = this.getSuitSymbol(suit);

    // Rank text (top-left and bottom-right)
    this.rankText = new Text({
      text: rank,
      style: new TextStyle({
        fontFamily: 'Arial, sans-serif',
        fontSize: width * 0.25,
        fill: color,
        fontWeight: 'bold',
        align: 'center',
      }),
    });
    this.rankText.anchor.set(0.5);
    this.rankText.position.set(-width / 3, -height / 3);
    this.frontCard.addChild(this.rankText);

    // Suit symbol (center)
    this.suitText = new Text({
      text: suitSymbol,
      style: new TextStyle({
        fontSize: width * 0.4,
        align: 'center',
      }),
    });
    this.suitText.anchor.set(0.5);
    this.frontCard.addChild(this.suitText);

    // Rank text bottom-right (rotated)
    const rankTextBottom = new Text({
      text: rank,
      style: new TextStyle({
        fontFamily: 'Arial, sans-serif',
        fontSize: width * 0.25,
        fill: color,
        fontWeight: 'bold',
        align: 'center',
      }),
    });
    rankTextBottom.anchor.set(0.5);
    rankTextBottom.position.set(width / 3, height / 3);
    rankTextBottom.rotation = Math.PI; // 180 degrees
    this.frontCard.addChild(rankTextBottom);

    this.container.addChild(this.frontCard);
  }

  private getSuitSymbol(suit: Suit): string {
    switch (suit) {
      case 'hearts':
        return '♥';
      case 'diamonds':
        return '♦';
      case 'clubs':
        return '♣';
      case 'spades':
        return '♠';
    }
  }

  private onHover(isHovered: boolean): void {
    if (this.state === 'decryptable' && isHovered) {
      this.container.alpha = 0.9;
    } else {
      this.container.alpha = 1.0;
    }
  }

  public setState(state: CardState): void {
    this.state = state;

    if (state === 'decryptable') {
      // Add glow effect for decryptable cards
      this.glowFilter ??= new BlurFilter({ strength: 8, quality: 4 });
      this.container.filters = [this.glowFilter];

      // Change tint based on viewer
      if (this.config.seatIndex === 0) {
        this.backCard.tint = 0xffd700; // Gold for viewer
      } else {
        this.backCard.tint = 0x90ee90; // Light green for others
      }
    } else {
      this.container.filters = [];
      this.backCard.tint = 0xffffff; // Reset tint
    }
  }

  /**
   * Flip the card to reveal its face
   * Returns a promise that resolves when flip animation completes
   */
  public async flip(duration = 500): Promise<void> {
    if (this.isFlipping) return;
    this.isFlipping = true;

    return new Promise((resolve) => {
      const startTime = Date.now();
      const startScaleX = this.container.scale.x;

      const animate = () => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Flip using scale.x (simulate 3D rotation)
        if (progress < 0.5) {
          // First half: scale down to 0
          const scaleProgress = 1 - (progress * 2);
          this.container.scale.x = startScaleX * scaleProgress;
        } else {
          // Second half: swap card and scale back up
          if (this.backCard.visible) {
            this.backCard.visible = false;
            this.frontCard.visible = true;
          }
          const scaleProgress = (progress - 0.5) * 2;
          this.container.scale.x = startScaleX * scaleProgress;
        }

        if (progress < 1) {
          requestAnimationFrame(animate);
        } else {
          this.container.scale.x = startScaleX;
          this.isFlipping = false;
          this.setState('revealed');
          resolve();
        }
      };

      animate();
    });
  }

  public setCard(suit: Suit, rank: Rank): void {
    this.config.suit = suit;
    this.config.rank = rank;

    // Recreate front card
    this.frontCard.removeChildren();
    this.createCardFront(suit, rank);
  }

  public setPosition(position: Point): void {
    this.container.position.set(position.x, position.y);
  }

  public getPosition(): Point {
    return {
      x: this.container.position.x,
      y: this.container.position.y,
    };
  }

  public getContainer(): Container {
    return this.container;
  }

  public getSeatIndex(): number {
    return this.config.seatIndex;
  }

  public getCardIndex(): number {
    return this.config.cardIndex;
  }

  public destroy(): void {
    this.container.destroy({ children: true });
  }
}
