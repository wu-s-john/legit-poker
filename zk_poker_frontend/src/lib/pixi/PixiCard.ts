import { Container, Sprite, Text, TextStyle, Rectangle, Graphics } from 'pixi.js';
import type { Point } from './utils';
import { getCardTexture, getCardBackTexture } from './CardAssets';

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
  private cardSprite: Sprite;
  private config: CardConfig;
  private state: CardState = 'face_down';
  private isFlipping = false;
  private isFrontVisible = false;
  private keyBadge: Text | null = null;
  private decryptableBorder: Graphics | null = null;

  constructor(config: CardConfig) {
    this.container = new Container();
    this.config = config;

    // Create card sprite with card back texture
    this.cardSprite = new Sprite(getCardBackTexture());
    this.setupCardSprite();

    // Create key badge for decryptable state indicator
    this.createKeyBadge();

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

  private setupCardSprite(): void {
    const { width, height } = this.config;

    // Center anchor point
    this.cardSprite.anchor.set(0.5);

    // Scale sprite to fit card dimensions
    // SVG cards are 269x404, scale to match config width/height
    this.cardSprite.width = width;
    this.cardSprite.height = height;

    this.container.addChild(this.cardSprite);
  }

  private createKeyBadge(): void {
    const { width, height } = this.config;

    this.keyBadge = new Text({
      text: '🔑',
      style: new TextStyle({
        fontSize: width * 0.25, // Scale with card size
        align: 'center',
      }),
    });

    // Position in top-right corner (4px padding from edges)
    this.keyBadge.anchor.set(1, 0); // Anchor at top-right of text
    this.keyBadge.position.set(width / 2 - 4, -height / 2 + 4);
    this.keyBadge.visible = false; // Hidden by default

    this.container.addChild(this.keyBadge);
  }

  private createDecryptableBorder(): Graphics {
    const { width, height } = this.config;
    const color = this.config.seatIndex === 0 ? 0xffd700 : 0x90ee90; // Gold or green

    const border = new Graphics();
    border.stroke({ color, width: 4, alpha: 0.9 });
    border.roundRect(-width / 2 - 2, -height / 2 - 2, width + 4, height + 4, 10);
    border.stroke();

    return border;
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
      // Create and show border (if not already created)
      if (!this.decryptableBorder) {
        this.decryptableBorder = this.createDecryptableBorder();
        this.container.addChildAt(this.decryptableBorder, 0); // Behind card sprite
      }
      this.decryptableBorder.visible = true;

      // Show key badge
      if (this.keyBadge) {
        this.keyBadge.visible = true;
      }
    } else {
      // Hide border
      if (this.decryptableBorder) {
        this.decryptableBorder.visible = false;
      }

      // Hide key badge
      if (this.keyBadge) {
        this.keyBadge.visible = false;
      }
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
          // Second half: swap texture and scale back up
          if (!this.isFrontVisible) {
            // Swap to front card texture
            if (this.config.suit && this.config.rank) {
              this.cardSprite.texture = getCardTexture(this.config.suit, this.config.rank);
              this.isFrontVisible = true;
            }

            // Hide key badge when revealing card
            if (this.keyBadge) {
              this.keyBadge.visible = false;
            }

            // Hide border when revealing card
            if (this.decryptableBorder) {
              this.decryptableBorder.visible = false;
            }
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

    // If card is already revealed, update texture immediately
    if (this.isFrontVisible) {
      this.cardSprite.texture = getCardTexture(suit, rank);
    }
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
    // Clean up key badge
    if (this.keyBadge) {
      this.keyBadge.destroy();
      this.keyBadge = null;
    }

    // Clean up decryptable border
    if (this.decryptableBorder) {
      this.decryptableBorder.destroy();
      this.decryptableBorder = null;
    }

    this.container.destroy({ children: true });
  }
}
