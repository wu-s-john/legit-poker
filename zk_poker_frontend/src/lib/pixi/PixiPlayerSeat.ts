import { Graphics, Container, Text, TextStyle, BlurFilter, Circle } from 'pixi.js';
import type { Point } from './utils';

export interface PlayerSeatConfig {
  position: Point;
  seatIndex: number;
  playerName?: string;
  isViewer: boolean;
  isActive?: boolean;
}

export class PixiPlayerSeat {
  private container: Container;
  private avatarCircle: Graphics;
  private avatarText: Text;
  private nameBadge: Container;
  private nameText: Text;
  private config: PlayerSeatConfig;
  private glowFilter: BlurFilter | null = null;

  constructor(config: PlayerSeatConfig) {
    this.container = new Container();
    this.config = config;

    // Create avatar circle
    this.avatarCircle = new Graphics();
    this.createAvatar();

    // Create avatar emoji/icon
    this.avatarText = new Text({
      text: '👤',
      style: new TextStyle({
        fontSize: 32,
        align: 'center',
      }),
    });
    this.avatarText.anchor.set(0.5);
    this.container.addChild(this.avatarText);

    // Create name badge
    this.nameBadge = new Container();
    this.nameText = new Text({
      text: config.playerName ?? `Player ${config.seatIndex + 1}`,
      style: new TextStyle({
        fontFamily: 'Arial, sans-serif',
        fontSize: 14,
        fill: 0xffffff,
        align: 'center',
      }),
    });
    this.nameText.anchor.set(0.5);
    this.createNameBadge();

    // Position the seat
    this.container.position.set(config.position.x, config.position.y);

    // Make interactive
    this.container.eventMode = 'static';
    this.container.cursor = 'pointer';

    // Set up hit area for better touch targets (minimum 44px)
    const hitRadius = Math.max(35, 22); // At least 22px radius (44px diameter)
    this.container.hitArea = new Circle(0, 0, hitRadius);

    // Add hover effect
    this.container.on('pointerover', () => this.onHover(true));
    this.container.on('pointerout', () => this.onHover(false));
  }

  private createAvatar(): void {
    const { isViewer } = this.config;
    const radius = 35;

    this.avatarCircle.clear();

    // Background circle
    this.avatarCircle.fill(isViewer ? 0xffd700 : 0xffffff);
    this.avatarCircle.circle(0, 0, radius);
    this.avatarCircle.fill();

    // Border
    this.avatarCircle.stroke({ color: isViewer ? 0xffa500 : 0xcccccc, width: 3 });
    this.avatarCircle.circle(0, 0, radius);
    this.avatarCircle.stroke();

    this.container.addChild(this.avatarCircle);
  }

  private createNameBadge(): void {
    const padding = 8;
    const badgeWidth = this.nameText.width + padding * 2;
    const badgeHeight = this.nameText.height + padding;

    const background = new Graphics();
    background.fill({ color: 0x000000, alpha: 0.6 });
    background.roundRect(-badgeWidth / 2, -badgeHeight / 2, badgeWidth, badgeHeight, 4);
    background.fill();

    this.nameBadge.addChild(background);
    this.nameBadge.addChild(this.nameText);

    // Position badge below avatar
    this.nameBadge.position.set(0, 50);

    this.container.addChild(this.nameBadge);
  }

  private onHover(isHovered: boolean): void {
    if (isHovered) {
      this.avatarCircle.alpha = 0.8;
    } else {
      this.avatarCircle.alpha = 1.0;
    }
  }

  public setActive(active: boolean): void {
    this.config.isActive = active;

    if (active) {
      // Add glow effect for active player
      this.glowFilter ??= new BlurFilter({ strength: 4, quality: 3 });
      this.container.filters = [this.glowFilter];

      // Subtle pulse animation could be added here via ticker
    } else {
      this.container.filters = [];
    }
  }

  public updateName(name: string): void {
    this.config.playerName = name;
    this.nameText.text = name;

    // Recreate badge to adjust for new width
    this.nameBadge.removeChildren();
    this.createNameBadge();
  }

  public getContainer(): Container {
    return this.container;
  }

  public getSeatIndex(): number {
    return this.config.seatIndex;
  }

  public destroy(): void {
    this.container.destroy({ children: true });
  }
}
