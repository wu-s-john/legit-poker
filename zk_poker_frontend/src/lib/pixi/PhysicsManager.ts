import Matter from 'matter-js';
import type { PixiCard } from './PixiCard';
import { DESIGN_W, DESIGN_H } from './utils';

export interface PhysicsConfig {
  gravity: {
    x: number;
    y: number;
  };
  enabled: boolean;
}

export class PhysicsManager {
  private engine: Matter.Engine;
  private world: Matter.World;
  private cardBodies = new Map<PixiCard, Matter.Body>();
  private config: PhysicsConfig;

  constructor(config?: Partial<PhysicsConfig>) {
    this.config = {
      gravity: { x: 0, y: 0 }, // No gravity by default (cards float)
      enabled: false, // Disabled by default
      ...config,
    };

    // Create physics engine
    this.engine = Matter.Engine.create({
      gravity: this.config.gravity,
    });

    this.world = this.engine.world;

    // Create table boundaries (invisible walls)
    this.createBoundaries();
  }

  /**
   * Create invisible boundaries around the table
   */
  private createBoundaries(): void {
    const wallThickness = 50;
    const walls = [
      // Top wall
      Matter.Bodies.rectangle(DESIGN_W / 2, -wallThickness / 2, DESIGN_W, wallThickness, {
        isStatic: true,
      }),
      // Bottom wall
      Matter.Bodies.rectangle(DESIGN_W / 2, DESIGN_H + wallThickness / 2, DESIGN_W, wallThickness, {
        isStatic: true,
      }),
      // Left wall
      Matter.Bodies.rectangle(-wallThickness / 2, DESIGN_H / 2, wallThickness, DESIGN_H, {
        isStatic: true,
      }),
      // Right wall
      Matter.Bodies.rectangle(DESIGN_W + wallThickness / 2, DESIGN_H / 2, wallThickness, DESIGN_H, {
        isStatic: true,
      }),
    ];

    Matter.Composite.add(this.world, walls);
  }

  /**
   * Add a card to the physics simulation
   */
  public addCard(card: PixiCard, width: number, height: number): void {
    const position = card.getPosition();

    // Create a physics body for the card
    const body = Matter.Bodies.rectangle(position.x, position.y, width, height, {
      restitution: 0.6, // Bounciness
      friction: 0.1,
      frictionAir: 0.05,
      density: 0.001,
    });

    Matter.Composite.add(this.world, body);
    this.cardBodies.set(card, body);
  }

  /**
   * Remove a card from the physics simulation
   */
  public removeCard(card: PixiCard): void {
    const body = this.cardBodies.get(card);
    if (body) {
      Matter.Composite.remove(this.world, body);
      this.cardBodies.delete(card);
    }
  }

  /**
   * Apply a force to a card (for throwing)
   */
  public throwCard(card: PixiCard, forceX: number, forceY: number): void {
    const body = this.cardBodies.get(card);
    if (body) {
      Matter.Body.applyForce(body, body.position, { x: forceX, y: forceY });
    }
  }

  /**
   * Set card position (override physics)
   */
  public setCardPosition(card: PixiCard, x: number, y: number): void {
    const body = this.cardBodies.get(card);
    if (body) {
      Matter.Body.setPosition(body, { x, y });
      Matter.Body.setVelocity(body, { x: 0, y: 0 });
      Matter.Body.setAngularVelocity(body, 0);
    }
  }

  /**
   * Update physics simulation and sync with Pixi sprites
   */
  public update(delta = 16.67): void {
    if (!this.config.enabled) return;

    // Update physics engine
    Matter.Engine.update(this.engine, delta);

    // Sync physics bodies with Pixi sprites
    this.cardBodies.forEach((body, card) => {
      const container = card.getContainer();
      container.position.set(body.position.x, body.position.y);
      container.rotation = body.angle;
    });
  }

  /**
   * Enable or disable physics simulation
   */
  public setEnabled(enabled: boolean): void {
    this.config.enabled = enabled;
  }

  /**
   * Set gravity
   */
  public setGravity(x: number, y: number): void {
    this.engine.gravity.x = x;
    this.engine.gravity.y = y;
  }

  /**
   * Clear all card bodies
   */
  public clear(): void {
    this.cardBodies.forEach((body) => {
      Matter.Composite.remove(this.world, body);
    });
    this.cardBodies.clear();
  }

  /**
   * Destroy the physics engine
   */
  public destroy(): void {
    this.clear();
    Matter.Engine.clear(this.engine);
  }
}
