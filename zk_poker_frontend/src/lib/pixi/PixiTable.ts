import { Container, Graphics, BlurFilter } from "pixi.js";
import { DESIGN_W, DESIGN_H } from "./utils";

export interface TableConfig {
  width: number;
  height: number;
  centerX: number;
  centerY: number;
}

/**
 * Professional casino-style poker table with multi-layered vector design:
 * - Black leather outer rail with drop shadow
 * - Metallic copper/bronze middle rail
 * - Light bronze inner bevel
 * - Green felt surface with depth simulation
 *
 * Implementation:
 * - Pure vector graphics using PixiJS Graphics API
 * - Infinitely scalable with no blur at any resolution
 * - Layered ellipses create depth and dimension
 * - BlurFilter provides drop shadow effect
 */
export class PixiTable {
  private container: Container;
  private config: TableConfig;
  private graphics: Graphics | null = null;
  private blurFilter: BlurFilter | null = null;

  constructor(config?: Partial<TableConfig>) {
    this.container = new Container();

    // Default configuration
    this.config = {
      width: 1320, // 85% of DESIGN_W
      height: 720, // 80% of 900px design height
      centerX: DESIGN_W / 2,
      centerY: DESIGN_H / 2,
      ...config,
    };

    // Create table immediately (synchronous)
    this.createTable();
  }

  /**
   * Creates the poker table using vector graphics (Graphics API)
   * Draws 5 concentric ellipses to simulate the multi-layer design
   */
  private createTable(): void {
    const { width, height, centerX, centerY } = this.config;

    // Calculate ellipse radii (half of width/height)
    const baseRadiusX = width / 2;
    const baseRadiusY = height / 2;

    // Create graphics object for all layers
    this.graphics = new Graphics();

    // Layer 1: Outer leather rail (black with subtle gradient simulation)
    // Use multiple concentric ellipses with slightly different shades for depth
    this.graphics
      .fill({ color: 0x0d0d0d }) // Darkest edge
      .ellipse(centerX, centerY, baseRadiusX, baseRadiusY)
      .fill();

    this.graphics
      .fill({ color: 0x1a1a1a }) // Mid-dark
      .ellipse(centerX, centerY, baseRadiusX * 0.99, baseRadiusY * 0.99)
      .fill();

    this.graphics
      .fill({ color: 0x2a2a2a }) // Lighter center
      .ellipse(centerX, centerY, baseRadiusX * 0.97, baseRadiusY * 0.97)
      .fill();

    // Layer 2: Metallic wood rail (copper/bronze with gradient simulation)
    const woodRadiusX = baseRadiusX * 0.972;
    const woodRadiusY = baseRadiusY * 0.972;

    this.graphics
      .fill({ color: 0x704214 }) // Dark bronze edge
      .ellipse(centerX, centerY, woodRadiusX, woodRadiusY)
      .fill();

    this.graphics
      .fill({ color: 0x8b4513 }) // Saddle brown
      .ellipse(centerX, centerY, woodRadiusX * 0.98, woodRadiusY * 0.98)
      .fill();

    this.graphics
      .fill({ color: 0xb8733a }) // Medium copper
      .ellipse(centerX, centerY, woodRadiusX * 0.96, woodRadiusY * 0.96)
      .fill();

    this.graphics
      .fill({ color: 0xcd7f32 }) // Bright copper center
      .ellipse(centerX, centerY, woodRadiusX * 0.94, woodRadiusY * 0.94)
      .fill();

    // Layer 3: Inner bevel highlight (light bronze)
    const bevelRadiusX = baseRadiusX * 0.944;
    const bevelRadiusY = baseRadiusY * 0.944;

    this.graphics
      .fill({ color: 0xd4983d }) // Dark gold edge
      .ellipse(centerX, centerY, bevelRadiusX, bevelRadiusY)
      .fill();

    this.graphics
      .fill({ color: 0xe6a85c }) // Medium gold
      .ellipse(centerX, centerY, bevelRadiusX * 0.98, bevelRadiusY * 0.98)
      .fill();

    this.graphics
      .fill({ color: 0xf5c88f }) // Light gold center
      .ellipse(centerX, centerY, bevelRadiusX * 0.96, bevelRadiusY * 0.96)
      .fill();

    // Layer 4: Felt surface (green with gradient simulation from bright center to dark edges)
    const feltRadiusX = baseRadiusX * 0.935;
    const feltRadiusY = baseRadiusY * 0.935;

    // Dark edge
    this.graphics
      .fill({ color: 0x0d3a22 })
      .ellipse(centerX, centerY, feltRadiusX, feltRadiusY)
      .fill();

    // Mid-dark
    this.graphics
      .fill({ color: 0x104a2a })
      .ellipse(centerX, centerY, feltRadiusX * 0.95, feltRadiusY * 0.95)
      .fill();

    // Medium
    this.graphics
      .fill({ color: 0x155a34 })
      .ellipse(centerX, centerY, feltRadiusX * 0.85, feltRadiusY * 0.85)
      .fill();

    // Bright center
    this.graphics
      .fill({ color: 0x1a6b3f })
      .ellipse(centerX, centerY, feltRadiusX * 0.7, feltRadiusY * 0.7)
      .fill();

    // Add subtle blur to table edges
    this.blurFilter = new BlurFilter({ strength: 2, quality: 1 });
    this.graphics.filters = [this.blurFilter];

    // Add to container
    this.container.addChild(this.graphics);
  }

  /**
   * Wait for table to finish loading
   * This is now a no-op since Graphics rendering is synchronous
   * Kept for API compatibility
   */
  public async waitForLoad(): Promise<void> {
    return Promise.resolve();
  }

  /**
   * Check if table has finished loading
   * Always returns true since Graphics rendering is synchronous
   */
  public isLoaded(): boolean {
    return this.graphics !== null;
  }

  public getContainer(): Container {
    return this.container;
  }

  public destroy(): void {
    this.container.destroy({ children: true });
    this.graphics = null;
  }
}
