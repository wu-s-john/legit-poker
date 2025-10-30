import { Graphics, Container } from 'pixi.js';
import { DESIGN_W, DESIGN_H } from './utils';

export interface TableConfig {
  width: number;
  height: number;
  centerX: number;
  centerY: number;
  feltColor: number;
  railColor: number;
  railWidth: number;
}

export class PixiTable {
  private container: Container;
  private config: TableConfig;

  constructor(config?: Partial<TableConfig>) {
    this.container = new Container();

    // Default configuration
    this.config = {
      width: 1320, // 85% of DESIGN_W
      height: 720, // ~35% of DESIGN_H scaled for ellipse
      centerX: DESIGN_W / 2,
      centerY: DESIGN_H / 2,
      feltColor: 0x124b2f, // Green felt
      railColor: 0x2e1a0b, // Dark wood
      railWidth: 18,
      ...config,
    };

    this.createTable();
  }

  private createTable(): void {
    const { width, height, centerX, centerY, feltColor, railColor, railWidth } = this.config;

    const graphics = new Graphics();

    // Calculate ellipse radii
    const radiusX = width / 2;
    const radiusY = height / 2;

    // Draw felt (green ellipse with radial gradient effect)
    // Create multiple ellipses with decreasing alpha for gradient effect
    const gradientSteps = 5;
    for (let i = gradientSteps; i >= 0; i--) {
      const scale = 1 - (i * 0.1);
      const alpha = 0.3 + (i * 0.14);
      graphics.fill({ color: feltColor, alpha });
      graphics.ellipse(centerX, centerY, radiusX * scale, radiusY * scale);
      graphics.fill();
    }

    // Main felt surface
    graphics.fill(feltColor);
    graphics.ellipse(centerX, centerY, radiusX, radiusY);
    graphics.fill();

    // Draw wood rail border
    graphics.stroke({ color: railColor, width: railWidth });
    graphics.ellipse(centerX, centerY, radiusX + railWidth / 2, radiusY + railWidth / 2);
    graphics.stroke();

    // Add graphics directly to container
    this.container.addChild(graphics);
  }

  public getContainer(): Container {
    return this.container;
  }

  public destroy(): void {
    this.container.destroy({ children: true, texture: true });
  }
}
