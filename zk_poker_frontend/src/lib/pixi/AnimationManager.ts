import type { PixiCard } from './PixiCard';
import { cubicBezier, easeOutCubic, type Point } from './utils';

export interface DealAnimationConfig {
  card: PixiCard;
  start: Point;
  end: Point;
  duration: number;
  delay?: number;
  onComplete?: () => void;
}

interface ActiveAnimation {
  card: PixiCard;
  start: Point;
  end: Point;
  controlPoint1: Point;
  controlPoint2: Point;
  duration: number;
  startTime: number;
  startRotation: number;
  startScale: number;
  endScale: number;
  onComplete?: () => void;
}

export class AnimationManager {
  private activeAnimations: ActiveAnimation[] = [];
  private isRunning = false;

  /**
   * Animate a card from deck to player position using a bezier curve
   */
  public dealCard(config: DealAnimationConfig): Promise<void> {
    return new Promise((resolve) => {
      // Calculate control points for cubic bezier curve
      const midX = (config.start.x + config.end.x) / 2;
      const midY = (config.start.y + config.end.y) / 2;

      // Add some height to the curve for arc effect
      const arcHeight = 150;

      const controlPoint1: Point = {
        x: midX + (config.start.x - config.end.x) * 0.2,
        y: midY - arcHeight,
      };

      const controlPoint2: Point = {
        x: midX + (config.end.x - config.start.x) * 0.2,
        y: midY - arcHeight,
      };

      const animation: ActiveAnimation = {
        card: config.card,
        start: config.start,
        end: config.end,
        controlPoint1,
        controlPoint2,
        duration: config.duration,
        startTime: Date.now() + (config.delay ?? 0),
        startRotation: 0,
        startScale: 0.6, // Cards start smaller from deck
        endScale: 1.0, // Full size when landed
        onComplete: () => {
          config.onComplete?.();
          resolve();
        },
      };

      this.activeAnimations.push(animation);

      if (!this.isRunning) {
        this.start();
      }
    });
  }

  /**
   * Start the animation loop
   */
  private start(): void {
    this.isRunning = true;
    this.update();
  }

  /**
   * Animation update loop
   */
  private update = (): void => {
    const now = Date.now();
    const completedIndices: number[] = [];

    this.activeAnimations.forEach((anim, index) => {
      // Skip if delay hasn't elapsed
      if (now < anim.startTime) {
        return;
      }

      const elapsed = now - anim.startTime;
      const rawProgress = Math.min(elapsed / anim.duration, 1);
      const progress = easeOutCubic(rawProgress);

      // Calculate position along bezier curve
      const position = cubicBezier(
        progress,
        anim.start,
        anim.controlPoint1,
        anim.controlPoint2,
        anim.end
      );

      // Update card position
      anim.card.setPosition(position);

      // Rotate card during flight (360 degree spin)
      const container = anim.card.getContainer();
      container.rotation = anim.startRotation + (Math.PI * 2 * progress);

      // Scale card during flight
      const scale = anim.startScale + (anim.endScale - anim.startScale) * progress;
      container.scale.set(scale);

      // Check if animation complete
      if (rawProgress >= 1) {
        // Ensure final values are exact
        anim.card.setPosition(anim.end);
        container.rotation = 0;
        container.scale.set(anim.endScale);

        completedIndices.push(index);
        anim.onComplete?.();
      }
    });

    // Remove completed animations (reverse order to maintain indices)
    for (let i = completedIndices.length - 1; i >= 0; i--) {
      const index = completedIndices[i];
      if (index !== undefined) {
        this.activeAnimations.splice(index, 1);
      }
    }

    // Continue loop if there are active animations
    if (this.activeAnimations.length > 0) {
      requestAnimationFrame(this.update);
    } else {
      this.isRunning = false;
    }
  };

  /**
   * Stop all active animations
   */
  public stopAll(): void {
    this.activeAnimations = [];
    this.isRunning = false;
  }

  /**
   * Get count of active animations
   */
  public getActiveCount(): number {
    return this.activeAnimations.length;
  }
}
