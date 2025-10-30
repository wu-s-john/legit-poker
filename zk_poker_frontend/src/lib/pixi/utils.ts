/**
 * Pixi.js utility functions for coordinate conversion and positioning
 */

export const DESIGN_W = 1600;
export const DESIGN_H = 900;

export interface Point {
  x: number;
  y: number;
}

export interface Position {
  x: number;
  y: number;
}

/**
 * Convert percentage-based position to pixel coordinates in the Pixi world
 * @param percent Position in percentage (0-100)
 * @returns Position in pixels (relative to DESIGN_W × DESIGN_H)
 */
export function percentToPixel(percent: Position): Point {
  return {
    x: (percent.x / 100) * DESIGN_W,
    y: (percent.y / 100) * DESIGN_H,
  };
}

/**
 * Convert pixel coordinates to percentage-based position
 * @param pixel Position in pixels
 * @returns Position in percentage (0-100)
 */
export function pixelToPercent(pixel: Point): Position {
  return {
    x: (pixel.x / DESIGN_W) * 100,
    y: (pixel.y / DESIGN_H) * 100,
  };
}

/**
 * Calculate player positions around an elliptical table
 * Adapted from existing positioning.ts logic
 * @param numPlayers Total number of players
 * @param tableCenter Center of the table in pixels
 * @param radiusX Horizontal radius of the ellipse
 * @param radiusY Vertical radius of the ellipse
 * @returns Array of player positions in pixels
 */
export function calculatePlayerPositions(
  numPlayers: number,
  tableCenter: Point = { x: DESIGN_W / 2, y: DESIGN_H / 2 },
  radiusX = 660,
  radiusY = 360
): Point[] {
  const angleIncrement = (2 * Math.PI) / numPlayers;
  const startAngle = -Math.PI / 2; // Start at top

  return Array.from({ length: numPlayers }, (_, i) => {
    const angle = startAngle + i * angleIncrement;
    return {
      x: tableCenter.x + radiusX * Math.cos(angle),
      y: tableCenter.y + radiusY * Math.sin(angle),
    };
  });
}

/**
 * Get the deck position (center of table)
 * @returns Deck position in pixels
 */
export function getDeckPosition(): Point {
  return {
    x: DESIGN_W / 2,
    y: DESIGN_H / 2,
  };
}

/**
 * Calculate card position for a specific seat and card index
 * @param seatPosition Player seat position in pixels
 * @param cardIndex 0 for left card, 1 for right card
 * @param cardWidth Width of a card in pixels
 * @param cardGap Gap between cards in pixels
 * @param isViewer Whether this is the viewer's seat (affects Y offset)
 * @returns Card position in pixels
 */
export function getCardPosition(
  seatPosition: Point,
  cardIndex: number,
  cardWidth = 80,
  cardGap = 10,
  isViewer = false
): Point {
  const totalWidth = cardWidth * 2 + cardGap;
  const yOffset = isViewer ? 60 : 50; // Viewer cards slightly closer to center

  // Offset cards toward table center
  const baseX = seatPosition.x - totalWidth / 2;
  const x = cardIndex === 0
    ? baseX + cardWidth / 2
    : baseX + totalWidth - cardWidth / 2;

  // Y position moves toward center
  const directionY = seatPosition.y > DESIGN_H / 2 ? -1 : 1;
  const y = seatPosition.y + directionY * yOffset;

  return { x, y };
}

/**
 * Easing function: ease out cubic
 */
export function easeOutCubic(t: number): number {
  return 1 - Math.pow(1 - t, 3);
}

/**
 * Easing function: ease in out cubic
 */
export function easeInOutCubic(t: number): number {
  return t < 0.5
    ? 4 * t * t * t
    : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

/**
 * Easing function: ease out quad
 */
export function easeOutQuad(t: number): number {
  return 1 - (1 - t) * (1 - t);
}

/**
 * Linear interpolation between two values
 */
export function lerp(start: number, end: number, t: number): number {
  return start + (end - start) * t;
}

/**
 * Linear interpolation between two points
 */
export function lerpPoint(start: Point, end: Point, t: number): Point {
  return {
    x: lerp(start.x, end.x, t),
    y: lerp(start.y, end.y, t),
  };
}

/**
 * Calculate point on a cubic bezier curve
 * @param t Progress along curve (0-1)
 * @param p0 Start point
 * @param p1 First control point
 * @param p2 Second control point
 * @param p3 End point
 */
export function cubicBezier(
  t: number,
  p0: Point,
  p1: Point,
  p2: Point,
  p3: Point
): Point {
  const u = 1 - t;
  const tt = t * t;
  const uu = u * u;
  const uuu = uu * u;
  const ttt = tt * t;

  return {
    x: uuu * p0.x + 3 * uu * t * p1.x + 3 * u * tt * p2.x + ttt * p3.x,
    y: uuu * p0.y + 3 * uu * t * p1.y + 3 * u * tt * p2.y + ttt * p3.y,
  };
}

/**
 * Clamp a value between min and max
 */
export function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Convert degrees to radians
 */
export function degToRad(degrees: number): number {
  return (degrees * Math.PI) / 180;
}

/**
 * Convert radians to degrees
 */
export function radToDeg(radians: number): number {
  return (radians * 180) / Math.PI;
}
