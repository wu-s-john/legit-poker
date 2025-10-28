/**
 * Player positioning around the poker table using polar coordinates
 */

export interface Position {
  x: number;
  y: number;
  angle: number;
}

export interface PlayerPosition {
  seat: number;
  position: Position;
  isViewer: boolean;
}

/**
 * Calculate player positions around the table
 * Uses polar coordinates with the table center as origin
 *
 * @param playerCount Number of players (2-9)
 * @param tableCenter Center point of the table {x, y}
 * @param baseDistance Distance from center (px)
 * @returns Array of player positions
 */
export function calculatePlayerPositions(
  playerCount: number,
  tableCenter: { x: number; y: number } = { x: 960, y: 400 },
  baseDistance = 420
): PlayerPosition[] {
  const positions: PlayerPosition[] = [];
  const angleIncrement = (2 * Math.PI) / playerCount;

  for (let seat = 0; seat < playerCount; seat++) {
    // Player 0 (viewer) is at bottom center (angle = 0)
    // Other players rotate clockwise
    const angle = seat * angleIncrement;

    // Convert polar to cartesian
    // y is inverted because screen coordinates have y increasing downward
    const x = tableCenter.x + Math.sin(angle) * baseDistance;
    const y = tableCenter.y + Math.cos(angle) * baseDistance;

    positions.push({
      seat,
      position: { x, y, angle },
      isViewer: seat === 0,
    });
  }

  return positions;
}

/**
 * Get deck center position (middle of table)
 */
export function getDeckPosition(
  tableCenter: { x: number; y: number } = { x: 960, y: 400 }
): Position {
  return {
    x: tableCenter.x,
    y: tableCenter.y,
    angle: 0,
  };
}

/**
 * Calculate card positions for a player's hole cards
 * Each player has 2 card slots positioned side by side
 *
 * @param playerPosition The player's center position
 * @param cardIndex Index of the card (0 or 1)
 * @param isViewer Whether this is the viewer's position (affects card size)
 * @param tableCenter Center point of the table {x, y}
 * @returns Position for the specific card
 */
export function getCardPosition(
  playerPosition: Position,
  cardIndex: number,
  isViewer: boolean,
  tableCenter: { x: number; y: number } = { x: 960, y: 400 }
): Position {
  // Card dimensions and spacing (must match CSS in demo.css)
  const cardWidth = isViewer ? 60 : 60; // Both use same width for now
  const cardGap = 8; // var(--space-2) = 8px

  // Offset distance for the player's card slot container
  // Cards should be positioned between the player and the table center
  const cardSlotOffset = isViewer ? 130 : 110; // Based on avatar size + badge + margin

  // Determine direction: cards should be offset TOWARD the table center
  // For players below table center (large Y), offset should be negative (cards go up)
  // For players above table center (small Y), offset should be positive (cards go down)
  const isBottomHalf = playerPosition.y > tableCenter.y;
  const cardSlotOffsetY = isBottomHalf ? -cardSlotOffset : cardSlotOffset;

  // Calculate horizontal offset for each card
  // Two cards centered around the player position
  const totalWidth = cardWidth * 2 + cardGap;
  const leftCardX = playerPosition.x - totalWidth / 2 + cardWidth / 2;
  const rightCardX = playerPosition.x + totalWidth / 2 - cardWidth / 2;

  return {
    x: cardIndex === 0 ? leftCardX : rightCardX,
    y: playerPosition.y + cardSlotOffsetY,
    angle: playerPosition.angle,
  };
}
