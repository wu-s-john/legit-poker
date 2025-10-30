/**
 * Player positioning around the poker table using polar coordinates
 * All positions are in percentage units (0-100) relative to container dimensions
 */

export interface Position {
  x: number; // Percentage (0-100)
  y: number; // Percentage (0-100)
  angle: number; // Radians
}

export interface PlayerPosition {
  seat: number;
  position: Position;
  isViewer: boolean;
}

/**
 * Calculate player positions around the table
 * Uses polar coordinates with the table center as origin
 * All values are in percentage units (0-100)
 *
 * @param playerCount Number of players (2-9)
 * @param tableCenter Center point of the table (percentage 0-100)
 * @param baseDistance Distance from center (percentage of width)
 * @returns Array of player positions with percentage coordinates
 */
export function calculatePlayerPositions(
  playerCount: number,
  tableCenter: { x: number; y: number } = { x: 50, y: 50 }, // Center at 50%, 50%
  baseDistance = 21.875 // 420px / 1920px = 21.875% of width
): PlayerPosition[] {
  const positions: PlayerPosition[] = [];
  const angleIncrement = (2 * Math.PI) / playerCount;

  for (let seat = 0; seat < playerCount; seat++) {
    // Player 0 (viewer) is at bottom center (angle = 0)
    // Other players rotate clockwise
    const angle = seat * angleIncrement;

    // Convert polar to cartesian (percentage coordinates)
    // y is inverted because screen coordinates have y increasing downward
    const x = tableCenter.x + Math.sin(angle) * baseDistance;
    const y = tableCenter.y + Math.cos(angle) * baseDistance * 2.4; // Multiply by aspect ratio for elliptical positioning

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
 * Returns percentage coordinates (0-100)
 */
export function getDeckPosition(
  tableCenter: { x: number; y: number } = { x: 50, y: 50 }
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
 * All values in percentage units (0-100)
 *
 * @param playerPosition The player's center position (percentages)
 * @param cardIndex Index of the card (0 or 1)
 * @param isViewer Whether this is the viewer's position (affects card size)
 * @param tableCenter Center point of the table (percentages)
 * @returns Position for the specific card in percentage units
 */
export function getCardPosition(
  playerPosition: Position,
  cardIndex: number,
  isViewer: boolean,
  tableCenter: { x: number; y: number } = { x: 50, y: 50 }
): Position {
  // Card dimensions and spacing as percentage of width
  const cardWidth = 3.125; // 60px / 1920px = 3.125%
  const cardGap = 0.417; // 8px / 1920px = 0.417%

  // Offset distance for the player's card slot container (percentage)
  // Cards should be positioned between the player and the table center
  const cardSlotOffset = isViewer ? 6.77 : 5.73; // 130px/1920px = 6.77%, 110px/1920px = 5.73%

  // Determine direction: cards should be offset TOWARD the table center
  // For players below table center (large Y %), offset should be negative (cards go up)
  // For players above table center (small Y %), offset should be positive (cards go down)
  const isBottomHalf = playerPosition.y > tableCenter.y;
  const cardSlotOffsetY = isBottomHalf ? -cardSlotOffset * 2.4 : cardSlotOffset * 2.4; // Multiply by aspect ratio

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
