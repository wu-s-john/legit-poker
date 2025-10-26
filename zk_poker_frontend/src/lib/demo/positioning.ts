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
  baseDistance: number = 420
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
