import { Assets, type Texture } from 'pixi.js';
import type { Suit, Rank } from '@/types/poker';

/**
 * CardAssets - Manages loading and caching of card SVG textures
 *
 * This module handles:
 * - Preloading all 52 card face SVGs + card back SVG
 * - Texture caching for performance
 * - Type-safe texture retrieval by suit/rank
 */

// Map suit/rank to SVG file names
const SUIT_FILE_MAP = {
  hearts: 'Heart',
  diamonds: 'Diamond',
  clubs: 'Club',
  spades: 'Spade',
} as const satisfies Record<Suit, string>;

const RANK_FILE_MAP = {
  '2': '2',
  '3': '3',
  '4': '4',
  '5': '5',
  '6': '6',
  '7': '7',
  '8': '8',
  '9': '9',
  '10': '10',
  'J': 'J',
  'Q': 'Q',
  'K': 'K',
  'A': 'A',
} as const satisfies Record<Rank, string>;

// Base path for card assets (served from public folder)
const CARD_ASSETS_PATH = '/cards';

// Cache for loaded textures
const textureCache = new Map<string, Texture>();
let cardBackTexture: Texture | null = null;
let assetsLoaded = false;

/**
 * Generate the file path for a card SVG
 */
function getCardFilePath(suit: Suit, rank: Rank): string {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
  const suitName = SUIT_FILE_MAP[suit];
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
  const rankName = RANK_FILE_MAP[rank];
  return `${CARD_ASSETS_PATH}/${suitName}_${rankName}.svg`;
}

/**
 * Generate cache key for a card texture
 */
function getCacheKey(suit: Suit, rank: Rank): string {
  return `${suit}_${rank}`;
}

/**
 * Preload all card assets (52 cards + card back)
 * Call this before creating any PixiCard instances
 */
export async function loadCardAssets(): Promise<void> {
  if (assetsLoaded) {
    console.log('[CardAssets] Assets already loaded, skipping');
    return;
  }

  console.log('[CardAssets] Starting asset preload...');
  const startTime = performance.now();

  try {
    // Build list of all assets to load
    const assetsToLoad: Array<{ alias: string; src: string }> = [];

    // Add card back
    assetsToLoad.push({
      alias: 'card_back',
      src: `${CARD_ASSETS_PATH}/card_back.svg`,
    });

    // Add all 52 cards
    const suits: Suit[] = ['hearts', 'diamonds', 'clubs', 'spades'];
    const ranks: Rank[] = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];

    for (const suit of suits) {
      for (const rank of ranks) {
        const cacheKey = getCacheKey(suit, rank);
        const filePath = getCardFilePath(suit, rank);
        assetsToLoad.push({
          alias: cacheKey,
          src: filePath,
        });
      }
    }

    // Load all assets in parallel using Pixi's Assets API
    await Assets.load(assetsToLoad.map(asset => asset.src));

    // Cache the textures
    for (const asset of assetsToLoad) {
      const texture = Assets.get<Texture>(asset.src);
      if (!texture) {
        throw new Error(`Failed to load texture: ${asset.src}`);
      }

      if (asset.alias === 'card_back') {
        cardBackTexture = texture;
      } else {
        textureCache.set(asset.alias, texture);
      }
    }

    assetsLoaded = true;
    const loadTime = performance.now() - startTime;
    console.log(`[CardAssets] Loaded ${assetsToLoad.length} assets in ${loadTime.toFixed(2)}ms`);
  } catch (error) {
    console.error('[CardAssets] Failed to load card assets:', error);
    throw error;
  }
}

/**
 * Get texture for a specific card
 * Must call loadCardAssets() first
 */
export function getCardTexture(suit: Suit, rank: Rank): Texture {
  if (!assetsLoaded) {
    throw new Error('[CardAssets] Assets not loaded. Call loadCardAssets() first.');
  }

  const cacheKey = getCacheKey(suit, rank);
  const texture = textureCache.get(cacheKey);

  if (!texture) {
    throw new Error(`[CardAssets] Texture not found for ${suit} ${rank}`);
  }

  return texture;
}

/**
 * Get texture for card back
 * Must call loadCardAssets() first
 */
export function getCardBackTexture(): Texture {
  if (!assetsLoaded) {
    throw new Error('[CardAssets] Assets not loaded. Call loadCardAssets() first.');
  }

  if (!cardBackTexture) {
    throw new Error('[CardAssets] Card back texture not loaded');
  }

  return cardBackTexture;
}

/**
 * Check if assets are loaded
 */
export function areAssetsLoaded(): boolean {
  return assetsLoaded;
}

/**
 * Unload all card assets and clear cache
 * Useful for cleanup or hot reload scenarios
 */
export async function unloadCardAssets(): Promise<void> {
  console.log('[CardAssets] Unloading assets...');

  // Clear texture cache
  textureCache.clear();
  cardBackTexture = null;

  // Unload from Pixi Assets
  const suits: Suit[] = ['hearts', 'diamonds', 'clubs', 'spades'];
  const ranks: Rank[] = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];

  const assetsToUnload: string[] = [`${CARD_ASSETS_PATH}/card_back.svg`];

  for (const suit of suits) {
    for (const rank of ranks) {
      assetsToUnload.push(getCardFilePath(suit, rank));
    }
  }

  await Assets.unload(assetsToUnload);

  assetsLoaded = false;
  console.log('[CardAssets] Assets unloaded');
}
