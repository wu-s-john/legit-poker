//! Pedersen commitment window configurations (bytes-oriented)
//!
//! These window definitions are used with arkworks' Pedersen commitment
//! primitives for byte-based messages. They are intentionally kept separate
//! so both native and gadget code can import them without pulling other items.

use ark_crypto_primitives::commitment::pedersen::Window as PedersenWindow;

/// Window configuration for Pedersen commitments over 32-byte messages
/// Supports 8 * 32 = 256 bits => 32-byte messages
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PedersenWin;

impl PedersenWindow for PedersenWin {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 32;
}

/// Window configuration for hashing a deck of 52 cards
/// Each card is represented by a byte (values 1-52), requiring 52 windows
/// This allows hashing a complete deck in a single operation (bytes-only)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DeckHashWindow;

impl PedersenWindow for DeckHashWindow {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 52; // For 52 cards in a deck
}

/// Window configuration for reencryption protocol commitments
/// Used for committing to power vectors in the Bayer-Groth protocol (bytes-only)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReencryptionWindow;

impl PedersenWindow for ReencryptionWindow {
    const WINDOW_SIZE: usize = 4;
    // Large enough that setup() yields many generators; > N is sufficient (we use ~52 max).
    const NUM_WINDOWS: usize = 416;
}

