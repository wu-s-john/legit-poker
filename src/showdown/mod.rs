//! showdown: shared types, constants, helpers

use core::cmp::Ordering;

pub type Rank = u8; // 2..14 (A=14)
pub type Index = u8; // 1..52 (1-based)

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Suit {
    Clubs = 0,    // C
    Diamonds = 1, // D
    Hearts = 2,   // H
    Spades = 3,   // S
}

impl Suit {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
    
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Suit::Clubs,
            1 => Suit::Diamonds,
            2 => Suit::Hearts,
            3 => Suit::Spades,
            _ => panic!("Invalid suit value: {value}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Card {
    pub rank: Rank, // 2..14
    pub suit: Suit, // enum
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HandCategory {
    HighCard = 0,
    OnePair = 1,
    TwoPair = 2,
    ThreeOfAKind = 3,
    Straight = 4,
    Flush = 5,
    FullHouse = 6,
    FourOfAKind = 7,
    StraightFlush = 8, // Royal is SF with high=14
}

impl HandCategory {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Base-16 multipliers (no shifting) for packing (cat,c1..c5)
pub const M5: u32 = 1_048_576; // 16^5
pub const M4: u32 = 65_536; // 16^4
pub const M3: u32 = 4_096; // 16^3
pub const M2: u32 = 256; // 16^2
pub const M1: u32 = 16; // 16^1
pub const M0: u32 = 1; // 16^0

/// Deterministic 1..52 -> Card mapping; 0=C,1=D,2=H,3=S; rank 2..14
#[inline]
pub fn decode_card(i: Index) -> Card {
    assert!((1..=52).contains(&i), "index out of range");
    let j = i - 1; // 0..51
    let suit = Suit::from_u8(j / 13);
    let r0 = j % 13;
    let rank = r0 + 2;
    Card { rank, suit }
}

/// Inverse helper for tests: (rank,suit) -> 1..52
#[inline]
pub fn idx_of(rank: Rank, suit: Suit) -> Index {
    assert!((2..=14).contains(&rank));
    13 * suit.as_u8() + (rank - 2) + 1
}

/// Deterministic sort-by-rank-desc, then suit-desc
pub fn sort_desc(cards: &mut [Card]) {
    cards.sort_by(|a, b| match b.rank.cmp(&a.rank) {
        Ordering::Equal => b.suit.cmp(&a.suit),
        o => o,
    });
}

/// Canonicality helpers used by both native & gadget logic
#[inline]
pub fn is_wheel_ranks(r: &[Rank; 5]) -> bool {
    r[0] == 5 && r[1] == 4 && r[2] == 3 && r[3] == 2 && r[4] == 14
}
#[inline]
pub fn is_run_desc_ranks(r: &[Rank; 5]) -> bool {
    r[0] == r[1] + 1 && r[1] == r[2] + 1 && r[2] == r[3] + 1 && r[3] == r[4] + 1
}

pub mod gadget;
pub mod hand_reveal_showdown_gadget;
pub mod native;

#[cfg(test)]
mod e2e;

pub use native::{
    choose_best5_from7, classify_five_and_canonicalize, pack_score_field, pack_score_u32,
    tiebreak_vector, verify_and_score_five, verify_and_score_from_indices,
};

pub use gadget::{
    // re-export gadget API
    verify_and_score_from_indices as verify_and_score_from_indices_gadget,
};
