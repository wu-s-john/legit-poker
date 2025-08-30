//! R1CS gadget: verify 5-card hand (indices 1..52) matches a claimed category
//! in canonical layout and pack score into a field element using constant multipliers.

use ark_ff::PrimeField;
use ark_r1cs_std::uint16::UInt16;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use core::borrow::Borrow;
use core::ops::Not;

use crate::showdown::{HandCategory, M0, M1, M2, M3, M4, M5};

/// Circuit representation of HandCategory enum
#[derive(Clone)]
pub struct HandCategoryVar<F: PrimeField> {
    value: UInt8<F>,
}

impl<F: PrimeField> HandCategoryVar<F> {
    /// HandCategory constants
    pub const HIGH_CARD: u8 = 0;
    pub const ONE_PAIR: u8 = 1;
    pub const TWO_PAIR: u8 = 2;
    pub const THREE_OF_A_KIND: u8 = 3;
    pub const STRAIGHT: u8 = 4;
    pub const FLUSH: u8 = 5;
    pub const FULL_HOUSE: u8 = 6;
    pub const FOUR_OF_A_KIND: u8 = 7;
    pub const STRAIGHT_FLUSH: u8 = 8;

    /// Create a constant HandCategoryVar from a HandCategory enum
    pub fn constant(cat: HandCategory) -> Self {
        Self {
            value: UInt8::constant(cat as u8),
        }
    }

    /// Create a HandCategoryVar from an existing UInt8
    pub fn from_uint8(value: UInt8<F>) -> Self {
        Self { value }
    }

    /// Get the underlying UInt8 value
    pub fn value(&self) -> &UInt8<F> {
        &self.value
    }

    /// Check if this category equals a specific HandCategory
    pub fn is_equal(&self, cat: HandCategory) -> Result<Boolean<F>, SynthesisError> {
        self.value.is_eq(&UInt8::constant(cat as u8))
    }

    /// Check if this is a straight or straight flush
    pub fn is_straight_type(&self) -> Result<Boolean<F>, SynthesisError> {
        let is_straight = self.is_equal(HandCategory::Straight)?;
        let is_straight_flush = self.is_equal(HandCategory::StraightFlush)?;
        Ok(&is_straight | &is_straight_flush)
    }
}

impl<F: PrimeField> AllocVar<HandCategory, F> for HandCategoryVar<F> {
    fn new_variable<T: Borrow<HandCategory>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let cat_value = f()?.borrow().clone();
        let value = UInt8::new_variable(cs, || Ok(cat_value as u8), mode)?;
        Ok(Self { value })
    }
}

/// Boolean assert helper
fn assert_true<F: PrimeField>(b: &Boolean<F>) -> Result<(), SynthesisError> {
    b.enforce_equal(&Boolean::TRUE)
}

/// Convert UInt8 to FpVar for field arithmetic
fn uint8_to_fpvar<F: PrimeField>(x: &UInt8<F>) -> Result<FpVar<F>, SynthesisError> {
    let bits = x.to_bits_le()?;
    let mut val = FpVar::<F>::zero();
    let mut pow = FpVar::<F>::one();
    for bit in bits.iter() {
        val += &pow * FpVar::<F>::from(bit.clone());
        pow = pow.double()?;
    }
    Ok(val)
}

/// Pack (cat, c1..c5) into field via base-16 multipliers.
fn pack_score_field_var<F: PrimeField>(
    cat: &HandCategoryVar<F>,
    c: &[UInt8<F>; 5],
) -> Result<FpVar<F>, SynthesisError> {
    let mut acc = uint8_to_fpvar(cat.value())? * FpVar::<F>::constant(F::from(M5 as u64));
    let mul = |x: &UInt8<F>, m: u32| -> Result<FpVar<F>, SynthesisError> {
        Ok(uint8_to_fpvar(x)? * FpVar::<F>::constant(F::from(m as u64)))
    };
    acc += mul(&c[0], M4)?;
    acc += mul(&c[1], M3)?;
    acc += mul(&c[2], M2)?;
    acc += mul(&c[3], M1)?;
    acc += mul(&c[4], M0)?;
    Ok(acc)
}

/// Convert UInt8 to UInt16 via zero-extend.
fn u8_to_u16<F: PrimeField>(x: &UInt8<F>) -> Result<UInt16<F>, SynthesisError> {
    let mut bits = x.to_bits_le()?;
    bits.resize(16, Boolean::FALSE);
    Ok(UInt16::from_bits_le(&bits))
}

/// Compute (q << k) as UInt16 by shifting bits (k ≤ 8).
fn shift_left_u8_to_u16<F: PrimeField>(
    x: &UInt8<F>,
    k: usize,
) -> Result<UInt16<F>, SynthesisError> {
    let mut bits = vec![Boolean::FALSE; k];
    bits.extend(x.to_bits_le()?);
    bits.resize(16, Boolean::FALSE);
    Ok(UInt16::from_bits_le(&bits))
}

/// Compute UInt8 + UInt8 -> UInt8 with overflow checking
fn uint8_add<F: PrimeField>(a: &UInt8<F>, b: &UInt8<F>) -> Result<UInt8<F>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut result_bits = Vec::new();
    let mut carry = Boolean::FALSE;

    for (a_bit, b_bit) in a_bits.iter().zip(b_bits.iter()) {
        // sum = a XOR b XOR carry
        let sum = a_bit ^ b_bit ^ &carry;
        // new_carry = (a AND b) OR (carry AND (a XOR b))
        let a_and_b = a_bit & b_bit;
        let a_xor_b = a_bit ^ b_bit;
        let carry_and_xor = &carry & &a_xor_b;
        carry = &a_and_b | &carry_and_xor;
        result_bits.push(sum);
    }

    Ok(UInt8::from_bits_le(&result_bits))
}

/// UInt16 addition
fn uint16_add<F: PrimeField>(a: &UInt16<F>, b: &UInt16<F>) -> Result<UInt16<F>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut result_bits = Vec::new();
    let mut carry = Boolean::FALSE;

    for (a_bit, b_bit) in a_bits.iter().zip(b_bits.iter()) {
        let sum = a_bit ^ b_bit ^ &carry;
        let a_and_b = a_bit & b_bit;
        let a_xor_b = a_bit ^ b_bit;
        let carry_and_xor = &carry & &a_xor_b;
        carry = &a_and_b | &carry_and_xor;
        result_bits.push(sum);
    }

    Ok(UInt16::from_bits_le(&result_bits))
}

/// Compute UInt8 - UInt8 -> UInt8
fn uint8_sub<F: PrimeField>(a: &UInt8<F>, b: &UInt8<F>) -> Result<UInt8<F>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut result_bits = Vec::new();
    let mut borrow = Boolean::FALSE;

    for (a_bit, b_bit) in a_bits.iter().zip(b_bits.iter()) {
        // diff = a XOR b XOR borrow
        let diff = a_bit ^ b_bit ^ &borrow;
        // new_borrow = (!a AND b) OR (borrow AND !(a XOR b))
        let not_a = a_bit.not();
        let not_a_and_b = &not_a & b_bit;
        let a_xor_b = a_bit ^ b_bit;
        let not_xor = a_xor_b.not();
        let borrow_and_not_xor = &borrow & &not_xor;
        borrow = &not_a_and_b | &borrow_and_not_xor;
        result_bits.push(diff);
    }

    Ok(UInt8::from_bits_le(&result_bits))
}

/// Compare UInt8 values (emulating is_cmp for greater/less)
fn uint8_is_less_than<F: PrimeField>(
    a: &UInt8<F>,
    b: &UInt8<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut less = Boolean::FALSE;
    let mut equal = Boolean::TRUE;

    // Compare from MSB to LSB
    for (a_bit, b_bit) in a_bits.iter().rev().zip(b_bits.iter().rev()) {
        // less = (equal AND !a AND b) OR less
        let not_a = a_bit.not();
        let not_a_and_b = &not_a & b_bit;
        let equal_and_condition = &equal & &not_a_and_b;
        less = &less | &equal_and_condition;

        // equal = equal AND (a == b)
        let bits_equal = (a_bit ^ b_bit).not();
        equal = &equal & &bits_equal;
    }

    Ok(less)
}

fn uint8_is_less_or_equal<F: PrimeField>(
    a: &UInt8<F>,
    b: &UInt8<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let less = uint8_is_less_than(a, b)?;
    let equal = a.is_eq(b)?;
    Ok(&less | &equal)
}

fn uint8_is_greater_or_equal<F: PrimeField>(
    a: &UInt8<F>,
    b: &UInt8<F>,
) -> Result<Boolean<F>, SynthesisError> {
    uint8_is_less_or_equal(b, a)
}

fn uint8_is_greater_than<F: PrimeField>(
    a: &UInt8<F>,
    b: &UInt8<F>,
) -> Result<Boolean<F>, SynthesisError> {
    uint8_is_less_than(b, a)
}

/// Decode index (1..52) -> (rank 2..14, suit 0..3) using divmod by 13 with constraints:
/// j = idx-1 = 13*q + r,  q in [0..3], r in [0..12]
fn decode_card_var<F: PrimeField>(idx: &UInt8<F>) -> Result<(UInt8<F>, UInt8<F>), SynthesisError> {
    // Range: 1..52
    let is_ge_1 = uint8_is_greater_or_equal(idx, &UInt8::constant(1))?;
    let is_le_52 = uint8_is_less_or_equal(idx, &UInt8::constant(52))?;
    assert_true(&is_ge_1)?;
    assert_true(&is_le_52)?;

    // j = idx - 1
    let j = uint8_sub(idx, &UInt8::constant(1))?;

    // Witness q, r (unique solution given j)
    let q_val = idx.value().map(|v| (v - 1) / 13).unwrap_or(0);
    let r_val = idx.value().map(|v| (v - 1) % 13).unwrap_or(0);
    let q = UInt8::new_witness(idx.cs(), || Ok(q_val))?;
    let r = UInt8::new_witness(idx.cs(), || Ok(r_val))?;

    // Bounds
    assert_true(&uint8_is_less_or_equal(&q, &UInt8::constant(3))?)?;
    assert_true(&uint8_is_less_or_equal(&r, &UInt8::constant(12))?)?;

    // Enforce j == 13*q + r using bit-shifts into UInt16:
    // 13 = 8 + 4 + 1
    let j16 = u8_to_u16(&j)?;
    let q8 = shift_left_u8_to_u16(&q, 3)?; // q << 3
    let q4 = shift_left_u8_to_u16(&q, 2)?; // q << 2
    let q1 = u8_to_u16(&q)?; // q
    let sum = uint16_add(&q8, &q4)?;
    let sum = uint16_add(&sum, &q1)?;
    let sum = uint16_add(&sum, &u8_to_u16(&r)?)?;
    sum.enforce_equal(&j16)?;

    // rank = r + 2; suit = q
    let rank = uint8_add(&r, &UInt8::constant(2))?;
    Ok((rank, q))
}

/// Category-specific tie-break vector c[5] from canonical ranks r0..r4
fn tiebreak_vector_var<F: PrimeField>(
    cat: &HandCategoryVar<F>,
    ranks: &[UInt8<F>; 5],
    is_wheel: &Boolean<F>,
) -> Result<[UInt8<F>; 5], SynthesisError> {
    let zero = UInt8::constant(0);
    let r0 = ranks[0].clone();
    let _r1 = ranks[1].clone();
    let r2 = ranks[2].clone();
    let r3 = ranks[3].clone();
    let r4 = ranks[4].clone();

    let cat_val = cat.value().value().unwrap_or(0);

    // Build output based on category
    let out = if cat_val == HandCategory::Straight as u8
        || cat_val == HandCategory::StraightFlush as u8
    {
        let high = UInt8::conditionally_select(is_wheel, &UInt8::constant(5), &r0)?;
        [high, zero.clone(), zero.clone(), zero.clone(), zero.clone()]
    } else if cat_val == HandCategory::FourOfAKind as u8 {
        [r0, r4, zero.clone(), zero.clone(), zero.clone()]
    } else if cat_val == HandCategory::FullHouse as u8 {
        [r0, r3, zero.clone(), zero.clone(), zero.clone()]
    } else if cat_val == HandCategory::Flush as u8 {
        [
            ranks[0].clone(),
            ranks[1].clone(),
            ranks[2].clone(),
            ranks[3].clone(),
            ranks[4].clone(),
        ]
    } else if cat_val == HandCategory::ThreeOfAKind as u8 {
        [r0, r3, r4, zero.clone(), zero.clone()]
    } else if cat_val == HandCategory::TwoPair as u8 {
        [r0, r2, r4, zero.clone(), zero.clone()]
    } else if cat_val == HandCategory::OnePair as u8 {
        [r0, r2, r3, r4, zero.clone()]
    } else {
        // High card
        [
            ranks[0].clone(),
            ranks[1].clone(),
            ranks[2].clone(),
            ranks[3].clone(),
            ranks[4].clone(),
        ]
    };
    Ok(out)
}

/// Gadget: given claimed category & 5 indices (1..52), verify category/canonical
/// and output packed score (FpVar) + tie-break digits (UInt8^5).
#[allow(clippy::too_many_arguments)]
pub fn verify_and_score_from_indices<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    claimed_cat: HandCategoryVar<F>,
    idx5: [UInt8<F>; 5],
) -> Result<(FpVar<F>, [UInt8<F>; 5]), SynthesisError> {
    // Decode all 5 indexes -> (rank,suit)
    let mut ranks: Vec<UInt8<F>> = Vec::with_capacity(5);
    let mut suits: Vec<UInt8<F>> = Vec::with_capacity(5);
    for i in 0..5 {
        let (r, s) = decode_card_var::<F>(&idx5[i])?;
        ranks.push(r);
        suits.push(s);
    }
    let ranks: [UInt8<F>; 5] = ranks.try_into().unwrap();
    let suits: [UInt8<F>; 5] = suits.try_into().unwrap();

    // same-suit?
    let mut same_suit = Boolean::TRUE;
    for i in 1..5 {
        let eq = suits[i].is_eq(&suits[0])?;
        same_suit = &same_suit & &eq;
    }

    // Convenience closures
    let eq = |a: &UInt8<F>, b: &UInt8<F>| a.is_eq(b);
    let gt = |a: &UInt8<F>, b: &UInt8<F>| uint8_is_greater_than(a, b);

    // Straight detection on ranks vector:
    let r = ranks.clone();
    let is_run = {
        let c1 = eq(&r[0], &uint8_add(&r[1], &UInt8::constant(1))?)?;
        let c2 = eq(&r[1], &uint8_add(&r[2], &UInt8::constant(1))?)?;
        let c3 = eq(&r[2], &uint8_add(&r[3], &UInt8::constant(1))?)?;
        let c4 = eq(&r[3], &uint8_add(&r[4], &UInt8::constant(1))?)?;
        let and1 = &c1 & &c2;
        let and2 = &c3 & &c4;
        &and1 & &and2
    };
    let is_wheel = {
        let a = eq(&r[0], &UInt8::constant(5))?;
        let b = eq(&r[1], &UInt8::constant(4))?;
        let c = eq(&r[2], &UInt8::constant(3))?;
        let d = eq(&r[3], &UInt8::constant(2))?;
        let e = eq(&r[4], &UInt8::constant(14))?;
        let and1 = &a & &b;
        let and2 = &c & &d;
        let and3 = &and1 & &and2;
        &and3 & &e
    };
    let is_straight = &is_run | &is_wheel;

    // Category exactness per canonical layout (as in native)
    let catv = claimed_cat.value().value().unwrap_or(0);
    match catv {
        x if x == HandCategory::StraightFlush as u8 => {
            assert_true(&same_suit)?;
            assert_true(&is_straight)?;
        }
        x if x == HandCategory::FourOfAKind as u8 => {
            assert_true(&eq(&r[0], &r[1])?)?;
            assert_true(&eq(&r[1], &r[2])?)?;
            assert_true(&eq(&r[2], &r[3])?)?;
            // r4 != r0
            assert_true(&eq(&r[4], &r[0])?.not())?;
        }
        x if x == HandCategory::FullHouse as u8 => {
            assert_true(&eq(&r[0], &r[1])?)?;
            assert_true(&eq(&r[1], &r[2])?)?;
            assert_true(&eq(&r[3], &r[4])?)?;
            assert_true(&eq(&r[2], &r[3])?.not())?;
        }
        x if x == HandCategory::Flush as u8 => {
            assert_true(&same_suit)?;
            // strictly descending
            assert_true(&gt(&r[0], &r[1])?)?;
            assert_true(&gt(&r[1], &r[2])?)?;
            assert_true(&gt(&r[2], &r[3])?)?;
            assert_true(&gt(&r[3], &r[4])?)?;
            // not straight
            assert_true(&is_straight.not())?;
        }
        x if x == HandCategory::Straight as u8 => {
            assert_true(&is_straight)?;
            assert_true(&same_suit.not())?;
        }
        x if x == HandCategory::ThreeOfAKind as u8 => {
            assert_true(&eq(&r[0], &r[1])?)?;
            assert_true(&eq(&r[1], &r[2])?)?;
            assert_true(&eq(&r[3], &r[0])?.not())?;
            assert_true(&eq(&r[4], &r[0])?.not())?;
            assert_true(&gt(&r[3], &r[4])?)?;
            assert_true(&eq(&r[3], &r[4])?.not())?;
        }
        x if x == HandCategory::TwoPair as u8 => {
            assert_true(&eq(&r[0], &r[1])?)?;
            assert_true(&eq(&r[2], &r[3])?)?;
            // r0 > r2
            assert_true(&gt(&r[0], &r[2])?)?;
            assert_true(&eq(&r[4], &r[0])?.not())?;
            assert_true(&eq(&r[4], &r[2])?.not())?;
        }
        x if x == HandCategory::OnePair as u8 => {
            assert_true(&eq(&r[0], &r[1])?)?;
            assert_true(&gt(&r[2], &r[3])?)?;
            assert_true(&gt(&r[3], &r[4])?)?;
            // kickers != pair
            assert_true(&eq(&r[2], &r[0])?.not())?;
            assert_true(&eq(&r[3], &r[0])?.not())?;
            assert_true(&eq(&r[4], &r[0])?.not())?;
            // all distinct kickers
            assert_true(&eq(&r[2], &r[3])?.not())?;
            assert_true(&eq(&r[3], &r[4])?.not())?;
            assert_true(&eq(&r[2], &r[4])?.not())?;
        }
        _ => {
            // High card
            assert_true(&gt(&r[0], &r[1])?)?;
            assert_true(&gt(&r[1], &r[2])?)?;
            assert_true(&gt(&r[2], &r[3])?)?;
            assert_true(&gt(&r[3], &r[4])?)?;
            assert_true(&is_straight.not())?;
            assert_true(&same_suit.not())?;
        }
    }

    // Build tie-break vector and pack
    let c = tiebreak_vector_var::<F>(&claimed_cat, &ranks, &is_wheel)?;
    let score = pack_score_field_var::<F>(&claimed_cat, &c)?;

    Ok((score, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::showdown::{idx_of, HandCategory, Suit};
    use ark_bn254::Fr;
    use ark_relations::gr1cs::ConstraintSystem;

    #[test]
    fn gadget_basic_scores_and_constraints() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Flush AQ972 (hearts)
        let cat = HandCategoryVar::new_witness(cs.clone(), || Ok(HandCategory::Flush)).unwrap();
        let idx5 = [
            UInt8::new_witness(cs.clone(), || Ok(idx_of(14, Suit::Hearts))).unwrap(),
            UInt8::new_witness(cs.clone(), || Ok(idx_of(12, Suit::Hearts))).unwrap(),
            UInt8::new_witness(cs.clone(), || Ok(idx_of(9, Suit::Hearts))).unwrap(),
            UInt8::new_witness(cs.clone(), || Ok(idx_of(7, Suit::Hearts))).unwrap(),
            UInt8::new_witness(cs.clone(), || Ok(idx_of(2, Suit::Hearts))).unwrap(),
        ];
        let (score, c) = verify_and_score_from_indices::<Fr>(cs.clone(), cat, idx5).unwrap();
        assert!(cs.is_satisfied().unwrap());
        // recompute natively and compare values
        use crate::showdown::native::verify_and_score_from_indices as native_vs;
        let (_u, c_native, s_native) = native_vs(
            HandCategory::Flush,
            [
                idx_of(14, Suit::Hearts),
                idx_of(12, Suit::Hearts),
                idx_of(9, Suit::Hearts),
                idx_of(7, Suit::Hearts),
                idx_of(2, Suit::Hearts),
            ],
        );
        assert_eq!(
            c.iter().map(|x| x.value().unwrap()).collect::<Vec<_>>(),
            c_native.iter().map(|&u| u).collect::<Vec<_>>()
        );
        assert_eq!(score.value().unwrap(), s_native);
    }

    #[test]
    fn gadget_ordering_intra_category() {
        let make_five_combo_hand = |cat: HandCategory, idx: [u8; 5]| -> Fr {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let catv = HandCategoryVar::new_witness(cs.clone(), || Ok(cat)).unwrap();
            let idxv = idx.map(|i| UInt8::new_witness(cs.clone(), || Ok(i)).unwrap());
            let (s, _) = verify_and_score_from_indices::<Fr>(cs.clone(), catv, idxv).unwrap();
            assert!(cs.is_satisfied().unwrap());
            s.value().unwrap()
        };
        // Straight: A-high > 9-high > wheel
        let st_a = [
            idx_of(14, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
            idx_of(12, Suit::Hearts),
            idx_of(11, Suit::Spades),
            idx_of(10, Suit::Clubs),
        ];
        let st_9 = [
            idx_of(9, Suit::Clubs),
            idx_of(8, Suit::Diamonds),
            idx_of(7, Suit::Hearts),
            idx_of(6, Suit::Spades),
            idx_of(5, Suit::Clubs),
        ];
        let st_w = [
            idx_of(5, Suit::Clubs),
            idx_of(4, Suit::Diamonds),
            idx_of(3, Suit::Hearts),
            idx_of(2, Suit::Spades),
            idx_of(14, Suit::Clubs),
        ];
        assert!(
            make_five_combo_hand(HandCategory::Straight, st_a)
                > make_five_combo_hand(HandCategory::Straight, st_9)
        );
        assert!(
            make_five_combo_hand(HandCategory::Straight, st_9)
                > make_five_combo_hand(HandCategory::Straight, st_w)
        );
    }
}
