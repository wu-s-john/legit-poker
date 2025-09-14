use crate::showdown::*;
use ark_bn254::Fr;
use ark_ff::PrimeField;

/// Best 5-card hand (canonical 5 + category), without score data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Best5Hand {
    pub cards: [Card; 5],
    pub category: HandCategory,
}

/// Best 5-card hand with associated tie-break vector and packed score.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Best5HandWithScore {
    pub hand: Best5Hand,
    pub tiebreak: [u8; 5],
    pub score_u32: u32,
}

impl Best5HandWithScore {
    #[inline]
    pub fn score_field<F: PrimeField>(&self) -> F {
        pack_score_field::<F>(self.hand.category, self.tiebreak)
    }
}

/// Pack (cat, c1..c5) into a u32 (base-16 digits; ≤ 16^6).
#[inline]
pub fn pack_score_u32(cat: HandCategory, c: [u8; 5]) -> u32 {
    (cat.as_u8() as u32) * M5
        + (c[0] as u32) * M4
        + (c[1] as u32) * M3
        + (c[2] as u32) * M2
        + (c[3] as u32) * M1
        + (c[4] as u32) * M0
}

/// Same packed score as a field element (Fr for convenience).
#[inline]
pub fn pack_score_field<F: PrimeField>(cat: HandCategory, c: [u8; 5]) -> F {
    let mut acc = F::from(cat.as_u8() as u64) * F::from(M5 as u64);
    acc += F::from(c[0] as u64) * F::from(M4 as u64);
    acc += F::from(c[1] as u64) * F::from(M3 as u64);
    acc += F::from(c[2] as u64) * F::from(M2 as u64);
    acc += F::from(c[3] as u64) * F::from(M1 as u64);
    acc += F::from(c[4] as u64) * F::from(M0 as u64);
    acc
}

/// Category-specific tie-break vector from a canonical 5-card hand.
pub fn tiebreak_vector(cat: HandCategory, h: &[Card; 5]) -> [u8; 5] {
    let r = [h[0].rank, h[1].rank, h[2].rank, h[3].rank, h[4].rank];
    match cat {
        HandCategory::StraightFlush | HandCategory::Straight => {
            let high = if is_wheel_ranks(&r) { 5 } else { r[0] };
            [high, 0, 0, 0, 0]
        }
        HandCategory::FourOfAKind => [r[0], r[4], 0, 0, 0],
        HandCategory::FullHouse => [r[0], r[3], 0, 0, 0],
        HandCategory::Flush => [r[0], r[1], r[2], r[3], r[4]],
        HandCategory::ThreeOfAKind => [r[0], r[3], r[4], 0, 0],
        HandCategory::TwoPair => [r[0], r[2], r[4], 0, 0],
        HandCategory::OnePair => [r[0], r[2], r[3], r[4], 0],
        HandCategory::HighCard => [r[0], r[1], r[2], r[3], r[4]],
    }
}

/// Assert the 5 cards `h` match `claimed` category **and** canonical layout.
/// Panics on failure (use in tests and native verification). Returns () if ok.
pub fn assert_category_exact(claimed: HandCategory, h: &[Card; 5]) {
    for c in h.iter() {
        assert!((2..=14).contains(&c.rank));
        assert!(c.suit.as_u8() <= 3);
    }
    let same_suit = h.iter().all(|c| c.suit == h[0].suit);
    let r = [h[0].rank, h[1].rank, h[2].rank, h[3].rank, h[4].rank];
    let is_run = is_run_desc_ranks(&r) || is_wheel_ranks(&r);

    match claimed {
        HandCategory::StraightFlush => {
            assert!(same_suit);
            assert!(is_run);
        }
        HandCategory::FourOfAKind => {
            assert!(r[0] == r[1] && r[1] == r[2] && r[2] == r[3]);
            assert!(r[4] != r[0]);
        }
        HandCategory::FullHouse => {
            assert!(r[0] == r[1] && r[1] == r[2]);
            assert!(r[3] == r[4] && r[2] != r[3]);
        }
        HandCategory::Flush => {
            assert!(same_suit);
            assert!(r[0] > r[1] && r[1] > r[2] && r[2] > r[3] && r[3] > r[4]);
            assert!(!is_run);
        }
        HandCategory::Straight => {
            assert!(is_run);
            assert!(!same_suit);
        }
        HandCategory::ThreeOfAKind => {
            assert!(r[0] == r[1] && r[1] == r[2]);
            assert!(r[3] != r[0] && r[4] != r[0]);
            assert!(r[3] > r[4] && r[3] != r[4]);
        }
        HandCategory::TwoPair => {
            assert!(r[0] == r[1] && r[2] == r[3] && r[0] > r[2]);
            assert!(r[4] != r[0] && r[4] != r[2]);
        }
        HandCategory::OnePair => {
            assert!(r[0] == r[1]);
            assert!(r[2] > r[3] && r[3] > r[4]);
            assert!(r[2] != r[0] && r[3] != r[0] && r[4] != r[0]);
            assert!(r[2] != r[3] && r[3] != r[4] && r[2] != r[4]);
        }
        HandCategory::HighCard => {
            assert!(r[0] > r[1] && r[1] > r[2] && r[2] > r[3] && r[3] > r[4]);
            assert!(!is_run && !same_suit);
        }
    }
}

/// Native: (claimed, 5 indices) -> validates + returns packed score (u32 and Fr).
pub fn verify_and_score_from_indices(
    claimed: HandCategory,
    idx5: [Index; 5],
) -> (u32, [u8; 5], Fr) {
    let mut h = [Card {
        rank: 0,
        suit: Suit::Clubs,
    }; 5];
    for i in 0..5 {
        h[i] = decode_card(idx5[i]);
    }
    // validate exact category + canonical layout for the 5 cards
    assert_category_exact(claimed, &h);
    let c = tiebreak_vector(claimed, &h);
    let s_u32 = pack_score_u32(claimed, c);
    let s_fr = pack_score_field::<Fr>(claimed, c);
    (s_u32, c, s_fr)
}

/// Classify any 5 cards and return (category, canonical 5)
pub fn classify_five_and_canonicalize(h5: [Card; 5]) -> (HandCategory, [Card; 5]) {
    let mut s = h5;
    sort_desc(&mut s);

    // Hist counts by rank
    let mut cnt = [0u8; 15]; // 0..14
    for c in s.iter() {
        cnt[c.rank as usize] += 1;
    }

    // helpers
    let same_suit = s.iter().all(|c| c.suit == s[0].suit);

    // Distinct ranks in desc order (input already sorted)
    let mut uniq: Vec<Rank> = s.iter().map(|c| c.rank).collect();
    uniq.dedup();

    // Straight detection (only if 5 distinct ranks)
    let (has_straight, straight_ranks): (bool, [Rank; 5]) = if uniq.len() == 5 {
        let r = [uniq[0], uniq[1], uniq[2], uniq[3], uniq[4]];
        if is_run_desc_ranks(&r) {
            (true, r)
        } else {
            let mut set = r;
            set.sort_unstable(); // asc
            if set == [2, 3, 4, 5, 14] {
                (true, [5, 4, 3, 2, 14])
            } else {
                (false, [0; 5])
            }
        }
    } else {
        (false, [0; 5])
    };

    // Straight Flush
    if has_straight && same_suit {
        // build canonical by straight_ranks in that suit
        let suit = s[0].suit;
        let k: [Card; 5] = std::array::from_fn(|i| {
            *s.iter()
                .find(|c| c.rank == straight_ranks[i] && c.suit == suit)
                .unwrap()
        });
        return (HandCategory::StraightFlush, k);
    }
    // Four of a kind
    if let Some((x_rank, _)) = (2..=14)
        .rev()
        .map(|r| (r, cnt[r as usize]))
        .find(|&(_r, c)| c == 4)
    {
        let quads: Vec<Card> = s.iter().filter(|c| c.rank == x_rank).cloned().collect();
        let kicker = s.iter().cloned().find(|c| c.rank != x_rank).unwrap();
        return (
            HandCategory::FourOfAKind,
            [quads[0], quads[1], quads[2], quads[3], kicker],
        );
    }
    // Full House
    let trips_ranks: Vec<Rank> = (2..=14).rev().filter(|&r| cnt[r as usize] >= 3).collect();
    if !trips_ranks.is_empty() {
        let t = trips_ranks[0];
        let pair_cands: Vec<Rank> = (2..=14)
            .rev()
            .filter(|&r| r != t && cnt[r as usize] >= 2)
            .collect();
        if !pair_cands.is_empty() {
            let p = pair_cands[0];
            let trips: Vec<Card> = s.iter().filter(|c| c.rank == t).take(3).cloned().collect();
            let pair: Vec<Card> = s.iter().filter(|c| c.rank == p).take(2).cloned().collect();
            return (
                HandCategory::FullHouse,
                [trips[0], trips[1], trips[2], pair[0], pair[1]],
            );
        }
    }
    // Flush (not straight flush)
    if same_suit {
        return (HandCategory::Flush, s);
    }
    // Straight (not flush)
    if has_straight {
        // choose any suit per rank, deterministically prefer higher suit id
        let k: [Card; 5] = std::array::from_fn(|i| {
            s.iter()
                .filter(|c| c.rank == straight_ranks[i])
                .max_by_key(|c| c.suit)
                .cloned()
                .unwrap()
        });
        return (HandCategory::Straight, k);
    }
    // Trips
    if let Some((t, _)) = (2..=14)
        .rev()
        .map(|r| (r, cnt[r as usize]))
        .find(|&(_r, c)| c >= 3)
    {
        let trips: Vec<Card> = s.iter().filter(|c| c.rank == t).take(3).cloned().collect();
        let mut kickers: Vec<Card> = s.iter().filter(|c| c.rank != t).cloned().collect();
        sort_desc(&mut kickers);
        let k1 = kickers[0];
        let k2 = kickers[1];
        return (
            HandCategory::ThreeOfAKind,
            [trips[0], trips[1], trips[2], k1, k2],
        );
    }
    // Two Pair
    let pairs: Vec<Rank> = (2..=14).rev().filter(|&r| cnt[r as usize] >= 2).collect();
    if pairs.len() >= 2 {
        let higher_pair_rank = pairs[0];
        let lower_pair_rank = pairs[1];
        let higher_pair: Vec<Card> = s
            .iter()
            .filter(|c| c.rank == higher_pair_rank)
            .take(2)
            .cloned()
            .collect();
        let lower_pair: Vec<Card> = s
            .iter()
            .filter(|c| c.rank == lower_pair_rank)
            .take(2)
            .cloned()
            .collect();
        let kicker = s
            .iter()
            .cloned()
            .find(|c| c.rank != higher_pair_rank && c.rank != lower_pair_rank)
            .unwrap();
        return (
            HandCategory::TwoPair,
            [
                higher_pair[0],
                higher_pair[1],
                lower_pair[0],
                lower_pair[1],
                kicker,
            ],
        );
    }
    // One Pair
    if let Some((p, _)) = (2..=14)
        .rev()
        .map(|r| (r, cnt[r as usize]))
        .find(|&(_r, c)| c >= 2)
    {
        let pair: Vec<Card> = s.iter().filter(|c| c.rank == p).take(2).cloned().collect();
        let mut kickers: Vec<Card> = s.iter().filter(|c| c.rank != p).cloned().collect();
        sort_desc(&mut kickers);
        return (
            HandCategory::OnePair,
            [pair[0], pair[1], kickers[0], kickers[1], kickers[2]],
        );
    }
    // High Card
    (HandCategory::HighCard, s)
}

/// Enumerate all 21 subsets from 7 indices and pick the maximum by packed score.
/// Returns (canonical best 5, category, tie-break digits, u32 score).
pub fn choose_best5_from7(idx7: [Index; 7]) -> Best5HandWithScore {
    let c7: [Card; 7] = idx7.map(decode_card);
    let mut best_score = 0u32;
    let mut have = false;
    let mut best = [Card {
        rank: 0,
        suit: Suit::Clubs,
    }; 5];
    let mut best_cat = HandCategory::HighCard;
    let mut best_c = [0u8; 5];

    for a in 0..=2 {
        for b in (a + 1)..=3 {
            for c in (b + 1)..=4 {
                for d in (c + 1)..=5 {
                    for e in (d + 1)..=6 {
                        let hand5 = [c7[a], c7[b], c7[c], c7[d], c7[e]];
                        let (cat, k5) = classify_five_and_canonicalize(hand5);
                        let cvec = tiebreak_vector(cat, &k5);
                        let score = pack_score_u32(cat, cvec);
                        if !have || score > best_score {
                            have = true;
                            best_score = score;
                            best = k5;
                            best_cat = cat;
                            best_c = cvec;
                        }
                    }
                }
            }
        }
    }
    Best5HandWithScore {
        hand: Best5Hand {
            cards: best,
            category: best_cat,
        },
        tiebreak: best_c,
        score_u32: best_score,
    }
}

/// Native scorer for a canonical 5-card hand (already validated)
pub fn verify_and_score_five(cat: HandCategory, k5: &[Card; 5]) -> (u32, [u8; 5], Fr) {
    // assuming canonical/validated by caller
    let c = tiebreak_vector(cat, k5);
    (pack_score_u32(cat, c), c, pack_score_field::<Fr>(cat, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::showdown::Suit;

    // Helper: get score (field) from gadget-free native verify function
    fn s(cat: HandCategory, idx5: [Index; 5]) -> Fr {
        let (_u, _c, fr) = verify_and_score_from_indices(cat, idx5);
        fr
    }

    #[test]
    fn ordering_intra_category() {
        // SF: Royal > 9-high > Wheel
        let sf_royal = [
            idx_of(14, Suit::Spades),
            idx_of(13, Suit::Spades),
            idx_of(12, Suit::Spades),
            idx_of(11, Suit::Spades),
            idx_of(10, Suit::Spades),
        ];
        let sf_9 = [
            idx_of(9, Suit::Hearts),
            idx_of(8, Suit::Hearts),
            idx_of(7, Suit::Hearts),
            idx_of(6, Suit::Hearts),
            idx_of(5, Suit::Hearts),
        ];
        let sf_wheel = [
            idx_of(5, Suit::Diamonds),
            idx_of(4, Suit::Diamonds),
            idx_of(3, Suit::Diamonds),
            idx_of(2, Suit::Diamonds),
            idx_of(14, Suit::Diamonds),
        ];
        assert!(s(HandCategory::StraightFlush, sf_royal) > s(HandCategory::StraightFlush, sf_9));
        assert!(s(HandCategory::StraightFlush, sf_9) > s(HandCategory::StraightFlush, sf_wheel));

        // 4K: Aces+K > Aces+2 > Queens+Ace
        let fk_ak = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(14, Suit::Hearts),
            idx_of(14, Suit::Spades),
            idx_of(13, Suit::Clubs),
        ];
        let fk_a2 = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(14, Suit::Hearts),
            idx_of(14, Suit::Spades),
            idx_of(2, Suit::Clubs),
        ];
        let fk_qa = [
            idx_of(12, Suit::Clubs),
            idx_of(12, Suit::Diamonds),
            idx_of(12, Suit::Hearts),
            idx_of(12, Suit::Spades),
            idx_of(14, Suit::Clubs),
        ];
        assert!(s(HandCategory::FourOfAKind, fk_ak) > s(HandCategory::FourOfAKind, fk_a2));
        assert!(s(HandCategory::FourOfAKind, fk_a2) > s(HandCategory::FourOfAKind, fk_qa));

        // FH: AAA-KK > KKK-AA > QQQ-99
        let fh1 = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(14, Suit::Hearts),
            idx_of(13, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
        ];
        let fh2 = [
            idx_of(13, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
            idx_of(13, Suit::Hearts),
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
        ];
        let fh3 = [
            idx_of(12, Suit::Clubs),
            idx_of(12, Suit::Diamonds),
            idx_of(12, Suit::Hearts),
            idx_of(9, Suit::Clubs),
            idx_of(9, Suit::Diamonds),
        ];
        assert!(s(HandCategory::FullHouse, fh1) > s(HandCategory::FullHouse, fh2));
        assert!(s(HandCategory::FullHouse, fh2) > s(HandCategory::FullHouse, fh3));

        // Flush lex order
        let fl_aq972 = [
            idx_of(14, Suit::Spades),
            idx_of(12, Suit::Spades),
            idx_of(9, Suit::Spades),
            idx_of(7, Suit::Spades),
            idx_of(2, Suit::Spades),
        ];
        let fl_aq965 = [
            idx_of(14, Suit::Hearts),
            idx_of(12, Suit::Hearts),
            idx_of(9, Suit::Hearts),
            idx_of(6, Suit::Hearts),
            idx_of(5, Suit::Hearts),
        ];
        let fl_k9843 = [
            idx_of(13, Suit::Diamonds),
            idx_of(9, Suit::Diamonds),
            idx_of(8, Suit::Diamonds),
            idx_of(4, Suit::Diamonds),
            idx_of(3, Suit::Diamonds),
        ];
        assert!(s(HandCategory::Flush, fl_aq972) > s(HandCategory::Flush, fl_aq965));
        assert!(s(HandCategory::Flush, fl_aq965) > s(HandCategory::Flush, fl_k9843));

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
        assert!(s(HandCategory::Straight, st_a) > s(HandCategory::Straight, st_9));
        assert!(s(HandCategory::Straight, st_9) > s(HandCategory::Straight, st_w));

        // Trips
        let tr_q_ak = [
            idx_of(12, Suit::Spades),
            idx_of(12, Suit::Hearts),
            idx_of(12, Suit::Diamonds),
            idx_of(14, Suit::Clubs),
            idx_of(13, Suit::Clubs),
        ];
        let tr_9_a2 = [
            idx_of(9, Suit::Spades),
            idx_of(9, Suit::Hearts),
            idx_of(9, Suit::Diamonds),
            idx_of(14, Suit::Clubs),
            idx_of(2, Suit::Clubs),
        ];
        assert!(s(HandCategory::ThreeOfAKind, tr_q_ak) > s(HandCategory::ThreeOfAKind, tr_9_a2));

        // Two Pair
        let tp1 = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(13, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
            idx_of(12, Suit::Clubs),
        ];
        let tp2 = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(13, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
            idx_of(2, Suit::Clubs),
        ];
        let tp3 = [
            idx_of(12, Suit::Clubs),
            idx_of(12, Suit::Diamonds),
            idx_of(10, Suit::Clubs),
            idx_of(10, Suit::Diamonds),
            idx_of(14, Suit::Clubs),
        ];
        assert!(s(HandCategory::TwoPair, tp1) > s(HandCategory::TwoPair, tp2));
        assert!(s(HandCategory::TwoPair, tp2) > s(HandCategory::TwoPair, tp3));

        // One Pair
        let op1 = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(13, Suit::Clubs),
            idx_of(12, Suit::Clubs),
            idx_of(11, Suit::Clubs),
        ];
        let op2 = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(13, Suit::Clubs),
            idx_of(12, Suit::Clubs),
            idx_of(10, Suit::Clubs),
        ];
        let op3 = [
            idx_of(13, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
            idx_of(14, Suit::Clubs),
            idx_of(12, Suit::Clubs),
            idx_of(11, Suit::Clubs),
        ];
        assert!(s(HandCategory::OnePair, op1) > s(HandCategory::OnePair, op2));
        assert!(s(HandCategory::OnePair, op2) > s(HandCategory::OnePair, op3));

        // High card
        let hc1 = [
            idx_of(14, Suit::Clubs),
            idx_of(12, Suit::Diamonds),
            idx_of(9, Suit::Spades),
            idx_of(7, Suit::Hearts),
            idx_of(3, Suit::Clubs),
        ];
        let hc2 = [
            idx_of(14, Suit::Clubs),
            idx_of(12, Suit::Diamonds),
            idx_of(9, Suit::Spades),
            idx_of(7, Suit::Hearts),
            idx_of(2, Suit::Clubs),
        ];
        assert!(s(HandCategory::HighCard, hc1) > s(HandCategory::HighCard, hc2));
    }

    #[test]
    fn tie_equality() {
        // Flush same ranks, different suits => same score
        let fl_s = [
            idx_of(14, Suit::Spades),
            idx_of(12, Suit::Spades),
            idx_of(9, Suit::Spades),
            idx_of(7, Suit::Spades),
            idx_of(2, Suit::Spades),
        ];
        let fl_h = [
            idx_of(14, Suit::Hearts),
            idx_of(12, Suit::Hearts),
            idx_of(9, Suit::Hearts),
            idx_of(7, Suit::Hearts),
            idx_of(2, Suit::Hearts),
        ];
        assert!(s(HandCategory::Flush, fl_s) == s(HandCategory::Flush, fl_h));

        // Straight equal highs different suits
        let st1 = [
            idx_of(9, Suit::Clubs),
            idx_of(8, Suit::Diamonds),
            idx_of(7, Suit::Hearts),
            idx_of(6, Suit::Spades),
            idx_of(5, Suit::Clubs),
        ];
        let st2 = [
            idx_of(9, Suit::Diamonds),
            idx_of(8, Suit::Hearts),
            idx_of(7, Suit::Spades),
            idx_of(6, Suit::Clubs),
            idx_of(5, Suit::Diamonds),
        ];
        assert!(s(HandCategory::Straight, st1) == s(HandCategory::Straight, st2));
    }

    #[test]
    fn cross_category_precedence() {
        let sf = [
            idx_of(14, Suit::Spades),
            idx_of(13, Suit::Spades),
            idx_of(12, Suit::Spades),
            idx_of(11, Suit::Spades),
            idx_of(10, Suit::Spades),
        ];
        let fk = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(14, Suit::Hearts),
            idx_of(14, Suit::Spades),
            idx_of(13, Suit::Clubs),
        ];
        let fh = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(14, Suit::Hearts),
            idx_of(13, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
        ];
        let fl = [
            idx_of(14, Suit::Spades),
            idx_of(12, Suit::Spades),
            idx_of(9, Suit::Spades),
            idx_of(7, Suit::Spades),
            idx_of(2, Suit::Spades),
        ];
        let st = [
            idx_of(14, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
            idx_of(12, Suit::Hearts),
            idx_of(11, Suit::Spades),
            idx_of(10, Suit::Clubs),
        ];
        let tr = [
            idx_of(12, Suit::Spades),
            idx_of(12, Suit::Hearts),
            idx_of(12, Suit::Diamonds),
            idx_of(14, Suit::Clubs),
            idx_of(13, Suit::Clubs),
        ];
        let tp = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(13, Suit::Clubs),
            idx_of(13, Suit::Diamonds),
            idx_of(12, Suit::Clubs),
        ];
        let op = [
            idx_of(14, Suit::Clubs),
            idx_of(14, Suit::Diamonds),
            idx_of(13, Suit::Clubs),
            idx_of(12, Suit::Clubs),
            idx_of(11, Suit::Clubs),
        ];
        let hc = [
            idx_of(14, Suit::Clubs),
            idx_of(12, Suit::Diamonds),
            idx_of(9, Suit::Spades),
            idx_of(7, Suit::Hearts),
            idx_of(3, Suit::Clubs),
        ];
        let ssf = s(HandCategory::StraightFlush, sf);
        let sfk = s(HandCategory::FourOfAKind, fk);
        let sfh = s(HandCategory::FullHouse, fh);
        let sfl = s(HandCategory::Flush, fl);
        let sst = s(HandCategory::Straight, st);
        let str = s(HandCategory::ThreeOfAKind, tr);
        let stp = s(HandCategory::TwoPair, tp);
        let sop = s(HandCategory::OnePair, op);
        let shc = s(HandCategory::HighCard, hc);
        assert!(
            ssf > sfk
                && sfk > sfh
                && sfh > sfl
                && sfl > sst
                && sst > str
                && str > stp
                && stp > sop
                && sop > shc
        );
    }
}
