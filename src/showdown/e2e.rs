use ark_r1cs_std::{alloc::AllocVar, GR1CSVar};
use rand::{seq::SliceRandom, thread_rng};

use crate::showdown::{
    choose_best5_from7, gadget, idx_of, pack_score_u32, verify_and_score_from_indices, Index,
};

#[test]
fn e2e_three_players_random_showdown() {
    // Build a shuffled deck of 1..52
    let mut deck: Vec<Index> = (1..=52u8).collect();
    deck.shuffle(&mut thread_rng());

    // Deal: 5 community + 3 players * 2 hole
    let board: [Index; 5] = deck[0..5].try_into().unwrap();
    let p1: [Index; 2] = deck[5..7].try_into().unwrap();
    let p2: [Index; 2] = deck[7..9].try_into().unwrap();
    let p3: [Index; 2] = deck[9..11].try_into().unwrap();

    // For each player, compute best 5 from their 7 (board + hole) using iterator + from_fn
    let bests: Vec<_> = [p1, p2, p3]
        .into_iter()
        .map(|hole| {
            let seven = std::array::from_fn(|i| if i < 5 { board[i] } else { hole[i - 5] });
            let best = choose_best5_from7(seven);
            (
                best.hand.cards,
                best.hand.category,
                best.tiebreak,
                best.score_u32,
            )
        })
        .collect();

    // Determine winner by score
    let max_score = bests.iter().map(|b| b.3).max().unwrap();
    let winners: Vec<usize> = bests
        .iter()
        .enumerate()
        .filter(|(_i, b)| b.3 == max_score)
        .map(|(i, _b)| i)
        .collect();

    // Also verify gadget scoring equals native scoring for the best hands
    use ark_bn254::Fr;
    use ark_r1cs_std::uint8::UInt8;
    use ark_relations::gr1cs::ConstraintSystem;

    for (k5, cat, cvec, s_nat) in bests.iter() {
        // convert best K5 (Card) back to indices (deterministic inverse)
        let idx5: [Index; 5] = k5.map(|c| idx_of(c.rank, c.suit));
        let cs = ConstraintSystem::<Fr>::new_ref();
        let catv = UInt8::new_witness(cs.clone(), || Ok(*cat as u8)).unwrap();
        let catv = gadget::HandCategoryVar::from_uint8(catv);
        let idxv = idx5.map(|i| UInt8::new_witness(cs.clone(), || Ok(i)).unwrap());
        let (score_var, _c_var) = gadget::verify_and_score_from_indices::<Fr>(catv, idxv).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // compare against native (field)
        let (_su32, _cnat, sfield) = verify_and_score_from_indices(*cat, idx5);
        assert_eq!(score_var.value().unwrap(), sfield);

        // Quick sanity: the u32 order and field order agree
        // (we just check equality of values is enough here)
        assert_eq!(*s_nat, pack_score_u32(*cat, *cvec));
    }

    // At least one winner
    assert!(!winners.is_empty());
    // Print (optional) — can be replaced by asserts about plausible ranges
    // eprintln!("Board: {:?}; winners: {:?}", board, winners);
}
