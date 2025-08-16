//! Grand-product permutation checks for RS shuffle

use crate::shuffling::data_structures::ElGamalCiphertextVar;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

const LOG_TARGET: &str = "nexus_nova::shuffling::rs_shuffle::permutation";

/// Trait for types that can be compressed into a field element for permutation products
/// The generic parameter N represents the number of challenges needed
pub trait PermutationProduct<F: PrimeField, const N: usize> {
    /// Compress the element using random challenges
    fn product(&self, challenges: &[FpVar<F>; N]) -> FpVar<F>;
}

/// Represents a pair of (index, position) for multiset equality checks
#[derive(Clone)]
pub struct IndexPositionPair<F: PrimeField> {
    pub idx: FpVar<F>,
    pub pos: FpVar<F>,
}

impl<F: PrimeField> IndexPositionPair<F> {
    pub fn new(idx: FpVar<F>, pos: FpVar<F>) -> Self {
        Self { idx, pos }
    }

    /// Compress the pair using challenges α and β
    pub fn compress(&self, alpha: &FpVar<F>, beta: &FpVar<F>) -> FpVar<F> {
        alpha * &self.idx + beta * &self.pos
    }
}

impl<F: PrimeField> PermutationProduct<F, 2> for IndexPositionPair<F> {
    fn product(&self, challenges: &[FpVar<F>; 2]) -> FpVar<F> {
        self.compress(&challenges[0], &challenges[1])
    }
}

/// Generic function to check multiset equality using grand product with any type implementing PermutationProduct
pub fn check_grand_product<F, T, const N: usize>(
    _cs: ConstraintSystemRef<F>,
    left: &[T],
    right: &[T],
    challenges: &[FpVar<F>; N],
) -> Result<(), SynthesisError>
where
    F: PrimeField,
    T: PermutationProduct<F, N>,
{
    // TODO: OPTIMIZATION for products can be done in a tree fashion
    //
    // Compute left product
    let mut prod_left = FpVar::<F>::one();
    for item in left {
        let compressed = item.product(challenges);
        prod_left *= &compressed;
    }

    // Compute right product
    let mut prod_right = FpVar::<F>::one();
    for item in right {
        let compressed = item.product(challenges);
        prod_right *= &compressed;
    }

    // Enforce equality using FpVar's enforce_equal
    // Debug trace the products before equality check
    tracing::debug!(
        target: LOG_TARGET,
        "Left product: {:?}, Right product: {:?}",
        prod_left.value(),
        prod_right.value()
    );
    prod_left.enforce_equal(&prod_right)?;

    Ok(())
}

/// Represents an index with ElGamal ciphertext for permutation check
/// This is used for the RS shuffle where we track (idx, ciphertext) pairs
pub struct IndexedElGamalCiphertext<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    pub idx: FpVar<G::BaseField>,
    pub ciphertext: ElGamalCiphertextVar<G>,
}

impl<G: SWCurveConfig> IndexedElGamalCiphertext<G>
where
    G::BaseField: PrimeField,
{
    pub fn new(idx: FpVar<G::BaseField>, ciphertext: ElGamalCiphertextVar<G>) -> Self {
        Self { idx, ciphertext }
    }
}

impl<G: SWCurveConfig> PermutationProduct<G::BaseField, 7> for IndexedElGamalCiphertext<G>
where
    G::BaseField: PrimeField,
{
    fn product(&self, challenges: &[FpVar<G::BaseField>; 7]) -> FpVar<G::BaseField> {
        // Compress: α₀*idx + α₁*c1.x + α₂*c1.y + α₃*c1.z + α₄*c2.x + α₅*c2.y + α₆*c2.z
        &challenges[0] * &self.idx
            + &challenges[1] * &self.ciphertext.c1.x
            + &challenges[2] * &self.ciphertext.c1.y
            + &challenges[3] * &self.ciphertext.c1.z
            + &challenges[4] * &self.ciphertext.c2.x
            + &challenges[5] * &self.ciphertext.c2.y
            + &challenges[6] * &self.ciphertext.c2.z
    }
}

/// Legacy triple for compatibility - maps (idx, ct_x, ct_y) to field elements
/// Used when we only have x,y coordinates instead of full ElGamal ciphertexts
#[derive(Clone)]
pub struct CiphertextTriple<F: PrimeField> {
    pub idx: FpVar<F>,
    pub ct_x: FpVar<F>,
    pub ct_y: FpVar<F>,
}

impl<F: PrimeField> CiphertextTriple<F> {
    pub fn new(idx: FpVar<F>, ct_x: FpVar<F>, ct_y: FpVar<F>) -> Self {
        Self { idx, ct_x, ct_y }
    }

    /// Compress the triple using challenges α, β, and γ
    pub fn compress(&self, alpha: &FpVar<F>, beta: &FpVar<F>, gamma: &FpVar<F>) -> FpVar<F> {
        alpha * &self.idx + beta * &self.ct_x + gamma * &self.ct_y
    }
}

impl<F: PrimeField> PermutationProduct<F, 3> for CiphertextTriple<F> {
    fn product(&self, challenges: &[FpVar<F>; 3]) -> FpVar<F> {
        self.compress(&challenges[0], &challenges[1], &challenges[2])
    }
}
