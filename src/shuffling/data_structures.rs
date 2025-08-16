use super::error::ShuffleError;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*, R1CSVar};
use ark_relations::r1cs;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DECK_SIZE: usize = 52;

/// Convert a scalar field element to a base field element representation
/// This is used when allocating scalar field values in constraint systems over the base field
pub fn scalar_to_base_field<ScalarField, BaseField>(scalar: &ScalarField) -> BaseField
where
    ScalarField: PrimeField,
    BaseField: PrimeField,
{
    // Convert through bytes to handle different BigInt types
    let mut bytes = Vec::new();
    scalar.serialize_uncompressed(&mut bytes).unwrap();
    BaseField::deserialize_uncompressed(&mut &bytes[..]).unwrap_or(BaseField::zero())
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamalCiphertext<C: CurveGroup> {
    pub c1: C,
    pub c2: C,
}

impl<C: CurveGroup> ElGamalCiphertext<C>
where
    C::BaseField: Field,
{
    pub fn new(c1: C, c2: C) -> Self {
        Self { c1, c2 }
    }

    /// Encrypt a message (curve point) using ElGamal encryption
    /// Returns ElGamalCiphertext(r*G, M + r*PK) where:
    /// - r is the randomness
    /// - G is the generator
    /// - M is the message (curve point)
    /// - PK is the public key
    pub fn encrypt(message: C, randomness: C::ScalarField, public_key: C) -> Self {
        // Start with (0, M) and add encryption layer
        let identity = C::zero();
        let initial_ciphertext = Self::new(identity, message);
        initial_ciphertext.add_encryption_layer(randomness, public_key)
    }

    /// Encrypt a scalar message by first converting it to a curve point (scalar * G)
    pub fn encrypt_scalar(
        message: C::ScalarField,
        randomness: C::ScalarField,
        public_key: C,
    ) -> Self {
        let generator = C::generator();
        let message_point = generator * message;
        Self::encrypt(message_point, randomness, public_key)
    }

    pub fn add_encryption_layer(&self, randomness: C::ScalarField, public_key: C) -> Self {
        let generator = C::generator();

        Self {
            c1: self.c1 + generator * randomness,
            c2: self.c2 + public_key * randomness,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ElGamalKeys<C: CurveGroup> {
    pub private_key: C::ScalarField,
    pub public_key: C,
}

impl<C: CurveGroup> ElGamalKeys<C> {
    pub fn new(private_key: C::ScalarField) -> Self {
        let generator = C::generator();
        let public_key = generator * private_key;
        Self { private_key, public_key }
    }
}

#[derive(Clone, Debug)]
pub struct ShuffleProof<C: CurveGroup> {
    pub input_deck: Vec<ElGamalCiphertext<C>>,
    /// Sorted list of (encrypted card, random value) pairs, sorted by random value in ascending order
    pub sorted_deck: Vec<(ElGamalCiphertext<C>, C::BaseField)>, // Not: That the sorted deck has not been reencrypted yet
    pub rerandomization_values: Vec<C::ScalarField>,
}

impl<C: CurveGroup> ShuffleProof<C> {
    pub fn new(
        input_deck: Vec<ElGamalCiphertext<C>>,
        sorted_deck: Vec<(ElGamalCiphertext<C>, C::BaseField)>,
        rerandomization_values: Vec<C::ScalarField>,
    ) -> Result<Self, ShuffleError> {
        if input_deck.len() != DECK_SIZE
            || sorted_deck.len() != DECK_SIZE
            || rerandomization_values.len() != DECK_SIZE
        {
            return Err(ShuffleError::InvalidDeckSize(input_deck.len()));
        }
        Ok(Self {
            input_deck,
            sorted_deck,
            rerandomization_values,
        })
    }
}

/// Optimized batch allocation for ElGamal ciphertexts
pub fn batch_allocate_ciphertexts<G: SWCurveConfig>(
    cs: impl Into<r1cs::Namespace<G::BaseField>>,
    ciphertexts: &[ElGamalCiphertext<Projective<G>>],
    mode: AllocationMode,
) -> Result<Vec<ElGamalCiphertextVar<G>>, SynthesisError>
where
    G::BaseField: PrimeField,
{
    let ns = cs.into();
    let cs = ns.cs();

    // Allocate all points without individual namespaces
    // DO NOT convert to affine - it's extremely expensive!
    let mut result = Vec::with_capacity(ciphertexts.len());

    for ct in ciphertexts {
        // Allocate projective points directly
        let c1 =
            ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(cs.clone(), || Ok(ct.c1), mode)?;

        let c2 =
            ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(cs.clone(), || Ok(ct.c2), mode)?;

        result.push(ElGamalCiphertextVar { c1, c2 });
    }

    Ok(result)
}

// Circuit representation of ElGamal ciphertext
pub struct ElGamalCiphertextVar<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    pub c1: ProjectiveVar<G, FpVar<G::BaseField>>,
    pub c2: ProjectiveVar<G, FpVar<G::BaseField>>,
}

impl<G: SWCurveConfig> Clone for ElGamalCiphertextVar<G>
where
    G::BaseField: PrimeField,
{
    fn clone(&self) -> Self {
        Self { c1: self.c1.clone(), c2: self.c2.clone() }
    }
}

impl<G: SWCurveConfig> ElGamalCiphertextVar<G>
where
    G::BaseField: PrimeField,
{
    /// Creates a new ElGamal ciphertext variable from two curve variables
    pub fn new(
        c1: ProjectiveVar<G, FpVar<G::BaseField>>,
        c2: ProjectiveVar<G, FpVar<G::BaseField>>,
    ) -> Self {
        Self { c1, c2 }
    }
}

impl<G: SWCurveConfig> R1CSVar<G::BaseField> for ElGamalCiphertextVar<G>
where
    G::BaseField: PrimeField,
{
    type Value = ElGamalCiphertext<Projective<G>>;

    fn cs(&self) -> r1cs::ConstraintSystemRef<G::BaseField> {
        self.c1.cs().or(self.c2.cs())
    }

    fn value(&self) -> Result<Self::Value, r1cs::SynthesisError> {
        Ok(ElGamalCiphertext {
            c1: self.c1.value()?,
            c2: self.c2.value()?,
        })
    }
}

impl<G: SWCurveConfig> AllocVar<ElGamalCiphertext<Projective<G>>, G::BaseField>
    for ElGamalCiphertextVar<G>
where
    G::BaseField: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<ElGamalCiphertext<Projective<G>>>>(
        cs: impl Into<r1cs::Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let _span =
            tracing::debug_span!(target: "shuffle::alloc", "alloc_elgamal_ciphertext").entered();

        let cs = cs.into().cs();
        let value = f()?;
        let ciphertext = value.borrow();

        // Allocate as ProjectiveVar directly
        tracing::trace!(target: "shuffle::alloc", "Allocating c1 ProjectiveVar");
        let c1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            cs.clone(),
            || Ok(ciphertext.c1),
            mode,
        )?;

        tracing::trace!(target: "shuffle::alloc", "Allocating c2 ProjectiveVar");
        let c2 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            cs.clone(),
            || Ok(ciphertext.c2),
            mode,
        )?;

        Ok(Self { c1, c2 })
    }
}

// Circuit representation of shuffled deck proof
pub struct ShuffleProofVar<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    pub input_deck: Vec<ElGamalCiphertextVar<G>>,
    /// Sorted list of (encrypted card, random value) pairs, sorted by random value in ascending order
    pub sorted_deck: Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>,
    pub encryption_randomization_values: Vec<FpVar<G::BaseField>>,
}

impl<G: SWCurveConfig> AllocVar<ShuffleProof<Projective<G>>, G::BaseField> for ShuffleProofVar<G>
where
    G::BaseField: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<ShuffleProof<Projective<G>>>>(
        cs: impl Into<r1cs::Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let value = f()?;
        let proof = value.borrow();

        tracing::debug!(target: "shuffle::alloc", "Starting optimized allocation");

        // Batch allocate input deck
        let input_deck = batch_allocate_ciphertexts(cs.clone(), &proof.input_deck, mode)?;

        tracing::debug!(target: "shuffle::alloc", "sorted deck allocation");
        // Allocate sorted deck with minimal overhead
        // DO NOT convert to affine - extremely expensive!
        let mut sorted_deck = Vec::with_capacity(proof.sorted_deck.len());
        for (ct, random_val) in &proof.sorted_deck {
            let c1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
                cs.clone(),
                || Ok(ct.c1),
                mode,
            )?;

            let c2 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
                cs.clone(),
                || Ok(ct.c2),
                mode,
            )?;

            let random_var =
                FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*random_val), mode)?;

            sorted_deck.push((ElGamalCiphertextVar { c1, c2 }, random_var));
        }

        tracing::debug!(target: "shuffle::alloc", "randomization values allocation");
        // Batch allocate rerandomization values
        // Note: Converting from ScalarField to BaseField representation
        let rerandomization_values: Result<Vec<_>, _> = proof
            .rerandomization_values
            .iter()
            .map(|val| {
                let base_field_val = scalar_to_base_field::<G::ScalarField, G::BaseField>(val);
                FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(base_field_val), mode)
            })
            .collect();

        tracing::debug!(target: "shuffle::alloc", "done allocation");
        Ok(Self {
            input_deck,
            sorted_deck,
            encryption_randomization_values: rerandomization_values?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetrics {
    pub setup_time: Option<Duration>,
    pub constraint_generation_time: Duration,
    pub witness_synthesis_time: Duration,
    pub commitment_time: Duration,
    pub polynomial_construction_time: Duration,
    pub proof_generation_time: Duration,
    pub total_time: Duration,
    pub constraint_count: usize,
    pub witness_count: usize,
    pub proof_size_bytes: usize,
}

impl Default for ProofMetrics {
    fn default() -> Self {
        Self {
            setup_time: None,
            constraint_generation_time: Duration::default(),
            witness_synthesis_time: Duration::default(),
            commitment_time: Duration::default(),
            polynomial_construction_time: Duration::default(),
            proof_generation_time: Duration::default(),
            total_time: Duration::default(),
            constraint_count: 0,
            witness_count: 0,
            proof_size_bytes: 0,
        }
    }
}
