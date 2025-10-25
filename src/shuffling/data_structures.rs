use super::error::ShuffleError;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::Namespace;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::signing::DomainSeparated;

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

#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct ElGamalCiphertext<C: CurveGroup> {
    #[serde(with = "crate::crypto_serde::curve")]
    pub c1: C,
    #[serde(with = "crate::crypto_serde::curve")]
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
        Self {
            private_key,
            public_key,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize, C::BaseField: CanonicalSerialize, C::ScalarField: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize, C::BaseField: CanonicalDeserialize, C::ScalarField: CanonicalDeserialize"
))]
pub struct ShuffleProof<C: CurveGroup> {
    pub input_deck: Vec<ElGamalCiphertext<C>>,
    /// Sorted list of (encrypted card, random value) pairs, sorted by random value in ascending order
    #[serde(with = "crate::crypto_serde::shuffle_sorted_deck")]
    pub sorted_deck: Vec<(ElGamalCiphertext<C>, C::BaseField)>, // Not: That the sorted deck has not been reencrypted yet
    #[serde(with = "crate::crypto_serde::field_vec")]
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



impl<C> DomainSeparated for ElGamalCiphertext<C>
where
    C: CurveGroup,
{
    fn domain_string() -> &'static str {
        "shuffling/elgamal_ciphertext_v1"
    }
}

impl<C> DomainSeparated for ShuffleProof<C>
where
    C: CurveGroup,
{
    fn domain_string() -> &'static str {
        "shuffling/shuffle_proof_v1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::serde::{assert_round_trip_eq, assert_round_trip_json};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_grumpkin::Projective as GrumpkinProjective;

    type Curve = GrumpkinProjective;
    type Scalar = <Curve as PrimeGroup>::ScalarField;
    type Base = <Curve as CurveGroup>::BaseField;

    fn sample_ciphertext() -> ElGamalCiphertext<Curve> {
        let generator = Curve::generator();
        let scalar = Scalar::from(5u64);
        ElGamalCiphertext::new(generator * scalar, generator * scalar)
    }

    #[test]
    fn ciphertext_signing_bytes_are_deterministic() {
        let cipher_a = sample_ciphertext();
        let cipher_b = cipher_a.clone();

        let bytes_a = crate::signing::signing_bytes(&cipher_a).unwrap();
        let bytes_b = crate::signing::signing_bytes(&cipher_b).unwrap();
        assert_eq!(bytes_a, bytes_b);

        let generator = Curve::generator();
        let different = ElGamalCiphertext::new(
            generator * Scalar::from(7u64),
            generator * Scalar::from(11u64),
        );

        let bytes_different = crate::signing::signing_bytes(&different).unwrap();
        assert_ne!(bytes_a, bytes_different);
    }

    fn sample_shuffle_proof() -> ShuffleProof<Curve> {
        let deck = vec![sample_ciphertext(); DECK_SIZE];
        let sorted_deck = vec![(sample_ciphertext(), Base::from(0u64)); DECK_SIZE];
        let rerandomization_values = vec![Scalar::from(0u64); DECK_SIZE];
        ShuffleProof::new(deck, sorted_deck, rerandomization_values).expect("valid shuffle proof")
    }

    #[test]
    fn shuffle_proof_signing_bytes_are_deterministic() {
        let proof_a = sample_shuffle_proof();
        let proof_b = proof_a.clone();

        let bytes_a = crate::signing::signing_bytes(&proof_a).unwrap();
        let bytes_b = crate::signing::signing_bytes(&proof_b).unwrap();
        assert_eq!(bytes_a, bytes_b);

        let mut different = proof_a.clone();
        different.rerandomization_values[0] = Scalar::from(1u64);

        let bytes_different = crate::signing::signing_bytes(&different).unwrap();
        assert_ne!(bytes_a, bytes_different);
    }

    #[test]
    fn ciphertext_round_trips_with_serde() {
        assert_round_trip_eq(&sample_ciphertext());
    }

    #[test]
    fn shuffle_proof_round_trips_with_serde() {
        let proof = sample_shuffle_proof();
        assert_round_trip_json(&proof);
    }
}

/// Optimized batch allocation for ElGamal ciphertexts
pub fn batch_allocate_ciphertexts<C, CV>(
    cs: impl Into<Namespace<C::BaseField>>,
    ciphertexts: &[ElGamalCiphertext<C>],
    mode: AllocationMode,
) -> Result<Vec<ElGamalCiphertextVar<C, CV>>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    let ns = cs.into();
    let cs = ns.cs();

    // Allocate all points without individual namespaces
    // DO NOT convert to affine - it's extremely expensive!
    let mut result = Vec::with_capacity(ciphertexts.len());

    for ct in ciphertexts {
        // Allocate curve points directly
        let c1 = CV::new_variable(cs.clone(), || Ok(ct.c1), mode)?;

        let c2 = CV::new_variable(cs.clone(), || Ok(ct.c2), mode)?;

        result.push(ElGamalCiphertextVar::new(c1, c2));
    }

    Ok(result)
}

// Circuit representation of ElGamal ciphertext
#[derive(Debug)]
pub struct ElGamalCiphertextVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    pub c1: CV,
    pub c2: CV,
    _curve: std::marker::PhantomData<C>,
}

impl<C, CV> Clone for ElGamalCiphertextVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            c1: self.c1.clone(),
            c2: self.c2.clone(),
            _curve: std::marker::PhantomData,
        }
    }
}

impl<C, CV> ElGamalCiphertextVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    /// Creates a new ElGamal ciphertext variable from two curve variables
    pub fn new(c1: CV, c2: CV) -> Self {
        Self {
            c1,
            c2,
            _curve: std::marker::PhantomData,
        }
    }
}

impl<C, CV> GR1CSVar<C::BaseField> for ElGamalCiphertextVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    type Value = ElGamalCiphertext<C>;

    fn cs(&self) -> ConstraintSystemRef<C::BaseField> {
        self.c1.cs().or(self.c2.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(ElGamalCiphertext {
            c1: self.c1.value()?,
            c2: self.c2.value()?,
        })
    }
}

impl<C, CV> AllocVar<ElGamalCiphertext<C>, C::BaseField> for ElGamalCiphertextVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: std::borrow::Borrow<ElGamalCiphertext<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let _span =
            tracing::debug_span!(target: "legit_poker::shuffling::alloc", "alloc_elgamal_ciphertext").entered();

        let cs = cs.into().cs();
        let value = f()?;
        let ciphertext = value.borrow();

        // Allocate as CurveVar directly
        tracing::trace!(target: "legit_poker::shuffling::alloc", "Allocating c1 CurveVar");
        let c1 = CV::new_variable(cs.clone(), || Ok(ciphertext.c1), mode)?;

        tracing::trace!(target: "legit_poker::shuffling::alloc", "Allocating c2 CurveVar");
        let c2 = CV::new_variable(cs.clone(), || Ok(ciphertext.c2), mode)?;

        Ok(Self {
            c1,
            c2,
            _curve: std::marker::PhantomData,
        })
    }
}

// Circuit representation of shuffled deck proof
pub struct ShuffleProofVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    pub input_deck: Vec<ElGamalCiphertextVar<C, CV>>,
    /// Sorted list of (encrypted card, random value) pairs, sorted by random value in ascending order
    pub sorted_deck: Vec<(ElGamalCiphertextVar<C, CV>, FpVar<C::BaseField>)>,
    pub encryption_randomization_values: Vec<FpVar<C::BaseField>>,
}

impl<C, CV> AllocVar<ShuffleProof<C>, C::BaseField> for ShuffleProofVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: std::borrow::Borrow<ShuffleProof<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let value = f()?;
        let proof = value.borrow();

        tracing::debug!(target: "legit_poker::shuffling::alloc", "Starting optimized allocation");

        // Batch allocate input deck
        let input_deck = batch_allocate_ciphertexts::<C, CV>(cs.clone(), &proof.input_deck, mode)?;

        tracing::debug!(target: "legit_poker::shuffling::alloc", "sorted deck allocation");
        // Allocate sorted deck with minimal overhead
        // DO NOT convert to affine - extremely expensive!
        let mut sorted_deck = Vec::with_capacity(proof.sorted_deck.len());
        for (ct, random_val) in &proof.sorted_deck {
            let c1 = CV::new_variable(cs.clone(), || Ok(ct.c1), mode)?;

            let c2 = CV::new_variable(cs.clone(), || Ok(ct.c2), mode)?;

            let random_var =
                FpVar::<C::BaseField>::new_variable(cs.clone(), || Ok(*random_val), mode)?;

            sorted_deck.push((ElGamalCiphertextVar::new(c1, c2), random_var));
        }

        tracing::debug!(target: "legit_poker::shuffling::alloc", "randomization values allocation");
        // Batch allocate rerandomization values
        // Note: Converting from ScalarField to BaseField representation
        let rerandomization_values: Result<Vec<_>, _> = proof
            .rerandomization_values
            .iter()
            .map(|val| {
                let base_field_val = scalar_to_base_field::<C::ScalarField, C::BaseField>(val);
                FpVar::<C::BaseField>::new_variable(cs.clone(), || Ok(base_field_val), mode)
            })
            .collect();

        tracing::debug!(target: "legit_poker::shuffling::alloc", "done allocation");
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
