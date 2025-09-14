use anyhow::Result;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::Rng;

use crate::shuffler::Shuffler;
use crate::shuffling::make_global_public_keys;

#[derive(Clone, Debug)]
pub struct ShufflerCluster<C: CurveGroup> {
    pub shufflers: Vec<Shuffler<C>>,
    pub aggregated_public_key: C,
}

impl<C> ShufflerCluster<C>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    /// Build from provided secrets and public keys
    pub fn from_secrets(secrets: Vec<C::ScalarField>, public_keys: Vec<C>) -> Result<Self> {
        assert_eq!(secrets.len(), public_keys.len());
        let aggregated_public_key = make_global_public_keys(public_keys.clone());

        let shufflers = secrets
            .into_iter()
            .zip(public_keys.into_iter())
            .enumerate()
            .map(|(i, (sk, pk))| Shuffler::new(i, sk, pk, aggregated_public_key))
            .collect();

        Ok(Self {
            shufflers,
            aggregated_public_key,
        })
    }

    /// Randomly generate N shufflers with (sk, pk), compute aggregated pk
    pub fn generate<R: Rng>(n: usize, rng: &mut R) -> Result<Self>
    where
        C::ScalarField: UniformRand,
    {
        let mut secrets = Vec::with_capacity(n);
        let mut public_keys = Vec::with_capacity(n);
        let generator = C::generator();

        for _ in 0..n {
            let sk = C::ScalarField::rand(rng);
            let pk = generator * sk;
            secrets.push(sk);
            public_keys.push(pk);
        }

        Self::from_secrets(secrets, public_keys)
    }
}
