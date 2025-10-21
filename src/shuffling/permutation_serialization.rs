use anyhow::{anyhow, Result};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_groth16::Proof as Groth16Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::shuffling::bayer_groth_permutation::reencryption_protocol::ReencryptionProof;
use crate::shuffling::data_structures::ElGamalCiphertext;
use crate::shuffling::pedersen_commitment::opening_proof::PedersenCommitmentOpeningProof;
use crate::shuffling::permutation_proof::proof_system::PublicData;
use crate::shuffling::shuffling_proof::ShufflingProof;

type ConstraintField<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// JSON-serializable representation of a Groth16 proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGroth16Proof {
    pub a: String,
    pub b: String,
    pub c: String,
}

/// JSON-serializable representation of a Pedersen opening proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPedersenOpeningProof {
    pub rounds: Vec<StoredPedersenRound>,
    pub a_final: String,
    pub r_final: String,
}

/// Commitment pair captured in a Pedersen opening round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPedersenRound {
    pub left: String,
    pub right: String,
}

/// JSON-serializable representation of the reencryption Σ-proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredReencryptionProof {
    pub blinding_factor_commitment: String,
    pub blinding_rerandomization_commitment: String,
    pub sigma_response_power_permutation_vector: Vec<String>,
    pub sigma_response_blinding: String,
    pub sigma_response_rerand: String,
}

/// Serialized shuffling proof artifacts for persistence or transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredShufflingProof {
    pub perm_snark_proof: StoredGroth16Proof,
    pub perm_snark_public_inputs: Vec<String>,
    pub power_opening_proof: StoredPedersenOpeningProof,
    pub reencryption_proof: StoredReencryptionProof,
}

/// Serialized public data exposed alongside permutation proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPublicData {
    pub nonce: String,
    pub pk_public: String,
    pub indices_init: Vec<String>,
    pub power_challenge_public: String,
    pub c_perm: String,
    pub c_power: String,
    pub power_opening_proof: StoredPedersenOpeningProof,
}

impl StoredGroth16Proof {
    pub fn from_proof<E>(proof: &Groth16Proof<E>) -> Result<Self>
    where
        E: Pairing,
        E::G1Affine: CanonicalSerialize,
        E::G2Affine: CanonicalSerialize,
    {
        Ok(Self {
            a: encode_hex(&proof.a)?,
            b: encode_hex(&proof.b)?,
            c: encode_hex(&proof.c)?,
        })
    }

    pub fn into_proof<E>(self) -> Result<Groth16Proof<E>>
    where
        E: Pairing,
        E::G1Affine: CanonicalDeserialize,
        E::G2Affine: CanonicalDeserialize,
    {
        let a = decode_hex::<E::G1Affine>(&self.a)?;
        let b = decode_hex::<E::G2Affine>(&self.b)?;
        let c = decode_hex::<E::G1Affine>(&self.c)?;
        Ok(Groth16Proof { a, b, c })
    }
}

impl StoredPedersenOpeningProof {
    pub fn from_proof<C>(proof: &PedersenCommitmentOpeningProof<C>) -> Result<Self>
    where
        C: CurveGroup,
        C::ScalarField: CanonicalSerialize,
        C: CanonicalSerialize,
    {
        let rounds = proof
            .folding_challenge_commitment_rounds
            .iter()
            .map(|(left, right)| {
                Ok(StoredPedersenRound {
                    left: encode_hex(left)?,
                    right: encode_hex(right)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            rounds,
            a_final: encode_hex(&proof.a_final)?,
            r_final: encode_hex(&proof.r_final)?,
        })
    }

    pub fn into_proof<C>(self) -> Result<PedersenCommitmentOpeningProof<C>>
    where
        C: CurveGroup,
        C::ScalarField: CanonicalDeserialize,
        C: CanonicalDeserialize,
    {
        let rounds = self
            .rounds
            .into_iter()
            .map(|round| {
                let left = decode_hex::<C>(&round.left)?;
                let right = decode_hex::<C>(&round.right)?;
                Ok((left, right))
            })
            .collect::<Result<Vec<_>>>()?;

        let a_final = decode_hex::<C::ScalarField>(&self.a_final)?;
        let r_final = decode_hex::<C::ScalarField>(&self.r_final)?;

        Ok(PedersenCommitmentOpeningProof {
            folding_challenge_commitment_rounds: rounds,
            a_final,
            r_final,
        })
    }
}

impl StoredReencryptionProof {
    pub fn from_proof<G, const N: usize>(proof: &ReencryptionProof<G, N>) -> Result<Self>
    where
        G: CurveGroup + CanonicalSerialize,
        G::ScalarField: CanonicalSerialize,
    {
        Ok(Self {
            blinding_factor_commitment: encode_hex(&proof.blinding_factor_commitment)?,
            blinding_rerandomization_commitment: encode_hex(
                &proof.blinding_rerandomization_commitment,
            )?,
            sigma_response_power_permutation_vector: proof
                .sigma_response_power_permutation_vector
                .iter()
                .map(encode_hex)
                .collect::<Result<Vec<_>>>()?,
            sigma_response_blinding: encode_hex(&proof.sigma_response_blinding)?,
            sigma_response_rerand: encode_hex(&proof.sigma_response_rerand)?,
        })
    }

    pub fn into_proof<G, const N: usize>(self) -> Result<ReencryptionProof<G, N>>
    where
        G: CurveGroup + CanonicalDeserialize,
        G::ScalarField: CanonicalDeserialize,
    {
        let blinding_factor_commitment = decode_hex::<G>(&self.blinding_factor_commitment)?;
        let blinding_rerandomization_commitment =
            decode_hex::<ElGamalCiphertext<G>>(&self.blinding_rerandomization_commitment)?;

        let responses_vec = self
            .sigma_response_power_permutation_vector
            .into_iter()
            .map(|value| decode_hex::<G::ScalarField>(&value))
            .collect::<Result<Vec<_>>>()?;
        let response_array =
            vec_to_array::<_, N>(responses_vec, "sigma_response_power_permutation_vector")?;

        let sigma_response_blinding = decode_hex::<G::ScalarField>(&self.sigma_response_blinding)?;
        let sigma_response_rerand = decode_hex::<G::ScalarField>(&self.sigma_response_rerand)?;

        Ok(ReencryptionProof {
            blinding_factor_commitment,
            blinding_rerandomization_commitment,
            sigma_response_power_permutation_vector: response_array,
            sigma_response_blinding,
            sigma_response_rerand,
        })
    }
}

impl StoredShufflingProof {
    pub fn from_proof<E, G, const N: usize>(proof: &ShufflingProof<E, G, N>) -> Result<Self>
    where
        E: Pairing,
        E::G1Affine: CanonicalSerialize,
        E::G2Affine: CanonicalSerialize,
        G: CurveGroup + CanonicalSerialize,
        G::ScalarField: CanonicalSerialize,
    {
        Ok(Self {
            perm_snark_proof: StoredGroth16Proof::from_proof(&proof.perm_snark_proof)?,
            perm_snark_public_inputs: proof
                .perm_snark_public_inputs
                .iter()
                .map(encode_hex)
                .collect::<Result<Vec<_>>>()?,
            power_opening_proof: StoredPedersenOpeningProof::from_proof(
                &proof.power_opening_proof,
            )?,
            reencryption_proof: StoredReencryptionProof::from_proof(&proof.reencryption_proof)?,
        })
    }

    pub fn into_proof<E, G, const N: usize>(self) -> Result<ShufflingProof<E, G, N>>
    where
        E: Pairing,
        E::G1Affine: CanonicalDeserialize,
        E::G2Affine: CanonicalDeserialize,
        G: CurveGroup + CanonicalDeserialize,
        G::ScalarField: CanonicalDeserialize,
    {
        let perm_snark_proof = self.perm_snark_proof.into_proof::<E>()?;
        let perm_snark_public_inputs = self
            .perm_snark_public_inputs
            .into_iter()
            .map(|value| decode_hex::<E::ScalarField>(&value))
            .collect::<Result<Vec<_>>>()?;
        let power_opening_proof = self.power_opening_proof.into_proof::<G>()?;
        let reencryption_proof = self.reencryption_proof.into_proof::<G, N>()?;

        Ok(ShufflingProof {
            perm_snark_proof,
            perm_snark_public_inputs,
            power_opening_proof,
            reencryption_proof,
        })
    }
}

impl StoredPublicData {
    pub fn from_public<C, const N: usize>(public: &PublicData<C, N>) -> Result<Self>
    where
        C: CurveGroup + CanonicalSerialize,
        C::ScalarField: CanonicalSerialize,
        C::BaseField: PrimeField,
        ConstraintField<C>: CanonicalSerialize,
    {
        Ok(Self {
            nonce: encode_hex(&public.nonce)?,
            pk_public: encode_hex(&public.pk_public)?,
            indices_init: public
                .indices_init
                .iter()
                .map(encode_hex)
                .collect::<Result<Vec<_>>>()?,
            power_challenge_public: encode_hex(&public.power_challenge_public)?,
            c_perm: encode_hex(&public.c_perm)?,
            c_power: encode_hex(&public.c_power)?,
            power_opening_proof: StoredPedersenOpeningProof::from_proof(
                &public.power_opening_proof,
            )?,
        })
    }

    pub fn into_public<C, const N: usize>(self) -> Result<PublicData<C, N>>
    where
        C: CurveGroup + CanonicalDeserialize,
        C::ScalarField: CanonicalDeserialize,
        C::BaseField: PrimeField,
        ConstraintField<C>: CanonicalDeserialize,
    {
        let nonce = decode_hex::<ConstraintField<C>>(&self.nonce)?;
        let pk_public = decode_hex::<C>(&self.pk_public)?;
        let indices_vec = self
            .indices_init
            .into_iter()
            .map(|value| decode_hex::<ConstraintField<C>>(&value))
            .collect::<Result<Vec<_>>>()?;
        let indices_init = vec_to_array::<_, N>(indices_vec, "indices_init")?;
        let power_challenge_public =
            decode_hex::<ConstraintField<C>>(&self.power_challenge_public)?;
        let c_perm = decode_hex::<C>(&self.c_perm)?;
        let c_power = decode_hex::<C>(&self.c_power)?;
        let power_opening_proof = self.power_opening_proof.into_proof::<C>()?;

        Ok(PublicData {
            nonce,
            pk_public,
            indices_init,
            power_challenge_public,
            c_perm,
            c_power,
            power_opening_proof,
        })
    }
}

fn encode_hex<T: CanonicalSerialize>(value: &T) -> Result<String> {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .map_err(|err| anyhow!("canonical serialize failed: {err}"))?;
    Ok(format!("0x{}", hex::encode(buf)))
}

fn decode_hex<T: CanonicalDeserialize>(value: &str) -> Result<T> {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("\\x"))
        .unwrap_or(trimmed);

    let needs_padding = without_prefix.len() % 2 == 1;
    let owned;
    let normalized = if needs_padding {
        owned = format!("0{}", without_prefix);
        owned.as_str()
    } else {
        without_prefix
    };

    let bytes =
        hex::decode(normalized).map_err(|err| anyhow!("failed to decode hex payload: {err}"))?;
    let mut slice = bytes.as_slice();
    T::deserialize_compressed(&mut slice)
        .map_err(|err| anyhow!("canonical deserialize failed: {err}"))
}

fn vec_to_array<T, const N: usize>(vec: Vec<T>, label: &str) -> Result<[T; N]> {
    vec.try_into()
        .map_err(|_| anyhow!("expected {N} elements while decoding {label} but lengths mismatched"))
}
