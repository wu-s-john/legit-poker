use anyhow::{anyhow, Result};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_std::rand::Rng;
use std::sync::Arc;

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::actor::ShufflerActor;
use crate::ledger::messages::{
    sign_enveloped_action, AnyGameMessage, AnyMessageEnvelope, EnvelopedMessage,
    GameBlindingDecryptionMessage, GameMessage, GamePartialUnblindingShareMessage,
    GameShuffleMessage, MetadataEnvelope,
};
use crate::shuffling::data_structures::ShuffleProof;
use crate::shuffling::{
    bayer_groth::decomposition::random_permutation as bg_random_permutation,
    shuffle_and_rerandomize_random, CommunityDecryptionShare, ElGamalCiphertext,
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
    DECK_SIZE,
};
use crate::signing::{Signable, SignatureBytes, WithSignature};

use super::Deck;

pub trait ShufflerSigningSecret<C: CurveGroup> {
    fn as_scalar(&self) -> C::ScalarField;
}

pub struct ShufflerEngine<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::SecretKey: ShufflerSigningSecret<C>,
{
    pub secret_key: Arc<S::SecretKey>,
    pub public_key: C,
    pub signing_params: Arc<S::Parameters>,
}

impl<C, S> ShufflerEngine<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::SecretKey: ShufflerSigningSecret<C>,
{
    pub(crate) fn new(
        secret_key: Arc<S::SecretKey>,
        public_key: C,
        signing_params: Arc<S::Parameters>,
    ) -> Self {
        Self {
            secret_key,
            public_key,
            signing_params,
        }
    }
}

pub trait ShufflerApi<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::SecretKey: ShufflerSigningSecret<C>,
{
    fn shuffle<const N: usize, R: Rng>(
        &self,
        aggregated_public_key: &C,
        input_deck: &Deck<C, N>,
        rng: &mut R,
    ) -> Result<(Deck<C, N>, ShuffleProof<C>)>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
        C::BaseField: PrimeField;

    fn provide_blinding_player_decryption_share<R: Rng>(
        &self,
        aggregated_public_key: &C,
        player_public_key: C,
        rng: &mut R,
    ) -> Result<PlayerTargetedBlindingContribution<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
        C: CurveAbsorb<C::BaseField>;

    fn provide_unblinding_decryption_share(
        &self,
        player_ciphertext: &PlayerAccessibleCiphertext<C>,
    ) -> Result<PartialUnblindingShare<C>>
    where
        C::ScalarField: PrimeField;

    fn provide_community_decryption_share<R: Rng>(
        &self,
        ciphertext: &ElGamalCiphertext<C>,
        rng: &mut R,
    ) -> Result<CommunityDecryptionShare<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C: CurveAbsorb<C::BaseField>;

    fn shuffle_and_sign<R: Rng>(
        &self,
        aggregated_public_key: &C,
        ctx: &MetadataEnvelope<C, ShufflerActor<C>>,
        deck_in: &Deck<C, DECK_SIZE>,
        turn_index: u16,
        rng: &mut R,
    ) -> Result<(
        EnvelopedMessage<C, GameShuffleMessage<C>>,
        AnyMessageEnvelope<C>,
    )>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureBytes;

    fn player_blinding_and_sign<R: Rng>(
        &self,
        aggregated_public_key: &C,
        ctx: &MetadataEnvelope<C, ShufflerActor<C>>,
        deal_index: u8,
        player_public_key: &C,
        rng: &mut R,
    ) -> Result<(
        EnvelopedMessage<C, GameBlindingDecryptionMessage<C>>,
        AnyMessageEnvelope<C>,
    )>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
        C: CurveAbsorb<C::BaseField>,
        S::Signature: SignatureBytes;

    fn player_unblinding_and_sign<R: Rng>(
        &self,
        ctx: &MetadataEnvelope<C, ShufflerActor<C>>,
        deal_index: u8,
        player_public_key: &C,
        player_ciphertext: &PlayerAccessibleCiphertext<C>,
        rng: &mut R,
    ) -> Result<(
        EnvelopedMessage<C, GamePartialUnblindingShareMessage<C>>,
        AnyMessageEnvelope<C>,
    )>
    where
        C::ScalarField: PrimeField,
        S::Signature: SignatureBytes;
}

impl<C, S> ShufflerApi<C, S> for ShufflerEngine<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::SecretKey: ShufflerSigningSecret<C>,
{
    fn shuffle<const N: usize, R: Rng>(
        &self,
        aggregated_public_key: &C,
        input_deck: &Deck<C, N>,
        rng: &mut R,
    ) -> Result<(Deck<C, N>, ShuffleProof<C>)>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
        C::BaseField: PrimeField,
    {
        let perm_vec = bg_random_permutation(N, rng);
        let permutation: [usize; N] = core::array::from_fn(|i| perm_vec[i]);

        let (output_deck, rerands) = shuffle_and_rerandomize_random(
            input_deck,
            &permutation,
            aggregated_public_key.clone(),
            rng,
        );
        let input_vec = input_deck.to_vec();
        let sorted_pairs = output_deck
            .iter()
            .cloned()
            .map(|cipher| (cipher, C::BaseField::zero()))
            .collect();
        let rerand_vec = rerands.to_vec();
        let proof = ShuffleProof::new(input_vec, sorted_pairs, rerand_vec)
            .map_err(|err| anyhow!("failed to construct shuffle proof: {err}"))?;
        Ok((output_deck, proof))
    }

    fn provide_blinding_player_decryption_share<R: Rng>(
        &self,
        aggregated_public_key: &C,
        player_public_key: C,
        rng: &mut R,
    ) -> Result<PlayerTargetedBlindingContribution<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
        C: CurveAbsorb<C::BaseField>,
    {
        let delta_j = self.secret_scalar();

        let contribution = crate::shuffling::player_decryption::native::PlayerTargetedBlindingContribution::generate(
            delta_j,
            aggregated_public_key.clone(),
            player_public_key,
            rng,
        );
        Ok(contribution)
    }

    fn provide_unblinding_decryption_share(
        &self,
        player_ciphertext: &PlayerAccessibleCiphertext<C>,
    ) -> Result<PartialUnblindingShare<C>>
    where
        C::ScalarField: PrimeField,
    {
        let member_key = crate::ledger::CanonicalKey::new(self.public_key.clone());
        let share = crate::shuffling::generate_committee_decryption_share(
            player_ciphertext,
            self.secret_scalar(),
            member_key,
        );
        Ok(share)
    }

    fn provide_community_decryption_share<R: Rng>(
        &self,
        ciphertext: &ElGamalCiphertext<C>,
        rng: &mut R,
    ) -> Result<CommunityDecryptionShare<C>>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C: CurveAbsorb<C::BaseField>,
    {
        let member_key = crate::ledger::CanonicalKey::new(self.public_key.clone());
        let share = crate::shuffling::CommunityDecryptionShare::generate(
            ciphertext,
            self.secret_scalar(),
            member_key,
            rng,
        );
        Ok(share)
    }

    fn shuffle_and_sign<R: Rng>(
        &self,
        aggregated_public_key: &C,
        ctx: &MetadataEnvelope<C, ShufflerActor<C>>,
        deck_in: &Deck<C, DECK_SIZE>,
        turn_index: u16,
        rng: &mut R,
    ) -> Result<(
        EnvelopedMessage<C, GameShuffleMessage<C>>,
        AnyMessageEnvelope<C>,
    )>
    where
        C::Config: CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S::Signature: SignatureBytes,
    {
        let (deck_out, proof) =
            self.shuffle::<DECK_SIZE, _>(aggregated_public_key, deck_in, rng)?;
        let message = GameShuffleMessage::new(deck_in.clone(), deck_out, proof, turn_index);
        self.sign_and_wrap(ctx, message, rng)
    }

    fn player_blinding_and_sign<R: Rng>(
        &self,
        aggregated_public_key: &C,
        ctx: &MetadataEnvelope<C, ShufflerActor<C>>,
        deal_index: u8,
        player_public_key: &C,
        rng: &mut R,
    ) -> Result<(
        EnvelopedMessage<C, GameBlindingDecryptionMessage<C>>,
        AnyMessageEnvelope<C>,
    )>
    where
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
        C: CurveAbsorb<C::BaseField>,
        S::Signature: SignatureBytes,
    {
        let contribution = self.provide_blinding_player_decryption_share(
            aggregated_public_key,
            player_public_key.clone(),
            rng,
        )?;
        let message =
            GameBlindingDecryptionMessage::new(deal_index, contribution, player_public_key.clone());
        self.sign_and_wrap(ctx, message, rng)
    }

    fn player_unblinding_and_sign<R: Rng>(
        &self,
        ctx: &MetadataEnvelope<C, ShufflerActor<C>>,
        deal_index: u8,
        player_public_key: &C,
        player_ciphertext: &PlayerAccessibleCiphertext<C>,
        rng: &mut R,
    ) -> Result<(
        EnvelopedMessage<C, GamePartialUnblindingShareMessage<C>>,
        AnyMessageEnvelope<C>,
    )>
    where
        C::ScalarField: PrimeField,
        S::Signature: SignatureBytes,
    {
        let share = self.provide_unblinding_decryption_share(player_ciphertext)?;
        let message =
            GamePartialUnblindingShareMessage::new(deal_index, share, player_public_key.clone());
        self.sign_and_wrap(ctx, message, rng)
    }
}

impl<C, S> ShufflerEngine<C, S>
where
    C: CurveGroup,
    S: SignatureScheme<PublicKey = C::Affine>,
    S::SecretKey: ShufflerSigningSecret<C>,
{
    fn secret_scalar(&self) -> C::ScalarField {
        self.secret_key.as_ref().as_scalar()
    }

    fn sign_and_wrap<M, R>(
        &self,
        ctx: &MetadataEnvelope<C, ShufflerActor<C>>,
        message: M,
        rng: &mut R,
    ) -> Result<(EnvelopedMessage<C, M>, AnyMessageEnvelope<C>)>
    where
        M: GameMessage<C, Actor = ShufflerActor<C>> + Signable + Clone,
        R: Rng,
        S::Signature: SignatureBytes,
        AnyGameMessage<C>: From<M>,
    {
        let meta = MetadataEnvelope {
            hand_id: ctx.hand_id,
            game_id: ctx.game_id,
            actor: ctx.actor.clone(),
            nonce: ctx.nonce,
            public_key: ctx.public_key.clone(),
        };

        let signed = sign_enveloped_action::<S, C, M, _>(
            meta,
            message,
            self.signing_params.as_ref(),
            self.secret_key.as_ref(),
            rng,
        )?;

        let any = Self::to_any_envelope(&signed);
        Ok((signed, any))
    }

    fn to_any_envelope<M>(envelope: &EnvelopedMessage<C, M>) -> AnyMessageEnvelope<C>
    where
        M: GameMessage<C, Actor = ShufflerActor<C>> + Clone + Signable,
        AnyGameMessage<C>: From<M>,
    {
        let ShufflerActor {
            shuffler_id,
            shuffler_key,
        } = envelope.actor.clone();

        AnyMessageEnvelope {
            hand_id: envelope.hand_id,
            game_id: envelope.game_id,
            actor: crate::ledger::actor::AnyActor::Shuffler {
                shuffler_id,
                shuffler_key,
            },
            nonce: envelope.nonce,
            public_key: envelope.public_key.clone(),
            message: WithSignature {
                value: AnyGameMessage::from(envelope.message.value.clone()),
                signature: envelope.message.signature.clone(),
                transcript: envelope.message.transcript.clone(),
            },
        }
    }
}
