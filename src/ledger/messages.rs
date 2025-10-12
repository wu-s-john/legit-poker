use ark_ec::CurveGroup;
use serde::Serialize;
use std::marker::PhantomData;

use crate::chaum_pedersen::ChaumPedersenProof;
use crate::engine::nl::actions::PlayerBetAction;
use crate::ledger::actor::AnyActor;
use crate::ledger::{GameActor, GameId, HandId, PlayerActor, ShufflerActor};
use crate::player::signing::append_player_bet_action;
use crate::shuffling::data_structures::{
    append_ciphertext, append_shuffle_proof, ElGamalCiphertext, ShuffleProof, DECK_SIZE,
};
use crate::shuffling::player_decryption::{
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
};
use crate::signing::{Signable, TranscriptBuilder, WithSignature};

use super::snapshot::phases::{
    HandPhase, PhaseBetting, PhaseDealing, PhaseShowdown, PhaseShuffling,
};
use super::types::{HandStatus, SignatureBytes};

pub trait Street: Clone + Default + Serialize {
    fn status() -> HandStatus;
    fn transcript_kind() -> &'static str;
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PreflopStreet;
#[derive(Debug, Clone, Default, Serialize)]
pub struct FlopStreet;
#[derive(Debug, Clone, Default, Serialize)]
pub struct TurnStreet;
#[derive(Debug, Clone, Default, Serialize)]
pub struct RiverStreet;

impl Street for PreflopStreet {
    fn status() -> HandStatus {
        HandStatus::Betting
    }

    fn transcript_kind() -> &'static str {
        "preflop"
    }
}
impl Street for FlopStreet {
    fn status() -> HandStatus {
        HandStatus::Betting
    }

    fn transcript_kind() -> &'static str {
        "flop"
    }
}
impl Street for TurnStreet {
    fn status() -> HandStatus {
        HandStatus::Betting
    }

    fn transcript_kind() -> &'static str {
        "turn"
    }
}
impl Street for RiverStreet {
    fn status() -> HandStatus {
        HandStatus::Betting
    }

    fn transcript_kind() -> &'static str {
        "river"
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = ""))]
pub struct GamePlayerMessage<R, C>
where
    R: Street,
    C: CurveGroup,
{
    pub street: R,
    pub action: PlayerBetAction,
    #[serde(skip)]
    pub _curve: PhantomData<C>,
}

impl<R, C> Signable for GamePlayerMessage<R, C>
where
    R: Street,
    C: CurveGroup,
{
    fn domain_kind(&self) -> &'static str {
        "ledger/game_player_message_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_bytes(R::transcript_kind().as_bytes());
        append_player_bet_action(builder, &self.action);
    }
}

impl<R, C> GamePlayerMessage<R, C>
where
    R: Street + Default,
    C: CurveGroup,
{
    #[inline]
    pub fn new(action: PlayerBetAction) -> Self {
        Self {
            street: R::default(),
            action,
            _curve: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GameShuffleMessage<C>
where
    C: CurveGroup,
{
    pub deck_in: [ElGamalCiphertext<C>; DECK_SIZE],
    pub deck_out: [ElGamalCiphertext<C>; DECK_SIZE],
    pub proof: ShuffleProof<C>,
    pub _curve: PhantomData<C>,
}

impl<C> Signable for GameShuffleMessage<C>
where
    C: CurveGroup,
{
    fn domain_kind(&self) -> &'static str {
        "ledger/game_shuffle_message_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        for cipher in &self.deck_in {
            append_ciphertext(builder, cipher);
        }
        for cipher in &self.deck_out {
            append_ciphertext(builder, cipher);
        }
        append_shuffle_proof(builder, &self.proof);
    }
}

impl<C> GameShuffleMessage<C>
where
    C: CurveGroup,
{
    #[inline]
    pub fn new(
        deck_in: [ElGamalCiphertext<C>; DECK_SIZE],
        deck_out: [ElGamalCiphertext<C>; DECK_SIZE],
        proof: ShuffleProof<C>,
    ) -> Self {
        Self {
            deck_in,
            deck_out,
            proof,
            _curve: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GameBlindingDecryptionMessage<C>
where
    C: CurveGroup,
{
    pub card_in_deck_position: u8,
    pub share: PlayerTargetedBlindingContribution<C>,
    pub _curve: PhantomData<C>,
}

impl<C> Signable for GameBlindingDecryptionMessage<C>
where
    C: CurveGroup,
{
    fn domain_kind(&self) -> &'static str {
        "ledger/game_blinding_decryption_message_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(self.card_in_deck_position);
        self.share.write_transcript(builder);
    }
}

impl<C> GameBlindingDecryptionMessage<C>
where
    C: CurveGroup,
{
    #[inline]
    pub fn new(card_in_deck_position: u8, share: PlayerTargetedBlindingContribution<C>) -> Self {
        Self {
            card_in_deck_position,
            share,
            _curve: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GamePartialUnblindingShareMessage<C>
where
    C: CurveGroup,
{
    pub card_in_deck_position: u8,
    pub share: PartialUnblindingShare<C>,
    pub _curve: PhantomData<C>,
}

impl<C> Signable for GamePartialUnblindingShareMessage<C>
where
    C: CurveGroup,
{
    fn domain_kind(&self) -> &'static str {
        "ledger/game_partial_unblinding_share_message_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(self.card_in_deck_position);
        self.share.write_transcript(builder);
    }
}

impl<C> GamePartialUnblindingShareMessage<C>
where
    C: CurveGroup,
{
    #[inline]
    pub fn new(card_in_deck_position: u8, share: PartialUnblindingShare<C>) -> Self {
        Self {
            card_in_deck_position,
            share,
            _curve: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GameShowdownMessage<C>
where
    C: CurveGroup,
{
    pub chaum_pedersen_proofs: [ChaumPedersenProof<C>; 2],
    pub card_in_deck_position: [u8; 2],
    pub hole_ciphertexts: [PlayerAccessibleCiphertext<C>; 2],
    pub _curve: PhantomData<C>,
}

impl<C> Signable for GameShowdownMessage<C>
where
    C: CurveGroup,
{
    fn domain_kind(&self) -> &'static str {
        "ledger/game_showdown_message_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        for proof in &self.chaum_pedersen_proofs {
            proof.write_transcript(builder);
        }
        for &pos in &self.card_in_deck_position {
            builder.append_u8(pos);
        }
        for ct in &self.hole_ciphertexts {
            ct.write_transcript(builder);
        }
    }
}

impl<C> GameShowdownMessage<C>
where
    C: CurveGroup,
{
    #[inline]
    pub fn new(
        chaum_pedersen_proofs: [ChaumPedersenProof<C>; 2],
        card_in_deck_position: [u8; 2],
        hole_ciphertexts: [PlayerAccessibleCiphertext<C>; 2],
    ) -> Self {
        Self {
            chaum_pedersen_proofs,
            card_in_deck_position,
            hole_ciphertexts,
            _curve: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AnyGameMessage<C>
where
    C: CurveGroup,
{
    Shuffle(GameShuffleMessage<C>),
    Blinding(GameBlindingDecryptionMessage<C>),
    PartialUnblinding(GamePartialUnblindingShareMessage<C>),
    PlayerPreflop(GamePlayerMessage<PreflopStreet, C>),
    PlayerFlop(GamePlayerMessage<FlopStreet, C>),
    PlayerTurn(GamePlayerMessage<TurnStreet, C>),
    PlayerRiver(GamePlayerMessage<RiverStreet, C>),
    Showdown(GameShowdownMessage<C>),
}

impl<C> Signable for AnyGameMessage<C>
where
    C: CurveGroup,
{
    fn domain_kind(&self) -> &'static str {
        "ledger/message_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        match self {
            AnyGameMessage::Shuffle(msg) => {
                builder.append_u8(0);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            AnyGameMessage::Blinding(msg) => {
                builder.append_u8(1);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            AnyGameMessage::PartialUnblinding(msg) => {
                builder.append_u8(2);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            AnyGameMessage::PlayerPreflop(msg) => {
                builder.append_u8(3);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            AnyGameMessage::PlayerFlop(msg) => {
                builder.append_u8(4);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            AnyGameMessage::PlayerTurn(msg) => {
                builder.append_u8(5);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            AnyGameMessage::PlayerRiver(msg) => {
                builder.append_u8(6);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            AnyGameMessage::Showdown(msg) => {
                builder.append_u8(7);
                builder.append_bytes(&msg.to_signing_bytes());
            }
        }
    }
}

impl<C> AnyGameMessage<C>
where
    C: CurveGroup,
{
    pub fn phase(&self) -> HandStatus {
        match self {
            AnyGameMessage::Shuffle(_) => HandStatus::Shuffling,
            AnyGameMessage::Blinding(_) => HandStatus::Dealing,
            AnyGameMessage::PartialUnblinding(_) => HandStatus::Showdown,
            AnyGameMessage::PlayerPreflop(_) => HandStatus::Betting,
            AnyGameMessage::PlayerFlop(_) => HandStatus::Betting,
            AnyGameMessage::PlayerTurn(_) => HandStatus::Betting,
            AnyGameMessage::PlayerRiver(_) => HandStatus::Betting,
            AnyGameMessage::Showdown(_) => HandStatus::Showdown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnvelopedMessage<C, M = AnyGameMessage<C>>
where
    C: CurveGroup,
    M: GameMessage<C> + Signable,
{
    pub hand_id: HandId,
    pub game_id: GameId,
    pub actor: M::Actor,
    pub nonce: u64,
    pub public_key: C,
    pub message: WithSignature<SignatureBytes, M>,
}

#[derive(Debug, Clone)]
pub struct AnyMessageEnvelope<C>
where
    C: CurveGroup,
{
    pub hand_id: HandId,
    pub game_id: GameId,
    pub actor: AnyActor,
    pub nonce: u64,
    pub public_key: C,
    pub message: WithSignature<SignatureBytes, AnyGameMessage<C>>,
}

pub trait GameMessage<C>
where
    C: CurveGroup,
{
    type Phase: HandPhase<C>;
    type Actor: GameActor;
}

impl<C: CurveGroup> GameMessage<C> for GameShuffleMessage<C> {
    type Phase = PhaseShuffling;
    type Actor = ShufflerActor;
}

impl<C: CurveGroup> GameMessage<C> for GameBlindingDecryptionMessage<C> {
    type Phase = PhaseDealing;
    type Actor = ShufflerActor;
}

impl<C: CurveGroup> GameMessage<C> for GamePartialUnblindingShareMessage<C> {
    type Phase = PhaseDealing;
    type Actor = ShufflerActor;
}

impl<C: CurveGroup> GameMessage<C> for GamePlayerMessage<PreflopStreet, C> {
    type Phase = PhaseBetting<PreflopStreet>;
    type Actor = PlayerActor;
}

impl<C: CurveGroup> GameMessage<C> for GamePlayerMessage<FlopStreet, C> {
    type Phase = PhaseBetting<FlopStreet>;
    type Actor = PlayerActor;
}

impl<C: CurveGroup> GameMessage<C> for GamePlayerMessage<TurnStreet, C> {
    type Phase = PhaseBetting<TurnStreet>;
    type Actor = PlayerActor;
}

impl<C: CurveGroup> GameMessage<C> for GamePlayerMessage<RiverStreet, C> {
    type Phase = PhaseBetting<RiverStreet>;
    type Actor = PlayerActor;
}

impl<C: CurveGroup> GameMessage<C> for GameShowdownMessage<C> {
    type Phase = PhaseShowdown;
    type Actor = PlayerActor;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::player::signing::PlayerActionBet;
    use crate::signing::{Signable, WithSignature};
    use anyhow::Result;
    use ark_crypto_primitives::signature::{schnorr::Schnorr, SignatureScheme};
    use ark_ec::CurveGroup;
    use ark_ff::Zero;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use rand::{rngs::StdRng, SeedableRng};
    use sha2::Sha256;

    type Scheme = Schnorr<GrumpkinProjective, Sha256>;

    fn test_keypair() -> (
        <Scheme as SignatureScheme>::Parameters,
        <Scheme as SignatureScheme>::PublicKey,
        <Scheme as SignatureScheme>::SecretKey,
    ) {
        let mut rng = StdRng::from_seed([1u8; 32]);
        let params = Scheme::setup(&mut rng).expect("setup");
        let (pk, sk) = Scheme::keygen(&params, &mut rng).expect("keygen");
        (params, pk, sk)
    }

    fn sample_ledger_messages() -> Vec<AnyGameMessage<GrumpkinProjective>> {
        vec![
            AnyGameMessage::Shuffle(GameShuffleMessage::new(
                sample_deck(),
                sample_deck(),
                sample_shuffle_proof(),
            )),
            AnyGameMessage::Blinding(GameBlindingDecryptionMessage::new(
                7,
                sample_blinding_contribution(),
            )),
            AnyGameMessage::PartialUnblinding(GamePartialUnblindingShareMessage::new(
                13,
                sample_partial_unblinding_share(),
            )),
            AnyGameMessage::PlayerPreflop(
                GamePlayerMessage::<PreflopStreet, GrumpkinProjective>::new(PlayerBetAction::Call),
            ),
            AnyGameMessage::PlayerFlop(GamePlayerMessage::<FlopStreet, GrumpkinProjective>::new(
                PlayerBetAction::Check,
            )),
            AnyGameMessage::PlayerTurn(GamePlayerMessage::<TurnStreet, GrumpkinProjective>::new(
                PlayerBetAction::BetTo { to: 42 },
            )),
            AnyGameMessage::PlayerRiver(GamePlayerMessage::<RiverStreet, GrumpkinProjective>::new(
                PlayerBetAction::RaiseTo { to: 64 },
            )),
            AnyGameMessage::Showdown(GameShowdownMessage::new(
                [sample_cp_proof(), sample_cp_proof()],
                [5u8, 6],
                [
                    sample_accessible_ciphertext(),
                    sample_accessible_ciphertext(),
                ],
            )),
        ]
    }

    fn sign_and_verify<T>(value: T) -> Result<()>
    where
        T: Signable + Clone,
    {
        let (params, pk, sk) = test_keypair();
        let mut rng = StdRng::from_seed([99u8; 32]);
        let expected = value.to_signing_bytes();
        let signed = WithSignature::<<Scheme as SignatureScheme>::Signature, T>::new::<
            Scheme,
            StdRng,
        >(value.clone(), &params, &sk, &mut rng)?;
        assert_eq!(signed.transcript, expected);
        assert!(signed.verify::<Scheme>(&params, &pk)?);
        Ok(())
    }

    #[test]
    fn ledger_message_variants_can_be_signed_and_verified() -> Result<()> {
        for message in sample_ledger_messages() {
            sign_and_verify(message)?;
        }
        Ok(())
    }

    #[test]
    fn base_messages_have_canonical_transcripts() -> Result<()> {
        sign_and_verify(GameShuffleMessage::<GrumpkinProjective>::new(
            sample_deck(),
            sample_deck(),
            sample_shuffle_proof(),
        ))?;
        sign_and_verify(GameBlindingDecryptionMessage::<GrumpkinProjective>::new(
            1,
            sample_blinding_contribution(),
        ))?;
        sign_and_verify(
            GamePartialUnblindingShareMessage::<GrumpkinProjective>::new(
                2,
                sample_partial_unblinding_share(),
            ),
        )?;
        sign_and_verify(GameShowdownMessage::<GrumpkinProjective>::new(
            [sample_cp_proof(), sample_cp_proof()],
            [14, 15],
            [
                sample_accessible_ciphertext(),
                sample_accessible_ciphertext(),
            ],
        ))?;
        sign_and_verify(GamePlayerMessage::<PreflopStreet, GrumpkinProjective>::new(
            PlayerBetAction::AllIn,
        ))?;
        sign_and_verify(PlayerActionBet {
            seat: 1,
            action: PlayerBetAction::Check,
            nonce: 0,
        })?;
        Ok(())
    }

    fn sample_cipher<C: CurveGroup>() -> ElGamalCiphertext<C> {
        ElGamalCiphertext::new(C::zero(), C::zero())
    }

    fn sample_deck<C: CurveGroup>() -> [ElGamalCiphertext<C>; DECK_SIZE] {
        std::array::from_fn(|_| sample_cipher())
    }

    fn sample_shuffle_proof<C: CurveGroup>() -> ShuffleProof<C> {
        ShuffleProof::new(
            sample_deck().to_vec(),
            vec![(sample_cipher(), C::BaseField::zero()); DECK_SIZE],
            vec![C::ScalarField::zero(); DECK_SIZE],
        )
        .unwrap()
    }

    fn sample_cp_proof<C: CurveGroup>() -> ChaumPedersenProof<C> {
        ChaumPedersenProof {
            t_g: C::zero(),
            t_h: C::zero(),
            z: C::ScalarField::zero(),
        }
    }

    fn sample_blinding_contribution<C: CurveGroup>() -> PlayerTargetedBlindingContribution<C> {
        PlayerTargetedBlindingContribution {
            blinding_base_contribution: C::zero(),
            blinding_combined_contribution: C::zero(),
            proof: sample_cp_proof(),
        }
    }

    fn sample_partial_unblinding_share<C: CurveGroup>() -> PartialUnblindingShare<C> {
        PartialUnblindingShare {
            share: C::zero(),
            member_index: 0,
        }
    }

    fn sample_accessible_ciphertext<C: CurveGroup>() -> PlayerAccessibleCiphertext<C> {
        PlayerAccessibleCiphertext {
            blinded_base: C::zero(),
            blinded_message_with_player_key: C::zero(),
            player_unblinding_helper: C::zero(),
            shuffler_proofs: Vec::new(),
        }
    }
}
