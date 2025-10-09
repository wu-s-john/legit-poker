use ark_ec::CurveGroup;
use serde::Serialize;
use std::marker::PhantomData;

use crate::engine::nl::actions::PlayerBetAction;
use crate::player::signing::append_player_bet_action;
use crate::signing::{Signable, TranscriptBuilder, WithSignature};

use super::types::{ActorKind, HandStatus, NonceKey, PublicKeyBytes, SignatureBytes};

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

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = ""))]
pub struct GameShuffleMessage<C>
where
    C: CurveGroup,
{
    pub deck_in: Vec<u8>,
    pub deck_out: Vec<u8>,
    #[serde(skip)]
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
        builder.append_bytes(&self.deck_in);
        builder.append_bytes(&self.deck_out);
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = ""))]
pub struct GameBlindingDecryptionMessage<C>
where
    C: CurveGroup,
{
    pub card_in_deck_position: u8,
    pub share_bytes: Vec<u8>,
    #[serde(skip)]
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
        builder.append_bytes(&self.share_bytes);
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = ""))]
pub struct GamePartialUnblindingShareMessage<C>
where
    C: CurveGroup,
{
    pub card_in_deck_position: u8,
    pub share_bytes: Vec<u8>,
    #[serde(skip)]
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
        builder.append_bytes(&self.share_bytes);
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = ""))]
pub struct GameShowdownMessage<C>
where
    C: CurveGroup,
{
    pub chaum_pedersen_proofs: [Vec<u8>; 2],
    pub card_in_deck_position: [u8; 2],
    pub hole_ciphertexts: [Vec<u8>; 2],
    #[serde(skip)]
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
            builder.append_bytes(proof);
        }
        for &pos in &self.card_in_deck_position {
            builder.append_u8(pos);
        }
        for ct in &self.hole_ciphertexts {
            builder.append_bytes(ct);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "data", bound(serialize = ""))]
pub enum LedgerMessage<C>
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

impl<C> Signable for LedgerMessage<C>
where
    C: CurveGroup,
{
    fn domain_kind(&self) -> &'static str {
        "ledger/message_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        match self {
            LedgerMessage::Shuffle(msg) => {
                builder.append_u8(0);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            LedgerMessage::Blinding(msg) => {
                builder.append_u8(1);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            LedgerMessage::PartialUnblinding(msg) => {
                builder.append_u8(2);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            LedgerMessage::PlayerPreflop(msg) => {
                builder.append_u8(3);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            LedgerMessage::PlayerFlop(msg) => {
                builder.append_u8(4);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            LedgerMessage::PlayerTurn(msg) => {
                builder.append_u8(5);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            LedgerMessage::PlayerRiver(msg) => {
                builder.append_u8(6);
                builder.append_bytes(&msg.to_signing_bytes());
            }
            LedgerMessage::Showdown(msg) => {
                builder.append_u8(7);
                builder.append_bytes(&msg.to_signing_bytes());
            }
        }
    }
}

impl<C> LedgerMessage<C>
where
    C: CurveGroup,
{
    pub fn phase(&self) -> HandStatus {
        match self {
            LedgerMessage::Shuffle(_) => HandStatus::Shuffling,
            LedgerMessage::Blinding(_) => HandStatus::Dealing,
            LedgerMessage::PartialUnblinding(_) => HandStatus::Showdown,
            LedgerMessage::PlayerPreflop(_) => HandStatus::Betting,
            LedgerMessage::PlayerFlop(_) => HandStatus::Betting,
            LedgerMessage::PlayerTurn(_) => HandStatus::Betting,
            LedgerMessage::PlayerRiver(_) => HandStatus::Betting,
            LedgerMessage::Showdown(_) => HandStatus::Showdown,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = ""))]
pub struct ActionEnvelope<C>
where
    C: CurveGroup,
{
    pub public_key: PublicKeyBytes,
    pub actor: ActorKind,
    pub nonce: u64,
    pub signed_message: WithSignature<SignatureBytes, LedgerMessage<C>>,
}

#[derive(Debug, Clone)]
pub struct VerifiedEnvelope<C>
where
    C: CurveGroup,
{
    pub key: NonceKey,
    pub nonce: u64,
    pub phase: HandStatus,
    pub message: LedgerMessage<C>,
    pub raw: ActionEnvelope<C>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::player::signing::PlayerActionBet;
    use crate::signing::{Signable, WithSignature};
    use anyhow::Result;
    use ark_crypto_primitives::signature::{schnorr::Schnorr, SignatureScheme};
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

    fn sample_ledger_messages() -> Vec<LedgerMessage<GrumpkinProjective>> {
        vec![
            LedgerMessage::Shuffle(GameShuffleMessage {
                deck_in: vec![0, 1, 2],
                deck_out: vec![3, 4, 5],
                _curve: PhantomData,
            }),
            LedgerMessage::Blinding(GameBlindingDecryptionMessage {
                card_in_deck_position: 7,
                share_bytes: vec![11, 12],
                _curve: PhantomData,
            }),
            LedgerMessage::PartialUnblinding(GamePartialUnblindingShareMessage {
                card_in_deck_position: 13,
                share_bytes: vec![21, 22, 23],
                _curve: PhantomData,
            }),
            LedgerMessage::PlayerPreflop(GamePlayerMessage {
                street: PreflopStreet,
                action: PlayerBetAction::Call,
                _curve: PhantomData,
            }),
            LedgerMessage::PlayerFlop(GamePlayerMessage {
                street: FlopStreet,
                action: PlayerBetAction::Check,
                _curve: PhantomData,
            }),
            LedgerMessage::PlayerTurn(GamePlayerMessage {
                street: TurnStreet,
                action: PlayerBetAction::BetTo { to: 42 },
                _curve: PhantomData,
            }),
            LedgerMessage::PlayerRiver(GamePlayerMessage {
                street: RiverStreet,
                action: PlayerBetAction::RaiseTo { to: 64 },
                _curve: PhantomData,
            }),
            LedgerMessage::Showdown(GameShowdownMessage {
                chaum_pedersen_proofs: [vec![1u8, 2], vec![3u8, 4]],
                card_in_deck_position: [5u8, 6],
                hole_ciphertexts: [vec![7u8, 8], vec![9u8, 10]],
                _curve: PhantomData,
            }),
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
        sign_and_verify(GameShuffleMessage::<GrumpkinProjective> {
            deck_in: vec![1, 2, 3],
            deck_out: vec![4, 5, 6],
            _curve: PhantomData,
        })?;
        sign_and_verify(GameBlindingDecryptionMessage::<GrumpkinProjective> {
            card_in_deck_position: 1,
            share_bytes: vec![7, 8, 9],
            _curve: PhantomData,
        })?;
        sign_and_verify(GamePartialUnblindingShareMessage::<GrumpkinProjective> {
            card_in_deck_position: 2,
            share_bytes: vec![10, 11],
            _curve: PhantomData,
        })?;
        sign_and_verify(GameShowdownMessage::<GrumpkinProjective> {
            chaum_pedersen_proofs: [vec![12], vec![13]],
            card_in_deck_position: [14, 15],
            hole_ciphertexts: [vec![16], vec![17]],
            _curve: PhantomData,
        })?;
        sign_and_verify(GamePlayerMessage::<PreflopStreet, GrumpkinProjective> {
            street: PreflopStreet,
            action: PlayerBetAction::AllIn,
            _curve: PhantomData,
        })?;
        sign_and_verify(PlayerActionBet {
            seat: 1,
            action: PlayerBetAction::Check,
            nonce: 0,
        })?;
        Ok(())
    }
}
