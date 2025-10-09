use ark_ec::CurveGroup;
use serde::Serialize;
use std::marker::PhantomData;

use crate::engine::nl::actions::PlayerBetAction;
use crate::player::signing::WithSignature;

use super::types::{ActorKind, HandStatus, NonceKey, PublicKeyBytes, SignatureBytes};

pub trait Street: Clone + Default + Serialize {
    fn status() -> HandStatus;
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
}
impl Street for FlopStreet {
    fn status() -> HandStatus {
        HandStatus::Betting
    }
}
impl Street for TurnStreet {
    fn status() -> HandStatus {
        HandStatus::Betting
    }
}
impl Street for RiverStreet {
    fn status() -> HandStatus {
        HandStatus::Betting
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
