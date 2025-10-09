use std::convert::TryFrom;

use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

use crate::ledger::actor::ActorEncode;
use crate::ledger::messages::{EnvelopedMessage, GameMessage};
use crate::ledger::snapshot::{
    HandPhase, PlayerRoster, PlayerStackInfo, PlayerStacks, SeatingMap, TableSnapshot,
};
use crate::ledger::types::{GameId, HandId, StateHash};
use crate::shuffler::Shuffler;
use crate::signing::Signable;

use crate::engine::nl::types::{HandConfig, PlayerStatus, TableStakes};

const DOMAIN_INITIAL: &[u8] = b"zkpoker/state/init/v1";
const DOMAIN_MESSAGE: &[u8] = b"zkpoker/state/message/v1";
const DOMAIN_CHAIN: &[u8] = b"zkpoker/state/chain/v1";

fn finalize_hash(hasher: Sha256) -> StateHash {
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    StateHash::from(bytes)
}

fn write_len(hasher: &mut Sha256, len: usize) {
    let len_u32 = u32::try_from(len).expect("length exceeds u32");
    hasher.update(&len_u32.to_be_bytes());
}

fn write_u8(hasher: &mut Sha256, value: u8) {
    hasher.update(&[value]);
}

fn write_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(&value.to_be_bytes());
}

fn write_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(&value.to_be_bytes());
}

fn write_bool(hasher: &mut Sha256, value: bool) {
    hasher.update(&[value as u8]);
}

fn write_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    write_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn write_curve<C: CurveGroup>(hasher: &mut Sha256, value: &C) {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .expect("curve serialization");
    write_bytes(hasher, &buf);
}

fn hash_hand_config(hasher: &mut Sha256, cfg: &HandConfig) {
    hasher.update(b"hand_config");
    hash_table_stakes(hasher, &cfg.stakes);
    write_u8(hasher, cfg.button);
    write_u8(hasher, cfg.small_blind_seat);
    write_u8(hasher, cfg.big_blind_seat);
    write_bool(hasher, cfg.check_raise_allowed);
}

fn hash_table_stakes(hasher: &mut Sha256, stakes: &TableStakes) {
    hasher.update(b"table_stakes");
    write_u64(hasher, stakes.small_blind);
    write_u64(hasher, stakes.big_blind);
    write_u64(hasher, stakes.ante);
}

fn hash_shufflers<C: CurveGroup>(hasher: &mut Sha256, shufflers: &[Shuffler<C>]) {
    hasher.update(b"shufflers");
    write_len(hasher, shufflers.len());
    for shuffler in shufflers {
        write_u64(hasher, shuffler.index as u64);
        write_curve(hasher, &shuffler.public_key);
        write_curve(hasher, &shuffler.aggregated_public_key);
    }
}

fn hash_player_roster<C: CurveGroup>(hasher: &mut Sha256, roster: &PlayerRoster<C>) {
    hasher.update(b"player_roster");
    write_len(hasher, roster.len());
    for (player_id, identity) in roster {
        write_u64(hasher, *player_id);
        write_u8(hasher, identity.seat);
        write_u64(hasher, identity.nonce);
        write_curve(hasher, &identity.public_key);
    }
}

fn hash_seating_map(hasher: &mut Sha256, seating: &SeatingMap) {
    hasher.update(b"seating_map");
    write_len(hasher, seating.len());
    for (seat, player) in seating {
        write_u8(hasher, *seat);
        match player {
            Some(id) => {
                write_u8(hasher, 1);
                write_u64(hasher, *id);
            }
            None => write_u8(hasher, 0),
        }
    }
}

fn hash_player_stacks(hasher: &mut Sha256, stacks: &PlayerStacks) {
    hasher.update(b"player_stacks");
    write_len(hasher, stacks.len());
    for (seat, info) in stacks {
        write_u8(hasher, *seat);
        hash_player_stack_info(hasher, info);
    }
}

fn hash_player_stack_info(hasher: &mut Sha256, info: &PlayerStackInfo) {
    match info.player_id {
        Some(id) => {
            write_u8(hasher, 1);
            write_u64(hasher, id);
        }
        None => write_u8(hasher, 0),
    }

    write_u64(hasher, info.starting_stack);
    write_u64(hasher, info.committed_blind);
    write_u8(hasher, player_status_code(info.status));
}

fn player_status_code(status: PlayerStatus) -> u8 {
    match status {
        PlayerStatus::Active => 0,
        PlayerStatus::Folded => 1,
        PlayerStatus::AllIn => 2,
        PlayerStatus::SittingOut => 3,
    }
}

fn write_ids(hasher: &mut Sha256, game_id: GameId, hand_id: Option<HandId>) {
    write_i64(hasher, game_id);
    match hand_id {
        Some(id) => {
            write_u8(hasher, 1);
            write_i64(hasher, id);
        }
        None => write_u8(hasher, 0),
    }
}

pub fn compute_initial_state_hash<P, C>(snapshot: &TableSnapshot<P, C>) -> StateHash
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_INITIAL);
    write_ids(&mut hasher, snapshot.game_id, snapshot.hand_id);

    if let Some(cfg) = snapshot.cfg.as_ref() {
        write_u8(&mut hasher, 1);
        hash_hand_config(&mut hasher, cfg);
    } else {
        write_u8(&mut hasher, 0);
    }

    hash_shufflers(&mut hasher, snapshot.shufflers.as_ref());
    hash_player_roster(&mut hasher, snapshot.players.as_ref());
    hash_seating_map(&mut hasher, snapshot.seating.as_ref());
    hash_player_stacks(&mut hasher, snapshot.stacks.as_ref());

    finalize_hash(hasher)
}

pub fn hash_envelope<C, M>(envelope: &EnvelopedMessage<C, M>) -> StateHash
where
    C: CurveGroup,
    M: GameMessage<C> + Signable,
    M::Actor: ActorEncode,
{
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MESSAGE);
    write_ids(&mut hasher, envelope.game_id, Some(envelope.hand_id));
    write_u64(&mut hasher, envelope.nonce);

    let mut actor_buf = Vec::new();
    envelope.actor.encode(&mut actor_buf);
    write_bytes(&mut hasher, &actor_buf);

    let mut pk_bytes = Vec::new();
    envelope
        .public_key
        .serialize_compressed(&mut pk_bytes)
        .expect("public key serialization");
    write_bytes(&mut hasher, &pk_bytes);

    write_bytes(&mut hasher, &envelope.message.transcript);

    finalize_hash(hasher)
}

pub fn chain_state_hash(previous: StateHash, message_hash: StateHash) -> StateHash {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_CHAIN);
    hasher.update(previous.as_bytes());
    hasher.update(message_hash.as_bytes());
    finalize_hash(hasher)
}

impl<P, C> TableSnapshot<P, C>
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    pub fn initialize_hash(&mut self) {
        self.previous_hash = None;
        self.state_hash = compute_initial_state_hash(self);
    }

    pub fn advance_state(&mut self, message_hash: StateHash) {
        let prev = self.state_hash;
        self.previous_hash = Some(prev);
        self.state_hash = chain_state_hash(prev, message_hash);
    }

    pub fn advance_state_with_message<M>(&mut self, envelope: &EnvelopedMessage<C, M>)
    where
        M: GameMessage<C> + Signable,
        M::Actor: ActorEncode,
    {
        let message_hash = hash_envelope(envelope);
        self.advance_state(message_hash);
    }
}
