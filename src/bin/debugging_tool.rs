use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Arc;

use ark_bn254::G1Projective as Curve;
use hex;
use serde_json::{self, Value};
use sha2::{Digest, Sha256};
use zk_poker::db;
use zk_poker::debugging_tools::fetch_hand_archive;
use zk_poker::ledger::actor::AnyActor;
use zk_poker::ledger::messages::{AnyGameMessage, AnyMessageEnvelope, FinalizedAnyMessageEnvelope};
use zk_poker::ledger::query::{HandMessagesQuery, SequenceBounds};
use zk_poker::ledger::snapshot::{rehydrate_snapshot_by_hash, SnapshotSeq, SnapshotStatus};
use zk_poker::ledger::store::SeaOrmEventStore;
use zk_poker::ledger::types::{EventPhase, StateHash};
use zk_poker::ledger::{GameId, HandId, SignatureBytes};
use zk_poker::signing::WithSignature;

#[derive(Parser)]
#[command(author, version, about = "Ledger debugging utilities", long_about = None)]
struct Cli {
    /// Pretty-print JSON output
    #[arg(long, default_value_t = true, global = true)]
    pretty: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dump the archived hand data (legacy command)
    Archive(ArchiveArgs),
    /// Fetch the latest snapshot (or a specific hash) for a hand
    Latest(LatestArgs),
}

#[derive(Parser, Debug)]
struct ArchiveArgs {
    #[arg(long)]
    game: GameId,

    #[arg(long)]
    hand: HandId,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_include_events: bool,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_include_snapshots: bool,
}

#[derive(Parser, Debug)]
struct LatestArgs {
    #[arg(long)]
    game: GameId,

    #[arg(long)]
    hand: HandId,

    /// Optional state hash (0x-prefixed hex). If omitted, uses the tip hash.
    #[arg(long)]
    state_hash: Option<String>,

    /// Fetch finalized messages up to the snapshot (messages are not serialized yet).
    #[arg(long)]
    include_messages: bool,
}

#[derive(Serialize)]
struct ArchiveOutput<T> {
    data: T,
}

#[derive(Serialize, Deserialize)]
struct LatestSnapshotOutput {
    snapshot: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    messages: Option<Vec<FinalizedEnvelopeDisplay>>,
}

fn write_json<T: Serialize>(value: &T, pretty: bool) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if pretty {
        serde_json::to_writer_pretty(&mut handle, value)?;
    } else {
        serde_json::to_writer(&mut handle, value)?;
    }
    handle.write_all(b"\n")?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();

    match cli.command {
        Command::Archive(args) => run_archive(args, cli.pretty).await?,
        Command::Latest(args) => run_latest(args, cli.pretty).await?,
    }

    Ok(())
}

async fn run_archive(args: ArchiveArgs, pretty: bool) -> Result<()> {
    let conn = db::connect().await?;
    let include_events = !args.no_include_events;
    let include_snapshots = !args.no_include_snapshots;

    let archive = fetch_hand_archive(
        &conn,
        args.game,
        args.hand,
        include_events,
        include_snapshots,
    )
    .await?;

    write_json(&ArchiveOutput { data: archive }, pretty)
}

async fn run_latest(args: LatestArgs, pretty: bool) -> Result<()> {
    let conn = db::connect().await?;

    let state_hash = match args.state_hash {
        Some(ref hex) => {
            parse_state_hash(hex).with_context(|| format!("invalid state hash {hex}"))?
        }
        None => fetch_tip_hash(&conn, args.hand)
            .await?
            .context("hand has no current_state_hash")?,
    };

    let snapshot =
        rehydrate_snapshot_by_hash::<Curve>(&conn, args.game, args.hand, state_hash).await?;

    let mut snapshot_json = serde_json::to_value(&snapshot)?;
    normalize_hash_fields(&mut snapshot_json);

    let messages = if args.include_messages {
        let store = SeaOrmEventStore::<Curve>::new(conn.clone());
        let query = HandMessagesQuery::new(Arc::new(store));
        let bounds = SequenceBounds::new(None, Some(snapshot.sequence()))?;
        let events = query.execute(args.hand, &bounds).await?;
        Some(events)
    } else {
        None
    };

    let normalized_messages =
        messages.map(|m| m.into_iter().map(FinalizedEnvelopeDisplay::from).collect());

    let payload = LatestSnapshotOutput {
        snapshot: snapshot_json,
        messages: normalized_messages,
    };

    write_json(&payload, pretty)
}

fn parse_state_hash(input: &str) -> Result<StateHash> {
    let trimmed = input.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(without_prefix)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("state hash must be 32 bytes"))?;
    Ok(StateHash::from(array))
}

async fn fetch_tip_hash(conn: &DatabaseConnection, hand_id: HandId) -> Result<Option<StateHash>> {
    use sea_orm::EntityTrait;
    use zk_poker::db::entity::hands;

    let row = hands::Entity::find_by_id(hand_id).one(conn).await?;
    if let Some(model) = row {
        Ok(model
            .current_state_hash
            .map(|bytes| state_hash_from_bytes(bytes).unwrap_or_else(|_| StateHash::zero())))
    } else {
        anyhow::bail!("hand {hand_id} not found");
    }
}

fn state_hash_from_bytes(bytes: Vec<u8>) -> Result<StateHash> {
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("state hash must be 32 bytes"))?;
    Ok(StateHash::from(array))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn normalize_hash_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(hash) = map.get_mut("state_hash") {
                if let Some(hex) = array_to_hex(hash) {
                    *hash = Value::String(hex);
                }
            }
            if let Some(prev) = map.get_mut("previous_hash") {
                if let Some(hex) = array_to_hex(prev) {
                    *prev = Value::String(hex);
                }
            }
            for v in map.values_mut() {
                normalize_hash_fields(v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                normalize_hash_fields(v);
            }
        }
        _ => {}
    }
}

fn array_to_hex(value: &Value) -> Option<String> {
    if let Value::Array(arr) = value {
        if arr.len() == 32 {
            let mut bytes = [0u8; 32];
            for (i, v) in arr.iter().enumerate() {
                let n = v.as_u64()?;
                if n > 255 {
                    return None;
                }
                bytes[i] = n as u8;
            }
            return Some(format!("0x{}", hex::encode(bytes)));
        }
    }
    None
}

#[derive(Serialize, Deserialize)]
struct FinalizedEnvelopeDisplay {
    envelope: MessageEnvelopeDisplay,
    snapshot_status: SnapshotStatus,
    applied_phase: EventPhase,
    snapshot_sequence_id: SnapshotSeq,
}

impl From<FinalizedAnyMessageEnvelope<Curve>> for FinalizedEnvelopeDisplay {
    fn from(value: FinalizedAnyMessageEnvelope<Curve>) -> Self {
        Self {
            envelope: MessageEnvelopeDisplay::from(value.envelope),
            snapshot_status: value.snapshot_status,
            applied_phase: value.applied_phase,
            snapshot_sequence_id: value.snapshot_sequence_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MessageEnvelopeDisplay {
    hand_id: HandId,
    game_id: GameId,
    actor: AnyActor,
    nonce: u64,
    #[serde(with = "zk_poker::crypto_serde::curve")]
    public_key: Curve,
    message: MessageWithSignatureDisplay,
}

impl From<AnyMessageEnvelope<Curve>> for MessageEnvelopeDisplay {
    fn from(envelope: AnyMessageEnvelope<Curve>) -> Self {
        Self {
            hand_id: envelope.hand_id,
            game_id: envelope.game_id,
            actor: envelope.actor,
            nonce: envelope.nonce,
            public_key: envelope.public_key,
            message: MessageWithSignatureDisplay::from(envelope.message),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MessageWithSignatureDisplay {
    value: AnyGameMessage<Curve>,
    signature_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript_hex: Option<String>,
}

impl From<WithSignature<SignatureBytes, AnyGameMessage<Curve>>> for MessageWithSignatureDisplay {
    fn from(with_sig: WithSignature<SignatureBytes, AnyGameMessage<Curve>>) -> Self {
        let signature_hash = sha256_hex(&with_sig.signature);
        let transcript_hex = if with_sig.transcript.is_empty() {
            None
        } else {
            Some(format!("0x{}", hex::encode(&with_sig.transcript)))
        };

        Self {
            value: with_sig.value,
            signature_sha256: signature_hash,
            transcript_hex,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LatestSnapshotOutput;
    use ark_bn254::G1Projective;
    use ark_ec::PrimeGroup;
    use serde_json;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use zk_poker::engine::nl::actions::PlayerBetAction;
    use zk_poker::engine::nl::types::{HandConfig, PlayerStatus, TableStakes};
    use zk_poker::ledger::actor::AnyActor;
    use zk_poker::ledger::messages::{
        AnyGameMessage, AnyMessageEnvelope, FinalizedAnyMessageEnvelope, GamePlayerMessage,
        PreflopStreet,
    };
    use zk_poker::ledger::snapshot::{
        phases::PhaseShuffling, AnyTableSnapshot, PlayerIdentity, PlayerStackInfo,
        ShufflerIdentity, ShufflingSnapshot, SnapshotStatus, TableSnapshot,
    };
    use zk_poker::ledger::types::{EventPhase, ShufflerId, StateHash};
    use zk_poker::shuffling::data_structures::{ElGamalCiphertext, DECK_SIZE};
    use zk_poker::signing::{Signable, WithSignature};

    type Curve = G1Projective;

    fn sample_ciphertext() -> ElGamalCiphertext<Curve> {
        let generator = Curve::generator();
        ElGamalCiphertext::new(generator, generator)
    }

    #[test]
    fn latest_snapshot_output_round_trips_with_serde() {
        let cfg = HandConfig {
            stakes: TableStakes {
                small_blind: 1,
                big_blind: 2,
                ante: 0,
            },
            button: 0,
            small_blind_seat: 1,
            big_blind_seat: 2,
            check_raise_allowed: true,
        };

        let mut shufflers = BTreeMap::<ShufflerId, ShufflerIdentity<Curve>>::new();
        shufflers.insert(
            100,
            ShufflerIdentity {
                public_key: Curve::generator(),
                aggregated_public_key: Curve::generator(),
            },
        );

        let mut players = BTreeMap::new();
        players.insert(
            200u64,
            PlayerIdentity {
                public_key: Curve::generator(),
                nonce: 0,
                seat: 0,
            },
        );

        let mut seating = BTreeMap::new();
        seating.insert(0, Some(200u64));

        let mut stacks = BTreeMap::new();
        stacks.insert(
            0,
            PlayerStackInfo {
                seat: 0,
                player_id: Some(200u64),
                starting_stack: 1_000,
                committed_blind: 0,
                status: PlayerStatus::Active,
            },
        );

        let deck: [ElGamalCiphertext<Curve>; DECK_SIZE] =
            std::array::from_fn(|_| sample_ciphertext());
        let shuffling = ShufflingSnapshot {
            initial_deck: deck.clone(),
            steps: Vec::new(),
            final_deck: deck,
            expected_order: vec![100],
        };

        let table: TableSnapshot<PhaseShuffling, Curve> = TableSnapshot {
            game_id: 1,
            hand_id: Some(2),
            sequence: 0,
            cfg: Arc::new(cfg),
            shufflers: Arc::new(shufflers),
            players: Arc::new(players),
            seating: Arc::new(seating),
            stacks: Arc::new(stacks),
            previous_hash: None,
            state_hash: StateHash::zero(),
            status: SnapshotStatus::Success,
            shuffling,
            dealing: (),
            betting: (),
            reveals: (),
        };

        let snapshot = AnyTableSnapshot::Shuffling(table);
        let mut snapshot_json = serde_json::to_value(&snapshot).expect("serialize snapshot");
        super::normalize_hash_fields(&mut snapshot_json);

        let game_message = AnyGameMessage::PlayerPreflop(
            GamePlayerMessage::<PreflopStreet, Curve>::new(PlayerBetAction::Call),
        );
        let transcript = game_message.to_signing_bytes();
        let envelope = AnyMessageEnvelope {
            hand_id: 2,
            game_id: 1,
            actor: AnyActor::Player {
                seat_id: 0,
                player_id: 200,
            },
            nonce: 3,
            public_key: Curve::generator(),
            message: WithSignature {
                value: game_message,
                signature: vec![0, 1, 2, 3],
                transcript,
            },
        };
        let finalized = FinalizedAnyMessageEnvelope {
            envelope,
            snapshot_status: SnapshotStatus::Success,
            applied_phase: EventPhase::Shuffling,
            snapshot_sequence_id: 1,
        };

        let payload = LatestSnapshotOutput {
            snapshot: snapshot_json,
            messages: Some(vec![finalized.into()]),
        };

        let json = serde_json::to_value(&payload).expect("serialization should succeed");
        let messages = json
            .get("messages")
            .and_then(|v| v.as_array())
            .expect("messages array serialized");
        let message = messages.first().expect("at least one message serialized");
        let signature = message
            .get("envelope")
            .and_then(|v| v.get("message"))
            .and_then(|v| v.get("signature_sha256"))
            .and_then(|v| v.as_str())
            .expect("signature hash present");
        assert!(signature.starts_with("0x"));
        assert_eq!(signature.len(), 66, "expected 32-byte hash rendered as hex");
    }
}
