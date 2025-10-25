use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Arc;

use ark_bn254::G1Projective as Curve;
use hex;
use serde_json;
use sha2::{Digest, Sha256};
use zk_poker::db;
use zk_poker::debugging_tools::fetch_hand_archive;
use zk_poker::ledger::actor::AnyActor;
use zk_poker::ledger::messages::{AnyGameMessage, AnyMessageEnvelope, FinalizedAnyMessageEnvelope};
use zk_poker::ledger::query::{HandMessagesQuery, SequenceBounds};
use zk_poker::ledger::snapshot::{rehydrate_snapshot, SnapshotSeq, SnapshotStatus};
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

    /// Optional state hash (0x-prefixed hex). If omitted, fetches the latest snapshot.
    #[arg(long)]
    state_hash: Option<StateHash>,

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
    snapshot: zk_poker::ledger::snapshot::AnyTableSnapshot<Curve>,
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

    let snapshot =
        rehydrate_snapshot::<Curve>(&conn, args.game, args.hand, args.state_hash).await?;

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
        snapshot,
        messages: normalized_messages,
    };

    write_json(&payload, pretty)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("0x{}", hex::encode(hasher.finalize()))
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
    actor: AnyActor<Curve>,
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
        // Transcript is now computed on-demand via signing_bytes()
        let transcript_hex = match zk_poker::signing::signing_bytes(&with_sig.value) {
            Ok(bytes) if !bytes.is_empty() => Some(format!("0x{}", hex::encode(&bytes))),
            _ => None,
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
    use zk_poker::ledger::messages::{
        AnyGameMessage, AnyMessageEnvelope, FinalizedAnyMessageEnvelope, GamePlayerMessage,
        PreflopStreet,
    };
    use zk_poker::ledger::snapshot::{
        phases::PhaseShuffling, AnyTableSnapshot, PlayerIdentity, PlayerStackInfo,
        ShufflerIdentity, ShufflingSnapshot, SnapshotStatus, TableSnapshot,
    };
    use zk_poker::ledger::types::{EventPhase, StateHash};
    use zk_poker::ledger::{actor::AnyActor, CanonicalKey};
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

        let shuffler_public = Curve::generator();
        let shuffler_key = CanonicalKey::new(shuffler_public);
        let mut shufflers = BTreeMap::<CanonicalKey<Curve>, ShufflerIdentity<Curve>>::new();
        shufflers.insert(
            shuffler_key.clone(),
            ShufflerIdentity {
                public_key: shuffler_public,
                shuffler_key: shuffler_key.clone(),
                shuffler_id: 100,
                aggregated_public_key: shuffler_public,
            },
        );

        let player_public = Curve::generator();
        let player_key = CanonicalKey::new(player_public);
        let mut players = BTreeMap::new();
        players.insert(
            player_key.clone(),
            PlayerIdentity {
                public_key: player_public,
                player_key: player_key.clone(),
                player_id: 200,
                nonce: 0,
                seat: 0,
            },
        );

        let mut seating = BTreeMap::new();
        seating.insert(0, Some(player_key.clone()));

        let mut stacks = BTreeMap::new();
        stacks.insert(
            0,
            PlayerStackInfo {
                seat: 0,
                player_key: Some(player_key.clone()),
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
            expected_order: vec![shuffler_key],
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
                player_key: CanonicalKey::new(Curve::generator()),
            },
            nonce: 3,
            public_key: Curve::generator(),
            message: WithSignature {
                value: game_message,
                signature: vec![0, 1, 2, 3],
                transcript,
            },
        };
        let finalized = FinalizedAnyMessageEnvelope::new(
            envelope,
            SnapshotStatus::Success,
            EventPhase::Shuffling,
            1,
        );

        let payload = LatestSnapshotOutput {
            snapshot,
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
