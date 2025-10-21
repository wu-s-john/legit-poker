use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use sea_orm::DatabaseConnection;
use std::io::Write;

use zk_poker::debugging_tools::fetch_hand_archive;
use zk_poker::ledger::{GameId, HandId};
use zk_poker::ledger::snapshot::rehydrate_snapshot_by_hash;
use zk_poker::ledger::types::StateHash;
use zk_poker::db;
use zk_poker::ledger::query::{HandMessagesQuery, SequenceBounds};
use zk_poker::ledger::messages::FinalizedAnyMessageEnvelope;
use ark_bn254::G1Projective as Curve;

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

#[derive(Serialize)]
struct LatestSnapshotOutput<T> {
    snapshot: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(skip)]
    #[allow(dead_code)]
    messages: Option<Vec<FinalizedAnyMessageEnvelope<Curve>>>,
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
        Some(ref hex) => parse_state_hash(hex)
            .with_context(|| format!("invalid state hash {hex}"))?,
        None => fetch_tip_hash(&conn, args.hand)
            .await?
            .context("hand has no current_state_hash")?,
    };

    let snapshot = rehydrate_snapshot_by_hash::<Curve>(&conn, args.game, args.hand, state_hash).await?;

    let messages = if args.include_messages {
        // TODO: JSON serialization for finalized messages
        let store = zk_poker::ledger::store::SeaOrmEventStore::<Curve>::new(conn.clone());
        let query = HandMessagesQuery::new(std::sync::Arc::new(store));
        let events = query
            .execute(
                args.hand,
                &SequenceBounds {
                    from: None,
                    to: None,
                },
            )
            .await
            .unwrap_or_default();
        Some(events)
    } else {
        None
    };

    let payload = LatestSnapshotOutput {
        snapshot,
        messages,
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

async fn fetch_tip_hash(
    conn: &DatabaseConnection,
    hand_id: HandId,
) -> Result<Option<StateHash>> {
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
