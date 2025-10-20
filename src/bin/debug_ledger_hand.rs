use std::io::{self, Write};

use anyhow::Result;
use clap::Parser;

use zk_poker::db;
use zk_poker::debugging_tools::fetch_hand_archive;

#[derive(Debug, Parser)]
#[command(author, version, about = "Dump ledger hand archive for debugging", long_about = None)]
struct Args {
    /// Game identifier
    #[arg(long)]
    game: i64,

    /// Hand identifier
    #[arg(long)]
    hand: i64,

    /// Omit events from the archive output
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_include_events: bool,

    /// Omit snapshots/phases from the archive output
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_include_snapshots: bool,

    /// Pretty-print JSON output
    #[arg(long, default_value_t = true)]
    pretty: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    if args.pretty {
        serde_json::to_writer_pretty(&mut handle, &archive)?;
    } else {
        serde_json::to_writer(&mut handle, &archive)?;
    }
    handle.write_all(b"\n")?;

    Ok(())
}
