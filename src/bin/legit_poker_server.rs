use anyhow::{anyhow, Context, Result};
use ark_bn254::{Fr as Scalar, G1Projective as Curve};
use ark_ff::{PrimeField, UniformRand};
use clap::Parser;
use rand::{rngs::StdRng, SeedableRng};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::warn;
use tracing_subscriber::{fmt, EnvFilter};
use url::Url;

use zk_poker::game::coordinator::{load_shuffler_secrets_from_env, ShufflerSecretConfig};
use zk_poker::server::{run_server as run_http_server, ServerConfig};

use serde_json::Value as JsonValue;

const LOG_TARGET: &str = "bin::legit_poker_server";
const DEFAULT_BIND: &str = "127.0.0.1:4000";
const DEFAULT_SHUFFLER_ENV: &str = "SERVER_SHUFFLER_SECRETS";
const REQUIRED_SHUFFLER_COUNT: usize = 7;

#[derive(Debug, Parser)]
#[command(name = "legit_poker_server")]
#[command(about = "Launch the Axum coordinator API server", long_about = None)]
struct Args {
    /// Address to bind the HTTP server to (host:port)
    #[arg(long, env = "SERVER_BIND", default_value = DEFAULT_BIND)]
    bind: SocketAddr,

    /// SeaORM-compatible Postgres URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Supabase REST base URL (used to derive realtime websocket URL)
    #[arg(long, env = "SUPABASE_URL")]
    supabase_url: String,

    /// Supabase anon key for realtime websocket auth
    #[arg(long, env = "SUPABASE_ANON_KEY")]
    supabase_anon_key: String,

    /// Optional explicit Supabase realtime websocket URL
    #[arg(long, env = "SUPABASE_REALTIME_URL")]
    supabase_realtime_url: Option<String>,

    /// Optional RNG seed for deterministic shuffler key sampling
    #[arg(long, env = "SERVER_RNG_SEED")]
    rng_seed: Option<u64>,

    /// Toggle structured (JSON) logs
    #[arg(long, env = "SERVER_LOG_JSON", default_value_t = false)]
    json: bool,

    /// Environment variable name (or inline JSON string) for shuffler secrets
    #[arg(long, env = "SERVER_SHUFFLER_SOURCE", default_value = DEFAULT_SHUFFLER_ENV)]
    shuffler_source: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    load_dotenv();
    let args = Args::parse();
    init_tracing(args.json)?;
    let config = build_config(args).context("failed to build server config")?;
    run_http_server(config).await
}

fn load_dotenv() {
    let manifest_env = env!("CARGO_MANIFEST_DIR");
    let manifest_env_path = PathBuf::from(manifest_env).join(".env");
    dotenv::from_filename(manifest_env_path).ok();
    dotenv::dotenv().ok();
}

fn init_tracing(json: bool) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = fmt::fmt().with_env_filter(filter).with_target(false);

    if json {
        builder.json().flatten_event(true).init();
    } else {
        builder.compact().init();
    }

    Ok(())
}

fn build_config(args: Args) -> Result<ServerConfig<Curve>> {
    let realtime_url = match args.supabase_realtime_url {
        Some(url) => Url::parse(&url).context("invalid SUPABASE_REALTIME_URL")?,
        None => derive_realtime_url(&args.supabase_url)?,
    };

    let rng_seed = args.rng_seed.map(seed_to_array);
    let mut rng = args
        .rng_seed
        .map(StdRng::seed_from_u64)
        .unwrap_or_else(StdRng::from_entropy);

    let shufflers = load_or_sample_shufflers(&args.shuffler_source, &mut rng)?;
    if shufflers.len() != REQUIRED_SHUFFLER_COUNT {
        return Err(anyhow!(
            "expected {} shuffler secrets, received {}",
            REQUIRED_SHUFFLER_COUNT,
            shufflers.len()
        ));
    }

    Ok(ServerConfig {
        bind: args.bind,
        database_url: args.database_url,
        supabase_realtime: realtime_url,
        supabase_anon_key: args.supabase_anon_key,
        shufflers,
        rng_seed,
    })
}

fn derive_realtime_url(rest_base: &str) -> Result<Url> {
    let mut base = Url::parse(rest_base).context("invalid SUPABASE_URL")?;
    let target_scheme = {
        let scheme = base.scheme();
        match scheme {
            "https" => "wss".to_string(),
            "http" => "ws".to_string(),
            other => other.to_string(),
        }
    };
    base.set_path("/realtime/v1");
    base.set_query(None);
    base.set_fragment(None);
    base.set_scheme(target_scheme.as_str())
        .map_err(|_| anyhow!("failed to convert Supabase URL scheme"))?;
    Ok(base)
}

fn load_or_sample_shufflers(
    source: &str,
    rng: &mut StdRng,
) -> Result<Vec<ShufflerSecretConfig<Curve>>> {
    if let Ok(raw) = env::var(source) {
        parse_shuffler_env(source, &raw)
    } else if let Ok(json_like) = serde_json::from_str::<JsonValue>(source) {
        parse_shuffler_json_value(json_like)
    } else {
        warn!(
            target = LOG_TARGET,
            source, "no shuffler secrets provided; sampling ephemeral shufflers"
        );
        sample_shufflers(rng)
    }
}

fn parse_shuffler_env(var: &str, raw: &str) -> Result<Vec<ShufflerSecretConfig<Curve>>> {
    // reuse helper for the canonical env format
    env::set_var(var, raw);
    load_shuffler_secrets_from_env(var).context("failed to parse shuffler secrets")
}

fn parse_shuffler_json_value(value: serde_json::Value) -> Result<Vec<ShufflerSecretConfig<Curve>>> {
    let array = value.as_array().cloned().ok_or_else(|| {
        anyhow!(
            "expected JSON array for shuffler secrets but found {:?}",
            value
        )
    })?;
    let mut configs = Vec::with_capacity(array.len());
    for entry in array {
        let id = entry
            .get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("shuffler entry missing numeric id"))?;
        let secret_hex = entry
            .get("secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("shuffler entry missing secret string"))?;
        let secret = parse_scalar(secret_hex)?;
        configs.push(ShufflerSecretConfig { id, secret });
    }
    if configs.is_empty() {
        return Err(anyhow!(
            "parsed shuffler configuration is empty; require {} entries",
            REQUIRED_SHUFFLER_COUNT
        ));
    }
    Ok(configs)
}

fn sample_shufflers(rng: &mut StdRng) -> Result<Vec<ShufflerSecretConfig<Curve>>> {
    let mut configs = Vec::with_capacity(REQUIRED_SHUFFLER_COUNT);
    for idx in 0..REQUIRED_SHUFFLER_COUNT {
        let secret = Scalar::rand(rng);
        configs.push(ShufflerSecretConfig {
            id: (idx + 1) as i64,
            secret,
        });
    }
    Ok(configs)
}

fn parse_scalar(input: &str) -> Result<Scalar> {
    let trimmed = input.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(without_prefix).context("invalid shuffler secret hex")?;
    if bytes.is_empty() {
        return Err(anyhow!("shuffler secret cannot be empty"));
    }
    Ok(Scalar::from_le_bytes_mod_order(&bytes))
}

fn seed_to_array(seed: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes
}
