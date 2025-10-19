use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ark_ec::CurveGroup;
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::broadcast;
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;

use crate::{
    db::entity::events,
    ledger::{
        actor::{AnyActor, ShufflerActor},
        messages::{AnyGameMessage, AnyMessageEnvelope},
        store::event::model_to_envelope,
        EnvelopedMessage, GameShuffleMessage,
    },
    signing::WithSignature,
};

use crate::db::entity::sea_orm_active_enums::EventPhase;
use sea_orm::prelude::TimeDateTimeWithTimeZone;
use sea_orm::JsonValue;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const LOG_TARGET: &str = "game::coordinator::realtime";

#[derive(Debug, Clone)]
pub struct SupabaseRealtimeClientConfig {
    pub realtime_url: Url,
    pub api_key: String,
    pub schema: String,
    pub table: String,
    pub event: String,
    pub filter: String,
    pub handshake_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub reconnect_delay: Duration,
    pub broadcast_capacity: usize,
}

impl SupabaseRealtimeClientConfig {
    pub fn new(realtime_url: Url, api_key: impl Into<String>) -> Self {
        Self {
            realtime_url,
            api_key: api_key.into(),
            schema: "public".to_string(),
            table: "events".to_string(),
            event: "INSERT".to_string(),
            filter: "message_type=eq.shuffle".to_string(),
            handshake_timeout: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(15),
            reconnect_delay: Duration::from_secs(5),
            broadcast_capacity: 64,
        }
    }

    pub fn topic(&self) -> String {
        format!("realtime:{}:{}", self.schema, self.table)
    }
}

pub struct SupabaseRealtimeClient<C>
where
    C: CurveGroup,
{
    cfg: SupabaseRealtimeClientConfig,
    tx: broadcast::Sender<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    stop: CancellationToken,
}

impl<C> SupabaseRealtimeClient<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub fn broadcaster(&self) -> broadcast::Sender<EnvelopedMessage<C, GameShuffleMessage<C>>> {
        self.tx.clone()
    }

    pub fn new(
        cfg: SupabaseRealtimeClientConfig,
        stop: CancellationToken,
    ) -> (
        Self,
        broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    ) {
        let capacity = cfg.broadcast_capacity;
        let (tx, rx) = broadcast::channel(capacity);
        (Self { cfg, tx, stop }, rx)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EnvelopedMessage<C, GameShuffleMessage<C>>> {
        self.tx.subscribe()
    }

    pub async fn run(self) -> Result<()> {
        info!(target = LOG_TARGET, url = %self.cfg.realtime_url, "starting Supabase realtime client");
        while !self.stop.is_cancelled() {
            match self.connect().await {
                Ok(stream) => {
                    if let Err(err) = self.pump(stream).await {
                        warn!(target = LOG_TARGET, error = %err, "realtime stream ended with error");
                    }
                }
                Err(err) => {
                    warn!(target = LOG_TARGET, error = %err, "failed to connect to Supabase realtime");
                }
            }

            if self.stop.is_cancelled() {
                break;
            }

            debug!(
                target = LOG_TARGET,
                delay_secs = self.cfg.reconnect_delay.as_secs_f32(),
                "waiting before reconnect attempt"
            );
            sleep(self.cfg.reconnect_delay).await;
        }

        info!(target = LOG_TARGET, "Supabase realtime client stopped");
        Ok(())
    }

    async fn connect(&self) -> Result<WsStream> {
        let ws_url = self.cfg.realtime_url.to_string();
        let connect_fut = connect_async(ws_url.clone());
        let (stream, _) = timeout(self.cfg.handshake_timeout, connect_fut)
            .await
            .context("Supabase realtime handshake timed out")?
            .context("Supabase realtime handshake failed")?;

        Ok(stream)
    }

    async fn pump(&self, stream: WsStream) -> Result<()> {
        let (mut sink, mut source) = stream.split();

        let join_message = self.join_message()?;
        sink.send(Message::Text(join_message))
            .await
            .context("failed to send join message")?;

        let mut heartbeat = interval(self.cfg.heartbeat_interval);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let heartbeat_msg = heartbeat_message()?;
        let topic = self.cfg.topic();

        let mut joined = false;

        loop {
            tokio::select! {
                _ = self.stop.cancelled() => {
                    debug!(target = LOG_TARGET, "shutdown signal received");
                    break;
                }
                _ = heartbeat.tick() => {
                    if let Err(err) = sink.send(Message::Text(heartbeat_msg.clone())).await {
                        warn!(target = LOG_TARGET, error = %err, "heartbeat send failed, ending loop");
                        break;
                    }
                }
                msg = source.next() => {
                    match msg {
                        Some(Ok(Message::Text(txt))) => {
                            info!(target = LOG_TARGET, %txt, "received realtime text message");
                            if let Err(err) = self.handle_text(&topic, &mut joined, txt).await {
                                warn!(target = LOG_TARGET, error = %err, "failed to handle realtime message");
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            sink.send(Message::Pong(payload)).await.ok();
                        }
                        Some(Ok(Message::Close(frame))) => {
                            debug!(target = LOG_TARGET, ?frame, "socket closed by server");
                            break;
                        }
                        Some(Ok(_)) => {}
                        Some(Err(err)) => {
                            warn!(target = LOG_TARGET, error = %err, "websocket error");
                            break;
                        }
                        None => {
                            debug!(target = LOG_TARGET, "websocket stream ended");
                            break;
                        }
                    }
                }
            }
        }

        self.send_leave(&mut sink).await.ok();
        let _ = sink.close().await;

        Ok(())
    }

    async fn handle_text(&self, topic: &str, joined: &mut bool, txt: String) -> Result<()> {
        let message: IncomingMessage<Value> =
            serde_json::from_str(&txt).context("failed to deserialize realtime message")?;

        match message.event.as_str() {
            "phx_reply" => {
                if message.topic == topic {
                    if let Some(payload) = message.payload {
                        let reply: ReplyPayload = serde_json::from_value(payload)
                            .context("failed to decode phx_reply payload")?;
                        if reply.status == "ok" {
                            *joined = true;
                            debug!(target = LOG_TARGET, "subscription acknowledged");
                        } else {
                            warn!(
                                target = LOG_TARGET,
                                status = reply.status,
                                "subscription rejected"
                            );
                        }
                    }
                }
            }
            "postgres_changes" => {
                if !*joined {
                    debug!(target = LOG_TARGET, "ignoring change before join ack");
                    return Ok(());
                }
                if let Some(payload) = message.payload {
                    let payload: PgPayload<Change<Value>> = serde_json::from_value(payload)
                        .context("failed to parse postgres change payload")?;
                    if let Some(change) = payload.data {
                        self.handle_change(change).await?;
                    }
                }
            }
            other => {
                if other.eq_ignore_ascii_case("system") {
                    debug!(
                        target = LOG_TARGET,
                        event = other,
                        payload = ?message.payload,
                        "received realtime system event"
                    );
                } else {
                    debug!(
                        target = LOG_TARGET,
                        event = other,
                        "ignoring realtime event"
                    );
                }
            }
        }

        Ok(())
    }

    async fn handle_change(&self, change: Change<Value>) -> Result<()> {
        if !change
            .event_type
            .eq_ignore_ascii_case(self.cfg.event.as_str())
        {
            debug!(
                target = LOG_TARGET,
                event_type = %change.event_type,
                expected = %self.cfg.event,
                "skipping non-matching change"
            );
            return Ok(());
        }

        let new_row = change
            .new
            .ok_or_else(|| anyhow!("change payload missing `new`/`record` field"))?;

        let model = decode_event_row(new_row.clone())
            .with_context(|| anyhow!("failed to deserialize events row: {new_row:?}"))?;

        let finalized = model_to_envelope::<C>(model).map_err(|err| {
            tracing::error!(
                target = LOG_TARGET,
                error = %err,
                debug_error = ?err,
                "failed to convert realtime row into envelope"
            );
            err.context("failed to convert row to envelope")
        })?;
        match into_shuffle_envelope(finalized.envelope)? {
            Some(shuffle) => {
                let _ = self.tx.send(shuffle);
            }
            None => {
                debug!(
                    target = LOG_TARGET,
                    "filtered envelope from realtime change"
                );
            }
        }

        Ok(())
    }

    async fn send_leave(
        &self,
        sink: &mut futures::stream::SplitSink<WsStream, Message>,
    ) -> Result<()> {
        let leave = leave_message(self.cfg.topic())?;
        sink.send(Message::Text(leave))
            .await
            .context("failed to send leave message")
    }

    fn join_message(&self) -> Result<String> {
        let payload = JoinPayload {
            access_token: &self.cfg.api_key,
            user_token: &self.cfg.api_key,
            config: JoinConfig {
                broadcast: broadcast_defaults(),
                postgres_changes: [PostgresChange {
                    event: self.cfg.event.as_str(),
                    schema: self.cfg.schema.as_str(),
                    table: self.cfg.table.as_str(),
                    filter: self.cfg.filter.as_str(),
                }],
            },
        };

        let envelope = PhoenixEnvelope {
            topic: self.cfg.topic(),
            event: "phx_join",
            reference: "1",
            payload,
        };

        encode_message(&envelope)
    }
}

fn heartbeat_message() -> Result<String> {
    let envelope = PhoenixEnvelope {
        topic: "phoenix".to_string(),
        event: "heartbeat",
        reference: "hb",
        payload: EmptyPayload {},
    };
    encode_message(&envelope)
}

fn leave_message(topic: String) -> Result<String> {
    let envelope = PhoenixEnvelope {
        topic,
        event: "phx_leave",
        reference: "2",
        payload: EmptyPayload {},
    };
    encode_message(&envelope)
}

fn encode_message<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("failed to serialize realtime message")
}

#[derive(serde::Serialize)]
struct PhoenixEnvelope<T> {
    topic: String,
    event: &'static str,
    #[serde(rename = "ref")]
    reference: &'static str,
    payload: T,
}

#[derive(serde::Serialize)]
struct EmptyPayload {}

#[derive(serde::Serialize)]
struct JoinPayload<'a> {
    access_token: &'a str,
    user_token: &'a str,
    config: JoinConfig<'a>,
}

#[derive(serde::Serialize)]
struct JoinConfig<'a> {
    #[serde(default = "broadcast_defaults")]
    broadcast: BroadcastConfig,
    #[serde(rename = "postgres_changes")]
    postgres_changes: [PostgresChange<'a>; 1],
}

fn broadcast_defaults() -> BroadcastConfig {
    BroadcastConfig {
        ack: false,
        self_notify: false,
    }
}

#[derive(serde::Serialize)]
struct BroadcastConfig {
    ack: bool,
    #[serde(rename = "self")]
    self_notify: bool,
}

#[derive(serde::Serialize)]
struct PostgresChange<'a> {
    event: &'a str,
    schema: &'a str,
    table: &'a str,
    filter: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct IncomingMessage<T = Value> {
    topic: String,
    event: String,
    #[serde(rename = "ref")]
    _ref: Option<String>,
    payload: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
struct PgPayload<T> {
    data: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
struct Change<T> {
    #[serde(default)]
    _schema: String,
    #[serde(default)]
    _table: String,
    #[serde(rename = "commit_timestamp")]
    _commit_timestamp: String,
    #[serde(rename = "eventType", alias = "type")]
    event_type: String,
    #[serde(default, rename = "new", alias = "record")]
    new: Option<T>,
    #[serde(default, rename = "old", alias = "old_record")]
    _old: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
struct ReplyPayload {
    status: String,
}

#[derive(Debug, serde::Deserialize)]
struct RawEventRow {
    id: i64,
    game_id: i64,
    hand_id: i64,
    entity_kind: i16,
    entity_id: i64,
    actor_kind: i16,
    seat_id: Option<i16>,
    shuffler_id: Option<i16>,
    public_key: String,
    nonce: i64,
    phase: String,
    snapshot_number: i32,
    is_successful: bool,
    failure_message: Option<String>,
    resulting_phase: String,
    message_type: String,
    payload: JsonValue,
    signature: String,
    inserted_at: String,
}

fn parse_bytea(input: &str) -> Result<Vec<u8>> {
    let trimmed = input
        .strip_prefix("\\x")
        .or_else(|| input.strip_prefix("\\\\x"))
        .unwrap_or(input);
    let mut bytes =
        hex::decode(trimmed).with_context(|| anyhow!("failed to decode bytea value: {input}"))?;
    if looks_like_ascii_hex(&bytes) {
        if let Ok(ascii) = std::str::from_utf8(&bytes) {
            match hex::decode(ascii) {
                Ok(decoded) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        original_len = bytes.len(),
                        "bytea payload contained nested hex, normalizing"
                    );
                    bytes = decoded;
                }
                Err(err) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        error = %err,
                        "failed to normalize nested hex bytea payload; leaving as-is"
                    );
                }
            }
        }
    }
    Ok(bytes)
}

fn looks_like_ascii_hex(bytes: &[u8]) -> bool {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return false;
    }
    bytes.iter().all(|byte| {
        matches!(
            byte,
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'
        )
    })
}

fn decode_event_row(value: Value) -> Result<events::Model> {
    let raw: RawEventRow =
        serde_json::from_value(value).context("failed to parse change row fields")?;

    let public_key = parse_bytea(&raw.public_key)?;
    let signature = parse_bytea(&raw.signature)?;

    let phase = parse_event_phase(&raw.phase)?;
    let resulting_phase = parse_event_phase(&raw.resulting_phase)?;

    let inserted_at: TimeDateTimeWithTimeZone =
        OffsetDateTime::parse(&raw.inserted_at, &Rfc3339)
            .with_context(|| anyhow!("invalid timestamp {}", raw.inserted_at))?;

    Ok(events::Model {
        id: raw.id,
        game_id: raw.game_id,
        hand_id: raw.hand_id,
        entity_kind: raw.entity_kind,
        entity_id: raw.entity_id,
        actor_kind: raw.actor_kind,
        seat_id: raw.seat_id,
        shuffler_id: raw.shuffler_id,
        public_key,
        nonce: raw.nonce,
        phase,
        snapshot_number: raw.snapshot_number,
        is_successful: raw.is_successful,
        failure_message: raw.failure_message,
        resulting_phase,
        message_type: raw.message_type,
        payload: raw.payload,
        signature,
        inserted_at,
    })
}

fn parse_event_phase(value: &str) -> Result<EventPhase> {
    match value {
        "pending" => Ok(EventPhase::Pending),
        "shuffling" => Ok(EventPhase::Shuffling),
        "dealing" => Ok(EventPhase::Dealing),
        "betting" => Ok(EventPhase::Betting),
        "reveals" => Ok(EventPhase::Reveals),
        "showdown" => Ok(EventPhase::Showdown),
        "complete" => Ok(EventPhase::Complete),
        "cancelled" => Ok(EventPhase::Cancelled),
        other => Err(anyhow!("invalid phase {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_bytea_handles_nested_hex() {
        let raw = "\\x35313166363666626532326530623265323864636535666466333734646261323265633564343864343264316366643732336639636564383662666563313864";
        let decoded = parse_bytea(raw).expect("decode succeeds");
        assert_eq!(
            hex::encode(decoded),
            "511f66fbe22e0b2e28dce5fdf374dba22ec5d48d42d1cfd723f9ced86bfec18d"
        );
    }

    #[test]
    fn decode_event_row_decodes_hex_bytea() {
        let raw = json!({
            "id": 1,
            "hand_id": 7,
            "entity_kind": 2,
            "entity_id": 3,
            "actor_kind": 4,
            "seat_id": null,
            "shuffler_id": 5,
            "public_key": "\\x010203",
            "nonce": 42,
            "phase": "shuffling",
            "message_type": "shuffle",
            "payload": {"foo": "bar"},
            "signature": "\\x0a0b0c",
            "inserted_at": "2025-10-17T00:00:00Z"
        });

        let model = decode_event_row(raw).expect("decode succeeds");
        assert_eq!(model.id, 1);
        assert_eq!(model.hand_id, 7);
        assert_eq!(model.public_key, vec![1, 2, 3]);
        assert_eq!(model.signature, vec![10, 11, 12]);
        assert_eq!(model.phase, EventPhase::Shuffling);
        assert_eq!(model.message_type, "shuffle");
        assert_eq!(model.payload, json!({"foo": "bar"}));
        assert_eq!(
            model.inserted_at.format(&Rfc3339).unwrap(),
            "2025-10-17T00:00:00Z"
        );
    }
}

fn into_shuffle_envelope<C>(
    envelope: AnyMessageEnvelope<C>,
) -> Result<Option<EnvelopedMessage<C, GameShuffleMessage<C>>>>
where
    C: CurveGroup,
{
    let AnyMessageEnvelope {
        hand_id,
        game_id,
        actor,
        nonce,
        public_key,
        message,
    } = envelope;

    let WithSignature {
        value,
        signature,
        transcript,
    } = message;

    let shuffle_message = match value {
        AnyGameMessage::Shuffle(msg) => msg,
        other => {
            warn!(
                target = LOG_TARGET,
                message = ?other,
                "received non-shuffle message in shuffle subscription"
            );
            return Ok(None);
        }
    };

    let shuffler_actor = match actor {
        AnyActor::Shuffler { shuffler_id } => ShufflerActor { shuffler_id },
        other => {
            warn!(
                target = LOG_TARGET,
                actor = ?other,
                "received shuffle message with non-shuffler actor"
            );
            return Ok(None);
        }
    };

    let typed = EnvelopedMessage {
        hand_id,
        game_id,
        actor: shuffler_actor,
        nonce,
        public_key,
        message: WithSignature {
            value: shuffle_message,
            signature,
            transcript,
        },
    };

    Ok(Some(typed))
}
