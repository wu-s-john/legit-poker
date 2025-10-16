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
                debug!(
                    target = LOG_TARGET,
                    event = other,
                    "ignoring realtime event"
                );
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
            .ok_or_else(|| anyhow!("change payload missing `new` record"))?;

        let model: events::Model =
            serde_json::from_value(new_row).context("failed to deserialize events row")?;

        let envelope =
            model_to_envelope::<C>(model).context("failed to convert row to envelope")?;
        if let Some(shuffle) = into_shuffle_envelope(envelope)? {
            let _ = self.tx.send(shuffle);
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
    #[serde(rename = "postgres_changes")]
    postgres_changes: [PostgresChange<'a>; 1],
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
    new: Option<T>,
    #[serde(default)]
    _old: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
struct ReplyPayload {
    status: String,
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
