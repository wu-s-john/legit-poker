use anyhow::Result;
use futures::{SinkExt, StreamExt};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use tracing::info;
use tracing_subscriber::EnvFilter;

use zk_poker::db::{self, entity::test};

#[tokio::main]
async fn main() -> Result<()> {
    // Logging with file:line
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .init();

    dotenv::dotenv().ok();

    // SeaORM connection for typed reads/writes
    let conn = db::connect().await?;

    // Supabase Realtime subscription (WebSocket): prints INSERT/UPDATE with before/after
    // Requires (run once on the DB):
    //   alter publication supabase_realtime add table public.test;
    //   alter table public.test replica identity full;
    let supabase_url =
        std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:54321".into());
    let supabase_key = std::env::var("SUPABASE_ANON_KEY").expect("SUPABASE_ANON_KEY not set");
    let ws_url = to_realtime_ws(&supabase_url, &supabase_key);
    info!(target = "db", %ws_url, "connecting to supabase realtime");

    // Connect socket and split sink/source
    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url).await?;
    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // Join the realtime channel and subscribe to postgres changes for public.test
    let topic = format!("realtime:{}:{}", "public", "test");
    let join = JoinMessage::new_all_changes("public", "test", &supabase_key);
    ws_sink
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&join)?,
        ))
        .await?;

    // Heartbeats to keep socket alive
    tokio::spawn(async move {
        loop {
            let msg = PhoenixMessage::heartbeat();
            if ws_sink
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    serde_json::to_string(&msg).unwrap(),
                ))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
    });

    // Row type used for deserializing change payloads
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
    struct Row {
        foo: i32,
        bar: i32,
        baz: i32,
    }

    // Read messages; signal once join is acked so we don't write before subscribing
    let (join_tx, join_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut join_tx = Some(join_tx);
        while let Some(Ok(msg)) = ws_source.next().await {
            if let tokio_tungstenite::tungstenite::Message::Text(txt) = msg {
                // First, parse generically to see the event kind
                if let Ok(env) = serde_json::from_str::<IncomingMessage<serde_json::Value>>(&txt) {
                    match env.event.as_str() {
                        "phx_reply" => {
                            info!(target = "db", topic=%env.topic, payload=?env.payload, "realtime join reply");
                            if env.topic == topic {
                                if let Some(serde_json::Value::Object(obj)) = &env.payload {
                                    if let Some(serde_json::Value::String(status)) =
                                        obj.get("status")
                                    {
                                        if status == "ok" {
                                            if let Some(tx) = join_tx.take() {
                                                let _ = tx.send(());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "postgres_changes" => {
                            // Reparse as typed payload for changes
                            if let Ok(incoming) = serde_json::from_str::<
                                IncomingMessage<PgPayload<Change<Row>>>,
                            >(&txt)
                            {
                                if let Some(payload) = incoming.payload {
                                    if let Some(change) = payload.data {
                                        match change.event_type.as_str() {
                                            "INSERT" => {
                                                info!(target = "db", ?change.new, "inserted")
                                            }
                                            "UPDATE" => {
                                                info!(target = "db", ?change.old, ?change.new, "updated")
                                            }
                                            "DELETE" => {
                                                info!(target = "db", ?change.old, "deleted")
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            // Ignore other events quietly
                        }
                    }
                }
            }
        }
    });

    // Wait until the subscription is active before writing rows
    let _ = join_rx.await;

    // Demo: insert a row, then update foo value and observe before/after
    // Insert
    let am = test::ActiveModel {
        foo: Set(1),
        bar: Set(10),
        baz: Set(100),
    };
    let _ = am.insert(&conn).await?;
    info!(target = "db", "inserted row (foo=1, bar=10, baz=100)");

    // Update foo value (primary key) using SeaORM DSL
    use sea_orm::sea_query::Expr;
    test::Entity::update_many()
        .col_expr(test::Column::Foo, Expr::value(2))
        .filter(test::Column::Foo.eq(1))
        .exec(&conn)
        .await?;
    info!(target = "db", "updated foo from 1 -> 2");

    // Update bar for the new PK to show another change event
    test::Entity::update_many()
        .col_expr(test::Column::Bar, Expr::value(11))
        .filter(test::Column::Foo.eq(2))
        .exec(&conn)
        .await?;
    info!(target = "db", "updated bar for foo=2");

    // Keep the process alive to receive and print notifications
    info!(target = "db", "waiting 10s to receive realtime events...");
    for i in 1..=10 {
        info!(target = "db", "tick {}/10", i);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Ok(())
}

fn to_realtime_ws(api_url: &str, key: &str) -> String {
    let api = api_url.trim_end_matches('/');
    let ws = api
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    format!("{ws}/realtime/v1/websocket?apikey={key}&vsn=1.0.0")
}

#[derive(serde::Serialize)]
struct JoinMessage {
    topic: String,
    event: &'static str,
    payload: serde_json::Value,
    r#ref: &'static str,
}

impl JoinMessage {
    fn new_all_changes(schema: &str, table: &str, token: &str) -> Self {
        let payload = serde_json::json!({
            "config": {
                "broadcast": {"ack": false, "self": false},
                "postgres_changes": [
                    {"event": "*", "schema": schema, "table": table}
                ]
            },
            // Provide JWT so postgres_changes is authorized
            "access_token": token,
            "user_token": token
        });
        let topic = format!("realtime:{schema}:{table}");
        Self {
            topic,
            event: "phx_join",
            payload,
            r#ref: "1",
        }
    }
}

#[derive(serde::Serialize)]
struct PhoenixMessage<'a> {
    topic: &'a str,
    event: &'a str,
    payload: serde_json::Value,
    r#ref: &'a str,
}

impl<'a> PhoenixMessage<'a> {
    fn heartbeat() -> Self {
        Self {
            topic: "phoenix",
            event: "heartbeat",
            payload: serde_json::json!({}),
            r#ref: "hb",
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct IncomingMessage<T = serde_json::Value> {
    topic: String,
    event: String,
    payload: Option<T>,
    r#ref: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct PgPayload<T> {
    data: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
struct Change<T> {
    // Supabase may use either "eventType" or "type"
    #[serde(rename = "eventType", alias = "type")]
    event_type: String,
    schema: String,
    table: String,
    // And either "new"/"old" or "record"/"old_record"
    #[serde(rename = "new", alias = "record")]
    new: Option<T>,
    #[serde(rename = "old", alias = "old_record")]
    old: Option<T>,
}
