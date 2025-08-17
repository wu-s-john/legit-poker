//! Transcript types and operations

use super::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A row in the unified transcript table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptRow {
    pub seq: i64,
    pub room_id: RoomId,
    pub ts: DateTime<Utc>,
    
    pub actor_type: ActorType,
    pub actor_id: String,
    
    pub category: Category,
    pub kind: String,
    
    pub correlation_id: CorrelationId,
    pub idempotency_key: Option<String>,
    
    pub payload: serde_json::Value,
    
    pub prev_hash: Option<HashHex>,
    pub hash: Option<HashHex>,
}

/// Thin wrapper for a room's transcript
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GameTranscript {
    pub room_id: RoomId,
    pub items: Vec<TranscriptRow>,
    pub last_seq: i64,
}

impl GameTranscript {
    pub fn new(room_id: RoomId) -> Self {
        Self {
            room_id,
            items: Vec::new(),
            last_seq: 0,
        }
    }
    
    pub fn push(&mut self, row: TranscriptRow) {
        self.last_seq = self.last_seq.max(row.seq);
        self.items.push(row);
    }
    
    /// Get all rows for a specific correlation_id
    pub fn by_correlation(&self, correlation_id: &str) -> Vec<&TranscriptRow> {
        self.items
            .iter()
            .filter(|row| row.correlation_id == correlation_id)
            .collect()
    }
    
    /// Get the latest row for a correlation_id
    pub fn latest_by_correlation(&self, correlation_id: &str) -> Option<&TranscriptRow> {
        self.items
            .iter()
            .rev()
            .find(|row| row.correlation_id == correlation_id)
    }
}

/// Parameters for appending to transcript
#[derive(Debug, Clone)]
pub struct AppendParams {
    pub room_id: RoomId,
    pub actor_type: ActorType,
    pub actor_id: String,
    pub kind: String,
    pub payload: serde_json::Value,
    pub correlation_id: Option<CorrelationId>,
    pub idempotency_key: Option<String>,
}