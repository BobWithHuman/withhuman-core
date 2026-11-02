use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use withhuman_common::chunking::sha256;
use withhuman_contracts::decisions::DecisionResponse;

use crate::StoreError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredVerdict {
    pub decision: DecisionResponse,
    pub tool_name: String,
    /// SHA-256 of the authorized arguments' canonical JSON. The arguments themselves may hold
    /// secrets, so they are never stored.
    pub arguments_digest: String,
}

impl StoredVerdict {
    pub fn new(decision: DecisionResponse, tool_name: String, arguments: &Value) -> Self {
        Self {
            decision,
            tool_name,
            arguments_digest: arguments_digest(arguments),
        }
    }

    /// Whether `arguments` are exactly the authorized ones.
    pub fn authorizes(&self, arguments: &Value) -> bool {
        self.arguments_digest == arguments_digest(arguments)
    }
}

/// Equal JSON values share a digest whatever their key order.
fn arguments_digest(arguments: &Value) -> String {
    let mut canonical = String::new();
    write_canonical(arguments, &mut canonical);
    sha256(&canonical)
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(fields) => {
            let mut fields: Vec<_> = fields.iter().collect();
            fields.sort_by_key(|(name, _)| *name);
            out.push('{');
            for (index, (name, item)) in fields.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(name.clone()).to_string());
                out.push(':');
                write_canonical(item, out);
            }
            out.push('}');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// Verdicts written by the PreToolUse Hook and read by the AgentGateway extAuthz check.
#[async_trait]
pub trait VerdictStore: Send + Sync {
    async fn insert(&self, tool_use_id: String, verdict: StoredVerdict) -> Result<(), StoreError>;
    async fn get(&self, tool_use_id: &str) -> Result<Option<StoredVerdict>, StoreError>;
}

/// Single-instance store that evicts the oldest verdict beyond `capacity`.
#[derive(Debug, Clone)]
pub struct InMemoryVerdictStore {
    capacity: usize,
    inner: Arc<Mutex<Verdicts>>,
}

#[derive(Debug, Default)]
struct Verdicts {
    values: HashMap<String, StoredVerdict>,
    insertion_order: VecDeque<String>,
}

impl InMemoryVerdictStore {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "verdict capacity must be positive");
        Self {
            capacity,
            inner: Arc::default(),
        }
    }
}

#[async_trait]
impl VerdictStore for InMemoryVerdictStore {
    async fn insert(&self, tool_use_id: String, verdict: StoredVerdict) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if !inner.values.contains_key(&tool_use_id) {
            inner.insertion_order.push_back(tool_use_id.clone());
        }
        inner.values.insert(tool_use_id, verdict);
        while inner.values.len() > self.capacity {
            if let Some(expired) = inner.insertion_order.pop_front() {
                inner.values.remove(&expired);
            }
        }
        Ok(())
    }

    async fn get(&self, tool_use_id: &str) -> Result<Option<StoredVerdict>, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values
            .get(tool_use_id)
            .cloned())
    }
}

/// Verdicts shared by every Collector replica: the Hook and the extAuthz check of one tool call
/// come from different clients and may reach different replicas.
///
/// Verdicts expire after `ttl` instead of being evicted by count. `get` does not delete the
/// verdict (no `GETDEL`): AgentGateway may run extAuthz more than once for the same MCP call
/// (client retries, replays after a reconnect), and a consume-once read would deny those as
/// missing. Reuse is bounded by the TTL and by the tool name and argument match in extAuthz.
#[derive(Clone)]
pub struct RedisVerdictStore {
    connection: ConnectionManager,
    ttl_secs: u64,
}

impl RedisVerdictStore {
    pub fn new(connection: ConnectionManager, ttl: Duration) -> Self {
        Self {
            connection,
            ttl_secs: ttl.as_secs().max(1),
        }
    }
}

fn verdict_key(tool_use_id: &str) -> String {
    format!("withhuman:verdict:{tool_use_id}")
}

#[async_trait]
impl VerdictStore for RedisVerdictStore {
    async fn insert(&self, tool_use_id: String, verdict: StoredVerdict) -> Result<(), StoreError> {
        let value = serde_json::to_string(&verdict)?;
        redis::cmd("SET")
            .arg(verdict_key(&tool_use_id))
            .arg(value)
            .arg("EX")
            .arg(self.ttl_secs)
            .query_async::<()>(&mut self.connection.clone())
            .await?;
        Ok(())
    }

    async fn get(&self, tool_use_id: &str) -> Result<Option<StoredVerdict>, StoreError> {
        let value: Option<String> = redis::cmd("GET")
            .arg(verdict_key(tool_use_id))
            .query_async(&mut self.connection.clone())
            .await?;
        Ok(value
            .map(|value| serde_json::from_str(&value))
            .transpose()?)
    }
}
