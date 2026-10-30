use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, LazyLock, Mutex, MutexGuard},
    time::Duration,
};

use async_trait::async_trait;
use redis::{Script, aio::ConnectionManager};
use serde_json::Value;
use withhuman_contracts::events::{SessionCursor, SidePending};

use crate::StoreError;

/// Everything one emitted event changes in its session. A store applies it together with the
/// order reservation as one atomic step, so concurrent events of a session (possibly on other
/// replicas) never share an order or an agent sequence.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionUpdate {
    /// Replaces the session cwd when set.
    pub cwd: Option<String>,
    /// Replaces the session prompt id when set.
    pub prompt_id: Option<String>,
    /// Remembers a PreToolUse input until its result arrives: `(tool_use_id, tool_input)`.
    pub store_tool_input: Option<(String, Value)>,
    /// Removes and returns the input remembered for this tool_use_id.
    pub take_tool_input: Option<String>,
    /// Advances and returns this agent's sequence.
    pub agent_id: Option<String>,
    /// Adds the final fragment, then assembles and removes the message buffer.
    pub finish_message: Option<MessageFragment>,
    /// Remembers paths a command saves downloaded content to, so later reads of them count as
    /// external content.
    pub record_downloads: Vec<String>,
}

/// One MessageDisplay flush. Fragments are assembled by `index`, so retried or reordered
/// deliveries still produce the streamed text; without an index they join in arrival order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageFragment {
    pub message_id: String,
    pub index: Option<u64>,
    pub delta: String,
}

/// The session as seen by the event right after its [`SessionUpdate`] was applied.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionSnapshot {
    pub order: u64,
    pub cwd: Option<String>,
    pub prompt_id: Option<String>,
    pub side_pending: SidePending,
    pub agent_sequence: Option<u64>,
    pub tool_input: Option<Value>,
    pub message: Option<String>,
    /// The assembled message misses a fragment index below the final one.
    pub message_incomplete: bool,
    /// Every path the session downloaded content to, sorted.
    pub downloads: Vec<String>,
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Applies `update` and reserves the session's next order atomically. Fails with
    /// [`StoreError::UnknownSession`], changing nothing, until the session is [seeded].
    ///
    /// [seeded]: SessionStore::seed
    async fn apply_event(
        &self,
        session_id: &str,
        update: SessionUpdate,
    ) -> Result<SessionSnapshot, StoreError>;

    /// Starts a session this store holds no state for from `cursor`: the next order is
    /// `cursor.last_order + 1`, each agent continues after its sequence, and the cwd and prompt
    /// id are restored. A session that is already seeded, possibly by another replica, keeps
    /// its state.
    async fn seed(&self, session_id: &str, cursor: &SessionCursor) -> Result<(), StoreError>;

    /// Buffers a non-final message fragment; it reserves no order.
    async fn append_fragment(
        &self,
        session_id: &str,
        fragment: MessageFragment,
    ) -> Result<(), StoreError>;

    async fn set_side_pending(
        &self,
        session_id: &str,
        pending: SidePending,
    ) -> Result<(), StoreError>;
}

/// Single-instance store holding every session in process memory.
#[derive(Debug, Clone, Default)]
pub struct InMemorySessionStore {
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
}

impl InMemorySessionStore {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, SessionState>> {
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn apply_event(
        &self,
        session_id: &str,
        update: SessionUpdate,
    ) -> Result<SessionSnapshot, StoreError> {
        let mut sessions = self.lock();
        let Some(state) = sessions
            .get_mut(session_id)
            .filter(|state| state.last_order.is_some())
        else {
            return Err(StoreError::UnknownSession);
        };
        if update.cwd.is_some() {
            state.cwd = update.cwd;
        }
        if update.prompt_id.is_some() {
            state.prompt_id = update.prompt_id;
        }
        if let Some((tool_use_id, tool_input)) = update.store_tool_input {
            state.tool_inputs.insert(tool_use_id, tool_input);
        }
        let tool_input = update
            .take_tool_input
            .and_then(|tool_use_id| state.tool_inputs.remove(&tool_use_id));
        let agent_sequence = update.agent_id.map(|agent_id| {
            let sequence = state.agent_sequences.entry(agent_id).or_default();
            *sequence += 1;
            *sequence
        });
        let message = update.finish_message.map(|fragment| {
            let message_id = fragment.message_id.clone();
            state.add_fragment(fragment);
            let pieces = state
                .message_fragments
                .remove(&message_id)
                .unwrap_or_default();
            let incomplete = pieces.keys().copied().ne(0..pieces.len() as u64);
            (pieces.into_values().collect::<String>(), incomplete)
        });
        state.downloads.extend(update.record_downloads);
        let order = state.last_order.unwrap_or_default() + 1;
        state.last_order = Some(order);
        Ok(SessionSnapshot {
            order,
            cwd: state.cwd.clone(),
            prompt_id: state.prompt_id.clone(),
            side_pending: state.side_pending.clone(),
            agent_sequence,
            tool_input,
            message_incomplete: message.as_ref().is_some_and(|(_, incomplete)| *incomplete),
            message: message.map(|(text, _)| text),
            downloads: state.downloads.iter().cloned().collect(),
        })
    }

    async fn seed(&self, session_id: &str, cursor: &SessionCursor) -> Result<(), StoreError> {
        let mut sessions = self.lock();
        let state = sessions.entry(session_id.to_owned()).or_default();
        if state.last_order.is_none() {
            state.last_order = Some(cursor.last_order);
            state.cwd = cursor.cwd.clone();
            state.prompt_id = cursor.prompt_id.clone();
            for (agent_id, sequence) in &cursor.agent_sequences {
                state
                    .agent_sequences
                    .entry(agent_id.clone())
                    .or_insert(*sequence);
            }
        }
        Ok(())
    }

    async fn append_fragment(
        &self,
        session_id: &str,
        fragment: MessageFragment,
    ) -> Result<(), StoreError> {
        self.lock()
            .entry(session_id.to_owned())
            .or_default()
            .add_fragment(fragment);
        Ok(())
    }

    async fn set_side_pending(
        &self,
        session_id: &str,
        pending: SidePending,
    ) -> Result<(), StoreError> {
        self.lock()
            .entry(session_id.to_owned())
            .or_default()
            .side_pending = pending;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct SessionState {
    /// `None` until the session is seeded.
    last_order: Option<u64>,
    cwd: Option<String>,
    prompt_id: Option<String>,
    message_fragments: HashMap<String, BTreeMap<u64, String>>,
    tool_inputs: HashMap<String, Value>,
    agent_sequences: HashMap<String, u64>,
    side_pending: SidePending,
    downloads: BTreeSet<String>,
}

impl SessionState {
    /// Stores a fragment at its index (a repeated index replaces it); without an index it is
    /// numbered after the fragments already buffered.
    fn add_fragment(&mut self, fragment: MessageFragment) {
        let pieces = self
            .message_fragments
            .entry(fragment.message_id)
            .or_default();
        let index = fragment.index.unwrap_or(pieces.len() as u64);
        pieces.insert(index, fragment.delta);
    }
}

/// Applies one event's [`SessionUpdate`] and reserves its order in a single script run, so
/// replicas sharing Redis serialize per session exactly like the in-memory mutex does.
///
/// KEYS: session hash, tool input to store, tool input to take, message buffer, download set.
/// ARGV: ttl, then presence flag and value for cwd, prompt_id, stored tool input, taken tool
/// input (flag only), agent id, the final fragment (flag, index flag, index, delta), and the
/// downloaded paths to record. Flags keep `Some("")` distinct from `None`. An unseeded session
/// returns order 0 and writes nothing.
const APPLY_EVENT: &str = r"
local session = KEYS[1]
if redis.call('HEXISTS', session, 'next_order') == 0 then
  return {0, false, false, false, false, false, false, 0, {}}
end
local ttl = tonumber(ARGV[1])
if ARGV[2] == '1' then redis.call('HSET', session, 'cwd', ARGV[3]) end
if ARGV[4] == '1' then redis.call('HSET', session, 'prompt_id', ARGV[5]) end
if ARGV[6] == '1' then redis.call('SET', KEYS[2], ARGV[7], 'EX', ttl) end
local tool_input = false
if ARGV[8] == '1' then
  tool_input = redis.call('GET', KEYS[3])
  redis.call('DEL', KEYS[3])
end
local sequence = false
if ARGV[9] == '1' then sequence = redis.call('HINCRBY', session, 'agent:' .. ARGV[10], 1) end
local message = false
local incomplete = 0
if ARGV[11] == '1' then
  local index = ARGV[13]
  if ARGV[12] ~= '1' then index = tostring(redis.call('HLEN', KEYS[4])) end
  redis.call('HSET', KEYS[4], index, ARGV[14])
  local pieces = redis.call('HGETALL', KEYS[4])
  local indexes, deltas = {}, {}
  for i = 1, #pieces, 2 do
    local n = tonumber(pieces[i])
    indexes[#indexes + 1] = n
    deltas[n] = pieces[i + 1]
  end
  table.sort(indexes)
  local parts = {}
  for i, n in ipairs(indexes) do
    if n ~= i - 1 then incomplete = 1 end
    parts[i] = deltas[n]
  end
  message = table.concat(parts)
  redis.call('DEL', KEYS[4])
end
for i = 15, #ARGV do redis.call('SADD', KEYS[5], ARGV[i]) end
redis.call('EXPIRE', KEYS[5], ttl)
local downloads = redis.call('SMEMBERS', KEYS[5])
local order = redis.call('HINCRBY', session, 'next_order', 1)
redis.call('EXPIRE', session, ttl)
local fields = redis.call('HMGET', session, 'cwd', 'prompt_id', 'side_pending')
return {order, fields[1], fields[2], fields[3], sequence, tool_input, message, incomplete, downloads}
";

/// KEYS: session hash. ARGV: ttl, last order, presence flag and value for cwd and prompt_id,
/// then agent id and sequence pairs. Only the first replica to seed a session sets its state.
const SEED_SESSION: &str = r"
if redis.call('HSETNX', KEYS[1], 'next_order', ARGV[2]) == 1 then
  if ARGV[3] == '1' then redis.call('HSETNX', KEYS[1], 'cwd', ARGV[4]) end
  if ARGV[5] == '1' then redis.call('HSETNX', KEYS[1], 'prompt_id', ARGV[6]) end
  for i = 7, #ARGV, 2 do
    redis.call('HSETNX', KEYS[1], 'agent:' .. ARGV[i], ARGV[i + 1])
  end
end
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
";

/// KEYS: message buffer. ARGV: ttl, index flag, index, delta.
const APPEND_FRAGMENT: &str = r"
local index = ARGV[3]
if ARGV[2] ~= '1' then index = tostring(redis.call('HLEN', KEYS[1])) end
redis.call('HSET', KEYS[1], index, ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
";

static APPLY_EVENT_SCRIPT: LazyLock<Script> = LazyLock::new(|| Script::new(APPLY_EVENT));
static SEED_SESSION_SCRIPT: LazyLock<Script> = LazyLock::new(|| Script::new(SEED_SESSION));
static APPEND_FRAGMENT_SCRIPT: LazyLock<Script> = LazyLock::new(|| Script::new(APPEND_FRAGMENT));

/// Session state shared by every Collector replica. Each session lives in one hash; tool inputs
/// and message buffers are separate keys. Every key expires after `ttl` without activity.
///
/// The session id is a Redis Cluster hash tag (`{...}`), so all keys of a session share a slot
/// and the script may touch them together.
#[derive(Clone)]
pub struct RedisSessionStore {
    connection: ConnectionManager,
    ttl_secs: u64,
}

impl RedisSessionStore {
    pub fn new(connection: ConnectionManager, ttl: Duration) -> Self {
        Self {
            connection,
            ttl_secs: ttl.as_secs().max(1),
        }
    }
}

fn session_key(session_id: &str) -> String {
    format!("withhuman:session:{{{session_id}}}")
}

fn tool_input_key(session_id: &str, tool_use_id: &str) -> String {
    format!("{}:tool_input:{tool_use_id}", session_key(session_id))
}

fn fragment_key(session_id: &str, message_id: &str) -> String {
    format!("{}:fragment:{message_id}", session_key(session_id))
}

fn downloads_key(session_id: &str) -> String {
    format!("{}:downloads", session_key(session_id))
}

fn flag<T>(value: &Option<T>) -> &'static str {
    if value.is_some() { "1" } else { "0" }
}

type ApplyEventReply = (
    u64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<u64>,
    Option<String>,
    Option<String>,
    u8,
    Vec<String>,
);

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn apply_event(
        &self,
        session_id: &str,
        update: SessionUpdate,
    ) -> Result<SessionSnapshot, StoreError> {
        let stored_tool_input = update
            .store_tool_input
            .as_ref()
            .map(|(tool_use_id, input)| {
                Ok::<_, StoreError>((tool_use_id, serde_json::to_string(input)?))
            })
            .transpose()?;
        let (store_id, store_value) = stored_tool_input
            .as_ref()
            .map_or(("", ""), |(id, value)| (id.as_str(), value.as_str()));
        let take_id = update.take_tool_input.as_deref().unwrap_or_default();
        let fragment = update.finish_message.clone().unwrap_or_default();

        let mut invocation = APPLY_EVENT_SCRIPT.key(session_key(session_id));
        invocation
            .key(tool_input_key(session_id, store_id))
            .key(tool_input_key(session_id, take_id))
            .key(fragment_key(session_id, &fragment.message_id))
            .key(downloads_key(session_id))
            .arg(self.ttl_secs)
            .arg(flag(&update.cwd))
            .arg(update.cwd.as_deref().unwrap_or_default())
            .arg(flag(&update.prompt_id))
            .arg(update.prompt_id.as_deref().unwrap_or_default())
            .arg(flag(&stored_tool_input))
            .arg(store_value)
            .arg(flag(&update.take_tool_input))
            .arg(flag(&update.agent_id))
            .arg(update.agent_id.as_deref().unwrap_or_default())
            .arg(flag(&update.finish_message))
            .arg(flag(&fragment.index))
            .arg(fragment.index.unwrap_or_default())
            .arg(&fragment.delta);
        for path in &update.record_downloads {
            invocation.arg(path);
        }
        let (
            order,
            cwd,
            prompt_id,
            side_pending,
            agent_sequence,
            tool_input,
            message,
            incomplete,
            mut downloads,
        ): ApplyEventReply = invocation
            .invoke_async(&mut self.connection.clone())
            .await?;
        downloads.sort();
        if order == 0 {
            return Err(StoreError::UnknownSession);
        }

        Ok(SessionSnapshot {
            order,
            cwd,
            prompt_id,
            side_pending: side_pending
                .map(|value| serde_json::from_str(&value))
                .transpose()?
                .unwrap_or_default(),
            agent_sequence,
            tool_input: tool_input
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            message,
            message_incomplete: incomplete == 1,
            downloads,
        })
    }

    async fn seed(&self, session_id: &str, cursor: &SessionCursor) -> Result<(), StoreError> {
        let mut invocation = SEED_SESSION_SCRIPT.key(session_key(session_id));
        invocation
            .arg(self.ttl_secs)
            .arg(cursor.last_order)
            .arg(flag(&cursor.cwd))
            .arg(cursor.cwd.as_deref().unwrap_or_default())
            .arg(flag(&cursor.prompt_id))
            .arg(cursor.prompt_id.as_deref().unwrap_or_default());
        for (agent_id, sequence) in &cursor.agent_sequences {
            invocation.arg(agent_id).arg(sequence);
        }
        invocation
            .invoke_async::<()>(&mut self.connection.clone())
            .await?;
        Ok(())
    }

    async fn append_fragment(
        &self,
        session_id: &str,
        fragment: MessageFragment,
    ) -> Result<(), StoreError> {
        APPEND_FRAGMENT_SCRIPT
            .key(fragment_key(session_id, &fragment.message_id))
            .arg(self.ttl_secs)
            .arg(flag(&fragment.index))
            .arg(fragment.index.unwrap_or_default())
            .arg(&fragment.delta)
            .invoke_async::<()>(&mut self.connection.clone())
            .await?;
        Ok(())
    }

    async fn set_side_pending(
        &self,
        session_id: &str,
        pending: SidePending,
    ) -> Result<(), StoreError> {
        let key = session_key(session_id);
        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&key)
            .arg("side_pending")
            .arg(serde_json::to_string(&pending)?)
            .ignore()
            .cmd("EXPIRE")
            .arg(&key)
            .arg(self.ttl_secs)
            .ignore()
            .query_async::<()>(&mut self.connection.clone())
            .await?;
        Ok(())
    }
}
