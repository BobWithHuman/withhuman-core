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
    /// How the event takes part in the session-wide sequences.
    pub sequence_step: SequenceStep,
    /// Forgets the stated intent of the previous turn (a new prompt).
    pub clear_intent: bool,
}

/// How an event moves the session-wide sequence numbering (see
/// [`SessionSnapshot::session_sequence`]). Numbers are shared by the whole session, but the main
/// agent and each subagent keep their own open sequence, so a subagent's calls never join the
/// main agent's sequence or the other way round.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SequenceStep {
    /// Stays in the main agent's current sequence (sequence 0 before any other): session start,
    /// config and file changes, subagent lifecycle, tool descriptions, and Instructions — before
    /// the first Message they belong to sequence 0, later to the sequence that is open.
    #[default]
    Join,
    /// SubagentStart: joins like [`SequenceStep::Join`] and makes the agent's later calls a
    /// subagent's. Calls of an agent_id that never started (the main agent's) stay in the main
    /// agent's sequences.
    SubagentStart(String),
    /// A user prompt: sequence 0 for the first one, otherwise a sequence of its own. It ends the
    /// turn's calls, messages and subagent sequences.
    Request,
    /// A completed assistant message, by message_id: opens a sequence, or joins one a Call opened
    /// before the message arrived. A repeated message_id gets the sequence it got the first time.
    Message(String),
    /// A tool call: joins its agent's open sequence or opens one; remembered for its result.
    Call {
        tool_use_id: String,
        agent_id: Option<String>,
    },
    /// A tool result: the sequence of its Call.
    Result {
        tool_use_id: String,
        agent_id: Option<String>,
    },
    /// PostToolBatch: the sequence of its calls, which it closes if it is still its agent's open
    /// sequence (a repeated or late batch closes nothing).
    Batch {
        agent_id: Option<String>,
        tool_use_ids: Vec<String>,
    },
}

/// One MessageDisplay flush. Fragments are assembled by `index`, so retried or reordered
/// deliveries still produce the streamed text; without an index they join in arrival order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageFragment {
    pub message_id: String,
    pub index: Option<u64>,
    pub delta: String,
    /// The user intent the fragment states, kept as the session's current intent.
    pub intent: Option<String>,
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
    /// The session-wide sequence the event belongs to.
    pub session_sequence: u64,
    /// The user intent stated in the current turn.
    pub intent: Option<String>,
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
    /// `cursor.last_order + 1`, each agent continues after its sequence, sequences continue
    /// after the last one in a new sequence, and the cwd, prompt id and intent are restored. A
    /// session that is already seeded, possibly by another replica, keeps its state.
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
        let stated_intent = update
            .finish_message
            .as_ref()
            .and_then(|fragment| fragment.intent.clone());
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
        if update.clear_intent {
            state.intent = None;
        }
        if state.intent.is_none() {
            state.intent = stated_intent;
        }
        let session_sequence = state.sequences.step(&update.sequence_step);
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
            session_sequence,
            intent: state.intent.clone(),
        })
    }

    async fn seed(&self, session_id: &str, cursor: &SessionCursor) -> Result<(), StoreError> {
        let mut sessions = self.lock();
        let state = sessions.entry(session_id.to_owned()).or_default();
        if state.last_order.is_none() {
            state.last_order = Some(cursor.last_order);
            state.cwd = cursor.cwd.clone();
            state.prompt_id = cursor.prompt_id.clone();
            // A fragment buffered before the seed may already have stated this turn's intent.
            if state.intent.is_none() {
                state.intent.clone_from(&cursor.intent);
            }
            state.sequences = Sequences::resume(cursor);
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
        let mut sessions = self.lock();
        let state = sessions.entry(session_id.to_owned()).or_default();
        if state.intent.is_none() {
            state.intent.clone_from(&fragment.intent);
        }
        state.add_fragment(fragment);
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
    sequences: Sequences,
    intent: Option<String>,
}

/// Session-wide sequence numbering for the in-memory store; the Redis script mirrors it.
#[derive(Debug, Default)]
struct Sequences {
    /// The latest sequence number handed out.
    last: Option<u64>,
    /// Sequence 0 is still collecting the first Request and Instructions.
    zero: bool,
    zero_has_request: bool,
    main: Lane,
    /// Subagents' sequences, by agent_id.
    agents: HashMap<String, Lane>,
    /// Sequences of the turn's calls, by tool_use_id, until their batch.
    calls: HashMap<String, u64>,
    /// Sequences of the turn's messages, by message_id.
    messages: HashMap<String, u64>,
    /// Agents a SubagentStart announced.
    subagents: BTreeSet<String>,
}

/// One agent's latest sequence.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Lane {
    current: Option<u64>,
    /// A Message or Call opened it and no PostToolBatch closed it.
    open: bool,
    has_message: bool,
    has_call: bool,
}

impl Sequences {
    /// Continues the committed numbering inside the main agent's latest sequence. A session
    /// with history but no numbered sequence (committed before sequences existed) starts after
    /// sequence 0, which belongs to a session's first prompt.
    fn resume(cursor: &SessionCursor) -> Self {
        let (last, sequences) = (cursor.last_sequence, &cursor.sequences);
        if last.is_none() && cursor.last_order > 0 {
            return Self {
                last: Some(0),
                zero_has_request: true,
                main: Lane {
                    current: Some(0),
                    ..Lane::default()
                },
                ..Default::default()
            };
        }
        let cursor = sequences;
        Self {
            last,
            zero: last == Some(0),
            zero_has_request: cursor.zero_has_request,
            main: Lane {
                current: cursor.current.or(last),
                open: cursor.open,
                has_message: cursor.has_message,
                has_call: cursor.has_call,
            },
            calls: cursor.calls.clone().into_iter().collect(),
            ..Default::default()
        }
    }

    fn step(&mut self, step: &SequenceStep) -> u64 {
        match step {
            SequenceStep::Join => self.current(),
            SequenceStep::SubagentStart(agent_id) => {
                self.subagents.insert(agent_id.clone());
                self.current()
            }
            SequenceStep::Request => match self.last {
                None => {
                    self.start_zero();
                    self.zero_has_request = true;
                    0
                }
                Some(0) if self.zero && !self.zero_has_request => {
                    self.zero_has_request = true;
                    0
                }
                Some(_) => {
                    let number = self.next();
                    self.main = Lane {
                        current: Some(number),
                        ..Lane::default()
                    };
                    self.agents.clear();
                    self.calls.clear();
                    self.messages.clear();
                    number
                }
            },
            SequenceStep::Message(message_id) => {
                if let Some(number) = self.messages.get(message_id) {
                    return *number;
                }
                let number = if self.main.open && !self.main.has_message {
                    self.main.has_message = true;
                    self.current()
                } else {
                    self.open(&None, true)
                };
                self.messages.insert(message_id.clone(), number);
                number
            }
            SequenceStep::Call {
                tool_use_id,
                agent_id,
            } => {
                let number = if self.lane(agent_id).open {
                    self.lane_current(agent_id)
                } else {
                    self.open(agent_id, false)
                };
                self.lane(agent_id).has_call = true;
                self.calls.insert(tool_use_id.clone(), number);
                number
            }
            SequenceStep::Result {
                tool_use_id,
                agent_id,
            } => match self.calls.get(tool_use_id) {
                Some(number) => *number,
                None => self.lane_current(agent_id),
            },
            SequenceStep::Batch {
                agent_id,
                tool_use_ids,
            } => {
                let mapped = tool_use_ids
                    .iter()
                    .find_map(|tool_use_id| self.calls.get(tool_use_id).copied());
                for tool_use_id in tool_use_ids {
                    self.calls.remove(tool_use_id);
                }
                let current = self.lane_current(agent_id);
                let lane = self.lane(agent_id);
                let (number, closes) = match mapped {
                    Some(number) => (number, current == number),
                    // A batch naming only calls already batched is a repeat or arrived late.
                    None if !tool_use_ids.is_empty() => (current, false),
                    // A batch that names no calls closes a sequence that has calls.
                    None => (current, lane.has_call),
                };
                if lane.open && closes {
                    lane.open = false;
                }
                number
            }
        }
    }

    fn lane(&mut self, agent_id: &Option<String>) -> &mut Lane {
        match agent_id {
            Some(agent_id) if self.subagents.contains(agent_id) => {
                self.agents.entry(agent_id.clone()).or_default()
            }
            _ => &mut self.main,
        }
    }

    /// The agent's latest sequence, or the main agent's before the agent has one.
    fn lane_current(&mut self, agent_id: &Option<String>) -> u64 {
        match self.lane(agent_id).current {
            Some(number) => number,
            None => self.current(),
        }
    }

    /// Opens a new sequence for the agent.
    fn open(&mut self, agent_id: &Option<String>, has_message: bool) -> u64 {
        let number = self.next();
        *self.lane(agent_id) = Lane {
            current: Some(number),
            open: true,
            has_message,
            has_call: false,
        };
        number
    }

    fn start_zero(&mut self) {
        self.last = Some(0);
        self.zero = true;
        self.main = Lane {
            current: Some(0),
            ..Lane::default()
        };
    }

    /// The main agent's current sequence.
    fn current(&mut self) -> u64 {
        match self.main.current.or(self.last) {
            Some(number) => number,
            None => {
                self.start_zero();
                0
            }
        }
    }

    /// A new number after the latest one; it ends sequence 0's collection.
    fn next(&mut self) -> u64 {
        let number = self.last.map_or(0, |last| last + 1);
        self.last = Some(number);
        self.zero = false;
        number
    }
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
/// input (flag only), agent id, the final fragment (flag, index flag, index, delta), the sequence
/// step (name, tool_use_id, message_id or newline-separated batch ids, and the lane's agent id),
/// the intent (clear flag, set flag, value), and the downloaded paths to record. Flags keep `Some("")` distinct from `None`. An unseeded session
/// returns order 0 and writes nothing.
const APPLY_EVENT: &str = r"
local session = KEYS[1]
if redis.call('HEXISTS', session, 'next_order') == 0 then
  return {0, false, false, false, false, false, false, 0, {}, 0, false}
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
-- Session-wide sequences, mirroring `Sequences` of the in-memory store. The main agent's
-- sequence lives in `seq_cur/open/msg/call`, a subagent's in `seqa:<agent_id>:cur/open/msg/call`;
-- `subagent:<agent_id>` marks the agents a SubagentStart announced.
local function hget(field) return redis.call('HGET', session, field) end
local function set(field, value) redis.call('HSET', session, field, value) end
local function start_zero()
  set('seq_last', 0); set('seq_zero', '1'); set('seq_cur', 0)
  set('seq_open', '0'); set('seq_msg', '0'); set('seq_call', '0')
end
local function current()
  local cur = hget('seq_cur') or hget('seq_last')
  if not cur then start_zero(); return 0 end
  return tonumber(cur)
end
local function next_number()
  local last = hget('seq_last')
  local number = 0
  if last then number = tonumber(last) + 1 end
  set('seq_last', number); set('seq_zero', '0')
  return number
end
-- Seeded before sequences were numbered: continue after sequence 0, like a resumed session.
if not hget('seq_last') and tonumber(redis.call('HGET', session, 'next_order')) > 0 then
  set('seq_last', 0); set('seq_zero', '0'); set('seq_zero_req', '1'); set('seq_cur', 0)
end
local step, step_id, agent = ARGV[15], ARGV[16], ARGV[17]
local lane = 'seq_'
if agent ~= '' and hget('subagent:' .. agent) then lane = 'seqa:' .. agent .. ':' end
local function lane_current()
  local cur = hget(lane .. 'cur')
  if cur then return tonumber(cur) end
  return current()
end
local function open(has_message)
  local number = next_number()
  set(lane .. 'cur', number); set(lane .. 'open', '1')
  set(lane .. 'msg', has_message); set(lane .. 'call', '0')
  return number
end
local session_sequence
if step == 'request' then
  local last = hget('seq_last')
  if not last then
    start_zero(); set('seq_zero_req', '1'); session_sequence = 0
  elseif last == '0' and hget('seq_zero') == '1' and hget('seq_zero_req') ~= '1' then
    set('seq_zero_req', '1'); session_sequence = 0
  else
    session_sequence = next_number()
    set('seq_cur', session_sequence); set('seq_open', '0'); set('seq_msg', '0'); set('seq_call', '0')
    for _, field in ipairs(redis.call('HKEYS', session)) do
      if string.sub(field, 1, 8) == 'seqcall:' or string.sub(field, 1, 7) == 'seqmsg:'
          or string.sub(field, 1, 5) == 'seqa:' then
        redis.call('HDEL', session, field)
      end
    end
  end
elseif step == 'message' then
  local seen = hget('seqmsg:' .. step_id)
  if seen then
    session_sequence = tonumber(seen)
  else
    if hget('seq_open') == '1' and hget('seq_msg') ~= '1' then
      set('seq_msg', '1'); session_sequence = current()
    else
      session_sequence = open('1')
    end
    set('seqmsg:' .. step_id, session_sequence)
  end
elseif step == 'call' then
  if hget(lane .. 'open') == '1' then
    session_sequence = lane_current()
  else
    session_sequence = open('0')
  end
  set(lane .. 'call', '1')
  set('seqcall:' .. step_id, session_sequence)
elseif step == 'result' then
  local mapped = hget('seqcall:' .. step_id)
  if mapped then session_sequence = tonumber(mapped) else session_sequence = lane_current() end
elseif step == 'subagent' then
  set('subagent:' .. step_id, '1'); session_sequence = current()
elseif step == 'batch' then
  local mapped = false
  for id in string.gmatch(step_id, '[^\n]+') do
    local value = hget('seqcall:' .. id)
    if value and not mapped then mapped = tonumber(value) end
    redis.call('HDEL', session, 'seqcall:' .. id)
  end
  local closes
  if mapped then
    session_sequence = mapped
    closes = lane_current() == mapped
  else
    -- Naming only calls already batched: a repeat or late batch closes nothing.
    session_sequence = lane_current()
    closes = step_id == '' and hget(lane .. 'call') == '1'
  end
  if hget(lane .. 'open') == '1' and closes then set(lane .. 'open', '0') end
else
  session_sequence = current()
end
if ARGV[18] == '1' then redis.call('HDEL', session, 'intent') end
-- The first intent the turn states is kept.
if ARGV[19] == '1' then redis.call('HSETNX', session, 'intent', ARGV[20]) end
for i = 21, #ARGV do redis.call('SADD', KEYS[5], ARGV[i]) end
redis.call('EXPIRE', KEYS[5], ttl)
local downloads = redis.call('SMEMBERS', KEYS[5])
local order = redis.call('HINCRBY', session, 'next_order', 1)
redis.call('EXPIRE', session, ttl)
local fields = redis.call('HMGET', session, 'cwd', 'prompt_id', 'side_pending', 'intent')
return {order, fields[1], fields[2], fields[3], sequence, tool_input, message, incomplete, downloads,
  session_sequence, fields[4]}
";

/// KEYS: session hash. ARGV: ttl, last order, presence flag and value for cwd, prompt_id, the
/// last sequence and the intent; the main agent's sequence (presence flag and number, open,
/// has message, has call, sequence 0 has its request); the count of pending calls and their
/// tool_use_id and sequence pairs; then agent id and sequence pairs. Only the first replica to
/// seed a session sets its state.
const SEED_SESSION: &str = r"
if redis.call('HSETNX', KEYS[1], 'next_order', ARGV[2]) == 1 then
  if ARGV[3] == '1' then redis.call('HSETNX', KEYS[1], 'cwd', ARGV[4]) end
  if ARGV[5] == '1' then redis.call('HSETNX', KEYS[1], 'prompt_id', ARGV[6]) end
  if ARGV[7] == '1' then
    redis.call('HSETNX', KEYS[1], 'seq_last', ARGV[8])
    if ARGV[8] == '0' then redis.call('HSETNX', KEYS[1], 'seq_zero', '1') end
  elseif tonumber(ARGV[2]) > 0 then
    -- History without numbered sequences: continue after sequence 0.
    redis.call('HSETNX', KEYS[1], 'seq_last', 0)
    redis.call('HSETNX', KEYS[1], 'seq_cur', 0)
    redis.call('HSETNX', KEYS[1], 'seq_zero_req', '1')
  end
  if ARGV[9] == '1' then redis.call('HSETNX', KEYS[1], 'intent', ARGV[10]) end
  if ARGV[11] == '1' then redis.call('HSETNX', KEYS[1], 'seq_cur', ARGV[12]) end
  redis.call('HSETNX', KEYS[1], 'seq_open', ARGV[13])
  redis.call('HSETNX', KEYS[1], 'seq_msg', ARGV[14])
  redis.call('HSETNX', KEYS[1], 'seq_call', ARGV[15])
  redis.call('HSETNX', KEYS[1], 'seq_zero_req', ARGV[16])
  local calls = tonumber(ARGV[17])
  for i = 18, 17 + calls * 2, 2 do
    redis.call('HSETNX', KEYS[1], 'seqcall:' .. ARGV[i], ARGV[i + 1])
  end
  for i = 18 + calls * 2, #ARGV, 2 do
    redis.call('HSETNX', KEYS[1], 'agent:' .. ARGV[i], ARGV[i + 1])
  end
end
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
";

/// KEYS: message buffer, session hash. ARGV: ttl, index flag, index, delta, intent flag, intent.
const APPEND_FRAGMENT: &str = r"
local index = ARGV[3]
if ARGV[2] ~= '1' then index = tostring(redis.call('HLEN', KEYS[1])) end
redis.call('HSET', KEYS[1], index, ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[1])
if ARGV[5] == '1' then
  redis.call('HSETNX', KEYS[2], 'intent', ARGV[6])
  redis.call('EXPIRE', KEYS[2], ARGV[1])
end
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
    u64,
    Option<String>,
);

/// The step name, its id and the lane's agent id the script reads for a [`SequenceStep`].
fn sequence_arguments(step: &SequenceStep) -> (&'static str, String, &str) {
    fn lane(agent_id: &Option<String>) -> &str {
        agent_id.as_deref().unwrap_or_default()
    }
    match step {
        SequenceStep::Join => ("join", String::new(), ""),
        SequenceStep::SubagentStart(agent_id) => ("subagent", agent_id.clone(), ""),
        SequenceStep::Request => ("request", String::new(), ""),
        SequenceStep::Message(message_id) => ("message", message_id.clone(), ""),
        SequenceStep::Call {
            tool_use_id,
            agent_id,
        } => ("call", tool_use_id.clone(), lane(agent_id)),
        SequenceStep::Result {
            tool_use_id,
            agent_id,
        } => ("result", tool_use_id.clone(), lane(agent_id)),
        SequenceStep::Batch {
            agent_id,
            tool_use_ids,
        } => ("batch", tool_use_ids.join("\n"), lane(agent_id)),
    }
}

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
        let (step, step_id, lane) = sequence_arguments(&update.sequence_step);
        invocation
            .arg(step)
            .arg(step_id)
            .arg(lane)
            .arg(if update.clear_intent { "1" } else { "0" })
            .arg(flag(&fragment.intent))
            .arg(fragment.intent.as_deref().unwrap_or_default());
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
            session_sequence,
            intent,
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
            session_sequence,
            intent,
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
            .arg(cursor.prompt_id.as_deref().unwrap_or_default())
            .arg(flag(&cursor.last_sequence))
            .arg(cursor.last_sequence.unwrap_or_default())
            .arg(flag(&cursor.intent))
            .arg(cursor.intent.as_deref().unwrap_or_default());
        let sequences = &cursor.sequences;
        let bit = |value: bool| if value { "1" } else { "0" };
        invocation
            .arg(flag(&sequences.current))
            .arg(sequences.current.unwrap_or_default())
            .arg(bit(sequences.open))
            .arg(bit(sequences.has_message))
            .arg(bit(sequences.has_call))
            .arg(bit(sequences.zero_has_request))
            .arg(sequences.calls.len());
        for (tool_use_id, sequence) in &sequences.calls {
            invocation.arg(tool_use_id).arg(sequence);
        }
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
            .key(session_key(session_id))
            .arg(self.ttl_secs)
            .arg(flag(&fragment.index))
            .arg(fragment.index.unwrap_or_default())
            .arg(&fragment.delta)
            .arg(flag(&fragment.intent))
            .arg(fragment.intent.as_deref().unwrap_or_default())
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
