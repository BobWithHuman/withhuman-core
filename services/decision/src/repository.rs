use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use withhuman_contracts::decisions::{DecisionRequest, DecisionResponse};

use crate::{
    DecisionConfig,
    trace::{CallInfo, Member, MemberKind, ParentKey, TOKEN_KINDS, TraceGraph, Turn},
};

const VERIFY_GRAPH: &str = "\
MATCH (session:Session {session_id: $session_id}) \
MATCH (call:Call {session_id: $session_id, seq: $call_seq}) \
WHERE session.version >= $graph_version AND call.seq <= $graph_version \
RETURN session.version, call.seq";

// The verdict is kept on the Call itself.
const WRITE_DECISION: &str = "\
MATCH (session:Session {session_id: $session_id}) \
MATCH (call:Call {session_id: $session_id, seq: $call_seq}) \
SET call.decision = $decision, call.decision_reason = $reason, call.decision_rule = $rule, \
    call.decision_start = $start, call.decision_version = $graph_version, \
    call.decision_mode = $mode, call.decision_jev_json = $jev_json, \
    call.decided_at = timestamp() \
RETURN true AS written";

// The Call; the SubGraphs before it with the subagent whose calls they hold (none for the main
// agent; a subagent is an agent_id a SubagentStart announced); which of them hold content that
// was hidden where it appeared; which hold the latest mention before the Call (outside the
// Call's own SubGraph) of an exfiltration target or sensitive value — one per value whatever
// slot mentioned it — and whether the Call mentions that value too; every parent earlier Calls
// of a SubGraph chose; and every user prompt before the Call with the first intent the agent
// stated after it (and before the next prompt): an Intent node, or a Message that stated it
// before intents had nodes of their own. The prompt itself is not read.
const TRACE_GRAPH: &str = concat!(
    "\
MATCH (call:Call {session_id: $session_id, seq: $call_seq}) \
RETURN call.order, call.subgraph, call.payload_json, \
  COLLECT { MATCH (group:SubGraph {session_id: $session_id}) \
            WHERE group.number < call.subgraph \
            OPTIONAL MATCH (group)-[:MEMBER]->(member:Call) \
            WHERE EXISTS { MATCH (:SubagentStart {session_id: $session_id, agent_id: member.agent_id}) } \
            WITH group, head(collect(member.agent_id)) AS agent \
            RETURN [group.number, agent] } AS subgraphs, \
  COLLECT { MATCH (node:Segment|Error {session_id: $session_id}) \
                  -[:CONTAINS_PARAGRAPH]->(:Paragraph {hidden: true}) \
            WHERE node.subgraph < call.subgraph \
              AND node.order < call.order \
            RETURN DISTINCT node.subgraph } AS hidden, \
  COLLECT { MATCH (node:",
    withhuman_common::node_labels!(),
    " {session_id: $session_id}) \
                  -[:MENTIONS_TOKEN]->(token:Token) \
            WHERE token.key_kind IN $token_kinds AND node.order < call.order \
              AND node.subgraph < call.subgraph \
            WITH token.key_kind AS kind, token.key AS key, node ORDER BY node.order DESC \
            WITH kind, key, collect(node)[0] AS latest \
            RETURN [latest.subgraph, \
                    EXISTS { MATCH (call)-[:MENTIONS_TOKEN]->(:Token {key_kind: kind, key: key}) }] } \
    AS tokens, \
  COLLECT { MATCH (earlier:Call {session_id: $session_id}) \
            WHERE earlier.subgraph < call.subgraph \
              AND earlier.parent IS NOT NULL AND earlier.parent <> 'unresolved' \
            UNWIND coalesce(earlier.parents, [earlier.parent]) AS parent \
            RETURN DISTINCT [earlier.subgraph, parent] } AS parents, \
  CASE WHEN EXISTS { MATCH (:SubagentStart {session_id: $session_id, agent_id: call.agent_id}) } \
       THEN call.agent_id END, \
  COLLECT { MATCH (request:Request {session_id: $session_id}) \
            WHERE request.order < call.order \
            WITH request, coalesce(COLLECT { MATCH (next:Request {session_id: $session_id}) \
                                             WHERE next.order > request.order \
                                             RETURN min(next.order) }[0], call.order) AS until \
            RETURN [request.order, \
                    COLLECT { MATCH (stated:Intent|Message {session_id: $session_id}) \
                              WHERE stated.intent IS NOT NULL AND stated.order > request.order \
                                AND stated.order < until AND stated.order < call.order \
                              RETURN stated.intent ORDER BY stated.order LIMIT 1 }[0]] \
            ORDER BY request.order } AS turns"
);

// Tool results also bring the paragraphs hidden where they appeared, and whether a later Call
// was traced to them. ConfigChanges stand where Calls do, Errors where Segments do. A prompt's
// SubGraph holds its Request and the Intent stated for it.
const SUBGRAPH_MEMBERS: &str = "\
UNWIND $numbers AS number \
MATCH (:SubGraph {session_id: $session_id, number: number}) \
      -[:MEMBER]->(node:Request|Intent|Message|Call|ConfigChange|Segment|Error) \
WHERE node.order < $call_order \
RETURN number, node.seq, node.order, labels(node)[0], node.payload_json, \
  COLLECT { MATCH (node)-[:CONTAINS_PARAGRAPH]->(paragraph:Paragraph {hidden: true}) \
            RETURN paragraph.text ORDER BY paragraph.index } AS hidden, \
  EXISTS { MATCH (effect)-[:NEXT {kind: 'cause'}]->(node) \
           WHERE effect.order < $call_order } AS caused \
ORDER BY number, node.order";

// Takes the Session lock first like Generator commits, so the two never deadlock. The Call gets
// a NEXT edge (marked `kind: 'cause'`, apart from the order chain) to each activated tool result
// of the SubGraph it was traced to, or to the Request when that is a prompt's SubGraph. Pointing from the Call up
// to its causes, and each result up to its Call (`RESULT_OF`), they lead from a Call back to the
// prompt. A repeated decision of the same Call replaces its edges, and the SubGraph keeps the
// parents of its latest Call.
const PERSIST_TRACE: &str = "\
MATCH (session:Session {session_id: $session_id}) \
SET session.commit_lock = true \
WITH session \
MATCH (call:Call {session_id: $session_id, seq: $call_seq}) \
SET call.parent = $parent, call.parents = $parent_keys, call.trace_json = $trace_json, \
    call.intent_score = $intent_score \
WITH call \
CALL (call) { \
  OPTIONAL MATCH (call)-[old:NEXT {kind: 'cause', call_seq: $call_seq}]->() \
  DELETE old \
} \
MERGE (current:SubGraph {session_id: $session_id, number: $subgraph}) \
WITH call, current, coalesce(current.parent_call_order, -1) <= call.order AS latest \
SET current.parent = CASE WHEN latest THEN $parent ELSE current.parent END, \
    current.parents = CASE WHEN latest THEN $parent_keys ELSE current.parents END, \
    current.parent_call_seq = CASE WHEN latest THEN $call_seq ELSE current.parent_call_seq END, \
    current.parent_call_order = CASE WHEN latest THEN call.order ELSE current.parent_call_order END \
WITH call \
CALL (call) { \
  UNWIND $parents AS chosen \
  MATCH (:SubGraph {session_id: $session_id, number: chosen.number})-[:MEMBER]->(request:Request) \
  MERGE (call)-[edge:NEXT {kind: 'cause', call_seq: $call_seq}]->(request) \
  SET edge.probability = chosen.probability, edge.rank = chosen.rank, \
      edge.parent = 's' + toString(chosen.number) \
  RETURN count(edge) AS prompted \
} \
CALL (call) { \
  UNWIND $segments AS segment \
  MATCH (source:Segment|Error {session_id: $session_id, seq: segment.seq}) \
  MERGE (call)-[edge:NEXT {kind: 'cause', call_seq: $call_seq}]->(source) \
  SET edge.probability = segment.probability, edge.rank = segment.rank, \
      edge.parent = segment.parent \
  RETURN count(edge) AS linked \
} \
RETURN linked";

const MARK_UNRESOLVED: &str = "\
MATCH (session:Session {session_id: $session_id}) \
SET session.commit_lock = true \
WITH session \
MATCH (call:Call {session_id: $session_id, seq: $call_seq}) \
SET call.parent = 'unresolved', call.trace_error = $error \
RETURN true";

/// Concurrent writes to one session can deadlock; Neo4j reports that as a transient error and
/// the statement is safe to run again.
const TRANSIENT_ATTEMPTS: u32 = 5;

/// What tracing decided for a Call, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceRecord {
    pub subgraph: u64,
    /// The most influential parent: `s<number>` or `none`.
    pub parent: String,
    /// Every parent, the most influential first.
    pub parents: Vec<TracedParent>,
    pub candidates: Vec<String>,
    /// Activated tool results.
    pub segments: Vec<TracedSegment>,
    pub intent_score: Option<f64>,
    pub trace: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TracedParent {
    /// `s<number>` or `none`.
    pub key: String,
    /// None for `none`.
    pub number: Option<u64>,
    pub probability: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TracedSegment {
    /// The tool result's node seq.
    pub seq: u64,
    pub probability: f64,
    pub rank: usize,
    /// The parent whose result it is.
    pub parent: String,
}

#[async_trait]
pub trait DecisionRepository: Send + Sync + 'static {
    async fn health(&self) -> Result<(), RepositoryError>;
    async fn verify_graph(&self, request: &DecisionRequest) -> Result<(), RepositoryError>;
    async fn persist(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), RepositoryError>;

    async fn trace_graph(&self, _request: &DecisionRequest) -> Result<TraceGraph, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// The members of SubGraphs `numbers` before the Call at `call_order`.
    async fn subgraph_members(
        &self,
        _session_id: &str,
        _numbers: &[u64],
        _call_order: u64,
    ) -> Result<Vec<Member>, RepositoryError> {
        Ok(Vec::new())
    }

    async fn persist_trace(
        &self,
        _request: &DecisionRequest,
        _record: &TraceRecord,
    ) -> Result<(), RepositoryError> {
        Ok(())
    }

    /// Records that tracing the Call failed.
    async fn mark_unresolved(
        &self,
        _request: &DecisionRequest,
        _error: &str,
    ) -> Result<(), RepositoryError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct Neo4jDecisionRepository {
    endpoint: String,
    user: String,
    password: String,
    client: reqwest::Client,
}

impl Neo4jDecisionRepository {
    pub async fn connect(config: &DecisionConfig) -> Result<Self, RepositoryError> {
        let repository = Self {
            endpoint: format!(
                "{}/db/{}/query/v2",
                config.neo4j_url.trim_end_matches('/'),
                config.neo4j_database
            ),
            user: config.neo4j_user.clone(),
            password: config.neo4j_password.clone(),
            client: reqwest::Client::new(),
        };
        repository.health().await?;
        Ok(repository)
    }

    async fn execute(
        &self,
        statement: &str,
        parameters: Value,
    ) -> Result<QueryData, RepositoryError> {
        let mut attempt = 1;
        loop {
            match self.execute_once(statement, &parameters).await {
                Err(RepositoryError::Query(message))
                    if message.starts_with("Neo.TransientError.")
                        && attempt < TRANSIENT_ATTEMPTS =>
                {
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt) * 20)).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    async fn execute_once(
        &self,
        statement: &str,
        parameters: &Value,
    ) -> Result<QueryData, RepositoryError> {
        let response = self
            .client
            .post(&self.endpoint)
            .basic_auth(&self.user, Some(&self.password))
            .json(&QueryRequest {
                statement,
                parameters,
            })
            .send()
            .await
            .map_err(|error| RepositoryError::Unavailable(error.to_string()))?;
        let status = response.status();
        let body: QueryResponse = response
            .json()
            .await
            .map_err(|error| RepositoryError::InvalidResponse(error.to_string()))?;
        if !status.is_success() {
            return Err(RepositoryError::Unavailable(format!("HTTP {status}")));
        }
        if !body.errors.is_empty() {
            return Err(RepositoryError::Query(
                body.errors
                    .into_iter()
                    .map(|error| format!("{}: {}", error.code, error.message))
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
        body.data
            .ok_or_else(|| RepositoryError::InvalidResponse("missing data".into()))
    }
}

#[async_trait]
impl DecisionRepository for Neo4jDecisionRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        self.execute("RETURN 1", json!({})).await?;
        Ok(())
    }

    async fn verify_graph(&self, request: &DecisionRequest) -> Result<(), RepositoryError> {
        let data = self
            .execute(
                VERIFY_GRAPH,
                json!({
                    "session_id":request.session_id,
                    "call_seq":request.call_seq,
                    "graph_version":request.graph_version,
                }),
            )
            .await?;
        if data.values.is_empty() {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    async fn persist(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), RepositoryError> {
        let data = self
            .execute(
                WRITE_DECISION,
                json!({
                    "session_id":request.session_id,
                    "call_seq":request.call_seq,
                    "graph_version":request.graph_version,
                    "mode":request.mode,
                    "decision":response.decision,
                    "reason":response.reason,
                    "rule":response.rule,
                    "start":response.start,
                    "jev_json":serde_json::to_string(&response.jev)
                        .map_err(|error| RepositoryError::InvalidResponse(error.to_string()))?,
                }),
            )
            .await?;
        if data.values.is_empty() {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    async fn trace_graph(&self, request: &DecisionRequest) -> Result<TraceGraph, RepositoryError> {
        let data = self
            .execute(
                TRACE_GRAPH,
                json!({
                    "session_id": request.session_id,
                    "call_seq": request.call_seq,
                    "token_kinds": TOKEN_KINDS,
                }),
            )
            .await?;
        let row = data.values.first().ok_or(RepositoryError::NotFound)?;
        let call_payload = payload(row.get(2));
        let subgraph = row
            .get(1)
            .and_then(Value::as_u64)
            .ok_or(RepositoryError::NoSubGraph)?;
        let subgraphs = pairs(row.get(3))
            .filter_map(|pair| {
                Some((
                    pair.first()?.as_u64()?,
                    pair.get(1).and_then(Value::as_str).map(str::to_owned),
                ))
            })
            .collect();
        let mut tokens = BTreeSet::new();
        let mut shared_tokens = BTreeSet::new();
        for pair in pairs(row.get(5)) {
            let Some(number) = pair.first().and_then(Value::as_u64) else {
                continue;
            };
            tokens.insert(number);
            if pair.get(1).and_then(Value::as_bool) == Some(true) {
                shared_tokens.insert(number);
            }
        }
        let mut parents: BTreeMap<u64, BTreeSet<ParentKey>> = BTreeMap::new();
        for pair in pairs(row.get(6)) {
            let (Some(number), Some(parent)) = (
                pair.first().and_then(Value::as_u64),
                pair.get(1)
                    .and_then(Value::as_str)
                    .and_then(ParentKey::parse),
            ) else {
                continue;
            };
            parents.entry(number).or_default().insert(parent);
        }
        Ok(TraceGraph {
            call: CallInfo {
                seq: request.call_seq,
                order: number(row.first(), "call order")?,
                subgraph,
                agent_id: row.get(7).and_then(Value::as_str).map(str::to_owned),
                tool_name: call_payload
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                tool_input: call_payload
                    .get("tool_input")
                    .cloned()
                    .unwrap_or(Value::Null),
            },
            subgraphs,
            hidden: numbers(row.get(4)),
            tokens,
            shared_tokens,
            parents,
            turns: pairs(row.get(8))
                .map(|pair| Turn {
                    intent: pair.get(1).and_then(Value::as_str).map(str::to_owned),
                })
                .collect(),
        })
    }

    async fn subgraph_members(
        &self,
        session_id: &str,
        numbers: &[u64],
        call_order: u64,
    ) -> Result<Vec<Member>, RepositoryError> {
        if numbers.is_empty() {
            return Ok(Vec::new());
        }
        let data = self
            .execute(
                SUBGRAPH_MEMBERS,
                json!({"session_id": session_id, "numbers": numbers, "call_order": call_order}),
            )
            .await?;
        Ok(data
            .values
            .iter()
            .filter_map(|row| {
                Some(Member {
                    subgraph: row.first()?.as_u64()?,
                    seq: row.get(1)?.as_u64()?,
                    order: row.get(2)?.as_u64()?,
                    kind: MemberKind::from_node_type(row.get(3)?.as_str()?)?,
                    payload: payload(row.get(4)),
                    hidden: row
                        .get(5)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                    caused: row.get(6).and_then(Value::as_bool).unwrap_or_default(),
                })
            })
            .collect())
    }

    async fn persist_trace(
        &self,
        request: &DecisionRequest,
        record: &TraceRecord,
    ) -> Result<(), RepositoryError> {
        let segments: Vec<Value> = record
            .segments
            .iter()
            .map(|segment| {
                json!({
                    "seq": segment.seq,
                    "probability": segment.probability,
                    "rank": segment.rank,
                    "parent": segment.parent,
                })
            })
            .collect();
        let parents: Vec<Value> = record
            .parents
            .iter()
            .enumerate()
            .filter_map(|(index, parent)| {
                Some(json!({
                    "number": parent.number?,
                    "probability": parent.probability,
                    "rank": index + 1,
                }))
            })
            .collect();
        let parent_keys: Vec<&str> = record
            .parents
            .iter()
            .map(|parent| parent.key.as_str())
            .collect();
        self.execute(
            PERSIST_TRACE,
            json!({
                "session_id": request.session_id,
                "call_seq": request.call_seq,
                "subgraph": record.subgraph,
                "parent": record.parent,
                "parent_keys": parent_keys,
                "parents": parents,
                "segments": segments,
                "intent_score": record.intent_score,
                "trace_json": record.trace.to_string(),
            }),
        )
        .await?;
        Ok(())
    }

    async fn mark_unresolved(
        &self,
        request: &DecisionRequest,
        error: &str,
    ) -> Result<(), RepositoryError> {
        self.execute(
            MARK_UNRESOLVED,
            json!({"session_id": request.session_id, "call_seq": request.call_seq, "error": error}),
        )
        .await?;
        Ok(())
    }
}

fn number(value: Option<&Value>, field: &str) -> Result<u64, RepositoryError> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| RepositoryError::InvalidResponse(format!("{field} is not a number")))
}

fn pairs(value: Option<&Value>) -> impl Iterator<Item = &Vec<Value>> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
}

fn numbers(value: Option<&Value>) -> BTreeSet<u64> {
    value
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default()
}

fn payload(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_str)
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or(Value::Null)
}

#[derive(Serialize)]
struct QueryRequest<'a> {
    statement: &'a str,
    parameters: &'a Value,
}

#[derive(Deserialize)]
struct QueryResponse {
    #[serde(default)]
    data: Option<QueryData>,
    #[serde(default)]
    errors: Vec<QueryError>,
}

#[derive(Deserialize)]
struct QueryData {
    #[serde(default)]
    values: Vec<Vec<Value>>,
}

#[derive(Deserialize)]
struct QueryError {
    code: String,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    Unavailable(String),
    Query(String),
    InvalidResponse(String),
    NotFound,
    /// The Call was committed without a SubGraph (before SubGraphs were numbered).
    NoSubGraph,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "Neo4j unavailable: {error}"),
            Self::Query(error) => write!(formatter, "Neo4j query failed: {error}"),
            Self::InvalidResponse(error) => write!(formatter, "invalid Neo4j response: {error}"),
            Self::NotFound => formatter.write_str("requested graph version or Call was not found"),
            Self::NoSubGraph => formatter.write_str("the Call has no SubGraph"),
        }
    }
}

impl Error for RepositoryError {}
