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
    trace::{CallInfo, Member, MemberKind, ParentKey, TOKEN_KINDS, TraceGraph},
};

const VERIFY_GRAPH: &str = "\
MATCH (session:Session {session_id: $session_id}) \
MATCH (call:ExecutionNode {session_id: $session_id, seq: $call_seq, type: 'Call'}) \
WHERE session.version >= $graph_version AND call.seq <= $graph_version \
RETURN session.version, call.seq";

const WRITE_VERDICT: &str = "\
MATCH (session:Session {session_id: $session_id}) \
MATCH (call:ExecutionNode {session_id: $session_id, seq: $call_seq, type: 'Call'}) \
MERGE (verdict:Verdict {session_id: $session_id, call_seq: $call_seq}) \
SET verdict.decision = $decision, verdict.reason = $reason, verdict.rule = $rule, \
    verdict.start = $start, verdict.graph_version = $graph_version, \
    verdict.mode = $mode, verdict.jev_json = $jev_json, verdict.updated_at = timestamp() \
SET call.decision = $decision, call.decision_reason = $reason, call.decision_rule = $rule, \
    call.decision_start = $start, call.decision_version = $graph_version \
MERGE (call)-[cause:CAUSE {kind: 'mock'}]->(verdict) \
SET cause.graph_version = $graph_version \
MERGE (call)-[:HAS_VERDICT]->(verdict) \
RETURN true AS written";

// The Call; the sequences before it with the subagent whose calls they hold (none for the main
// agent; a subagent is an agent_id a SubagentStart announced); which of them hold content that was hidden where it appeared; which hold the latest
// mention before the Call (outside the Call's own sequence) of an exfiltration target or
// sensitive value — one per value whatever slot mentioned it — and whether the Call mentions
// that value too; every parent earlier Calls of a sequence chose; and the latest user prompt.
const TRACE_GRAPH: &str = "\
MATCH (call:ExecutionNode {session_id: $session_id, seq: $call_seq, type: 'Call'}) \
RETURN call.order, call.session_sequence, call.payload_json, \
  COLLECT { MATCH (group:Sequence {session_id: $session_id}) \
            WHERE group.number < call.session_sequence \
            OPTIONAL MATCH (group)-[:MEMBER]->(member:ExecutionNode {type: 'Call'}) \
            WHERE EXISTS { MATCH (:ExecutionNode {session_id: $session_id, type: 'SubagentStart', \
                                                  agent_id: member.agent_id}) } \
            WITH group, head(collect(member.agent_id)) AS agent \
            RETURN [group.number, agent] } AS sequences, \
  COLLECT { MATCH (node:ExecutionNode {session_id: $session_id})-[contains:CONTAINS_PARAGRAPH]->(:Paragraph) \
            WHERE contains.hidden AND node.session_sequence < call.session_sequence \
              AND node.order < call.order \
            RETURN DISTINCT node.session_sequence } AS hidden, \
  COLLECT { MATCH (node:ExecutionNode {session_id: $session_id})-[:MENTIONS_TOKEN]->(token:Token) \
            WHERE token.key_kind IN $token_kinds AND node.order < call.order \
              AND node.session_sequence < call.session_sequence \
            WITH token.key_kind AS kind, token.key AS key, node ORDER BY node.order DESC \
            WITH kind, key, collect(node)[0] AS latest \
            RETURN [latest.session_sequence, \
                    EXISTS { MATCH (call)-[:MENTIONS_TOKEN]->(:Token {key_kind: kind, key: key}) }] } \
    AS tokens, \
  COLLECT { MATCH (earlier:ExecutionNode {session_id: $session_id, type: 'Call'}) \
            WHERE earlier.session_sequence < call.session_sequence \
              AND earlier.parent IS NOT NULL AND earlier.parent <> 'unresolved' \
            RETURN DISTINCT [earlier.session_sequence, earlier.parent] } AS parents, \
  CASE WHEN EXISTS { MATCH (:ExecutionNode {session_id: $session_id, type: 'SubagentStart', \
                                            agent_id: call.agent_id}) } \
       THEN call.agent_id END, \
  COLLECT { MATCH (request:ExecutionNode {session_id: $session_id, type: 'Request'}) \
            WHERE request.order < call.order \
            RETURN request.payload_json ORDER BY request.order DESC LIMIT 1 }[0] AS request";

// Segments also bring the paragraphs hidden where they appeared, and whether a later Call was
// traced to them.
const SEQUENCE_MEMBERS: &str = "\
UNWIND $numbers AS number \
MATCH (:Sequence {session_id: $session_id, number: number})-[:MEMBER]->(node:ExecutionNode) \
WHERE node.type IN ['Request', 'Instructions', 'Message', 'Call', 'Segment'] \
  AND node.order < $call_order \
RETURN number, node.seq, node.order, node.type, node.payload_json, \
  COLLECT { MATCH (node)-[contains:CONTAINS_PARAGRAPH]->(paragraph:Paragraph) \
            WHERE contains.hidden RETURN paragraph.text ORDER BY contains.index } AS hidden, \
  EXISTS { MATCH (node)-[:NEXT {kind: 'cause'}]->(effect:ExecutionNode) \
           WHERE effect.order < $call_order } AS caused \
ORDER BY number, node.order";

// Takes the Session lock first like Generator commits, so the two never deadlock. Step 2 links
// the Call's sequence to the chosen one; step 4 links the activated Segments to the Call with
// NEXT edges (marked `kind: 'cause'`, apart from the order chain). A repeated decision of the
// same Call replaces its edges, and the Sequence keeps the parent of its latest Call.
const PERSIST_TRACE: &str = "\
MATCH (session:Session {session_id: $session_id}) \
SET session.commit_lock = true \
WITH session \
MATCH (call:ExecutionNode {session_id: $session_id, seq: $call_seq, type: 'Call'}) \
SET call.parent = $parent, call.trace_json = $trace_json, call.intent_score = $intent_score \
WITH call \
CALL (call) { \
  OPTIONAL MATCH ()-[old:NEXT {kind: 'cause', call_seq: $call_seq}]->(call) \
  DELETE old \
} \
CALL (call) { \
  OPTIONAL MATCH (:Sequence {session_id: $session_id})-[old:PARENT {call_seq: $call_seq}]->() \
  DELETE old \
} \
MERGE (current:Sequence {session_id: $session_id, number: $sequence}) \
WITH call, current, coalesce(current.parent_call_order, -1) <= call.order AS latest \
SET current.parent = CASE WHEN latest THEN $parent ELSE current.parent END, \
    current.parent_call_seq = CASE WHEN latest THEN $call_seq ELSE current.parent_call_seq END, \
    current.parent_call_order = CASE WHEN latest THEN call.order ELSE current.parent_call_order END \
WITH call, current \
OPTIONAL MATCH (parent:Sequence {session_id: $session_id, number: $parent_number}) \
FOREACH (_ IN CASE WHEN parent IS NULL THEN [] ELSE [1] END | \
  MERGE (current)-[edge:PARENT {call_seq: $call_seq}]->(parent) \
  SET edge.probability = $parent_probability, edge.candidates = $candidates, \
      edge.decided_at = timestamp() \
) \
WITH call \
CALL (call) { \
  UNWIND $segments AS segment \
  MATCH (source:ExecutionNode {session_id: $session_id, seq: segment.seq, type: 'Segment'}) \
  MERGE (source)-[edge:NEXT {kind: 'cause', call_seq: $call_seq}]->(call) \
  SET edge.probability = segment.probability, edge.rank = segment.rank \
  RETURN count(edge) AS linked \
} \
RETURN linked";

const MARK_UNRESOLVED: &str = "\
MATCH (session:Session {session_id: $session_id}) \
SET session.commit_lock = true \
WITH session \
MATCH (call:ExecutionNode {session_id: $session_id, seq: $call_seq, type: 'Call'}) \
SET call.parent = 'unresolved', call.trace_error = $error \
RETURN true";

/// Concurrent writes to one session can deadlock; Neo4j reports that as a transient error and
/// the statement is safe to run again.
const TRANSIENT_ATTEMPTS: u32 = 5;

/// What steps 1–4 decided for a Call, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceRecord {
    pub sequence: u64,
    /// `s<number>` or `none`.
    pub parent: String,
    pub parent_number: Option<u64>,
    pub parent_probability: f64,
    pub candidates: Vec<String>,
    /// `(segment node seq, probability, rank)`.
    pub segments: Vec<(u64, f64, usize)>,
    pub intent_score: Option<f64>,
    pub trace: Value,
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

    /// The members of sequences `numbers` before the Call at `call_order`.
    async fn sequence_members(
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
                WRITE_VERDICT,
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
        let sequence = row
            .get(1)
            .and_then(Value::as_u64)
            .ok_or(RepositoryError::Unsequenced)?;
        let sequences = pairs(row.get(3))
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
                sequence,
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
            sequences,
            hidden: numbers(row.get(4)),
            tokens,
            shared_tokens,
            parents,
            request: payload(row.get(8))
                .get("prompt")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    async fn sequence_members(
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
                SEQUENCE_MEMBERS,
                json!({"session_id": session_id, "numbers": numbers, "call_order": call_order}),
            )
            .await?;
        Ok(data
            .values
            .iter()
            .filter_map(|row| {
                Some(Member {
                    sequence: row.first()?.as_u64()?,
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
            .map(|(seq, probability, rank)| {
                json!({"seq": seq, "probability": probability, "rank": rank})
            })
            .collect();
        self.execute(
            PERSIST_TRACE,
            json!({
                "session_id": request.session_id,
                "call_seq": request.call_seq,
                "sequence": record.sequence,
                "parent": record.parent,
                "parent_number": record.parent_number,
                "parent_probability": record.parent_probability,
                "candidates": record.candidates,
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
    /// The Call was committed without a session sequence (before sequences were numbered).
    Unsequenced,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "Neo4j unavailable: {error}"),
            Self::Query(error) => write!(formatter, "Neo4j query failed: {error}"),
            Self::InvalidResponse(error) => write!(formatter, "invalid Neo4j response: {error}"),
            Self::NotFound => formatter.write_str("requested graph version or Call was not found"),
            Self::Unsequenced => formatter.write_str("the Call has no session sequence"),
        }
    }
}

impl Error for RepositoryError {}
