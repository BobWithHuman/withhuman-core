use std::{error::Error, fmt};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use withhuman_contracts::events::{
    CreatedNode, EventResponse, PieceClassificationRequest, PieceClassificationResponse,
    PieceReference, RequestContinuationRequest, RequestContinuationResponse,
};

use crate::{GeneratorConfig, GeneratorEvent, event::GraphMutation};

const COMMIT_EVENT: &str = "\
MERGE (session:Session {session_id: $session_id}) \
ON CREATE SET session.version = 0, session.created_at = $observed_at \
MERGE (commit:EventCommit {session_id: $session_id, order: $order}) \
ON CREATE SET commit.event_name = $event_name, commit.observed_at = $observed_at, \
commit.client_id = $client_id, commit.event_json = $event_json \
WITH session, commit, commit.version IS NULL AS is_new \
CALL (session, commit, is_new) { \
  WITH session, commit WHERE is_new \
  SET session.version = coalesce(session.version, 0) + 1 \
  SET commit.version = session.version, commit.has_node = $has_node \
  MERGE (session)-[:COMMITTED]->(commit) \
  RETURN true AS created \
  UNION \
  WITH session, commit WHERE NOT is_new \
  RETURN false AS created \
} \
FOREACH (_ IN CASE WHEN created AND $has_node THEN [1] ELSE [] END | \
  CREATE (node:ExecutionNode { \
    session_id: $session_id, seq: commit.version, type: $node_type, \
    depth: $node_depth, \
    event_name: $event_name, order: $order, observed_at: $observed_at, \
    client_id: $client_id, sequence: $sequence, prompt_id: $prompt_id, \
    agent_id: $agent_id, agent_type: $agent_type, cwd: $cwd, \
    tool_use_id: $tool_use_id, tool_name: $tool_name, turn_id: $turn_id, \
    repository: $repository, file_path: $file_path, body: $body, payload_json: $payload_json \
  }) \
  CREATE (commit)-[:CREATED]->(node) \
  CREATE (session)-[:CONTAINS]->(node) \
) \
WITH session, commit, created \
OPTIONAL MATCH (node:ExecutionNode {session_id: $session_id, seq: commit.version}) \
FOREACH (_ IN CASE WHEN created AND $sequence IS NOT NULL AND $node_depth = 2 THEN [1] ELSE [] END | \
  MERGE (sequence_node:ExecutionNode {session_id: $session_id, type: 'Sequence', depth: 1, sequence: $sequence}) \
  ON CREATE SET sequence_node.seq = -($sequence + 1), sequence_node.body = '', \
                sequence_node.agent_id = $agent_id, sequence_node.prompt_id = $prompt_id, \
                sequence_node.parent_state = 'pending' \
  MERGE (node)-[:LINK {kind: 'member'}]->(sequence_node) \
) \
WITH commit, node \
OPTIONAL MATCH (sequence_node:ExecutionNode {session_id: $session_id, type: 'Sequence', depth: 1, sequence: $sequence}) \
FOREACH (_ IN CASE WHEN node IS NULL OR sequence_node IS NULL OR $event_name <> 'MessageDisplay' THEN [] ELSE [1] END | \
  SET sequence_node.body = coalesce($body, ''), sequence_node.has_message = true \
) \
FOREACH (_ IN CASE WHEN node IS NULL OR sequence_node IS NULL OR $event_name <> 'PreToolUse' OR coalesce(sequence_node.has_message, false) THEN [] ELSE [1] END | \
  SET sequence_node.body = CASE WHEN coalesce(sequence_node.body, '') = '' THEN $body ELSE sequence_node.body + '\\n' + $body END \
) \
WITH commit, node \
OPTIONAL MATCH (call:ExecutionNode { \
  session_id: $session_id, type: 'Call', tool_use_id: $tool_use_id \
}) \
FOREACH (_ IN CASE WHEN node IS NULL OR call IS NULL OR NOT $is_tool_result THEN [] ELSE [1] END | \
  MERGE (call)-[:LINK {kind: 'result'}]->(node) \
) \
WITH commit, node \
OPTIONAL MATCH (message:ExecutionNode {session_id: $session_id, type: 'Message', sequence: $sequence}) \
FOREACH (_ IN CASE WHEN node IS NULL OR message IS NULL OR $event_name <> 'PreToolUse' THEN [] ELSE [1] END | \
  MERGE (node)-[:LINK {kind: 'follows'}]->(message) \
) \
WITH commit, node \
FOREACH (_ IN CASE WHEN node IS NULL OR $file_path IS NULL OR $is_tool_result THEN [] ELSE [1] END | \
  MERGE (file:File {repository: coalesce($repository, ''), path: $file_path}) \
  MERGE (node)-[:LINK {kind: 'executes'}]->(file) \
) \
WITH commit, node \
CALL (node, commit) { \
  WITH node, commit WHERE node IS NOT NULL AND size($pieces) > 0 \
  MATCH (session:Session {session_id: $session_id}) \
  UNWIND $pieces AS piece \
  MERGE (stored:ExecutionNode {session_id: $session_id, content_hash: piece.hash, depth: 3}) \
  ON CREATE SET stored.seq = commit.version * 1000000 + piece.index + 1, \
                stored.type = node.type, stored.text = piece.text, stored.source = piece.source, \
                stored.hidden = piece.hidden, stored.flagged = piece.flagged, \
                stored.from_user_doc = piece.from_user_doc, stored.index = piece.index, \
                stored.sequence = node.sequence, stored.tool_name = node.tool_name, \
                stored.tool_use_id = node.tool_use_id, stored.file_path = node.file_path, \
                stored.created_in_seq = node.seq \
  MERGE (session)-[:CONTAINS]->(stored) \
  MERGE (stored)-[:LINK {kind: 'part_of'}]->(node) \
  WITH node, stored, piece \
  OPTIONAL MATCH (pending:PendingPieceEnrichment {session_id: $session_id, hash: piece.hash}) \
  SET stored.instructs = coalesce(pending.instructs, stored.instructs), \
      stored.jev_ms = coalesce(pending.jev_ms, stored.jev_ms), \
      stored.jev_error = coalesce(pending.error, stored.jev_error) \
  FOREACH (_ IN CASE WHEN pending IS NULL THEN [] ELSE [1] END | DELETE pending) \
  RETURN collect({hash: stored.content_hash, seq: stored.seq, new: stored.created_in_seq = node.seq}) AS piece_refs \
  UNION \
  WITH node, commit WHERE node IS NULL OR size($pieces) = 0 \
  RETURN [] AS piece_refs \
} \
WITH commit, node, piece_refs \
CALL (node, commit) { \
  WITH node, commit WHERE node IS NOT NULL AND size($tokens) > 0 \
  UNWIND $tokens AS token \
  OPTIONAL MATCH (piece:ExecutionNode {session_id: $session_id, content_hash: token.piece_hash, depth: 3}) \
  WITH node, commit, token, CASE WHEN token.piece_hash IS NULL THEN node ELSE piece END AS owner \
  WHERE owner IS NOT NULL \
  MERGE (stored_token:Token {session_id: $session_id, key_kind: token.key_kind, key: token.key, slot: token.slot}) \
  ON CREATE SET stored_token.node_seq = owner.seq, stored_token.decoded = token.decoded, \
                stored_token.encoding = token.encoding, stored_token.version = commit.version \
  MERGE (owner)-[:LINK {kind: 'mentions_token', slot: token.slot}]->(stored_token) \
  RETURN count(stored_token) AS token_count \
  UNION \
  WITH node, commit WHERE node IS NULL OR size($tokens) = 0 \
  RETURN 0 AS token_count \
} \
WITH commit, node, piece_refs \
OPTIONAL MATCH (pending_request:PendingRequestContinuation {session_id: $session_id, order: $order}) \
OPTIONAL MATCH (target_commit:EventCommit {session_id: $session_id, order: pending_request.choice_order})-[:CREATED]->(target_request:ExecutionNode {type: 'Request'}) \
FOREACH (_ IN CASE WHEN node.type = 'Request' AND pending_request IS NOT NULL THEN [1] ELSE [] END | \
  SET node.continues = CASE WHEN pending_request.choice = 'none' THEN NULL ELSE target_request.seq END, \
      node.continuation_choice = pending_request.choice, \
      node.continuation_probabilities_json = pending_request.probabilities_json, \
      node.continuation_jev_ms = pending_request.jev_ms, \
      node.continuation_error = pending_request.error \
  DELETE pending_request \
) \
RETURN commit.version AS version, node.seq AS node_seq, node.type AS node_type, piece_refs, \
       commit.event_json = $event_json AS same_event";

const APPLY_PIECE_CLASSIFICATION: &str = "\
MATCH (session:Session {session_id: $session_id}) \
OPTIONAL MATCH (session)-[:CONTAINS]->(piece:ExecutionNode {depth: 3, content_hash: $hash}) \
WITH session, collect(DISTINCT piece) AS pieces \
CALL (session, pieces) { \
  WITH session, pieces WHERE size(pieces) > 0 \
  UNWIND pieces AS piece \
  SET piece.instructs = $instructs, piece.jev_ms = $jev_ms, piece.jev_error = $error \
  WITH session, count(piece) AS updated \
  OPTIONAL MATCH (pending:PendingPieceEnrichment {session_id: $session_id, hash: $hash}) \
  DELETE pending \
  RETURN true AS applied \
  UNION \
  WITH session, pieces WHERE size(pieces) = 0 \
  MERGE (pending:PendingPieceEnrichment {session_id: $session_id, hash: $hash}) \
  SET pending.instructs = $instructs, pending.jev_ms = $jev_ms, pending.error = $error \
  RETURN false AS applied \
} \
RETURN applied, $instructs AS instructs";

const APPLY_REQUEST_CONTINUATION: &str = "\
MATCH (session:Session {session_id: $session_id}) \
OPTIONAL MATCH (commit:EventCommit {session_id: $session_id, order: $order})-[:CREATED]->(request:ExecutionNode {type: 'Request'}) \
OPTIONAL MATCH (target_commit:EventCommit {session_id: $session_id, order: $choice_order})-[:CREATED]->(target:ExecutionNode {type: 'Request'}) \
WITH session, request, target \
CALL (session, request, target) { \
  WITH session, request, target WHERE request IS NOT NULL \
  SET request.continues = CASE WHEN $choice = 'none' THEN NULL ELSE target.seq END, \
      request.continuation_choice = $choice, request.continuation_probabilities_json = $probabilities_json, \
      request.continuation_jev_ms = $jev_ms, request.continuation_error = $error \
  WITH session, request \
  OPTIONAL MATCH (pending:PendingRequestContinuation {session_id: $session_id, order: $order}) \
  DELETE pending \
  RETURN true AS applied, request.seq AS request_seq \
  UNION \
  WITH session, request, target WHERE request IS NULL \
  MERGE (pending:PendingRequestContinuation {session_id: $session_id, order: $order}) \
  SET pending.choice = $choice, pending.choice_order = $choice_order, \
      pending.probabilities_json = $probabilities_json, pending.jev_ms = $jev_ms, pending.error = $error \
  RETURN false AS applied, NULL AS request_seq \
} \
RETURN applied, request_seq";

#[async_trait]
pub trait GraphRepository: Send + Sync + 'static {
    async fn health(&self) -> Result<(), RepositoryError>;
    async fn commit(&self, event: GeneratorEvent) -> Result<EventResponse, RepositoryError>;
    async fn classify_piece(
        &self,
        _session_id: &str,
        _hash: &str,
        _request: PieceClassificationRequest,
    ) -> Result<PieceClassificationResponse, RepositoryError> {
        Err(RepositoryError::NotFound)
    }
    async fn continue_request(
        &self,
        _session_id: &str,
        _order: u64,
        _request: RequestContinuationRequest,
    ) -> Result<RequestContinuationResponse, RepositoryError> {
        Err(RepositoryError::NotFound)
    }
}

#[derive(Clone)]
pub struct Neo4jRepository {
    endpoint: String,
    user: String,
    password: String,
    client: reqwest::Client,
}

impl Neo4jRepository {
    pub async fn connect(config: &GeneratorConfig) -> Result<Self, RepositoryError> {
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
            .ok_or_else(|| RepositoryError::InvalidResponse("missing data".to_owned()))
    }

    async fn commit_mutation(
        &self,
        mutation: GraphMutation,
    ) -> Result<EventResponse, RepositoryError> {
        let has_node = mutation.node_type.is_some();
        let is_tool_result = matches!(mutation.node_type, Some("Segment" | "Error"));
        let node_depth = match mutation.node_type {
            Some("Request" | "Instruction") => 1,
            Some(_) => 2,
            None => 0,
        };
        let parameters = json!({
            "session_id": mutation.session_id,
            "order": mutation.order,
            "observed_at": mutation.observed_at,
            "event_name": mutation.event_name,
            "node_type": mutation.node_type,
            "node_depth": node_depth,
            "has_node": has_node,
            "client_id": mutation.client_id,
            "sequence": mutation.sequence,
            "prompt_id": mutation.prompt_id,
            "agent_id": mutation.agent_id,
            "agent_type": mutation.agent_type,
            "cwd": mutation.cwd,
            "tool_use_id": mutation.tool_use_id,
            "turn_id": mutation.turn_id,
            "repository": mutation.repository,
            "event_json": mutation.event_json,
            "payload_json": mutation.payload_json,
            "file_path": mutation.file_path,
            "tool_name": mutation.tool_name,
            "body": mutation.body,
            "pieces": mutation.pieces,
            "tokens": mutation.tokens,
            "is_tool_result": is_tool_result,
        });
        let data = self.execute(COMMIT_EVENT, parameters).await?;
        let row = data
            .values
            .first()
            .ok_or_else(|| RepositoryError::InvalidResponse("missing commit row".to_owned()))?;
        if !value_at(row, 4, "same_event")?.as_bool().ok_or_else(|| {
            RepositoryError::InvalidResponse("same_event is not a boolean".to_owned())
        })? {
            return Err(RepositoryError::InvalidEvent(format!(
                "order {} was already committed with different content",
                mutation.order
            )));
        }
        let version = unsigned(value_at(row, 0, "version")?, "version")?;
        let nodes = match row.get(1) {
            Some(Value::Null) | None => Vec::new(),
            Some(value) => vec![CreatedNode {
                seq: unsigned(value, "node_seq")?,
                node_type: value_at(row, 2, "node_type")?
                    .as_str()
                    .ok_or_else(|| {
                        RepositoryError::InvalidResponse("node_type is not a string".to_owned())
                    })?
                    .to_owned(),
            }],
        };
        let pieces = value_at(row, 3, "piece_refs")?
            .as_array()
            .ok_or_else(|| {
                RepositoryError::InvalidResponse("piece_refs is not an array".to_owned())
            })?
            .iter()
            .map(|reference| {
                Ok(PieceReference {
                    hash: reference
                        .get("hash")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            RepositoryError::InvalidResponse(
                                "piece hash is not a string".to_owned(),
                            )
                        })?
                        .to_owned(),
                    seq: unsigned(
                        reference.get("seq").ok_or_else(|| {
                            RepositoryError::InvalidResponse("missing piece seq".to_owned())
                        })?,
                        "piece seq",
                    )?,
                    new: reference
                        .get("new")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| {
                            RepositoryError::InvalidResponse(
                                "piece new is not a boolean".to_owned(),
                            )
                        })?,
                })
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?;

        Ok(EventResponse {
            nodes,
            pieces: (!pieces.is_empty()).then_some(pieces),
            version,
            decision_response: None,
        })
    }
}

#[async_trait]
impl GraphRepository for Neo4jRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        self.execute("RETURN 1 AS ready", json!({})).await?;
        Ok(())
    }

    async fn commit(&self, event: GeneratorEvent) -> Result<EventResponse, RepositoryError> {
        self.commit_mutation(event.into_mutation()?).await
    }

    async fn classify_piece(
        &self,
        session_id: &str,
        hash: &str,
        request: PieceClassificationRequest,
    ) -> Result<PieceClassificationResponse, RepositoryError> {
        let instructs = request
            .error
            .is_none()
            .then(|| {
                request
                    .sentences
                    .iter()
                    .map(|sentence| sentence.p)
                    .reduce(f64::max)
            })
            .flatten();
        let data = self
            .execute(
                APPLY_PIECE_CLASSIFICATION,
                json!({
                    "session_id": session_id,
                    "hash": hash,
                    "instructs": instructs,
                    "jev_ms": request.jev_ms,
                    "error": request.error,
                }),
            )
            .await?;
        let row = data.values.first().ok_or(RepositoryError::NotFound)?;
        Ok(PieceClassificationResponse {
            applied: value_at(row, 0, "applied")?.as_bool().ok_or_else(|| {
                RepositoryError::InvalidResponse("applied is not a boolean".into())
            })?,
            instructs: row.get(1).and_then(Value::as_f64),
        })
    }

    async fn continue_request(
        &self,
        session_id: &str,
        order: u64,
        request: RequestContinuationRequest,
    ) -> Result<RequestContinuationResponse, RepositoryError> {
        let choice = request.choice.as_deref().unwrap_or("none");
        let choice_order = parse_choice_order(choice)?;
        let data = self
            .execute(
                APPLY_REQUEST_CONTINUATION,
                json!({
                    "session_id": session_id,
                    "order": order,
                    "choice": choice,
                    "choice_order": choice_order,
                    "probabilities_json": serde_json::to_string(&request.probabilities)
                        .map_err(|error| RepositoryError::InvalidEvent(error.to_string()))?,
                    "jev_ms": request.jev_ms,
                    "error": request.error,
                }),
            )
            .await?;
        let row = data.values.first().ok_or(RepositoryError::NotFound)?;
        Ok(RequestContinuationResponse {
            applied: value_at(row, 0, "applied")?.as_bool().ok_or_else(|| {
                RepositoryError::InvalidResponse("applied is not a boolean".into())
            })?,
            request_seq: row.get(1).and_then(Value::as_u64),
        })
    }
}

fn parse_choice_order(choice: &str) -> Result<Option<u64>, RepositoryError> {
    if choice == "none" {
        return Ok(None);
    }
    choice
        .strip_prefix('o')
        .and_then(|order| order.parse().ok())
        .map(Some)
        .ok_or_else(|| RepositoryError::InvalidEvent("choice must be `none` or `o<order>`".into()))
}

fn value_at<'a>(row: &'a [Value], index: usize, field: &str) -> Result<&'a Value, RepositoryError> {
    row.get(index)
        .ok_or_else(|| RepositoryError::InvalidResponse(format!("missing {field}")))
}

fn unsigned(value: &Value, field: &str) -> Result<u64, RepositoryError> {
    value
        .as_u64()
        .ok_or_else(|| RepositoryError::InvalidResponse(format!("{field} is not an integer")))
}

#[derive(Serialize)]
struct QueryRequest<'a> {
    statement: &'a str,
    parameters: Value,
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
    #[allow(dead_code)]
    fields: Vec<String>,
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
    InvalidEvent(String),
    Query(String),
    InvalidResponse(String),
    NotFound,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "Neo4j unavailable: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid graph event: {error}"),
            Self::Query(error) => write!(formatter, "Neo4j query failed: {error}"),
            Self::InvalidResponse(error) => write!(formatter, "invalid Neo4j response: {error}"),
            Self::NotFound => formatter.write_str("graph resource not found"),
        }
    }
}

impl Error for RepositoryError {}
