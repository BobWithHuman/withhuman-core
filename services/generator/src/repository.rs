use std::{
    error::Error,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use withhuman_contracts::events::{
    CreatedNode, EventResponse, ParagraphClassificationRequest, ParagraphClassificationResponse,
    ParagraphReference, RequestContinuationRequest, RequestContinuationResponse, SessionCursor,
    ToolCall,
};

use crate::{GeneratorConfig, GeneratorEvent, event::GraphMutation};

// Events of one session may arrive in any order and concurrently (several Collector replicas).
// `SET session.commit_lock` takes the Session write lock first, so commits of a session queue up
// instead of deadlocking, and every later read sees the previous commit. `seq` stays the arrival
// version that Decision snapshots against; NEXT, AGENT_SEQUENCE and a Token's first mention
// follow `order` and are repaired when an earlier event arrives late.
const COMMIT_EVENT: &str = "\
MERGE (session:Session {session_id: $session_id}) \
ON CREATE SET session.version = 0, session.created_at = $observed_at \
SET session.commit_lock = true \
MERGE (commit:EventCommit {session_id: $session_id, order: $order}) \
ON CREATE SET commit.event_name = $event_name, commit.observed_at = $observed_at, \
commit.client_id = $client_id, commit.event_json = $event_json, \
commit.cwd = $cwd, commit.prompt_id = $prompt_id \
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
    event_name: $event_name, order: $order, observed_at: $observed_at, \
    client_id: $client_id, sequence: $sequence, prompt_id: $prompt_id, \
    agent_id: $agent_id, agent_type: $agent_type, cwd: $cwd, \
    tool_use_id: $tool_use_id, turn_id: $turn_id, repository: $repository, \
    intent: $intent, payload_json: $payload_json \
  }) \
  CREATE (commit)-[:CREATED]->(node) \
  CREATE (session)-[:CONTAINS]->(node) \
) \
WITH session, commit, created \
OPTIONAL MATCH (node:ExecutionNode {session_id: $session_id, seq: commit.version}) \
CALL (node, created) { \
  WITH node WHERE created AND node IS NOT NULL \
  OPTIONAL MATCH (before:ExecutionNode {session_id: $session_id}) WHERE before.order < node.order \
  WITH node, before ORDER BY before.order DESC LIMIT 1 \
  OPTIONAL MATCH (after:ExecutionNode {session_id: $session_id}) WHERE after.order > node.order \
  WITH node, before, after ORDER BY after.order LIMIT 1 \
  OPTIONAL MATCH (before)-[stale:NEXT]->(after) \
  DELETE stale \
  FOREACH (_ IN CASE WHEN before IS NULL THEN [] ELSE [1] END | \
    MERGE (before)-[edge:NEXT]->(node) \
    ON CREATE SET edge.edge_id = $session_id + ':' + toString(before.seq) + ':' + toString(node.seq), \
                  edge.probability = 1.0 \
  ) \
  FOREACH (_ IN CASE WHEN after IS NULL THEN [] ELSE [1] END | \
    MERGE (node)-[edge:NEXT]->(after) \
    ON CREATE SET edge.edge_id = $session_id + ':' + toString(node.seq) + ':' + toString(after.seq), \
                  edge.probability = 1.0 \
  ) \
  RETURN count(*) AS linked \
} \
WITH commit, node \
OPTIONAL MATCH (agent_previous:ExecutionNode { \
  session_id: $session_id, agent_id: $agent_id, sequence: $previous_sequence \
}) \
FOREACH (_ IN CASE WHEN node IS NULL OR agent_previous IS NULL THEN [] ELSE [1] END | \
  MERGE (agent_previous)-[:AGENT_SEQUENCE]->(node) \
) \
WITH commit, node \
OPTIONAL MATCH (agent_next:ExecutionNode { \
  session_id: $session_id, agent_id: $agent_id, sequence: $next_sequence \
}) \
FOREACH (_ IN CASE WHEN node IS NULL OR agent_next IS NULL THEN [] ELSE [1] END | \
  MERGE (node)-[:AGENT_SEQUENCE]->(agent_next) \
) \
WITH commit, node \
OPTIONAL MATCH (call:ExecutionNode { \
  session_id: $session_id, type: 'Call', tool_use_id: $tool_use_id \
}) \
FOREACH (_ IN CASE WHEN node IS NULL OR call IS NULL OR NOT $is_tool_result THEN [] ELSE [1] END | \
  MERGE (call)-[:RESULTED_IN]->(node) \
) \
WITH commit, node \
FOREACH (_ IN CASE WHEN node IS NULL OR $file_path IS NULL THEN [] ELSE [1] END | \
  MERGE (file:File {repository: coalesce($repository, ''), path: $file_path}) \
  MERGE (node)-[:REFERENCES_FILE]->(file) \
) \
WITH commit, node \
CALL (node) { \
  WITH node WHERE node IS NOT NULL AND size($paragraphs) > 0 \
  UNWIND $paragraphs AS paragraph \
  MERGE (stored:Paragraph {hash: paragraph.hash}) \
  ON CREATE SET stored.text = paragraph.text, stored.source = paragraph.source, \
                stored.hidden = paragraph.hidden, stored.hidden_rules = paragraph.hidden_rules, \
                stored.from_user_doc = paragraph.from_user_doc, \
                stored.long_paragraph = paragraph.long_paragraph, stored.created_in_seq = node.seq \
  ON MATCH SET stored.hidden = coalesce(stored.hidden, false) OR paragraph.hidden, \
               stored.hidden_rules = coalesce(stored.hidden_rules, []) + \
                 [rule IN paragraph.hidden_rules WHERE NOT rule IN coalesce(stored.hidden_rules, [])] \
  MERGE (node)-[:CONTAINS_PARAGRAPH {index: paragraph.index}]->(stored) \
  WITH node, stored, paragraph \
  OPTIONAL MATCH (pending:PendingParagraphEnrichment {session_id: $session_id, hash: paragraph.hash}) \
  SET stored.instructs = coalesce(pending.instructs, stored.instructs), \
      stored.jev_ms = coalesce(pending.jev_ms, stored.jev_ms), \
      stored.jev_error = coalesce(pending.error, stored.jev_error) \
  FOREACH (_ IN CASE WHEN pending IS NULL THEN [] ELSE [1] END | DELETE pending) \
  RETURN collect({hash: stored.hash, seq: node.seq, new: stored.created_in_seq = node.seq}) AS paragraph_refs \
  UNION \
  WITH node WHERE node IS NULL OR size($paragraphs) = 0 \
  RETURN [] AS paragraph_refs \
} \
WITH commit, node, paragraph_refs \
CALL (node, commit) { \
  WITH node, commit WHERE node IS NOT NULL AND size($tokens) > 0 \
  UNWIND $tokens AS token \
  MERGE (stored_token:Token {session_id: $session_id, key_kind: token.key_kind, key: token.key, slot: token.slot}) \
  ON CREATE SET stored_token.node_seq = node.seq, stored_token.node_order = node.order, \
                stored_token.decoded = token.decoded, stored_token.category = token.category, \
                stored_token.version = commit.version \
  ON MATCH SET stored_token.node_seq = CASE WHEN node.order < stored_token.node_order \
                 THEN node.seq ELSE stored_token.node_seq END, \
               stored_token.version = CASE WHEN node.order < stored_token.node_order \
                 THEN commit.version ELSE stored_token.version END, \
               stored_token.node_order = CASE WHEN node.order < stored_token.node_order \
                 THEN node.order ELSE stored_token.node_order END \
  MERGE (node)-[:MENTIONS_TOKEN {slot: token.slot}]->(stored_token) \
  RETURN count(stored_token) AS token_count \
  UNION \
  WITH node, commit WHERE node IS NULL OR size($tokens) = 0 \
  RETURN 0 AS token_count \
} \
WITH commit, node, paragraph_refs \
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
RETURN commit.version AS version, node.seq AS node_seq, node.type AS node_type, paragraph_refs, \
       commit.event_json = $event_json AS same_event";

const APPLY_PARAGRAPH_CLASSIFICATION: &str = "\
MATCH (session:Session {session_id: $session_id}) \
OPTIONAL MATCH (session)-[:CONTAINS]->(:ExecutionNode)-[:CONTAINS_PARAGRAPH]->(paragraph:Paragraph {hash: $hash}) \
WITH session, collect(DISTINCT paragraph) AS paragraphs \
CALL (session, paragraphs) { \
  WITH session, paragraphs WHERE size(paragraphs) > 0 \
  UNWIND paragraphs AS paragraph \
  SET paragraph.instructs = $instructs, paragraph.jev_ms = $jev_ms, paragraph.jev_error = $error \
  WITH session, count(paragraph) AS updated \
  OPTIONAL MATCH (pending:PendingParagraphEnrichment {session_id: $session_id, hash: $hash}) \
  DELETE pending \
  RETURN true AS applied \
  UNION \
  WITH session, paragraphs WHERE size(paragraphs) = 0 \
  MERGE (pending:PendingParagraphEnrichment {session_id: $session_id, hash: $hash}) \
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

// Every event carries the session cwd and prompt id as they were after it, so the values of the
// highest order are the current ones. Commits made before they were recorded on EventCommit fall
// back to their ExecutionNode.
const SESSION_CURSOR: &str = "\
OPTIONAL MATCH (commit:EventCommit {session_id: $session_id}) \
WITH coalesce(max(commit.order), 0) AS last_order \
OPTIONAL MATCH (node:ExecutionNode {session_id: $session_id}) \
WHERE node.agent_id IS NOT NULL AND node.sequence IS NOT NULL \
WITH last_order, node.agent_id AS agent_id, max(node.sequence) AS sequence \
WITH last_order, \
     collect(CASE WHEN agent_id IS NULL THEN NULL ELSE [agent_id, sequence] END) AS agents \
RETURN last_order, agents, \
  coalesce( \
    COLLECT { MATCH (c:EventCommit {session_id: $session_id}) WHERE c.cwd IS NOT NULL \
              RETURN c.cwd ORDER BY c.order DESC LIMIT 1 }[0], \
    COLLECT { MATCH (n:ExecutionNode {session_id: $session_id}) WHERE n.cwd IS NOT NULL \
              RETURN n.cwd ORDER BY n.order DESC LIMIT 1 }[0]) AS cwd, \
  coalesce( \
    COLLECT { MATCH (c:EventCommit {session_id: $session_id}) WHERE c.prompt_id IS NOT NULL \
              RETURN c.prompt_id ORDER BY c.order DESC LIMIT 1 }[0], \
    COLLECT { MATCH (n:ExecutionNode {session_id: $session_id}) WHERE n.prompt_id IS NOT NULL \
              RETURN n.prompt_id ORDER BY n.order DESC LIMIT 1 }[0]) AS prompt_id";

const TOOL_CALL: &str = "\
MATCH (call:ExecutionNode {session_id: $session_id, type: 'Call', tool_use_id: $tool_use_id}) \
RETURN call.payload_json ORDER BY call.order DESC LIMIT 1";

const DELETE_PARAGRAPHS: &str = "\
MATCH (paragraph) WHERE paragraph:Paragraph OR paragraph:PendingParagraphEnrichment \
DETACH DELETE paragraph";

const LIST_NODE_COMMITS: &str = "\
MATCH (commit:EventCommit) WHERE commit.has_node \
RETURN commit.event_name, commit.event_json \
ORDER BY commit.observed_at, commit.session_id, commit.order \
SKIP $skip LIMIT $limit";

const REINDEX_PARAGRAPHS: &str = "\
UNWIND $rows AS row \
MATCH (commit:EventCommit {session_id: row.session_id, order: row.order})-[:CREATED]->(node:ExecutionNode) \
CALL (node, row) { \
  UNWIND row.paragraphs AS paragraph \
  MERGE (stored:Paragraph {hash: paragraph.hash}) \
  ON CREATE SET stored.text = paragraph.text, stored.source = paragraph.source, \
                stored.hidden = paragraph.hidden, stored.hidden_rules = paragraph.hidden_rules, \
                stored.from_user_doc = paragraph.from_user_doc, \
                stored.long_paragraph = paragraph.long_paragraph, stored.created_in_seq = node.seq \
  ON MATCH SET stored.hidden = coalesce(stored.hidden, false) OR paragraph.hidden, \
               stored.hidden_rules = coalesce(stored.hidden_rules, []) + \
                 [rule IN paragraph.hidden_rules WHERE NOT rule IN coalesce(stored.hidden_rules, [])] \
  MERGE (node)-[:CONTAINS_PARAGRAPH {index: paragraph.index}]->(stored) \
} \
CALL (node, commit, row) { \
  UNWIND row.tokens AS token \
  MERGE (stored_token:Token {session_id: row.session_id, key_kind: token.key_kind, key: token.key, slot: token.slot}) \
  ON CREATE SET stored_token.node_seq = node.seq, stored_token.node_order = node.order, \
                stored_token.decoded = token.decoded, stored_token.category = token.category, \
                stored_token.version = commit.version \
  MERGE (node)-[:MENTIONS_TOKEN {slot: token.slot}]->(stored_token) \
} \
RETURN count(node) AS reindexed";

const REINDEX_PAGE: usize = 500;

/// Concurrent commits to one session can deadlock on the Session node. Neo4j reports that
/// as a transient error and the whole statement is safe to run again.
const TRANSIENT_ATTEMPTS: u32 = 5;

/// Outcome of [`Neo4jRepository::reindex_paragraphs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReindexReport {
    pub scanned: usize,
    pub reindexed: usize,
}

#[async_trait]
pub trait GraphRepository: Send + Sync + 'static {
    async fn health(&self) -> Result<(), RepositoryError>;
    async fn commit(&self, event: GeneratorEvent) -> Result<EventResponse, RepositoryError>;
    async fn classify_paragraph(
        &self,
        _session_id: &str,
        _hash: &str,
        _request: ParagraphClassificationRequest,
    ) -> Result<ParagraphClassificationResponse, RepositoryError> {
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

    /// Unknown sessions have a zero cursor.
    async fn session_cursor(&self, _session_id: &str) -> Result<SessionCursor, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// The committed PreToolUse call with this tool_use_id; `NotFound` when there is none.
    async fn tool_call(
        &self,
        _session_id: &str,
        _tool_use_id: &str,
    ) -> Result<ToolCall, RepositoryError> {
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
        let mut attempt = 1;
        loop {
            match self.execute_once(statement, &parameters).await {
                Err(error) if is_transient(&error) && attempt < TRANSIENT_ATTEMPTS => {
                    tokio::time::sleep(retry_delay(attempt)).await;
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
            .ok_or_else(|| RepositoryError::InvalidResponse("missing data".to_owned()))
    }

    /// Drops every Paragraph and re-chunks the text of each committed event with the current
    /// rules. Paragraph classifications are lost and must be requested again.
    pub async fn reindex_paragraphs(&self) -> Result<ReindexReport, RepositoryError> {
        self.execute(DELETE_PARAGRAPHS, json!({})).await?;
        let mut report = ReindexReport {
            scanned: 0,
            reindexed: 0,
        };
        loop {
            let page = self
                .execute(
                    LIST_NODE_COMMITS,
                    json!({"skip": report.scanned, "limit": REINDEX_PAGE}),
                )
                .await?;
            if page.values.is_empty() {
                return Ok(report);
            }
            report.scanned += page.values.len();
            let mut rows = Vec::new();
            for row in &page.values {
                let text = |index, field| {
                    value_at(row, index, field)?.as_str().ok_or_else(|| {
                        RepositoryError::InvalidResponse(format!("{field} is not a string"))
                    })
                };
                let mutation =
                    GeneratorEvent::from_json(text(0, "event_name")?, text(1, "event_json")?)?
                        .into_mutation()?;
                if !mutation.paragraphs.is_empty() {
                    rows.push(json!({
                        "session_id": mutation.session_id,
                        "order": mutation.order,
                        "paragraphs": mutation.paragraphs,
                        "tokens": mutation.tokens,
                    }));
                }
            }
            if rows.is_empty() {
                continue;
            }
            let data = self
                .execute(REINDEX_PARAGRAPHS, json!({"rows": rows}))
                .await?;
            report.reindexed += data
                .values
                .first()
                .and_then(|row| row.first())
                .and_then(Value::as_u64)
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0);
        }
    }

    async fn commit_mutation(
        &self,
        mutation: GraphMutation,
    ) -> Result<EventResponse, RepositoryError> {
        let has_node = mutation.node_type.is_some();
        let is_tool_result = matches!(mutation.node_type, Some("Sequence" | "Error"));
        let previous_sequence = mutation.sequence.map(|sequence| sequence - 1);
        let next_sequence = mutation.sequence.map(|sequence| sequence + 1);
        let parameters = json!({
            "session_id": mutation.session_id,
            "order": mutation.order,
            "observed_at": mutation.observed_at,
            "event_name": mutation.event_name,
            "node_type": mutation.node_type,
            "has_node": has_node,
            "client_id": mutation.client_id,
            "sequence": mutation.sequence,
            "previous_sequence": previous_sequence,
            "next_sequence": next_sequence,
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
            "paragraphs": mutation.paragraphs,
            "tokens": mutation.tokens,
            "intent": mutation.intent,
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
        let paragraphs = value_at(row, 3, "paragraph_refs")?
            .as_array()
            .ok_or_else(|| {
                RepositoryError::InvalidResponse("paragraph_refs is not an array".to_owned())
            })?
            .iter()
            .map(|reference| {
                Ok(ParagraphReference {
                    hash: reference
                        .get("hash")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            RepositoryError::InvalidResponse(
                                "paragraph hash is not a string".to_owned(),
                            )
                        })?
                        .to_owned(),
                    seq: unsigned(
                        reference.get("seq").ok_or_else(|| {
                            RepositoryError::InvalidResponse("missing paragraph seq".to_owned())
                        })?,
                        "paragraph seq",
                    )?,
                    new: reference
                        .get("new")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| {
                            RepositoryError::InvalidResponse(
                                "paragraph new is not a boolean".to_owned(),
                            )
                        })?,
                })
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?;

        Ok(EventResponse {
            nodes,
            paragraphs: (!paragraphs.is_empty()).then_some(paragraphs),
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

    async fn classify_paragraph(
        &self,
        session_id: &str,
        hash: &str,
        request: ParagraphClassificationRequest,
    ) -> Result<ParagraphClassificationResponse, RepositoryError> {
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
                APPLY_PARAGRAPH_CLASSIFICATION,
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
        Ok(ParagraphClassificationResponse {
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

    async fn session_cursor(&self, session_id: &str) -> Result<SessionCursor, RepositoryError> {
        let data = self
            .execute(SESSION_CURSOR, json!({"session_id": session_id}))
            .await?;
        let row = data
            .values
            .first()
            .ok_or_else(|| RepositoryError::InvalidResponse("missing cursor row".to_owned()))?;
        Ok(SessionCursor {
            last_order: unsigned(value_at(row, 0, "last_order")?, "last_order")?,
            agent_sequences: value_at(row, 1, "agents")?
                .as_array()
                .ok_or_else(|| {
                    RepositoryError::InvalidResponse("agents is not an array".to_owned())
                })?
                .iter()
                .map(agent_sequence)
                .collect::<Result<_, _>>()?,
            cwd: row.get(2).and_then(Value::as_str).map(str::to_owned),
            prompt_id: row.get(3).and_then(Value::as_str).map(str::to_owned),
        })
    }

    async fn tool_call(
        &self,
        session_id: &str,
        tool_use_id: &str,
    ) -> Result<ToolCall, RepositoryError> {
        let data = self
            .execute(
                TOOL_CALL,
                json!({"session_id": session_id, "tool_use_id": tool_use_id}),
            )
            .await?;
        let payload = data
            .values
            .first()
            .and_then(|row| row.first())
            .and_then(Value::as_str)
            .ok_or(RepositoryError::NotFound)?;
        serde_json::from_str(payload)
            .map_err(|error| RepositoryError::InvalidResponse(error.to_string()))
    }
}

fn agent_sequence(pair: &Value) -> Result<(String, u64), RepositoryError> {
    let invalid = || RepositoryError::InvalidResponse("invalid agent sequence".to_owned());
    let agent_id = pair.get(0).and_then(Value::as_str).ok_or_else(invalid)?;
    let sequence = pair.get(1).and_then(Value::as_u64).ok_or_else(invalid)?;
    Ok((agent_id.to_owned(), sequence))
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

fn is_transient(error: &RepositoryError) -> bool {
    matches!(error, RepositoryError::Query(message) if message.starts_with("Neo.TransientError."))
}

/// Linear backoff with jitter so transactions that deadlocked together do not retry in lockstep.
fn retry_delay(attempt: u32) -> Duration {
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |now| now.subsec_nanos() % 20);
    Duration::from_millis(u64::from(attempt * 20 + jitter))
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
