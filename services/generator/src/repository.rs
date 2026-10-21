use std::{error::Error, fmt};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use withhuman_contracts::events::{CreatedNode, EventResponse, ParagraphReference};

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
    event_name: $event_name, order: $order, observed_at: $observed_at, \
    client_id: $client_id, sequence: $sequence, prompt_id: $prompt_id, \
    agent_id: $agent_id, agent_type: $agent_type, cwd: $cwd, \
    tool_use_id: $tool_use_id, turn_id: $turn_id, repository: $repository, \
    payload_json: $payload_json \
  }) \
  CREATE (commit)-[:CREATED]->(node) \
  CREATE (session)-[:CONTAINS]->(node) \
) \
WITH session, commit \
OPTIONAL MATCH (node:ExecutionNode {session_id: $session_id, seq: commit.version}) \
OPTIONAL MATCH (previous:ExecutionNode {session_id: $session_id, seq: commit.version - 1}) \
FOREACH (_ IN CASE WHEN node IS NULL OR previous IS NULL THEN [] ELSE [1] END | \
  MERGE (previous)-[edge:NEXT]->(node) \
  ON CREATE SET edge.edge_id = $session_id + ':' + toString(previous.seq) + ':' + toString(node.seq), \
                edge.probability = 1.0 \
) \
WITH commit, node \
OPTIONAL MATCH (agent_previous:ExecutionNode { \
  session_id: $session_id, agent_id: $agent_id, sequence: $previous_sequence \
}) \
FOREACH (_ IN CASE WHEN node IS NULL OR agent_previous IS NULL THEN [] ELSE [1] END | \
  MERGE (agent_previous)-[:AGENT_SEQUENCE]->(node) \
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
                stored.hidden = paragraph.hidden, stored.from_user_doc = paragraph.from_user_doc, \
                stored.created_in_seq = node.seq \
  MERGE (node)-[:CONTAINS_PARAGRAPH {index: paragraph.index}]->(stored) \
  RETURN collect({hash: stored.hash, seq: node.seq, new: stored.created_in_seq = node.seq}) AS paragraph_refs \
  UNION \
  WITH node WHERE node IS NULL OR size($paragraphs) = 0 \
  RETURN [] AS paragraph_refs \
} \
RETURN commit.version AS version, node.seq AS node_seq, node.type AS node_type, paragraph_refs, \
       commit.event_json = $event_json AS same_event";

#[async_trait]
pub trait GraphRepository: Send + Sync + 'static {
    async fn health(&self) -> Result<(), RepositoryError>;
    async fn commit(&self, event: GeneratorEvent) -> Result<EventResponse, RepositoryError>;
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
        let is_tool_result = matches!(mutation.node_type, Some("Sequence" | "Error"));
        let previous_sequence = mutation.sequence.map(|sequence| sequence - 1);
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
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "Neo4j unavailable: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid graph event: {error}"),
            Self::Query(error) => write!(formatter, "Neo4j query failed: {error}"),
            Self::InvalidResponse(error) => write!(formatter, "invalid Neo4j response: {error}"),
        }
    }
}

impl Error for RepositoryError {}
