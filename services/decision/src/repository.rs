use std::{error::Error, fmt};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use withhuman_contracts::decisions::{DecisionRequest, DecisionResponse};

use crate::DecisionConfig;

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

#[async_trait]
pub trait DecisionRepository: Send + Sync + 'static {
    async fn health(&self) -> Result<(), RepositoryError>;
    async fn verify_graph(&self, request: &DecisionRequest) -> Result<(), RepositoryError>;
    async fn persist(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), RepositoryError>;
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
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "Neo4j unavailable: {error}"),
            Self::Query(error) => write!(formatter, "Neo4j query failed: {error}"),
            Self::InvalidResponse(error) => write!(formatter, "invalid Neo4j response: {error}"),
            Self::NotFound => formatter.write_str("requested graph version or Call was not found"),
        }
    }
}

impl Error for RepositoryError {}
