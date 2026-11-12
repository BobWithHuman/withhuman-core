use crate::trace::{Member, TraceGraph};
use async_trait::async_trait;
use serde_json::Value;
use std::{error::Error, fmt};
use withhuman_contracts::decisions::{DecisionRequest, DecisionResponse};

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
    /// The paragraph of the tool result, or none for the result whole.
    pub paragraph: Option<u64>,
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

    /// The file changes the session's earlier Calls made to `path` and that ran (their result is
    /// in the graph), oldest first: what a file change that undoes them is checked against.
    async fn earlier_file_changes(
        &self,
        _session_id: &str,
        _call_order: u64,
        _path: &str,
    ) -> Result<Vec<crate::check::FileDiff>, RepositoryError> {
        Ok(Vec::new())
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
            Self::Unavailable(error) => write!(formatter, "PostgreSQL unavailable: {error}"),
            Self::Query(error) => write!(formatter, "PostgreSQL query failed: {error}"),
            Self::InvalidResponse(error) => {
                write!(formatter, "invalid PostgreSQL response: {error}")
            }
            Self::NotFound => formatter.write_str("requested graph version or Call was not found"),
            Self::NoSubGraph => formatter.write_str("the Call has no SubGraph"),
        }
    }
}

impl Error for RepositoryError {}
