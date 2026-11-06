use crate::GeneratorEvent;
use async_trait::async_trait;
use std::{error::Error, fmt};
use withhuman_contracts::events::{
    EventResponse, ParagraphClassificationRequest, ParagraphClassificationResponse,
    RequestContinuationRequest, RequestContinuationResponse, SessionCursor, ToolCall,
};

/// Outcome of [`crate::PgGraphRepository::reindex_paragraphs`].
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
            Self::Unavailable(error) => write!(formatter, "PostgreSQL unavailable: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid graph event: {error}"),
            Self::Query(error) => write!(formatter, "PostgreSQL query failed: {error}"),
            Self::InvalidResponse(error) => {
                write!(formatter, "invalid PostgreSQL response: {error}")
            }
            Self::NotFound => formatter.write_str("graph resource not found"),
        }
    }
}

impl Error for RepositoryError {}
