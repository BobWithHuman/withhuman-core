use crate::GeneratorEvent;
use async_trait::async_trait;
use std::{error::Error, fmt};
use withhuman_contracts::{
    events::{
        EventResponse, ParagraphClassificationRequest, ParagraphClassificationResponse,
        RequestContinuationRequest, RequestContinuationResponse, SessionCursor, ToolCall,
    },
    inventory::{
        ClientRecord, ClientRegistrationRecord, KeyDenial, KeyRecord, NewKey, RevokeKeyRequest,
        VerifyKeyRequest, VerifyKeyResponse,
    },
};

/// The keys a revocation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScope<'a> {
    Key(&'a str),
    /// Every key of the user (an email).
    User(&'a str),
}

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

    /// Records a device a setup registered, or updates it.
    async fn register_client(
        &self,
        _record: ClientRegistrationRecord,
    ) -> Result<ClientRecord, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Registered and seen devices, last active first.
    async fn clients(&self) -> Result<Vec<ClientRecord>, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Whose key has this id and hash, and whether it was revoked.
    async fn verify_key(
        &self,
        _request: VerifyKeyRequest,
    ) -> Result<VerifyKeyResponse, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Records a PreToolUse turned back for a revoked key; `NotFound` for an unknown key.
    async fn record_key_denial(
        &self,
        _key_id: &str,
        _denial: KeyDenial,
    ) -> Result<(), RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    async fn issue_key(&self, _key: NewKey) -> Result<KeyRecord, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Revokes the scope's active keys; every key of the scope after it, `NotFound` for none.
    async fn revoke_keys(
        &self,
        _scope: KeyScope<'_>,
        _request: RevokeKeyRequest,
        _revoked_at: u64,
    ) -> Result<Vec<KeyRecord>, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Every key, or a user's, newest first.
    async fn keys(&self, _user: Option<&str>) -> Result<Vec<KeyRecord>, RepositoryError> {
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
