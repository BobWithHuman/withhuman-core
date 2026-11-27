use crate::GeneratorEvent;
use async_trait::async_trait;
use std::{error::Error, fmt};
use withhuman_contracts::{
    events::{
        EventResponse, ParagraphClassificationRequest, ParagraphClassificationResponse,
        RequestContinuationRequest, RequestContinuationResponse, SessionCursor, ToolCall,
    },
    inventory::{
        ClientRecord, ClientRegistrationRecord, ClientState, DeletedClient, KeyDenial, KeyRecord,
        NewKey, Review, ReviewRequest, RevokeKeyRequest, SessionFlags, SessionStop,
        SessionStopRequest, SetOwnerRequest, StopClientRequest, StopDenial, VerifyKeyRequest,
        VerifyKeyResponse,
    },
    triage::{
        DistrustSourceRequest, Evidence, MarkSessionRequest, MarkSessionsRequest, MarkedSession,
        MarkedSessions, SourceTrust,
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

/// Outcome of [`crate::PgGraphRepository::backtrack_secrets`]. Counts only, never a value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BacktrackReport {
    /// Tokens whose first mention in their session was the agent's.
    pub scanned: usize,
    /// Of those, the ones whose value was found again in the session's stored text.
    pub recovered: usize,
    /// Of those, the ones an earlier node now mentions.
    pub traced: usize,
    /// Stored rows (nodes, paragraphs, commits) whose copy of a value was masked.
    pub masked: usize,
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

    /// Names the device's owner, or clears it; `NotFound` for an unknown device.
    async fn set_client_owner(
        &self,
        _client_id: &str,
        _request: SetOwnerRequest,
        _set_at: u64,
    ) -> Result<ClientRecord, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Stops the device, or releases it; `NotFound` for an unknown device.
    async fn stop_client(
        &self,
        _client_id: &str,
        _request: StopClientRequest,
        _at: u64,
    ) -> Result<ClientRecord, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Deletes the device and every session it ran, with all that was recorded of them;
    /// `NotFound` for a device the store holds nothing of.
    async fn delete_client(&self, _client_id: &str) -> Result<DeletedClient, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Whether the device is stopped; an unknown device is not.
    async fn client_state(&self, _client_id: &str) -> Result<ClientState, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Counts a PreToolUse refused for a stopped device; `NotFound` when it is not stopped.
    async fn record_stop_denial(
        &self,
        _client_id: &str,
        _denial: StopDenial,
    ) -> Result<(), RepositoryError> {
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

    /// The session's active stop; none for an unknown session.
    async fn session_flags(&self, _session_id: &str) -> Result<SessionFlags, RepositoryError> {
        Ok(SessionFlags::default())
    }

    /// Stops a recorded session (keeping an active stop); `NotFound` for an unknown session.
    async fn stop_session(
        &self,
        _session_id: &str,
        _request: SessionStopRequest,
        _at: u64,
    ) -> Result<SessionStop, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Releases the session's active stop; `NotFound` when it has none.
    async fn release_session(
        &self,
        _session_id: &str,
        _request: SessionStopRequest,
        _at: u64,
    ) -> Result<SessionStop, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Records a PreToolUse its session's stop turned back.
    async fn record_session_denial(
        &self,
        _session_id: &str,
        _at: u64,
    ) -> Result<(), RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Records a review of a Call; `NotFound` when no Call is `(session_id, seq)`.
    async fn add_review(
        &self,
        _request: ReviewRequest,
        _at: u64,
    ) -> Result<Review, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Sets the session's mark, or takes it off; `NotFound` for an unknown session.
    async fn mark_session(
        &self,
        _session_id: &str,
        _request: MarkSessionRequest,
        _set_at: u64,
    ) -> Result<MarkedSession, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Sets one mark on several sessions, or takes theirs off; the sessions the store does not
    /// hold are returned as unknown.
    async fn mark_sessions(
        &self,
        _request: MarkSessionsRequest,
        _set_at: u64,
    ) -> Result<MarkedSessions, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// Distrusts a source, or trusts it again.
    async fn distrust_source(
        &self,
        _request: DistrustSourceRequest,
        _set_at: u64,
    ) -> Result<SourceTrust, RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    /// One Call's evidence; `NotFound` for an unknown session or Call.
    async fn evidence(&self, _session_id: &str, _seq: u64) -> Result<Evidence, RepositoryError> {
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
