use std::{error::Error, fmt};

use async_trait::async_trait;
use std::time::Duration;

use serde_json::Value;
use withhuman_contracts::{
    events::{EventResponse, SessionCursor, ToolCall},
    inventory::{KeyDenial, VerifyKeyRequest, VerifyKeyResponse},
};

use crate::NormalizedEvent;

/// Bounds the lookups that restore session state the Collector lost.
const CURSOR_TIMEOUT: Duration = Duration::from_secs(2);

#[async_trait]
pub trait GeneratorTransport: Send + Sync {
    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError>;

    /// The last order and agent sequences committed for a session; zero when it is unknown.
    async fn session_cursor(&self, _session_id: &str) -> Result<SessionCursor, GeneratorError> {
        Ok(SessionCursor::default())
    }

    /// The input of a committed PreToolUse call; `None` when no such call was committed.
    async fn tool_input(
        &self,
        _session_id: &str,
        _tool_use_id: &str,
    ) -> Result<Option<Value>, GeneratorError> {
        Ok(None)
    }

    /// Whose key has this id and hash, and whether it was revoked.
    async fn verify_key(
        &self,
        _request: VerifyKeyRequest,
    ) -> Result<VerifyKeyResponse, GeneratorError> {
        Err(GeneratorError::Rejected(404))
    }

    /// Records a PreToolUse turned back because its key was revoked.
    async fn record_key_denial(
        &self,
        _key_id: &str,
        _denial: KeyDenial,
    ) -> Result<(), GeneratorError> {
        Ok(())
    }

    /// The Generator's inventory API below `/v1` (clients, users and keys), its status and JSON
    /// body passed back as they are.
    async fn inventory(
        &self,
        _method: reqwest::Method,
        _segments: &[&str],
        _body: Option<Value>,
    ) -> Result<(u16, Value), GeneratorError> {
        Err(GeneratorError::Rejected(404))
    }
}

#[derive(Debug, Clone)]
pub struct GeneratorHttpClient {
    base_url: String,
    client: reqwest::Client,
}

impl GeneratorHttpClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl GeneratorTransport for GeneratorHttpClient {
    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        let event_name = event.event_name();
        let body = event_body(&event)?;
        let response = self
            .client
            .post(format!("{}/v1/events/{event_name}", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|error| GeneratorError::Unavailable(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(GeneratorError::Rejected(status.as_u16()));
        }
        response
            .json()
            .await
            .map_err(|error| GeneratorError::InvalidResponse(error.to_string()))
    }

    async fn session_cursor(&self, session_id: &str) -> Result<SessionCursor, GeneratorError> {
        self.get_json(&["v1", "sessions", session_id, "cursor"])
            .await?
            .ok_or(GeneratorError::Rejected(404))
    }

    async fn tool_input(
        &self,
        session_id: &str,
        tool_use_id: &str,
    ) -> Result<Option<Value>, GeneratorError> {
        Ok(self
            .get_json::<ToolCall>(&["v1", "sessions", session_id, "calls", tool_use_id])
            .await?
            .map(|call| call.tool_input))
    }

    async fn verify_key(
        &self,
        request: VerifyKeyRequest,
    ) -> Result<VerifyKeyResponse, GeneratorError> {
        let (status, body) = self
            .inventory(
                reqwest::Method::POST,
                &["keys", "verify"],
                Some(serde_json::to_value(request).map_err(invalid_request)?),
            )
            .await?;
        if status != 200 {
            return Err(GeneratorError::Rejected(status));
        }
        serde_json::from_value(body)
            .map_err(|error| GeneratorError::InvalidResponse(error.to_string()))
    }

    async fn record_key_denial(
        &self,
        key_id: &str,
        denial: KeyDenial,
    ) -> Result<(), GeneratorError> {
        let (status, _) = self
            .inventory(
                reqwest::Method::POST,
                &["keys", key_id, "denials"],
                Some(serde_json::to_value(denial).map_err(invalid_request)?),
            )
            .await?;
        match status {
            200..=299 => Ok(()),
            status => Err(GeneratorError::Rejected(status)),
        }
    }

    async fn inventory(
        &self,
        method: reqwest::Method,
        segments: &[&str],
        body: Option<Value>,
    ) -> Result<(u16, Value), GeneratorError> {
        let mut url = reqwest::Url::parse(&self.base_url).map_err(invalid_request)?;
        url.path_segments_mut()
            .map_err(|()| GeneratorError::InvalidRequest("Generator URL has no path".to_owned()))?
            .push("v1")
            .extend(segments);
        let mut request = self.client.request(method, url).timeout(CURSOR_TIMEOUT);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| GeneratorError::Unavailable(error.to_string()))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| GeneratorError::InvalidResponse(error.to_string()))?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|error| GeneratorError::InvalidResponse(error.to_string()))?
        };
        Ok((status, body))
    }
}

fn invalid_request(error: impl fmt::Display) -> GeneratorError {
    GeneratorError::InvalidRequest(error.to_string())
}

impl GeneratorHttpClient {
    /// GETs a JSON resource below the Generator URL; `None` when it does not exist.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        segments: &[&str],
    ) -> Result<Option<T>, GeneratorError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|error| GeneratorError::InvalidRequest(error.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GeneratorError::InvalidRequest("Generator URL has no path".to_owned()))?
            .extend(segments);
        let response = self
            .client
            .get(url)
            .timeout(CURSOR_TIMEOUT)
            .send()
            .await
            .map_err(|error| GeneratorError::Unavailable(error.to_string()))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(GeneratorError::Rejected(status.as_u16()));
        }
        response
            .json()
            .await
            .map(Some)
            .map_err(|error| GeneratorError::InvalidResponse(error.to_string()))
    }
}

fn event_body(event: &NormalizedEvent) -> Result<serde_json::Value, GeneratorError> {
    let result = match event {
        NormalizedEvent::SessionStart(value) => serde_json::to_value(value),
        NormalizedEvent::SessionEnd(value) => serde_json::to_value(value),
        NormalizedEvent::UserPromptSubmit(value) => serde_json::to_value(value),
        NormalizedEvent::PreToolUse(value) => serde_json::to_value(value),
        NormalizedEvent::PostToolUse(value) => serde_json::to_value(value),
        NormalizedEvent::PostToolUseFailure(value) => serde_json::to_value(value),
        NormalizedEvent::SubagentStart(value) => serde_json::to_value(value),
        NormalizedEvent::SubagentStop(value) => serde_json::to_value(value),
        NormalizedEvent::ConfigChange(value) => serde_json::to_value(value),
        NormalizedEvent::MessageDisplay(value) => serde_json::to_value(value),
        NormalizedEvent::Intent(value) => serde_json::to_value(value),
        NormalizedEvent::PostToolBatch(value) => serde_json::to_value(value),
        NormalizedEvent::ToolDescriptions(value) => serde_json::to_value(value),
    };
    result.map_err(|error| GeneratorError::InvalidRequest(error.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorError {
    InvalidRequest(String),
    Unavailable(String),
    Rejected(u16),
    InvalidResponse(String),
    Timeout,
}

impl fmt::Display for GeneratorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(error) => write!(formatter, "invalid Generator request: {error}"),
            Self::Unavailable(error) => write!(formatter, "Generator unavailable: {error}"),
            Self::Rejected(status) => write!(formatter, "Generator returned HTTP {status}"),
            Self::InvalidResponse(error) => {
                write!(formatter, "invalid Generator response: {error}")
            }
            Self::Timeout => formatter.write_str("Generator request timed out"),
        }
    }
}

impl Error for GeneratorError {}
