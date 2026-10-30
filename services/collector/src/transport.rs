use std::{error::Error, fmt};

use async_trait::async_trait;
use std::time::Duration;

use serde_json::Value;
use withhuman_contracts::events::{EventResponse, SessionCursor, ToolCall};

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
        NormalizedEvent::UserPromptSubmit(value) => serde_json::to_value(value),
        NormalizedEvent::PreToolUse(value) => serde_json::to_value(value),
        NormalizedEvent::PostToolUse(value) => serde_json::to_value(value),
        NormalizedEvent::PostToolUseFailure(value) => serde_json::to_value(value),
        NormalizedEvent::SubagentStart(value) => serde_json::to_value(value),
        NormalizedEvent::SubagentStop(value) => serde_json::to_value(value),
        NormalizedEvent::InstructionsLoaded(value) => serde_json::to_value(value),
        NormalizedEvent::ConfigChange(value) => serde_json::to_value(value),
        NormalizedEvent::FileChanged(value) => serde_json::to_value(value),
        NormalizedEvent::MessageDisplay(value) => serde_json::to_value(value),
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
