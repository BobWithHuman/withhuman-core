//! Jev (`POST {JEV_URL}/v1/systemone`): a model that answers structured questions about a
//! shared `state`. `choice` questions return a probability per option, `noul` questions the
//! probability that a statement is true.

use std::{collections::BTreeMap, error::Error, fmt, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JevRequest {
    pub model: String,
    /// Context the questions refer to by key in backticks.
    pub state: BTreeMap<String, Value>,
    pub questions: BTreeMap<String, JevQuestion>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JevQuestion {
    #[serde(rename = "type")]
    pub kind: QuestionKind,
    pub instructions: String,
    /// Options of a choice question (`null` names a text in `state`), or the meanings of
    /// `true` and `false` for a noul question.
    pub criteria: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QuestionKind {
    Choice,
    Noul,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct JevResponse {
    #[serde(default)]
    pub answers: BTreeMap<String, JevAnswer>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct JevAnswer {
    #[serde(default)]
    pub choice: Option<String>,
    #[serde(default)]
    pub probabilities: BTreeMap<String, f64>,
    #[serde(default)]
    pub noul: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JevError {
    Unavailable(String),
    Timeout,
    Rejected(u16),
    InvalidResponse(String),
}

impl fmt::Display for JevError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "Jev unavailable: {error}"),
            Self::Timeout => formatter.write_str("Jev did not answer in time"),
            Self::Rejected(status) => write!(formatter, "Jev returned HTTP {status}"),
            Self::InvalidResponse(error) => write!(formatter, "invalid Jev response: {error}"),
        }
    }
}

impl Error for JevError {}

#[async_trait]
pub trait JevClient: Send + Sync + 'static {
    async fn ask(&self, request: &JevRequest, timeout: Duration) -> Result<JevResponse, JevError>;
}

#[derive(Clone)]
pub struct HttpJevClient {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    api_key: String,
}

impl HttpJevClient {
    pub fn new(base_url: &str, api_key: impl Into<String>) -> Result<Self, JevError> {
        let endpoint = reqwest::Url::parse(base_url)
            .and_then(|url| url.join("/v1/systemone"))
            .map_err(|error| JevError::Unavailable(format!("invalid JEV_URL: {error}")))?;
        Ok(Self {
            client: reqwest::Client::new(),
            endpoint,
            api_key: api_key.into(),
        })
    }
}

#[async_trait]
impl JevClient for HttpJevClient {
    async fn ask(&self, request: &JevRequest, timeout: Duration) -> Result<JevResponse, JevError> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(&self.api_key)
            .timeout(timeout)
            .json(request)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    JevError::Timeout
                } else {
                    JevError::Unavailable(error.to_string())
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(JevError::Rejected(status.as_u16()));
        }
        response
            .json()
            .await
            .map_err(|error| JevError::InvalidResponse(error.to_string()))
    }
}
