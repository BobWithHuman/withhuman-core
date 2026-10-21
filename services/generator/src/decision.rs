use std::{error::Error, fmt, time::Duration};

use async_trait::async_trait;
use withhuman_contracts::decisions::{DecisionRequest, DecisionResponse};

use crate::GeneratorConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    InvalidEndpoint(String),
    Unavailable(String),
    InvalidResponse(String),
}

impl fmt::Display for DecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(message) => {
                write!(formatter, "invalid Decision endpoint: {message}")
            }
            Self::Unavailable(message) => write!(formatter, "Decision unavailable: {message}"),
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid Decision response: {message}")
            }
        }
    }
}

impl Error for DecisionError {}

#[async_trait]
pub trait DecisionClient: Send + Sync + 'static {
    async fn decide(&self, request: DecisionRequest) -> Result<DecisionResponse, DecisionError>;
}

#[derive(Clone)]
pub struct HttpDecisionClient {
    client: reqwest::Client,
    endpoint: reqwest::Url,
}

impl HttpDecisionClient {
    pub fn new(config: &GeneratorConfig) -> Result<Self, DecisionError> {
        let endpoint = reqwest::Url::parse(&config.decision_url)
            .and_then(|url| url.join("/v1/decide"))
            .map_err(|error| DecisionError::InvalidEndpoint(error.to_string()))?;
        Ok(Self {
            client: reqwest::Client::new(),
            endpoint,
        })
    }
}

#[async_trait]
impl DecisionClient for HttpDecisionClient {
    async fn decide(&self, request: DecisionRequest) -> Result<DecisionResponse, DecisionError> {
        let timeout = request.deadline_ms.map(Duration::from_millis);
        let mut request_builder = self.client.post(self.endpoint.clone()).json(&request);
        if let Some(timeout) = timeout {
            request_builder = request_builder.timeout(timeout);
        }
        let response = request_builder
            .send()
            .await
            .map_err(|error| DecisionError::Unavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(DecisionError::Unavailable(format!(
                "HTTP {}",
                response.status()
            )));
        }
        let response = response
            .json::<DecisionResponse>()
            .await
            .map_err(|error| DecisionError::InvalidResponse(error.to_string()))?;
        response
            .validate()
            .map_err(|error| DecisionError::InvalidResponse(error.to_string()))?;
        Ok(response)
    }
}
