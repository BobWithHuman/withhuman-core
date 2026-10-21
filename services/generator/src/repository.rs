use std::{error::Error, fmt};

use async_trait::async_trait;
use serde::Serialize;
use withhuman_contracts::events::EventResponse;

use crate::{GeneratorConfig, GeneratorEvent};

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

    async fn execute(&self, statement: &str) -> Result<(), RepositoryError> {
        let response = self
            .client
            .post(&self.endpoint)
            .basic_auth(&self.user, Some(&self.password))
            .json(&QueryRequest { statement })
            .send()
            .await
            .map_err(|error| RepositoryError::Unavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(RepositoryError::Unavailable(format!(
                "HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl GraphRepository for Neo4jRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        self.execute("RETURN 1").await
    }

    async fn commit(&self, _event: GeneratorEvent) -> Result<EventResponse, RepositoryError> {
        Err(RepositoryError::NotImplemented)
    }
}

#[derive(Serialize)]
struct QueryRequest<'a> {
    statement: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    Unavailable(String),
    InvalidEvent(String),
    NotImplemented,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "Neo4j unavailable: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid graph event: {error}"),
            Self::NotImplemented => formatter.write_str("graph mutation is not implemented"),
        }
    }
}

impl Error for RepositoryError {}
