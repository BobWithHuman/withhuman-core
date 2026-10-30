use std::{error::Error, fmt, time::Duration};

use redis::{
    Client,
    aio::{ConnectionManager, ConnectionManagerConfig},
};

/// Bounds one Redis round trip so a stalled Redis cannot consume the whole Hook decision budget.
const REDIS_TIMEOUT: Duration = Duration::from_secs(1);
const REDIS_RECONNECT_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Unavailable(String),
    Corrupt(String),
    /// The store holds no numbering for the session yet; it must be seeded first.
    UnknownSession,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "state store unavailable: {error}"),
            Self::Corrupt(error) => write!(formatter, "invalid state store value: {error}"),
            Self::UnknownSession => formatter.write_str("session has no stored numbering"),
        }
    }
}

impl Error for StoreError {}

impl From<redis::RedisError> for StoreError {
    fn from(error: redis::RedisError) -> Self {
        Self::Unavailable(error.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Corrupt(error.to_string())
    }
}

/// Opens a reconnecting Redis connection. The first connection is made lazily on the first
/// command, so the Collector starts (and applies its failure policies) while Redis is down.
pub fn redis_connection(url: &str) -> Result<ConnectionManager, StoreError> {
    let config = ConnectionManagerConfig::new()
        .set_connection_timeout(Some(REDIS_TIMEOUT))
        .set_response_timeout(Some(REDIS_TIMEOUT))
        .set_number_of_retries(REDIS_RECONNECT_ATTEMPTS);
    Ok(ConnectionManager::new_lazy_with_config(
        Client::open(url)?,
        config,
    )?)
}
