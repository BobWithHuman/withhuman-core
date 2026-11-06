//! Which database holds the execution graph: Neo4j (the default) or PostgreSQL.
//!
//! Generator and Decision both read this, and a graph written to one store and read from the
//! other traces every Call against an empty graph. So both read it here, the same way, and a
//! value neither knows stops the service instead of quietly meaning Neo4j.

use std::{env, io};

/// The variable that picks the store.
pub const GRAPH_STORE_VARIABLE: &str = "WITHHUMAN_GRAPH_STORE";

/// Connections each service keeps open to PostgreSQL unless `DATABASE_POOL_SIZE` says otherwise.
pub const DEFAULT_POOL_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphStore {
    Neo4j,
    Postgres,
}

impl GraphStore {
    /// The store `WITHHUMAN_GRAPH_STORE` names. Unset or empty is Neo4j, so a deployment that
    /// predates the choice, or a Compose file that passes the variable through blank, keeps
    /// running as it did.
    pub fn from_env() -> io::Result<Self> {
        let value = match env::var(GRAPH_STORE_VARIABLE) {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(invalid(format!("{GRAPH_STORE_VARIABLE} must be UTF-8")));
            }
        };
        Self::parse(value.as_deref()).map_err(invalid)
    }

    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("") | Some("neo4j") => Ok(Self::Neo4j),
            Some("postgres") => Ok(Self::Postgres),
            Some(other) => Err(format!(
                "unsupported {GRAPH_STORE_VARIABLE} `{other}`: expected `neo4j` or `postgres`"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Neo4j => "neo4j",
            Self::Postgres => "postgres",
        }
    }
}

/// Where and how widely a service connects to PostgreSQL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresSettings {
    pub database_url: String,
    pub pool_size: usize,
}

impl PostgresSettings {
    /// `DATABASE_URL` (required) and `DATABASE_POOL_SIZE` (optional, at least 1).
    pub fn from_env() -> io::Result<Self> {
        Self::parse(
            env::var("DATABASE_URL").ok(),
            env::var("DATABASE_POOL_SIZE").ok().as_deref(),
        )
        .map_err(invalid)
    }

    pub fn parse(database_url: Option<String>, pool_size: Option<&str>) -> Result<Self, String> {
        let database_url = database_url
            .filter(|url| !url.is_empty())
            .ok_or("DATABASE_URL must be configured")?;
        // A typo here would otherwise run the service on a pool nobody chose.
        let pool_size = match pool_size {
            None | Some("") => DEFAULT_POOL_SIZE,
            Some(size) => match size.parse::<usize>() {
                Ok(size) if size > 0 => size,
                _ => return Err(format!("invalid DATABASE_POOL_SIZE `{size}`")),
            },
        };
        Ok(Self {
            database_url,
            pool_size,
        })
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_keeps_neo4j() {
        assert_eq!(GraphStore::parse(None), Ok(GraphStore::Neo4j));
        assert_eq!(GraphStore::parse(Some("")), Ok(GraphStore::Neo4j));
        assert_eq!(GraphStore::parse(Some("neo4j")), Ok(GraphStore::Neo4j));
        assert_eq!(
            GraphStore::parse(Some("postgres")),
            Ok(GraphStore::Postgres)
        );
    }

    #[test]
    fn an_unknown_store_is_refused_rather_than_read_as_neo4j() {
        for value in ["Postgres", "pg", "postgres ", "postgresql"] {
            assert!(GraphStore::parse(Some(value)).is_err(), "{value}");
        }
    }

    #[test]
    fn postgres_needs_a_url_and_a_valid_pool_size() {
        let url = || Some("postgres://localhost/withhuman".to_owned());
        assert_eq!(
            PostgresSettings::parse(url(), None).map(|settings| settings.pool_size),
            Ok(DEFAULT_POOL_SIZE)
        );
        assert_eq!(
            PostgresSettings::parse(url(), Some("4")).map(|settings| settings.pool_size),
            Ok(4)
        );
        assert!(PostgresSettings::parse(None, None).is_err());
        assert!(PostgresSettings::parse(Some(String::new()), None).is_err());
        assert!(PostgresSettings::parse(url(), Some("0")).is_err());
        assert!(PostgresSettings::parse(url(), Some("sixteen")).is_err());
    }
}
