//! PostgreSQL connection settings shared by Generator and Decision.

use std::{env, io};

/// Connections each service keeps open to PostgreSQL unless `DATABASE_POOL_SIZE` says otherwise.
pub const DEFAULT_POOL_SIZE: usize = 16;

/// Where and how widely a service connects to PostgreSQL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresSettings {
    pub database_url: String,
    pub pool_size: usize,
}

impl PostgresSettings {
    /// `DATABASE_URL` (required) and `DATABASE_POOL_SIZE` (optional, at least 1).
    pub fn from_env() -> io::Result<Self> {
        match env::var("WITHHUMAN_GRAPH_STORE").as_deref() {
            Ok("" | "postgres") | Err(env::VarError::NotPresent) => {}
            _ => return Err(invalid("WITHHUMAN_GRAPH_STORE must be postgres or unset")),
        }
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
