use std::{env, io, net::SocketAddr};

const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8080";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectorConfig {
    pub bind_address: SocketAddr,
}

impl CollectorConfig {
    pub fn from_env() -> io::Result<Self> {
        let value = env::var("COLLECTOR_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDRESS.into());
        let bind_address = value.parse().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid COLLECTOR_ADDR {value:?}: {error}"),
            )
        })?;

        Ok(Self { bind_address })
    }
}
