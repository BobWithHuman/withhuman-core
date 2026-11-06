use std::{env, io, net::SocketAddr};

const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8081";
const DEFAULT_DECISION_URL: &str = "http://decision:8082";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorConfig {
    pub bind_address: SocketAddr,
    pub decision_url: String,
}

impl GeneratorConfig {
    pub fn from_env() -> io::Result<Self> {
        let bind_address = env::var("GENERATOR_ADDR")
            .unwrap_or_else(|_| DEFAULT_BIND_ADDRESS.to_owned())
            .parse()
            .map_err(|error| invalid(format!("invalid GENERATOR_ADDR: {error}")))?;

        Ok(Self {
            bind_address,
            decision_url: env::var("DECISION_URL")
                .unwrap_or_else(|_| DEFAULT_DECISION_URL.to_owned()),
        })
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
