use std::{env, io, net::SocketAddr};
use withhuman_common::graph_store::GraphStore;

const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8081";
const DEFAULT_NEO4J_URL: &str = "http://neo4j:7474";
const DEFAULT_NEO4J_USER: &str = "neo4j";
const DEFAULT_NEO4J_DATABASE: &str = "neo4j";
const DEFAULT_DECISION_URL: &str = "http://decision:8082";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorConfig {
    pub bind_address: SocketAddr,
    pub neo4j_url: String,
    pub neo4j_user: String,
    pub neo4j_password: String,
    pub neo4j_database: String,
    pub decision_url: String,
}

impl GeneratorConfig {
    pub fn from_env() -> io::Result<Self> {
        let bind_address = env::var("GENERATOR_ADDR")
            .unwrap_or_else(|_| DEFAULT_BIND_ADDRESS.to_owned())
            .parse()
            .map_err(|error| invalid(format!("invalid GENERATOR_ADDR: {error}")))?;
        // A Generator on PostgreSQL (`WITHHUMAN_GRAPH_STORE=postgres`) needs no Neo4j password.
        let on_postgres = GraphStore::from_env()? == GraphStore::Postgres;
        let neo4j_password = match env::var("NEO4J_PASSWORD") {
            Ok(password) if !password.is_empty() => password,
            Ok(_) if !on_postgres => return Err(invalid("NEO4J_PASSWORD must not be empty")),
            Err(_) if !on_postgres => return Err(invalid("NEO4J_PASSWORD must be configured")),
            _ => String::new(),
        };

        Ok(Self {
            bind_address,
            neo4j_url: env::var("NEO4J_URL").unwrap_or_else(|_| DEFAULT_NEO4J_URL.to_owned()),
            neo4j_user: env::var("NEO4J_USER").unwrap_or_else(|_| DEFAULT_NEO4J_USER.to_owned()),
            neo4j_password,
            neo4j_database: env::var("NEO4J_DATABASE")
                .unwrap_or_else(|_| DEFAULT_NEO4J_DATABASE.to_owned()),
            decision_url: env::var("DECISION_URL")
                .unwrap_or_else(|_| DEFAULT_DECISION_URL.to_owned()),
        })
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
