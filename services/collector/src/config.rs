use std::{env, io, net::SocketAddr, time::Duration};

use withhuman_contracts::events::EnforcementMode;

const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8080";
const DEFAULT_EXT_AUTHZ_ADDRESS: &str = "0.0.0.0:9000";
const DEFAULT_GENERATOR_URL: &str = "http://generator:8081";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewPolicy {
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorConfig {
    pub bind_address: SocketAddr,
    pub ext_authz_address: SocketAddr,
    pub generator_url: String,
    pub decision_budget: Duration,
    pub enforcement_mode: EnforcementMode,
    pub failure_policy: FailurePolicy,
    pub review_policy: ReviewPolicy,
    pub enforce_mcp_at_hook: bool,
    pub watch_paths: Vec<String>,
    pub verdict_capacity: usize,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            bind_address: DEFAULT_BIND_ADDRESS
                .parse()
                .expect("default address is valid"),
            ext_authz_address: DEFAULT_EXT_AUTHZ_ADDRESS
                .parse()
                .expect("default extAuthz address is valid"),
            generator_url: DEFAULT_GENERATOR_URL.to_owned(),
            decision_budget: Duration::from_millis(4_200),
            enforcement_mode: EnforcementMode::Enforce,
            failure_policy: FailurePolicy::Open,
            review_policy: ReviewPolicy::Deny,
            enforce_mcp_at_hook: false,
            watch_paths: Vec::new(),
            verdict_capacity: 10_000,
        }
    }
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
        let ext_authz_value = env::var("COLLECTOR_EXT_AUTHZ_ADDR")
            .unwrap_or_else(|_| DEFAULT_EXT_AUTHZ_ADDRESS.into());
        let ext_authz_address = ext_authz_value.parse().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid COLLECTOR_EXT_AUTHZ_ADDR {ext_authz_value:?}: {error}"),
            )
        })?;

        let decision_budget =
            Duration::from_millis(parse_env("WITHHUMAN_DECISION_TIMEOUT_MS", 4_200)?);
        let verdict_capacity = parse_env("WITHHUMAN_VERDICT_CAPACITY", 10_000)?;
        if verdict_capacity == 0 {
            return Err(invalid(
                "WITHHUMAN_VERDICT_CAPACITY must be greater than zero",
            ));
        }

        Ok(Self {
            bind_address,
            ext_authz_address,
            generator_url: env::var("GENERATOR_URL")
                .unwrap_or_else(|_| DEFAULT_GENERATOR_URL.into()),
            decision_budget,
            enforcement_mode: match_env("WITHHUMAN_MODE", EnforcementMode::Enforce, |value| {
                match value {
                    "record" => Some(EnforcementMode::Record),
                    "shadow" => Some(EnforcementMode::Shadow),
                    "enforce" => Some(EnforcementMode::Enforce),
                    _ => None,
                }
            })?,
            failure_policy: match_env("WITHHUMAN_ON_FAILURE", FailurePolicy::Open, |value| {
                match value {
                    "open" => Some(FailurePolicy::Open),
                    "closed" => Some(FailurePolicy::Closed),
                    _ => None,
                }
            })?,
            review_policy: match_env("WITHHUMAN_ASK", ReviewPolicy::Deny, |value| match value {
                "deny" => Some(ReviewPolicy::Deny),
                "ask" => Some(ReviewPolicy::Ask),
                _ => None,
            })?,
            enforce_mcp_at_hook: env::var("WITHHUMAN_MCP_ENFORCE")
                .is_ok_and(|value| value == "hook"),
            watch_paths: env::var("WITHHUMAN_WATCH_PATHS")
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            verdict_capacity,
        })
    }
}

fn parse_env<T>(name: &str, default: T) -> io::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|error| invalid(format!("invalid {name} {value:?}: {error}"))),
        Err(_) => Ok(default),
    }
}

fn match_env<T>(name: &str, default: T, parse: impl FnOnce(&str) -> Option<T>) -> io::Result<T> {
    match env::var(name) {
        Ok(value) => parse(&value).ok_or_else(|| invalid(format!("invalid {name} {value:?}"))),
        Err(_) => Ok(default),
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
