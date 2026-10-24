use std::{env, io, net::SocketAddr, time::Duration};

use withhuman_contracts::decisions::Decision;

use crate::trace::TraceSettings;

const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8082";
const DEFAULT_NEO4J_URL: &str = "http://neo4j:7474";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEnvironment {
    Development,
    Test,
    Production,
}

#[derive(Debug, Clone)]
pub struct DecisionConfig {
    pub bind_address: SocketAddr,
    pub environment: RuntimeEnvironment,
    pub provider: String,
    pub mock_decision: Decision,
    pub mock_reason: Option<String>,
    pub mock_delay: Duration,
    pub neo4j_url: String,
    pub neo4j_user: String,
    pub neo4j_password: String,
    pub neo4j_database: String,
    /// Set when `DECISION_PROVIDER=jev`.
    pub jev: Option<JevSettings>,
    /// A Call is denied when 1 − P(its chain of events serves the stated intent) exceeds this.
    pub intent_block_threshold: f64,
    pub trace: TraceSettings,
}

#[derive(Debug, Clone)]
pub struct JevSettings {
    pub url: String,
    pub api_key: String,
    pub timeout: Duration,
}

impl DecisionConfig {
    pub fn from_env() -> io::Result<Self> {
        let environment = match env::var("WITHHUMAN_ENV")
            .unwrap_or_else(|_| "development".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "development" => RuntimeEnvironment::Development,
            "test" => RuntimeEnvironment::Test,
            "production" => RuntimeEnvironment::Production,
            value => return Err(invalid(format!("unsupported WITHHUMAN_ENV `{value}`"))),
        };
        let provider = env::var("DECISION_PROVIDER").unwrap_or_else(|_| "mock".into());
        if environment == RuntimeEnvironment::Production && provider.eq_ignore_ascii_case("mock") {
            return Err(invalid(
                "the mock decision provider is forbidden in production",
            ));
        }
        let jev = if provider.eq_ignore_ascii_case("jev") {
            let api_key = env::var("JEV_API_KEY").unwrap_or_default();
            if api_key.trim().is_empty() {
                return Err(invalid(
                    "JEV_API_KEY must be configured for the jev provider",
                ));
            }
            Some(JevSettings {
                url: env::var("JEV_URL").unwrap_or_else(|_| "https://api.typesafe.ai".into()),
                api_key,
                timeout: Duration::from_millis(parse_env("JEV_TIMEOUT_MS", 3_000)?),
            })
        } else if provider.eq_ignore_ascii_case("mock") {
            None
        } else {
            return Err(invalid(format!(
                "unsupported DECISION_PROVIDER `{provider}`"
            )));
        };
        let intent_block_threshold = parse_env("WITHHUMAN_INTENT_BLOCK_THRESHOLD", 0.5_f64)?;
        if !(0.0..=1.0).contains(&intent_block_threshold) {
            return Err(invalid(
                "WITHHUMAN_INTENT_BLOCK_THRESHOLD must be between 0 and 1",
            ));
        }
        let defaults = TraceSettings::default();
        let trace = TraceSettings {
            model: env::var("JEV_MODEL").unwrap_or(defaults.model),
            window: parse_env("WITHHUMAN_PARENT_SEQ_WINDOW", defaults.window)?,
            max_extra_candidates: parse_env(
                "WITHHUMAN_TRACE_MAX_CANDIDATES",
                defaults.max_extra_candidates,
            )?,
            text_chars: parse_env("WITHHUMAN_TRACE_TEXT_CHARS", defaults.text_chars)?,
            max_hops: parse_env("WITHHUMAN_PARENT_MAX_HOPS", defaults.max_hops)?,
        };
        let mock_decision = match env::var("MOCK_DECISION")
            .unwrap_or_else(|_| "ALLOW".into())
            .to_ascii_uppercase()
            .as_str()
        {
            "ALLOW" => Decision::Allow,
            "DENY" => Decision::Deny,
            "REVIEW" => Decision::Review,
            value => return Err(invalid(format!("unsupported MOCK_DECISION `{value}`"))),
        };
        let neo4j_password =
            env::var("NEO4J_PASSWORD").map_err(|_| invalid("NEO4J_PASSWORD must be configured"))?;
        if neo4j_password.is_empty() {
            return Err(invalid("NEO4J_PASSWORD must not be empty"));
        }
        let mock_delay = env::var("MOCK_DECISION_DELAY_MS")
            .unwrap_or_else(|_| "0".into())
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|error| invalid(format!("invalid MOCK_DECISION_DELAY_MS: {error}")))?;

        Ok(Self {
            bind_address: env::var("DECISION_ADDR")
                .unwrap_or_else(|_| DEFAULT_BIND_ADDRESS.into())
                .parse()
                .map_err(|error| invalid(format!("invalid DECISION_ADDR: {error}")))?,
            environment,
            provider,
            mock_decision,
            mock_reason: env::var("MOCK_DECISION_REASON").ok(),
            mock_delay,
            neo4j_url: env::var("NEO4J_URL").unwrap_or_else(|_| DEFAULT_NEO4J_URL.into()),
            neo4j_user: env::var("NEO4J_USER").unwrap_or_else(|_| "neo4j".into()),
            neo4j_password,
            neo4j_database: env::var("NEO4J_DATABASE").unwrap_or_else(|_| "neo4j".into()),
            jev,
            intent_block_threshold,
            trace,
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

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
