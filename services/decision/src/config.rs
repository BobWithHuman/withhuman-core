use std::{env, fs, io, net::SocketAddr, path::PathBuf, time::Duration};

use withhuman_contracts::decisions::Decision;

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
    pub jev_url: String,
    pub jev_api_key: Option<String>,
    pub jev_model: String,
    pub jev_timeout: Duration,
    pub parent_seq_window: u64,
    pub parent_prompt_window: u64,
    pub parent_accept: f64,
    pub parent_max_hops: u64,
    pub parent_per_call: bool,
    pub parent_body_chars: usize,
    pub sentence_from: f64,
    pub data_dir: PathBuf,
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
        let provider = env::var("DECISION_PROVIDER").unwrap_or_else(|_| "jev".into());
        if environment == RuntimeEnvironment::Production && provider.eq_ignore_ascii_case("mock") {
            return Err(invalid(
                "the mock decision provider is forbidden in production",
            ));
        }
        if !provider.eq_ignore_ascii_case("mock") && !provider.eq_ignore_ascii_case("jev") {
            return Err(invalid(format!(
                "unsupported DECISION_PROVIDER `{provider}`"
            )));
        }
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
            jev_url: env::var("JEV_URL").unwrap_or_else(|_| "https://api.typesafe.ai".into()),
            jev_api_key: env::var("JEV_API_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or_else(read_local_jev_key),
            jev_model: env::var("JEV_MODEL").unwrap_or_else(|_| "jev-latest".into()),
            jev_timeout: Duration::from_millis(parse("WITHHUMAN_JEV_TIMEOUT_MS", 3_000)?),
            parent_seq_window: parse("WITHHUMAN_PARENT_SEQ_WINDOW", 3)?,
            parent_prompt_window: parse("WITHHUMAN_PARENT_PROMPT_WINDOW", 3)?,
            parent_accept: parse("WITHHUMAN_PARENT_ACCEPT", 0.6)?,
            parent_max_hops: parse("WITHHUMAN_PARENT_MAX_HOPS", 50)?,
            parent_per_call: env::var("WITHHUMAN_PARENT_PER_CALL").is_ok_and(|v| v == "true"),
            parent_body_chars: parse("WITHHUMAN_PARENT_BODY_CHARS", 1_500)?,
            sentence_from: parse("WITHHUMAN_SENTENCE_FROM", 0.5)?,
            data_dir: env::var("WITHHUMAN_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("data")),
        })
    }
}

fn parse<T>(name: &str, default: T) -> io::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|error| invalid(format!("invalid {name}: {error}")))
    })
}

fn read_local_jev_key() -> Option<String> {
    let contents = fs::read_to_string(".env").ok()?;
    contents.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == "JEV_API_KEY")
            .then(|| value.trim().trim_matches(['\'', '"']).to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
