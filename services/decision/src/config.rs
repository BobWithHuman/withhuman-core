use std::{env, io, net::SocketAddr, time::Duration};

use withhuman_contracts::decisions::Decision;

use crate::{
    check::CheckSettings,
    trace::{Thresholds, TraceSettings},
};

const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8082";

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
    /// Set when `DECISION_PROVIDER=jev`.
    pub jev: Option<JevSettings>,
    /// Deviations at which a Call is denied or reviewed, by what it follows from.
    pub thresholds: Thresholds,
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
            let url = env::var("JEV_URL").unwrap_or_else(|_| "https://api.typesafe.ai".into());
            if environment == RuntimeEnvironment::Production && !url.starts_with("https://") {
                return Err(invalid("JEV_URL must use https in production"));
            }
            let timeout_ms: u64 = parse_env("JEV_TIMEOUT_MS", 3_000)?;
            if !(1..=10_000).contains(&timeout_ms) {
                return Err(invalid("JEV_TIMEOUT_MS must be between 1 and 10000"));
            }
            Some(JevSettings {
                url,
                api_key,
                timeout: Duration::from_millis(timeout_ms),
            })
        } else if provider.eq_ignore_ascii_case("mock") {
            None
        } else {
            return Err(invalid(format!(
                "unsupported DECISION_PROVIDER `{provider}`"
            )));
        };
        let thresholds = thresholds()?;
        let defaults = TraceSettings::default();
        let trace = TraceSettings {
            model: env::var("JEV_MODEL").unwrap_or(defaults.model),
            max_segments: parse_range(
                "WITHHUMAN_TRACE_MAX_SEGMENTS",
                defaults.max_segments,
                1,
                64,
            )?,
            max_causes: parse_range("WITHHUMAN_TRACE_MAX_CAUSES", defaults.max_causes, 1, 200)?,
            cause_chars: parse_range(
                "WITHHUMAN_TRACE_CAUSE_CHARS",
                defaults.cause_chars,
                1_000,
                100_000,
            )?,
            text_chars: parse_range(
                "WITHHUMAN_TRACE_TEXT_CHARS",
                defaults.text_chars,
                100,
                20_000,
            )?,
            max_hops: parse_range("WITHHUMAN_PARENT_MAX_HOPS", defaults.max_hops, 1, 1_000)?,
            max_intents: parse_range("WITHHUMAN_TRACE_MAX_INTENTS", defaults.max_intents, 1, 200)?,
            check: check_settings()?,
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
            jev,
            thresholds,
            trace,
        })
    }
}

/// The deviation thresholds, each between 0 and 1 and none reviewing above where it denies.
fn thresholds() -> io::Result<Thresholds> {
    let defaults = Thresholds::default();
    let thresholds = Thresholds {
        deny: parse_range("WITHHUMAN_DEVIATION_DENY", defaults.deny, 0.0, 1.0)?,
        review: parse_range("WITHHUMAN_DEVIATION_REVIEW", defaults.review, 0.0, 1.0)?,
        untrusted_deny: parse_range(
            "WITHHUMAN_UNTRUSTED_DEVIATION_DENY",
            defaults.untrusted_deny,
            0.0,
            1.0,
        )?,
        untrusted_review: parse_range(
            "WITHHUMAN_UNTRUSTED_DEVIATION_REVIEW",
            defaults.untrusted_review,
            0.0,
            1.0,
        )?,
    };
    if thresholds.review > thresholds.deny
        || thresholds.untrusted_review > thresholds.untrusted_deny
    {
        return Err(invalid(
            "a deviation review threshold must not exceed its deny threshold",
        ));
    }
    Ok(thresholds)
}

/// The check settings; unset, the check is as it was.
fn check_settings() -> io::Result<CheckSettings> {
    Ok(CheckSettings {
        line_question: flag("WITHHUMAN_CHECK_LINE_QUESTION")?,
        file_always_checked: flag("WITHHUMAN_CHECK_FILE_ALWAYS")?,
        shell_writes_checked: flag("WITHHUMAN_CHECK_SHELL_WRITES")?,
        restore_aware: flag("WITHHUMAN_CHECK_RESTORE_AWARE")?,
        shell_split: flag("WITHHUMAN_CHECK_SHELL_SPLIT")?,
        shell_decode: flag("WITHHUMAN_CHECK_SHELL_DECODE")?,
        grades: flag("WITHHUMAN_GRADES")?,
        degraded_mode: flag("WITHHUMAN_DEGRADED_MODE")?,
        degraded_failures: parse_range("WITHHUMAN_DEGRADED_FAILURES", 3, 1, 100)?,
        degraded_seconds: parse_range("WITHHUMAN_DEGRADED_SECONDS", 60, 1, 3_600)?,
    })
}

/// `1`/`true` on, `0`/`false`/unset off.
fn flag(name: &str) -> io::Result<bool> {
    match env::var(name).as_deref() {
        Err(_) | Ok("") | Ok("0") | Ok("false") => Ok(false),
        Ok("1") | Ok("true") => Ok(true),
        Ok(value) => Err(invalid(format!(
            "invalid {name} {value:?}: expected 1 or 0"
        ))),
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

fn parse_range<T>(name: &str, default: T, min: T, max: T) -> io::Result<T>
where
    T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
    T::Err: std::fmt::Display,
{
    let value = parse_env(name, default)?;
    if value < min || value > max {
        return Err(invalid(format!("{name} must be between {min} and {max}")));
    }
    Ok(value)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
