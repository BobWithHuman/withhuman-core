use std::{env, io, net::SocketAddr, time::Duration};

use withhuman_common::profile::{Profile, personal};
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
    /// Set when `DECISION_PROVIDER` is `jev` or `jevstyle`.
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
        Self::from_env_as(Profile::from_env()?)
    }

    /// The settings with `profile`'s defaults: the personal engine asks Jev, as a production
    /// engine does, once it has a key (`JEV_API_KEY`), and judges by the rules alone before.
    pub fn from_env_as(profile: Profile) -> io::Result<Self> {
        let has_key = env::var("JEV_API_KEY").is_ok_and(|key| !key.trim().is_empty());
        let (default_environment, default_provider) = match profile {
            Profile::Enterprise => ("development", "mock"),
            Profile::Personal if has_key => ("production", "jev"),
            Profile::Personal => ("production", "rules"),
        };
        let environment = match env::var("WITHHUMAN_ENV")
            .unwrap_or_else(|_| default_environment.into())
            .to_ascii_lowercase()
            .as_str()
        {
            "development" => RuntimeEnvironment::Development,
            "test" => RuntimeEnvironment::Test,
            "production" => RuntimeEnvironment::Production,
            value => return Err(invalid(format!("unsupported WITHHUMAN_ENV `{value}`"))),
        };
        let provider = env::var("DECISION_PROVIDER").unwrap_or_else(|_| default_provider.into());
        if environment == RuntimeEnvironment::Production && provider.eq_ignore_ascii_case("mock") {
            return Err(invalid(
                "the mock decision provider is forbidden in production",
            ));
        }
        let preset = JevPreset::named(&provider);
        let jev = if let Some(preset) = preset {
            let api_key = env::var("JEV_API_KEY").unwrap_or_default();
            if api_key.trim().is_empty() {
                return Err(invalid(
                    "JEV_API_KEY must be configured for the jev and jevstyle providers",
                ));
            }
            let url = env::var("JEV_URL")
                .ok()
                .filter(|url| !url.trim().is_empty())
                .unwrap_or_else(|| preset.url.into());
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
        } else if provider.eq_ignore_ascii_case("mock") || provider.eq_ignore_ascii_case("rules") {
            None
        } else {
            return Err(invalid(format!(
                "unsupported DECISION_PROVIDER `{provider}`"
            )));
        };
        let thresholds = thresholds()?;
        let defaults = preset.map_or_else(TraceSettings::default, JevPreset::trace_defaults);
        let trace = TraceSettings {
            model: env::var("JEV_MODEL")
                .ok()
                .filter(|model| !model.trim().is_empty())
                .unwrap_or(defaults.model),
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
            check: check_settings(preset.is_some_and(|preset| preset.shared_capacity))?,
            distrusted_deny: flag("WITHHUMAN_DISTRUSTED_SOURCE_DENY")?,
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
                .unwrap_or_else(|_| {
                    profile.bind_address(DEFAULT_BIND_ADDRESS, personal::DECISION_PORT)
                })
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

/// A Jev-compatible judge `DECISION_PROVIDER` names, and the defaults it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JevPreset {
    url: &'static str,
    /// The model named in requests, and the longest cause and Call texts sent
    /// (`WITHHUMAN_TRACE_CAUSE_CHARS`, `_TEXT_CHARS`), where they differ from Jev's.
    trace: Option<(&'static str, usize, usize)>,
    /// Capacity shared by every key, so a 429 means busy now rather than refused.
    shared_capacity: bool,
}

impl JevPreset {
    /// TypeSafe's Jev, the paid judge.
    const JEV: Self = Self {
        url: "https://api.typesafe.ai",
        trace: None,
        shared_capacity: false,
    };
    /// JevStyle, a free model trained on Jev's answers, for trying WithHuman without paying.
    /// It answers with its own model whatever is named. Its hosted API takes at most 8,000
    /// tokens (32,000 bytes) a request, so the texts sent are cut shorter: a Korean prompt
    /// costs about a token a character.
    const JEVSTYLE: Self = Self {
        url: "https://api.jevstyle.com",
        trace: Some(("jev-style-2b-decision-v4", 3_000, 600)),
        shared_capacity: true,
    };

    fn named(provider: &str) -> Option<Self> {
        if provider.eq_ignore_ascii_case("jev") {
            Some(Self::JEV)
        } else if provider.eq_ignore_ascii_case("jevstyle") {
            Some(Self::JEVSTYLE)
        } else {
            None
        }
    }

    fn trace_defaults(self) -> TraceSettings {
        match self.trace {
            None => TraceSettings::default(),
            Some((model, cause_chars, text_chars)) => TraceSettings {
                model: model.to_owned(),
                cause_chars,
                text_chars,
                ..TraceSettings::default()
            },
        }
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

/// The rules-only mode's settings.
fn check_settings(shared_capacity: bool) -> io::Result<CheckSettings> {
    Ok(CheckSettings {
        degraded_failures: parse_range("WITHHUMAN_DEGRADED_FAILURES", 3, 1, 100)?,
        degraded_seconds: parse_range("WITHHUMAN_DEGRADED_SECONDS", 60, 1, 3_600)?,
        shared_capacity,
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jevstyle_fits_its_hosted_limit_and_jev_keeps_the_trace_defaults() {
        assert_eq!(JevPreset::named("JevStyle"), Some(JevPreset::JEVSTYLE));
        assert_eq!(JevPreset::named("jev"), Some(JevPreset::JEV));
        assert_eq!(JevPreset::named("mock"), None);

        let jev = JevPreset::JEV.trace_defaults();
        let defaults = TraceSettings::default();
        assert_eq!(
            (jev.model, jev.cause_chars, jev.text_chars),
            (defaults.model, defaults.cause_chars, defaults.text_chars)
        );

        let style = JevPreset::JEVSTYLE.trace_defaults();
        assert_eq!(JevPreset::JEVSTYLE.url, "https://api.jevstyle.com");
        assert_eq!(style.model, "jev-style-2b-decision-v4");
        // The action, the turn (twice the text limit) and the causes stay well under the
        // 8,000-token cap even at a token a character.
        assert!(style.cause_chars + style.text_chars * 3 < 6_000);
    }
}
