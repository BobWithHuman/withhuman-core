use std::{env, fmt, io, net::SocketAddr, path::PathBuf, time::Duration};

use withhuman_common::profile::{Profile, personal};

const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8081";
const DEFAULT_DECISION_URL: &str = "http://decision:8082";
// Two minutes: a coding agent is seen by the scan that catches it running, so the sooner a
// scan is read, the less a short run without hooks slips by between syncs.
const DEFAULT_WAZUH_SYNC_INTERVAL_SECS: u64 = 120;
const MIN_WAZUH_SYNC_INTERVAL_SECS: u64 = 60;
// Half of what a Wazuh manager takes in a minute by default (`max_request_per_minute: 300`),
// past which it refuses every user's requests until the minute ends.
const DEFAULT_WAZUH_REQUESTS_PER_MINUTE: u32 = 150;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorConfig {
    pub bind_address: SocketAddr,
    pub decision_url: String,
    /// The Wazuh manager whose device list is synced; none while `WITHHUMAN_WAZUH_URL` is unset.
    pub wazuh: Option<WazuhConfig>,
}

impl GeneratorConfig {
    pub fn from_env() -> io::Result<Self> {
        Self::from_env_as(Profile::from_env()?)
    }

    /// The settings with `profile`'s defaults. A personal engine has no company EDR to sync
    /// from: `WITHHUMAN_WAZUH_*` is not read.
    pub fn from_env_as(profile: Profile) -> io::Result<Self> {
        let bind_address = env::var("GENERATOR_ADDR")
            .unwrap_or_else(|_| {
                profile.bind_address(DEFAULT_BIND_ADDRESS, personal::GENERATOR_PORT)
            })
            .parse()
            .map_err(|error| invalid(format!("invalid GENERATOR_ADDR: {error}")))?;

        Ok(Self {
            bind_address,
            decision_url: env::var("DECISION_URL").unwrap_or_else(|_| {
                profile.service_url(DEFAULT_DECISION_URL, personal::DECISION_PORT)
            }),
            wazuh: if profile.is_personal() {
                None
            } else {
                WazuhConfig::from_lookup(|name| env::var(name).ok())?
            },
        })
    }
}

/// How the Wazuh manager's certificate is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WazuhTls {
    /// Against the public certificate authorities.
    PublicRoots,
    /// Against this PEM file alone: the authorities in it, or the manager's own self-signed
    /// certificate copied into it.
    CaFile(PathBuf),
    /// Not at all: `WITHHUMAN_WAZUH_TLS_SKIP_VERIFY=1`, said out loud at start.
    SkipVerification,
}

/// Where the company's device list comes from, and how often.
#[derive(Clone, PartialEq, Eq)]
pub struct WazuhConfig {
    /// The Wazuh server API, such as `https://wazuh.example.com:55000`.
    pub url: String,
    pub user: String,
    pub password: String,
    pub sync_interval: Duration,
    pub tls: WazuhTls,
    /// Requests sent in a minute at most; 0 for no pacing.
    pub requests_per_minute: u32,
}

impl WazuhConfig {
    /// Reads `WITHHUMAN_WAZUH_*` through `lookup`. An unset or empty variable is the default,
    /// and without a URL there is no sync, whatever else is set.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> io::Result<Option<Self>> {
        let get = |name: &str| {
            lookup(name)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let Some(url) = get("WITHHUMAN_WAZUH_URL") else {
            return Ok(None);
        };
        // The user and password travel in their own variables, so the URL can be logged.
        match reqwest::Url::parse(&url) {
            Ok(parsed)
                if matches!(parsed.scheme(), "https" | "http")
                    && parsed.host_str().is_some()
                    && parsed.username().is_empty()
                    && parsed.password().is_none() => {}
            _ => {
                return Err(invalid(
                    "invalid WITHHUMAN_WAZUH_URL: expected https://host:port, without a user",
                ));
            }
        }
        let required = |name: &str| {
            get(name).ok_or_else(|| invalid(format!("{name} is required with WITHHUMAN_WAZUH_URL")))
        };
        let user = required("WITHHUMAN_WAZUH_USER")?;
        // A password is taken as it is, spaces and all.
        let password = lookup("WITHHUMAN_WAZUH_PASSWORD")
            .filter(|password| !password.is_empty())
            .ok_or_else(|| {
                invalid("WITHHUMAN_WAZUH_PASSWORD is required with WITHHUMAN_WAZUH_URL")
            })?;
        let number = |name: &str, default: u64| match get(name) {
            Some(value) => value
                .parse::<u64>()
                .map_err(|error| invalid(format!("invalid {name} {value:?}: {error}"))),
            None => Ok(default),
        };
        let interval = number(
            "WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS",
            DEFAULT_WAZUH_SYNC_INTERVAL_SECS,
        )?;
        if interval < MIN_WAZUH_SYNC_INTERVAL_SECS {
            return Err(invalid(format!(
                "invalid WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS {interval}: at least \
                 {MIN_WAZUH_SYNC_INTERVAL_SECS}"
            )));
        }
        let requests_per_minute = u32::try_from(number(
            "WITHHUMAN_WAZUH_MAX_REQUESTS_PER_MINUTE",
            u64::from(DEFAULT_WAZUH_REQUESTS_PER_MINUTE),
        )?)
        .map_err(|_| invalid("invalid WITHHUMAN_WAZUH_MAX_REQUESTS_PER_MINUTE: too large"))?;
        let skip = match get("WITHHUMAN_WAZUH_TLS_SKIP_VERIFY").as_deref() {
            None | Some("0") => false,
            Some("1") => true,
            Some(value) => {
                return Err(invalid(format!(
                    "invalid WITHHUMAN_WAZUH_TLS_SKIP_VERIFY {value:?}: 1 or 0"
                )));
            }
        };
        let tls = match (get("WITHHUMAN_WAZUH_CA_FILE"), skip) {
            (Some(_), true) => {
                return Err(invalid(
                    "set WITHHUMAN_WAZUH_CA_FILE or WITHHUMAN_WAZUH_TLS_SKIP_VERIFY, not both",
                ));
            }
            (Some(path), false) => WazuhTls::CaFile(PathBuf::from(path)),
            (None, true) => WazuhTls::SkipVerification,
            (None, false) => WazuhTls::PublicRoots,
        };
        Ok(Some(Self {
            url,
            user,
            password,
            sync_interval: Duration::from_secs(interval),
            tls,
            requests_per_minute,
        }))
    }
}

// The password stays out of anything printed.
impl fmt::Debug for WazuhConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WazuhConfig")
            .field("url", &self.url)
            .field("user", &self.user)
            .field("sync_interval", &self.sync_interval)
            .field("tls", &self.tls)
            .field("requests_per_minute", &self.requests_per_minute)
            .finish_non_exhaustive()
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(variables: &[(&str, &str)]) -> io::Result<Option<WazuhConfig>> {
        WazuhConfig::from_lookup(|name| {
            variables
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    const BASE: [(&str, &str); 3] = [
        ("WITHHUMAN_WAZUH_URL", "https://wazuh.example.com:55000"),
        ("WITHHUMAN_WAZUH_USER", "withhuman"),
        ("WITHHUMAN_WAZUH_PASSWORD", "secret"),
    ];

    fn with(extra: &[(&'static str, &'static str)]) -> io::Result<Option<WazuhConfig>> {
        let mut variables = BASE.to_vec();
        variables.extend_from_slice(extra);
        config(&variables)
    }

    #[test]
    fn there_is_no_sync_without_a_url() {
        assert_eq!(config(&[]).unwrap(), None);
        // Whatever else is set, even wrongly.
        assert_eq!(
            config(&[
                ("WITHHUMAN_WAZUH_URL", " "),
                ("WITHHUMAN_WAZUH_USER", "withhuman"),
                ("WITHHUMAN_WAZUH_TLS_SKIP_VERIFY", "maybe"),
            ])
            .unwrap(),
            None
        );
    }

    #[test]
    fn the_defaults_verify_the_certificate() {
        let wazuh = with(&[]).unwrap().unwrap();
        assert_eq!(wazuh.url, "https://wazuh.example.com:55000");
        assert_eq!(wazuh.sync_interval, Duration::from_secs(120));
        assert_eq!(wazuh.requests_per_minute, 150);
        assert_eq!(wazuh.tls, WazuhTls::PublicRoots);
        // Empty values are defaults too, as Compose passes them.
        let empty = with(&[
            ("WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS", ""),
            ("WITHHUMAN_WAZUH_CA_FILE", ""),
            ("WITHHUMAN_WAZUH_TLS_SKIP_VERIFY", ""),
            ("WITHHUMAN_WAZUH_MAX_REQUESTS_PER_MINUTE", ""),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(empty, wazuh);
    }

    #[test]
    fn the_certificate_check_is_skipped_only_when_asked() {
        let ca = with(&[("WITHHUMAN_WAZUH_CA_FILE", "/etc/wazuh/ca.pem")])
            .unwrap()
            .unwrap();
        assert_eq!(ca.tls, WazuhTls::CaFile("/etc/wazuh/ca.pem".into()));
        let skip = with(&[("WITHHUMAN_WAZUH_TLS_SKIP_VERIFY", "1")])
            .unwrap()
            .unwrap();
        assert_eq!(skip.tls, WazuhTls::SkipVerification);
        let off = with(&[("WITHHUMAN_WAZUH_TLS_SKIP_VERIFY", "0")])
            .unwrap()
            .unwrap();
        assert_eq!(off.tls, WazuhTls::PublicRoots);
        for wrong in [
            vec![("WITHHUMAN_WAZUH_TLS_SKIP_VERIFY", "true")],
            vec![
                ("WITHHUMAN_WAZUH_TLS_SKIP_VERIFY", "1"),
                ("WITHHUMAN_WAZUH_CA_FILE", "/etc/wazuh/ca.pem"),
            ],
        ] {
            assert!(with(&wrong).is_err(), "{wrong:?}");
        }
    }

    #[test]
    fn a_url_needs_its_user_password_and_sane_numbers() {
        assert!(config(&BASE[..1]).is_err());
        assert!(config(&BASE[..2]).is_err());
        for url in [
            "wazuh.example.com",
            "ftp://wazuh.example.com",
            "https://u:p@wazuh.example.com",
        ] {
            let mut variables = BASE.to_vec();
            variables[0].1 = url;
            assert!(config(&variables).is_err(), "{url}");
        }
        assert!(with(&[("WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS", "5")]).is_err());
        assert!(with(&[("WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS", "soon")]).is_err());
        assert!(with(&[("WITHHUMAN_WAZUH_MAX_REQUESTS_PER_MINUTE", "-1")]).is_err());
        let custom = with(&[
            ("WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS", "3600"),
            ("WITHHUMAN_WAZUH_MAX_REQUESTS_PER_MINUTE", "0"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(custom.sync_interval, Duration::from_secs(3600));
        assert_eq!(custom.requests_per_minute, 0);
    }

    #[test]
    fn the_password_is_never_printed() {
        let wazuh = with(&[]).unwrap().unwrap();
        assert!(!format!("{wazuh:?}").contains("secret"));
    }
}
