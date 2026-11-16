//! The Wazuh server API, as far as the device sync reads it: a login, the agents, and each
//! agent's hardware, process and package inventory (syscollector).
//!
//! Written against the reference of Wazuh 4.14
//! (<https://documentation.wazuh.com/current/user-manual/api/reference.html>):
//! `POST /security/user/authenticate`, `GET /agents`, `GET /syscollector/{agent_id}/hardware`,
//! `GET /syscollector/{agent_id}/processes` and `GET /syscollector/{agent_id}/packages`. The
//! user needs `agent:read` and `syscollector:read`, which the default role `readonly` holds.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::{StatusCode, Url};
use rustls::{
    DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use serde::{Deserialize, de::DeserializeOwned};

use crate::{
    config::{WazuhConfig, WazuhTls},
    edr::EdrDevice,
};

/// How long one request may take, connecting included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Agents asked for at a time: what the reference recommends not to exceed.
const PAGE_SIZE: usize = 500;
/// An agent that never connected has sent no inventory.
const NEVER_CONNECTED: &str = "never_connected";
const AGENT_FIELDS: &str = "id,name,status,lastKeepAlive,os.name,os.version,os.platform";
/// Processes and packages whose name holds either word (`~` is "like", `,` is "or").
const PROGRAM_QUERY: &str = "name~claude,name~codex";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WazuhError {
    /// The client could not be built: a bad URL or CA file.
    Config(String),
    /// No answer in time, or none at all.
    Unavailable(String),
    /// The manager refused the user, or a token it had just issued.
    Unauthorized(String),
    /// Any other answer that is not a success.
    Status {
        status: u16,
        path: String,
        detail: String,
    },
    InvalidResponse(String),
}

impl fmt::Display for WazuhError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(formatter, "invalid Wazuh settings: {message}"),
            Self::Unavailable(message) => write!(formatter, "Wazuh unavailable: {message}"),
            Self::Unauthorized(message) => write!(formatter, "Wazuh refused the login: {message}"),
            Self::Status {
                status,
                path,
                detail,
            } => write!(
                formatter,
                "Wazuh answered HTTP {status} for {path}: {detail}"
            ),
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid Wazuh response: {message}")
            }
        }
    }
}

impl Error for WazuhError {}

/// One sync's connection to the manager. It logs in on its first request and again whenever
/// the manager stops taking its token, which lasts 900 seconds unless the manager says otherwise.
pub struct WazuhClient {
    http: reqwest::Client,
    base: Url,
    user: String,
    password: String,
    token: Option<String>,
    /// The least time between two requests; logins are not counted by the manager.
    gap: Duration,
    last_request: Option<Instant>,
    refused: usize,
}

impl WazuhClient {
    pub fn new(config: &WazuhConfig) -> Result<Self, WazuhError> {
        let mut base =
            Url::parse(&config.url).map_err(|error| WazuhError::Config(error.to_string()))?;
        if base.cannot_be_a_base() {
            return Err(WazuhError::Config("the URL cannot hold a path".into()));
        }
        // Paths are appended segment by segment, so a trailing slash would double.
        let path = base.path().trim_end_matches('/').to_owned();
        base.set_path(&path);
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT);
        match &config.tls {
            WazuhTls::PublicRoots => {}
            WazuhTls::CaFile(path) => builder = builder.use_preconfigured_tls(file_trust(path)?),
            WazuhTls::SkipVerification => builder = builder.danger_accept_invalid_certs(true),
        }
        Ok(Self {
            http: builder
                .build()
                .map_err(|error| WazuhError::Config(error.to_string()))?,
            base,
            user: config.user.clone(),
            password: config.password.clone(),
            token: None,
            gap: match config.requests_per_minute {
                0 => Duration::ZERO,
                limit => Duration::from_secs(60) / limit,
            },
            last_request: None,
            refused: 0,
        })
    }

    /// Every agent the manager lists, each with its board serial and whether a coding-agent
    /// program shows in its inventory. Any failure fails the whole read, so a half-read list is
    /// never taken for the manager's.
    pub async fn devices(&mut self) -> Result<Vec<EdrDevice>, WazuhError> {
        let mut devices = Vec::new();
        for agent in self.agents().await? {
            let reported = agent.status.as_deref() != Some(NEVER_CONNECTED);
            let (serial, program) = if reported && is_agent_id(&agent.id) {
                (
                    self.serial(&agent.id).await?,
                    self.program(&agent.id).await?,
                )
            } else {
                (None, None)
            };
            devices.push(EdrDevice {
                name: clean(agent.name),
                os: agent.os.and_then(AgentOs::label),
                status: clean(agent.status),
                serial,
                last_seen: agent.last_keep_alive.as_deref().and_then(epoch_millis),
                agent: program.map(str::to_owned),
                agent_id: agent.id,
            });
        }
        Ok(devices)
    }

    /// Inventory requests of the last read that the manager refused as unanswerable (HTTP 400 or
    /// 404) and were read as "nothing known".
    pub fn refused(&self) -> usize {
        self.refused
    }

    /// `GET /agents`, page after page, by ID. An agent that moves between pages is kept once.
    async fn agents(&mut self) -> Result<Vec<Agent>, WazuhError> {
        let mut agents = BTreeMap::new();
        let mut offset = 0;
        let limit = PAGE_SIZE.to_string();
        loop {
            let page: Page<Agent> = self
                .get(
                    &["agents"],
                    &[
                        ("offset", offset.to_string().as_str()),
                        ("limit", &limit),
                        ("sort", "+id"),
                        ("select", AGENT_FIELDS),
                    ],
                )
                .await?;
            let received = page.affected_items.len();
            for mut agent in page.affected_items {
                agent.id = agent.id.trim().to_owned();
                if !agent.id.is_empty() {
                    agents.insert(agent.id.clone(), agent);
                }
            }
            offset += received;
            if received == 0 || offset >= page.total_affected_items {
                return Ok(agents.into_values().collect());
            }
        }
    }

    /// `GET /syscollector/{agent_id}/hardware`: the motherboard's serial number.
    async fn serial(&mut self, agent_id: &str) -> Result<Option<String>, WazuhError> {
        let hardware: Option<Vec<Hardware>> = self
            .inventory(agent_id, "hardware", &[("select", "board_serial")])
            .await?;
        Ok(hardware
            .into_iter()
            .flatten()
            .find_map(|hardware| clean(hardware.board_serial)))
    }

    /// `claude-code` or `codex` when a process running at the agent's last scan, or else an
    /// installed package, has that word in its name. Both present reads as `claude-code`.
    /// Nothing found is not proof of absence: a program not running at the scan and installed
    /// outside a package manager the agent reads leaves no trace here.
    async fn program(&mut self, agent_id: &str) -> Result<Option<&'static str>, WazuhError> {
        let query = [("q", PROGRAM_QUERY), ("select", "name"), ("limit", "500")];
        let mut names: Vec<Named> = self
            .inventory(agent_id, "processes", &query)
            .await?
            .unwrap_or_default();
        if coding_agent(&names) != Some("claude-code") {
            names.extend(
                self.inventory::<Named>(agent_id, "packages", &query)
                    .await?
                    .unwrap_or_default(),
            );
        }
        Ok(coding_agent(&names))
    }

    /// One agent's inventory of a kind; none when the manager cannot answer for this agent.
    async fn inventory<T: DeserializeOwned>(
        &mut self,
        agent_id: &str,
        kind: &str,
        query: &[(&str, &str)],
    ) -> Result<Option<Vec<T>>, WazuhError> {
        match self.get(&["syscollector", agent_id, kind], query).await {
            Ok(page) => Ok(Some(page.affected_items)),
            Err(WazuhError::Status { status, .. }) if status == 400 || status == 404 => {
                self.refused += 1;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn get<T: DeserializeOwned>(
        &mut self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<Page<T>, WazuhError> {
        let url = self.url(segments);
        let path = url.path().to_owned();
        // A refused token is replaced once; refused again, the user is the problem.
        for fresh in [false, true] {
            let token = match self.token.clone() {
                Some(token) => token,
                None => self.login().await?,
            };
            self.pace().await;
            let response = self
                .http
                .get(url.clone())
                .query(query)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(unavailable)?;
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED {
                self.token = None;
                if fresh {
                    break;
                }
                continue;
            }
            if !status.is_success() {
                return Err(WazuhError::Status {
                    status: status.as_u16(),
                    path,
                    detail: detail(response).await,
                });
            }
            let envelope: Envelope<Page<T>> = response
                .json()
                .await
                .map_err(|error| WazuhError::InvalidResponse(format!("{path}: {error}")))?;
            return Ok(envelope.data);
        }
        Err(WazuhError::Unauthorized(format!(
            "a token just issued was refused for {path}"
        )))
    }

    /// `POST /security/user/authenticate` with the user's name and password.
    async fn login(&mut self) -> Result<String, WazuhError> {
        let response = self
            .http
            .post(self.url(&["security", "user", "authenticate"]))
            .basic_auth(&self.user, Some(&self.password))
            .send()
            .await
            .map_err(unavailable)?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(WazuhError::Unauthorized(detail(response).await));
        }
        if !status.is_success() {
            return Err(WazuhError::Status {
                status: status.as_u16(),
                path: "/security/user/authenticate".into(),
                detail: detail(response).await,
            });
        }
        let envelope: Envelope<Token> = response
            .json()
            .await
            .map_err(|error| WazuhError::InvalidResponse(format!("login: {error}")))?;
        if envelope.data.token.is_empty() {
            return Err(WazuhError::InvalidResponse("login: empty token".into()));
        }
        self.token = Some(envelope.data.token.clone());
        Ok(envelope.data.token)
    }

    async fn pace(&mut self) {
        if let Some(last) = self.last_request {
            tokio::time::sleep_until((last + self.gap).into()).await;
        }
        self.last_request = Some(Instant::now());
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .expect("the base was checked to hold a path")
            .extend(segments);
        url
    }
}

/// Trust for `WITHHUMAN_WAZUH_CA_FILE`: the certificates of that file and no others.
///
/// A manager's certificate is accepted when an authority in the file signed it for the
/// manager's hostname, or when it is, byte for byte, a certificate in the file. The second is
/// what a manager's own self-signed certificate needs: the one Wazuh generates is marked as an
/// authority and names no hostname, so no ordinary check passes it. A certificate matched that
/// way is trusted for what it is, whatever name or dates it carries; the manager still has to
/// prove it holds the key.
#[derive(Debug)]
struct FileTrust {
    certificates: Vec<CertificateDer<'static>>,
    authorities: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for FileTrust {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.certificates.iter().any(|known| known == end_entity) {
            return Ok(ServerCertVerified::assertion());
        }
        self.authorities.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.authorities.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.authorities.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.authorities.supported_verify_schemes()
    }
}

fn file_trust(path: &Path) -> Result<rustls::ClientConfig, WazuhError> {
    let pem = std::fs::read(path)
        .map_err(|error| WazuhError::Config(format!("cannot read {}: {error}", path.display())))?;
    let trust = FileTrust::from_pem(&pem)
        .map_err(|error| WazuhError::Config(format!("{}: {error}", path.display())))?;
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(trust))
                .with_no_client_auth()
        })
        .map_err(|error| WazuhError::Config(error.to_string()))
}

impl FileTrust {
    fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<_, _>>()
            .map_err(|error| format!("not PEM certificates: {error}"))?;
        let mut roots = RootCertStore::empty();
        let (usable, _) = roots.add_parsable_certificates(certificates.iter().cloned());
        if usable == 0 {
            return Err("no certificate found".into());
        }
        let authorities = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|error| error.to_string())?;
        Ok(Self {
            certificates,
            authorities,
        })
    }
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Deserialize)]
struct Token {
    token: String,
}

#[derive(Deserialize)]
struct Page<T> {
    #[serde(default = "Vec::new")]
    affected_items: Vec<T>,
    #[serde(default)]
    total_affected_items: usize,
}

#[derive(Deserialize)]
struct Agent {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "lastKeepAlive")]
    last_keep_alive: Option<String>,
    #[serde(default)]
    os: Option<AgentOs>,
}

#[derive(Deserialize)]
struct AgentOs {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    platform: Option<String>,
}

impl AgentOs {
    /// `Ubuntu 20.04.2 LTS`; the platform (`ubuntu`) when the agent gave no name.
    fn label(self) -> Option<String> {
        match (clean(self.name), clean(self.version)) {
            (Some(name), Some(version)) => Some(format!("{name} {version}")),
            (Some(name), None) => Some(name),
            (None, _) => clean(self.platform),
        }
    }
}

#[derive(Deserialize)]
struct Hardware {
    #[serde(default)]
    board_serial: Option<String>,
}

#[derive(Deserialize)]
struct Named {
    #[serde(default)]
    name: Option<String>,
}

/// The known coding-agent program among these names, Claude Code first.
fn coding_agent(names: &[Named]) -> Option<&'static str> {
    let has = |word: &str| {
        names
            .iter()
            .filter_map(|named| named.name.as_deref())
            .any(|name| name.to_lowercase().contains(word))
    };
    if has("claude") {
        Some("claude-code")
    } else if has("codex") {
        Some("codex")
    } else {
        None
    }
}

/// An agent ID is digits (`001`); anything else is not put into a path.
fn is_agent_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// Trimmed, without the NUL PostgreSQL refuses in text; none when nothing is left.
fn clean(value: Option<String>) -> Option<String> {
    let value = value?.replace('\0', "");
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// `2021-05-26T12:40:40Z` as epoch milliseconds: the UTC date and time the API gives. A date in
/// the year 9999, which stands for "always", is no time anything was seen.
fn epoch_millis(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, time) = text.split_once(['T', ' '])?;
    let mut date = date.split('-').map(|part| part.parse::<i64>().ok());
    let (year, month, day) = (date.next()??, date.next()??, date.next()??);
    if date.next().is_some() || !(1970..9999).contains(&year) {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // The zone is UTC, written `Z`, `+00:00` or not at all.
    let time = time
        .strip_suffix('Z')
        .or_else(|| time.strip_suffix("+00:00"))
        .unwrap_or(time);
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut clock = clock.split(':').map(|part| part.parse::<i64>().ok());
    let (hour, minute, second) = (clock.next()??, clock.next()??, clock.next()??);
    if clock.next().is_some()
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let millis = if fraction.is_empty() {
        0
    } else {
        if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        format!("{fraction:0<3}")[..3].parse::<i64>().ok()?
    };
    // Days since 1970-01-01 of a proleptic Gregorian date, counting years from March.
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year.rem_euclid(400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some((((days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + millis)
}

fn unavailable(error: reqwest::Error) -> WazuhError {
    // What failed and why (a refused connection, a certificate that does not verify), without
    // the URL.
    let error = error.without_url();
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !message.contains(&cause_text) {
            message = format!("{message}: {cause_text}");
        }
        source = cause.source();
    }
    WazuhError::Unavailable(message)
}

/// What the manager said about a refusal: the `title` and `detail` of its error, cut short.
async fn detail(response: reqwest::Response) -> String {
    #[derive(Deserialize)]
    struct Problem {
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        detail: Option<String>,
    }
    let text = response.text().await.unwrap_or_default();
    let message = match serde_json::from_str::<Problem>(&text) {
        Ok(Problem { title, detail }) if title.is_some() || detail.is_some() => [title, detail]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(": "),
        _ => text,
    };
    message.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public certificates made for this test with `openssl`; their keys were thrown away.
    // A self-signed certificate marked as an authority, as a Wazuh manager generates its own.
    const SELF_SIGNED: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBdDCCARugAwIBAgIUBdDDPLkgmO3vtDkmkfo6harXu8cwCgYIKoZIzj0EAwIw\n\
EDEOMAwGA1UEAwwFd2F6dWgwHhcNMjYxMTE2MDIxNTM4WhcNMzYxMTEzMDIxNTM4\n\
WjAQMQ4wDAYDVQQDDAV3YXp1aDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPz/\n\
Khjx1kGH3Cbq3iI+p2L3B0SdOzA22r3P3I+LP8AF6Xdx6Jq8A+Y5fHNEHYTz7FRQ\n\
lfjADtj++tAnnDfbtk6jUzBRMB0GA1UdDgQWBBQtFTVgEAE5nq8GfrgU/XNHuIaS\n\
0DAfBgNVHSMEGDAWgBQtFTVgEAE5nq8GfrgU/XNHuIaS0DAPBgNVHRMBAf8EBTAD\n\
AQH/MAoGCCqGSM49BAMCA0cAMEQCIGO9rpcRn92XyQdP1AdX2YbH6JDmDDCYHvXW\n\
n/wFKl7oAiAP90D87LFqHYELuSrgmpQxyNsXNxsACHKwFORYXj85OQ==\n\
-----END CERTIFICATE-----";
    // Another one with the same subject.
    const OTHER_SELF_SIGNED: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBdDCCARugAwIBAgIUKGxUeRgabP6lj5HdpjnFCioCzQQwCgYIKoZIzj0EAwIw\n\
EDEOMAwGA1UEAwwFd2F6dWgwHhcNMjYxMTE2MDIxNTM4WhcNMzYxMTEzMDIxNTM4\n\
WjAQMQ4wDAYDVQQDDAV3YXp1aDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOIh\n\
tcQJnJLX/eB8l7gEk50LSFnzCFg1BJmUEFP7pijsjpcHVx3dSEJQSQ+PmdWl8j/U\n\
w8ihPv81eJr+/d2evK+jUzBRMB0GA1UdDgQWBBTw0MFqdDmWL4NjmheNZZr6sQ2v\n\
uDAfBgNVHSMEGDAWgBTw0MFqdDmWL4NjmheNZZr6sQ2vuDAPBgNVHRMBAf8EBTAD\n\
AQH/MAoGCCqGSM49BAMCA0cAMEQCIE/hrqbEANOtoWKe4Rb6vqhClO2YHuuVTss0\n\
YBEZmrhPAiAIbhosGhC4Rw+fSAq/p3TdInIPRTVzUZfTxb9IyMbe1w==\n\
-----END CERTIFICATE-----";
    const AUTHORITY: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBijCCAS+gAwIBAgIUOpRyrx0edtvL3Rg8bsk3L4XMk9UwCgYIKoZIzj0EAwIw\n\
GjEYMBYGA1UEAwwPRXhhbXBsZSBUZXN0IENBMB4XDTI2MTExNjAyMTUzOFoXDTM2\n\
MTExMzAyMTUzOFowGjEYMBYGA1UEAwwPRXhhbXBsZSBUZXN0IENBMFkwEwYHKoZI\n\
zj0CAQYIKoZIzj0DAQcDQgAEiNAN6T7g0hSbsvs60yvui/qYMUjpY72iWPPYcAtA\n\
oD9XPGeulUnP/AjVXkcHKEioev6YeyyK+WQHygY5SZ4eyKNTMFEwHQYDVR0OBBYE\n\
FLjEycBlvHSRMbGkscCxSnxseBeJMB8GA1UdIwQYMBaAFLjEycBlvHSRMbGkscCx\n\
SnxseBeJMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAMzdc45q\n\
Fc/4z1ydc2YfAdeDEQDu2B+TrZFMKu4hKfujAiEA3IJBTUYy2EpY5AfXcPYkWOV/\n\
8FqzV5bPpc1Z8bDTiZ8=\n\
-----END CERTIFICATE-----";
    // Signed by AUTHORITY for wazuh.example.com.
    const SIGNED: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBxzCCAW2gAwIBAgIUZTtLdaSOxnomfXJkTPHjbYGR4MEwCgYIKoZIzj0EAwIw\n\
GjEYMBYGA1UEAwwPRXhhbXBsZSBUZXN0IENBMB4XDTI2MTExNjAyMTUzOFoXDTM2\n\
MTExMzAyMTUzOFowHDEaMBgGA1UEAwwRd2F6dWguZXhhbXBsZS5jb20wWTATBgcq\n\
hkjOPQIBBggqhkjOPQMBBwNCAATHDkzy5QKSyLHL3Vn04BDbQMtoywEuQ51JR+ZX\n\
fEHIw8Dl3DO2vBqmEQwzC1Kt9BDv55ptBLV5UGmvnOmmWPa4o4GOMIGLMBwGA1Ud\n\
EQQVMBOCEXdhenVoLmV4YW1wbGUuY29tMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeA\n\
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBQsUQWf8L/0nB44IC0MSIAF\n\
wwtGKDAfBgNVHSMEGDAWgBS4xMnAZbx0kTGxpLHAsUp8bHgXiTAKBggqhkjOPQQD\n\
AgNIADBFAiEAwJzF99mTYf4FzOoHKqfFSeBlo5MlHZkvTjq/jZpw7YYCIFRzI6qB\n\
IqrADJzA8KwFbVE/cGxF1OOGU8eh5qnMQg7U\n\
-----END CERTIFICATE-----";
    // A moment at which all four are valid.
    const THEN: Duration = Duration::from_secs(1_794_900_000);

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn check(trust: &FileTrust, pem: &str, host: &str) -> Result<(), rustls::Error> {
        let name = ServerName::try_from(host.to_owned()).unwrap();
        trust
            .verify_server_cert(&der(pem), &[], &name, &[], UnixTime::since_unix_epoch(THEN))
            .map(|_| ())
    }

    #[test]
    fn the_ca_file_trusts_its_own_certificates_and_what_its_authorities_signed() {
        // The manager's own certificate, copied into the file: trusted as it is, under whatever
        // name the manager is reached.
        let pinned = FileTrust::from_pem(SELF_SIGNED.as_bytes()).unwrap();
        check(&pinned, SELF_SIGNED, "10.0.0.5").unwrap();
        check(&pinned, SELF_SIGNED, "wazuh.internal").unwrap();
        // Nothing else is: not a look-alike, not what some other authority signed.
        check(&pinned, OTHER_SELF_SIGNED, "wazuh.internal").unwrap_err();
        check(&pinned, SIGNED, "wazuh.example.com").unwrap_err();

        // An authority in the file: what it signed, for the name it signed it for.
        let authority = FileTrust::from_pem(AUTHORITY.as_bytes()).unwrap();
        check(&authority, SIGNED, "wazuh.example.com").unwrap();
        check(&authority, SIGNED, "other.example.com").unwrap_err();
        check(&authority, SELF_SIGNED, "wazuh.example.com").unwrap_err();

        // A file may hold several.
        let both = FileTrust::from_pem(format!("{AUTHORITY}\n{SELF_SIGNED}\n").as_bytes()).unwrap();
        check(&both, SIGNED, "wazuh.example.com").unwrap();
        check(&both, SELF_SIGNED, "wazuh.example.com").unwrap();

        for empty in ["", "not a certificate"] {
            assert!(FileTrust::from_pem(empty.as_bytes()).is_err(), "{empty:?}");
        }
    }

    #[test]
    fn reads_the_last_keep_alive_as_epoch_milliseconds() {
        assert_eq!(epoch_millis("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            epoch_millis("2021-05-26T12:40:40Z"),
            Some(1_622_032_840_000)
        );
        assert_eq!(
            epoch_millis("2024-02-29T23:59:59.5+00:00"),
            Some(1_709_251_199_500)
        );
        assert_eq!(epoch_millis("2000-03-01 00:00:00"), Some(951_868_800_000));
        // The manager's own entry is "always" alive.
        assert_eq!(epoch_millis("9999-12-31T23:59:59Z"), None);
        for wrong in [
            "",
            "n/a",
            "2021-13-01T00:00:00Z",
            "2021-05-26",
            "2021-05-26T25:00:00Z",
        ] {
            assert_eq!(epoch_millis(wrong), None, "{wrong}");
        }
    }

    #[test]
    fn names_the_coding_agent_by_a_word_in_a_name() {
        let names = |names: &[&str]| -> Vec<Named> {
            names
                .iter()
                .map(|name| Named {
                    name: Some((*name).to_owned()),
                })
                .collect()
        };
        assert_eq!(
            coding_agent(&names(&["zsh", "claude"])),
            Some("claude-code")
        );
        assert_eq!(
            coding_agent(&names(&["@anthropic-ai/claude-code"])),
            Some("claude-code")
        );
        assert_eq!(coding_agent(&names(&["Codex"])), Some("codex"));
        assert_eq!(
            coding_agent(&names(&["codex", "Claude"])),
            Some("claude-code")
        );
        assert_eq!(coding_agent(&names(&["code", "cloud-init"])), None);
        assert_eq!(coding_agent(&[]), None);
    }

    #[test]
    fn describes_the_os_and_cleans_text() {
        let os = |name: Option<&str>, version: Option<&str>, platform: Option<&str>| AgentOs {
            name: name.map(str::to_owned),
            version: version.map(str::to_owned),
            platform: platform.map(str::to_owned),
        };
        assert_eq!(
            os(Some("Ubuntu"), Some("20.04.2 LTS"), Some("ubuntu")).label(),
            Some("Ubuntu 20.04.2 LTS".into())
        );
        assert_eq!(os(Some("macOS"), None, None).label(), Some("macOS".into()));
        assert_eq!(
            os(None, Some("11"), Some("darwin")).label(),
            Some("darwin".into())
        );
        assert_eq!(os(None, None, None).label(), None);
        assert_eq!(clean(Some("  A\0B ".into())), Some("AB".into()));
        assert_eq!(clean(Some(" ".into())), None);
        assert!(is_agent_id("001"));
        assert!(!is_agent_id("../agents"));
    }
}
