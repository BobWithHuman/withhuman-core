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
/// Packages whose name holds any of the words (`~` is "like", case-insensitive; `,` is "or").
const PROGRAM_QUERY: &str = "name~claude,name~codex,name~cursor,name~copilot,\
                             name~antigravity,name~agy,name~openclaw";
/// Processes with any of the words in their name, executable or arguments. The manager's match
/// is loose (`Claude Helper` and `CursorUIViewService` pass), so each is judged again by
/// [`process_agent`].
///
/// Cursor's CLI needs the `argvs` terms: it runs under `node` with its wrapper's name, so a
/// session started as `agent` says `cursor` nowhere but in the script path among its arguments.
/// Copilot needs them for the same reason, and its desktop app's own process is named
/// `github`, which is too common a word to ask for: the app is found by its path instead.
///
/// Antigravity's CLI is asked for by its own short name as well (`agy`): the path it runs from
/// says `antigravity` nowhere, and the binary is named neither after the product nor after the
/// company.
///
/// OpenClaw's Gateway and CLI are both `openclaw`, a name nothing else carries, and both run
/// under `node` out of its npm install — so the name is asked for in all three fields.
const PROCESS_QUERY: &str = "name~claude,name~codex,name~cursor,name~copilot,\
                             name~antigravity,name~agy,name~openclaw,\
                             cmd~claude,cmd~codex,cmd~cursor,cmd~copilot,\
                             cmd~antigravity,cmd~agy,cmd~openclaw,\
                             argvs~claude,argvs~codex,argvs~cursor,argvs~copilot,\
                             argvs~antigravity,argvs~agy,argvs~openclaw";
const PROCESS_FIELDS: &str = "name,cmd,argvs,scan.time";
const CLAUDE_CODE: &str = "claude-code";
const CODEX: &str = "codex";
const CURSOR: &str = "cursor";
const COPILOT: &str = "copilot";
const ANTIGRAVITY: &str = "antigravity";
const OPENCLAW: &str = "openclaw";

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
                (None, Sighting::default())
            };
            devices.push(EdrDevice {
                name: clean(agent.name),
                os: agent.os.and_then(AgentOs::label),
                status: clean(agent.status),
                serial,
                last_seen: agent.last_keep_alive.as_deref().and_then(epoch_millis),
                agent: program.agent.map(str::to_owned),
                running_at: program.running_at,
                command: program.command,
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

    /// Which coding agent the agent's last scans show, and when one was seen running.
    ///
    /// A process running at the last process scan decides first, by [`process_agent`]; failing
    /// that, an installed package, by [`package_agent`]. Nothing found is not proof of absence:
    /// a program not running at the scan and installed outside a package manager the agent
    /// reads leaves no trace here.
    async fn program(&mut self, agent_id: &str) -> Result<Sighting, WazuhError> {
        let query = [
            ("q", PROCESS_QUERY),
            ("select", PROCESS_FIELDS),
            ("limit", "500"),
        ];
        let processes: Vec<Process> = self
            .inventory(agent_id, "processes", &query)
            .await?
            .unwrap_or_default();
        let running = running(&processes);
        if running.agent.is_some() {
            return Ok(running);
        }
        let query = [("q", PROGRAM_QUERY), ("select", "name"), ("limit", "500")];
        let packages: Vec<Named> = self
            .inventory(agent_id, "packages", &query)
            .await?
            .unwrap_or_default();
        Ok(Sighting {
            agent: package_agent(&packages),
            ..Sighting::default()
        })
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

/// A process at the agent's last process scan, as `select=name,cmd,argvs,scan.time` gives it.
///
/// What the agent fills differs by system (Wazuh 4.14's `data_provider`): on Linux `name` is
/// the kernel's short name, `cmd` the first word of the command line and `argvs` the others
/// joined by spaces; on Windows `name` is the executable's file name (`claude.exe`) and `cmd`
/// its full path, without arguments; on macOS only `name` is filled.
#[derive(Deserialize, Default)]
struct Process {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    cmd: Option<String>,
    #[serde(default)]
    argvs: Option<Argvs>,
    #[serde(default)]
    scan: Option<Scan>,
}

/// The API documents a string; a list is read as well.
#[derive(Deserialize)]
#[serde(untagged)]
enum Argvs {
    Line(String),
    List(Vec<String>),
}

impl Argvs {
    fn words(&self) -> Vec<&str> {
        match self {
            Self::Line(line) => line.split_whitespace().collect(),
            Self::List(list) => list.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Deserialize, Default)]
struct Scan {
    #[serde(default)]
    time: Option<String>,
}

/// What a device's inventory says about coding agents: a row's `agent` and `running_at`.
#[derive(Debug, Default, PartialEq, Eq)]
struct Sighting {
    agent: Option<&'static str>,
    /// The latest scan, epoch milliseconds, that found a coding-agent process running.
    running_at: Option<i64>,
    /// The command line of the process that scan found, by [`command_line`].
    command: Option<String>,
}

/// The longest command line kept, in characters.
const COMMAND_CHARS: usize = 1000;

/// The coding agent among the processes, Claude Code first, the latest scan time of the
/// processes that are one, and the command line of one of them.
///
/// The command line is that of a process of the latest scan; among several, one of the agent
/// named (Claude Code before Codex), and then one with arguments, which is what tells a prompt
/// (`claude -p …`) or a resumed session (`claude --resume …`) apart.
fn running(processes: &[Process]) -> Sighting {
    let found: Vec<(&Process, &'static str, Option<i64>)> = processes
        .iter()
        .filter_map(|process| {
            let agent = process_agent(process)?;
            let scanned = process
                .scan
                .as_ref()
                .and_then(|scan| scan.time.as_deref())
                .and_then(epoch_millis);
            Some((process, agent, scanned))
        })
        .collect();
    let agent = if found.iter().any(|(_, agent, _)| *agent == CLAUDE_CODE) {
        Some(CLAUDE_CODE)
    } else {
        found.first().map(|(_, agent, _)| *agent)
    };
    // The first of the best (`max_by_key` keeps the last), so the manager's order breaks a tie.
    let command = found
        .iter()
        .rev()
        .max_by_key(|(process, process_agent, scanned)| {
            (
                *scanned,
                Some(*process_agent) == agent,
                process
                    .argvs
                    .as_ref()
                    .is_some_and(|argvs| !argvs.words().is_empty()),
            )
        })
        .and_then(|(process, ..)| command_line(process));
    Sighting {
        agent,
        running_at: found.iter().filter_map(|(.., scanned)| *scanned).max(),
        command,
    }
}

/// `cmd` and `argvs` joined by spaces (a list of `argvs` too), without NUL, trimmed and cut to
/// [`COMMAND_CHARS`]; none when both are empty.
fn command_line(process: &Process) -> Option<String> {
    let argvs = process.argvs.as_ref().map(|argvs| match argvs {
        Argvs::Line(line) => line.clone(),
        Argvs::List(list) => list.join(" "),
    });
    let line = [process.cmd.clone(), argvs]
        .into_iter()
        .flatten()
        .filter_map(|part| clean(Some(part)))
        .collect::<Vec<_>>()
        .join(" ");
    clean(Some(line.chars().take(COMMAND_CHARS).collect()))
}

/// Which coding agent a process is, Claude Code first and otherwise the first one seen.
///
/// It is one when its `name` is exactly `claude`, `codex`, `cursor-agent`, `cursor` or
/// `openclaw`
/// (`claude.exe` on Windows), or when its `cmd` or one of its `argvs` is such a program: a path
/// whose last segment is exactly that name, a path into Claude Code's native install
/// (`…/claude/versions/2.1.3`, which runs under its version's name) or Cursor's
/// (`…/cursor-agent/versions/2026.11.22/index.js`), or a path into the npm packages
/// `@anthropic-ai/claude-code` or `@openai/codex` (installed with npm, both run under
/// `node`), or a path into OpenClaw's npm install (`…/node_modules/openclaw/…`).
///
/// The case counts: the Claude desktop app's processes (`Claude`, `Claude Helper (Renderer)`)
/// are not Claude Code. Cursor's CLI is found by its install path rather than its name: it
/// runs under `node` with the name it was started as, which is `agent` as often as
/// `cursor-agent`, and `agent` says nothing on its own.
fn process_agent(process: &Process) -> Option<&'static str> {
    let mut found = process
        .name
        .as_deref()
        .and_then(|name| program_agent(name.trim()))
        .into_iter()
        .chain(process.cmd.as_deref().and_then(path_agent))
        .chain(
            process
                .argvs
                .iter()
                .flat_map(Argvs::words)
                .filter_map(path_agent),
        );
    let first = found.next()?;
    if first == CLAUDE_CODE || found.any(|agent| agent == CLAUDE_CODE) {
        Some(CLAUDE_CODE)
    } else {
        Some(first)
    }
}

/// A program's file name, exactly a coding agent's once a Windows `.exe` is taken off.
/// `cursor-agent` is Cursor's CLI and `cursor` the editor it ships beside.
fn program_agent(file_name: &str) -> Option<&'static str> {
    let file_name = file_name
        .strip_suffix(".exe")
        .or_else(|| file_name.strip_suffix(".EXE"))
        .unwrap_or(file_name);
    match file_name {
        "claude" => Some(CLAUDE_CODE),
        "codex" => Some(CODEX),
        "cursor-agent" => Some(CURSOR),
        // Cursor's editor is the same agent as its CLI and reads the same hooks, and unlike
        // Claude Code it shares its name with no desktop app that is not one — so the name
        // counts whatever the case (`Cursor` on macOS, `Cursor.exe` on Windows, `cursor` on
        // Linux). Its helpers (`Cursor Helper (Renderer)`) are not this name and do not count.
        name if name.eq_ignore_ascii_case("cursor") => Some(CURSOR),
        // Copilot's CLI runs as `copilot`, and the process it does the work in as
        // `copilot-runtime`. Its desktop app's binary is named `github`, which is left out:
        // the word is far too common to take for a coding agent, and the app is found by the
        // path it runs from instead.
        "copilot" | "copilot-runtime" => Some(COPILOT),
        // Antigravity's CLI is `agy`, a name nothing else on a developer's machine carries.
        // Its own name appears only in the folder it keeps its state in, which `path_agent`
        // reads.
        "agy" => Some(ANTIGRAVITY),
        // OpenClaw's Gateway and its CLI are the same program, and its name is its own: no
        // desktop app or library shares it, so the name alone counts. Its own processes run
        // under `node` with this name in the path, which [`path_agent`] reads.
        "openclaw" => Some(OPENCLAW),
        _ => None,
    }
}

/// A path (or a bare name) that runs a coding agent. `/` and `\` both separate segments.
fn path_agent(path: &str) -> Option<&'static str> {
    let path = path.trim().trim_matches(['"', '\'']).replace('\\', "/");
    if path.contains("@anthropic-ai/claude-code") {
        return Some(CLAUDE_CODE);
    }
    if path.contains("@openai/codex") {
        return Some(CODEX);
    }
    if path.contains("@github/copilot") || path.contains("GitHub Copilot.app") {
        return Some(COPILOT);
    }
    // Antigravity, by the folder it keeps its state and its CLI in, and by the editor that
    // ships the same agent.
    if path.contains("antigravity") || path.contains("Antigravity.app") {
        return Some(ANTIGRAVITY);
    }
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    // Cursor's CLI runs `index.js` out of its install, so the folder pair is the signal; its
    // own name is nowhere in the path a session started as `agent` reports.
    if segments
        .windows(2)
        .any(|pair| pair == ["cursor-agent", "versions"])
    {
        return Some(CURSOR);
    }
    // Copilot's desktop app keeps a CLI of its own under a cache folder, which is what a
    // session started from the app runs.
    if segments
        .windows(2)
        .any(|pair| pair == ["copilot-sdk", "cli"])
    {
        return Some(COPILOT);
    }
    // OpenClaw is an npm package, and its Gateway runs out of it under `node`. The folder pair
    // is the signal rather than the word: a project that merely depends on it would otherwise
    // report a coding agent on a device that runs none.
    if segments
        .windows(2)
        .any(|pair| pair == ["node_modules", "openclaw"])
    {
        return Some(OPENCLAW);
    }
    match segments[..] {
        [.., "claude", "versions", _] => Some(CLAUDE_CODE),
        [.., last] => program_agent(last),
        [] => None,
    }
}

/// The coding agent among installed packages, Claude Code first: a name holding `claude` or
/// `codex` in any case (`@anthropic-ai/claude-code`, `claude-code`, `codex`, `Codex CLI`), or
/// one of Cursor's own names. The Claude desktop app's package (`Claude`, or `Claude ` and more
/// that is not `Claude Code`) is not Claude Code.
fn package_agent(packages: &[Named]) -> Option<&'static str> {
    let names: Vec<String> = packages
        .iter()
        .filter_map(|package| package.name.as_deref())
        .map(str::trim)
        .filter(|name| !is_claude_desktop(name))
        .map(str::to_lowercase)
        .collect();
    if names.iter().any(|name| name.contains("claude")) {
        Some(CLAUDE_CODE)
    } else if names.iter().any(|name| name.contains("codex")) {
        Some(CODEX)
    } else if names.iter().any(|name| is_cursor_package(name)) {
        Some(CURSOR)
    } else if names.iter().any(|name| is_copilot_package(name)) {
        Some(COPILOT)
    } else if names.iter().any(|name| is_antigravity_package(name)) {
        Some(ANTIGRAVITY)
    } else if names.iter().any(|name| is_openclaw_package(name)) {
        Some(OPENCLAW)
    } else {
        None
    }
}

/// Cursor's own packages, in lower case: `cursor`, `cursor-agent`, or a name opening with
/// `cursor ` such as `Cursor CLI`.
///
/// Not a name that merely holds the word, as the rule for the others is: `libxcursor`,
/// `xcursor-themes` and `adwaita-cursor-theme` sit on every Linux desktop, and matching them
/// would report a coding agent on devices that have none.
fn is_cursor_package(name: &str) -> bool {
    name == "cursor" || name == "cursor-agent" || name.starts_with("cursor ")
}

/// Copilot's own packages, in lower case: the npm package its CLI is installed as, the command
/// that package leaves behind, and the desktop app that ships a CLI inside it.
///
/// Not a name that merely holds the word: `copilot` names an editor extension on many devices
/// that have no CLI, and reporting those would say a device runs a coding agent WithHuman can
/// see when it does not.
fn is_copilot_package(name: &str) -> bool {
    name == "copilot" || name == "@github/copilot" || name.starts_with("github copilot")
}

/// Antigravity's own packages, in lower case: the editor and the CLI it ships, however they
/// are named, and the command the CLI leaves behind.
///
/// Not a name that merely holds the word: `agy` is matched exactly, since a name holding those
/// three letters (`legacy`, `imagy`) says nothing about a coding agent.
fn is_antigravity_package(name: &str) -> bool {
    name == "agy"
        || name == "antigravity"
        || name.starts_with("antigravity ")
        || name.starts_with("google antigravity")
}

/// OpenClaw's own package, in lower case: `openclaw`, or a name opening with `openclaw ` such as
/// `OpenClaw CLI`.
///
/// Not a name that merely holds the word, as Cursor's rule is not: a plugin of OpenClaw's
/// (`openclaw-plugin-…`, which WithHuman's own client is one of) says a plugin was built, not
/// that the agent runs here, and the agent's own package is there when it does.
fn is_openclaw_package(name: &str) -> bool {
    name == "openclaw" || name.starts_with("openclaw ")
}

fn is_claude_desktop(package: &str) -> bool {
    package == "Claude"
        || (package.starts_with("Claude ") && !package.to_lowercase().contains("claude code"))
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

    fn process(name: &str, cmd: &str, argvs: &str) -> Process {
        let text = |text: &str| (!text.is_empty()).then(|| text.to_owned());
        Process {
            name: text(name),
            cmd: text(cmd),
            argvs: text(argvs).map(Argvs::Line),
            scan: None,
        }
    }

    /// Cursor's CLI, recorded from a real session: `node` runs its `index.js` under the name
    /// the user started it as, which the installer leaves as both `cursor-agent` and `agent`.
    /// So the install path is the signal, and the editor's own binary counts too.
    #[test]
    fn a_cursor_session_is_found_by_the_path_it_runs_from() {
        let agent = |name, cmd, argvs| process_agent(&process(name, cmd, argvs));
        // What `ps` showed for `agent status` on Linux: the thread's name, a wrapper called
        // `agent`, and the install path among the arguments.
        assert_eq!(
            agent(
                "MainThread",
                "/home/u/.local/bin/agent",
                "--disable-sigusr1 --use-system-ca \
                 /home/u/.local/share/cursor-agent/versions/2026.11.22-e9042b2/index.js status"
            ),
            Some("cursor")
        );
        // Started by its own name, and on Windows.
        assert_eq!(agent("cursor-agent", "", ""), Some("cursor"));
        // OpenClaw's Gateway and its CLI are the same program, under its own name. Its sessions
        // run under `node` out of the npm install, which the folder pair finds.
        assert_eq!(agent("openclaw", "", ""), Some("openclaw"));
        assert_eq!(
            agent(
                "node",
                "/home/u/.nvm/versions/node/v26.13.1/bin/openclaw",
                "chat"
            ),
            Some("openclaw")
        );
        assert_eq!(
            agent(
                "node",
                "",
                "/usr/lib/node_modules/openclaw/dist/index.js gateway"
            ),
            Some("openclaw")
        );
        // A project that merely depends on it is not a device running it.
        assert_eq!(agent("node", "/srv/app/build.js", "--openclaw-theme"), None);
        assert_eq!(
            agent("", r"C:\Users\ana\.local\bin\cursor-agent.exe", ""),
            Some("cursor")
        );
        // The editor it ships beside.
        assert_eq!(
            agent(
                "Cursor",
                "/Applications/Cursor.app/Contents/MacOS/Cursor",
                ""
            ),
            Some("cursor")
        );
        // Anything else holding the word is not a coding agent. The first is macOS's own text
        // input service, which the manager's loose match returns.
        for other in [
            "CursorUIViewService",
            "Cursor Helper (Renderer)",
            "cursor-agent-worker-sea",
            "xcursorgen",
            "libxcursor",
        ] {
            assert_eq!(agent(other, "", ""), None, "{other}");
        }
        assert_eq!(
            agent(
                "CursorUIViewService",
                "/System/Library/PrivateFrameworks/TextInputUIMacHelper.framework/Versions/A/\
                 XPCServices/CursorUIViewService.xpc/Contents/MacOS/CursorUIViewService",
                ""
            ),
            None
        );
    }

    /// Cursor's packages are matched by name and not by the word, unlike the others: a Linux
    /// desktop is full of cursor themes.
    #[test]
    fn cursor_packages_are_told_from_cursor_themes() {
        let named = |names: &[&str]| {
            package_agent(
                &names
                    .iter()
                    .map(|name| Named {
                        name: Some((*name).to_owned()),
                    })
                    .collect::<Vec<_>>(),
            )
        };
        for packages in [
            vec!["Cursor"],
            vec!["cursor-agent"],
            vec!["Cursor CLI"],
            vec!["git", "Cursor", "ripgrep"],
        ] {
            assert_eq!(named(&packages), Some("cursor"), "{packages:?}");
        }
        for packages in [
            vec!["openclaw"],
            vec!["OpenClaw CLI"],
            vec!["git", "openclaw"],
        ] {
            assert_eq!(named(&packages), Some("openclaw"), "{packages:?}");
        }
        // A plugin of OpenClaw's says a plugin was built, not that the agent runs here; the
        // agent's own package is there when it does. WithHuman's own client is such a plugin.
        for packages in [vec!["openclaw-plugin-withhuman"], vec!["openclaw-sdk"]] {
            assert_eq!(named(&packages), None, "{packages:?}");
        }
        for packages in [
            vec!["libxcursor1"],
            vec!["xcursor-themes"],
            vec!["adwaita-cursor-theme"],
            vec!["breeze-cursor-theme", "git"],
        ] {
            assert_eq!(named(&packages), None, "{packages:?}");
        }
        // Claude Code still wins when more than one is installed.
        assert_eq!(named(&["Cursor", "claude-code"]), Some("claude-code"));
    }

    /// Copilot's CLI is an npm package whose command is `copilot`, and the desktop app ships a
    /// CLI of its own under a cache folder. The app's own process is named `github`, which is
    /// deliberately not matched: the word says nothing about a coding agent.
    #[test]
    fn a_copilot_session_is_found_by_its_command_or_the_path_it_runs_from() {
        let agent = |name, cmd, argvs| process_agent(&process(name, cmd, argvs));
        // What `ps` showed on this device: the CLI installed as the npm package, and the
        // process it does the work in.
        assert_eq!(
            agent("copilot", "/opt/homebrew/bin/copilot", ""),
            Some("copilot")
        );
        assert_eq!(
            agent(
                "node",
                "/opt/homebrew/bin/node",
                "/opt/homebrew/lib/node_modules/@github/copilot/npm-loader.js"
            ),
            Some("copilot")
        );
        assert_eq!(
            agent(
                "copilot-runtime",
                "/Users/ana/Library/Caches/copilot-sdk/cli/1.0.115-7/copilot-runtime",
                ""
            ),
            Some("copilot")
        );
        // The desktop app, found by the path and not by the name its binary happens to have.
        assert_eq!(
            agent(
                "github",
                "/Applications/GitHub Copilot.app/Contents/MacOS/github",
                ""
            ),
            Some("copilot")
        );
        assert_eq!(agent("github", "/usr/local/bin/github", ""), None);
        // Anything else holding the word is not a coding agent. The first two are the editor
        // extension's, which run no hook of ours.
        for other in [
            "copilot-language-server",
            "git-credential-copilot",
            "copilotd",
        ] {
            assert_eq!(agent(other, "", ""), None, "{other}");
        }
    }

    /// Copilot's packages are matched by name and not by the word: `copilot` names an editor
    /// extension on many devices that have no CLI.
    #[test]
    fn copilot_packages_are_told_from_the_editor_extension() {
        let named = |names: &[&str]| {
            package_agent(
                &names
                    .iter()
                    .map(|name| Named {
                        name: Some((*name).to_owned()),
                    })
                    .collect::<Vec<_>>(),
            )
        };
        for packages in [
            vec!["copilot"],
            vec!["@github/copilot"],
            vec!["GitHub Copilot"],
            vec!["git", "GitHub Copilot", "ripgrep"],
        ] {
            assert_eq!(named(&packages), Some("copilot"), "{packages:?}");
        }
        for packages in [
            vec!["copilot-language-server"],
            vec!["github-copilot-intellij"],
            vec!["vscode-copilot-chat", "git"],
        ] {
            assert_eq!(named(&packages), None, "{packages:?}");
        }
        // Claude Code still wins when more than one is installed.
        assert_eq!(
            named(&["GitHub Copilot", "claude-code"]),
            Some("claude-code")
        );
    }

    /// Antigravity's CLI is a binary named `agy`, which says nothing about the product, and
    /// it runs from a path that does not either. Its name is matched exactly, and the folder
    /// it keeps its state in is the other signal.
    #[test]
    fn an_antigravity_session_is_found_by_its_command_or_its_state_folder() {
        let agent = |name, cmd, argvs| process_agent(&process(name, cmd, argvs));
        // What `ps` showed for this device's install.
        assert_eq!(
            agent("agy", "/Users/ana/.local/bin/agy", ""),
            Some("antigravity")
        );
        assert_eq!(
            agent(
                "agy",
                "/Users/ana/.local/bin/agy",
                "-p \"fix the build\" --dangerously-skip-permissions"
            ),
            Some("antigravity")
        );
        // A helper that runs out of its state folder, whatever it is called.
        assert_eq!(
            agent(
                "webm_encoder",
                "/Users/ana/.gemini/antigravity-cli/bin/webm_encoder",
                ""
            ),
            Some("antigravity")
        );
        // The editor that ships the same agent.
        assert_eq!(
            agent(
                "Antigravity",
                "/Applications/Antigravity.app/Contents/MacOS/Antigravity",
                ""
            ),
            Some("antigravity")
        );
        // Three letters are not a coding agent on their own: the manager's match is loose, and
        // these are what it returns for `agy`.
        for (name, cmd) in [
            ("legacy-sync", "/usr/bin/legacy-sync"),
            ("imagy", "/opt/imagy/bin/imagy"),
            ("agyrus", ""),
        ] {
            assert_eq!(agent(name, cmd, ""), None, "{name}");
        }
    }

    /// Antigravity's packages are matched by name and not by the word, as the others' are.
    #[test]
    fn antigravity_packages_are_told_from_names_that_merely_hold_the_letters() {
        let named = |names: &[&str]| {
            package_agent(
                &names
                    .iter()
                    .map(|name| Named {
                        name: Some((*name).to_owned()),
                    })
                    .collect::<Vec<_>>(),
            )
        };
        for packages in [
            vec!["Antigravity"],
            vec!["agy"],
            vec!["Antigravity CLI"],
            vec!["Google Antigravity"],
            vec!["git", "Antigravity", "ripgrep"],
        ] {
            assert_eq!(named(&packages), Some("antigravity"), "{packages:?}");
        }
        for packages in [
            vec!["legacy"],
            vec!["imagy"],
            vec!["antigravity-themes", "git"],
        ] {
            assert_eq!(named(&packages), None, "{packages:?}");
        }
        // Claude Code still wins when more than one is installed.
        assert_eq!(named(&["Antigravity", "claude-code"]), Some("claude-code"));
    }

    #[test]
    fn a_process_is_a_coding_agent_by_its_exact_program() {
        let agent = |name, cmd, argvs| process_agent(&process(name, cmd, argvs));
        // By name, as every system fills it.
        assert_eq!(agent("claude", "", ""), Some("claude-code"));
        assert_eq!(agent("codex", "", ""), Some("codex"));
        assert_eq!(agent("claude.exe", "", ""), Some("claude-code"));
        // The Claude desktop app is not Claude Code, nor is a name that only holds the word.
        for desktop in [
            "Claude",
            "Claude Helper",
            "Claude Helper (Renderer)",
            "Claude.exe",
            "claude-helper",
            "codex-tui",
        ] {
            assert_eq!(agent(desktop, "", ""), None, "{desktop}");
        }
        assert_eq!(
            agent(
                "Claude Helper (Renderer)",
                "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/\
                 Contents/MacOS/Claude Helper (Renderer)",
                "--type=renderer --user-data-dir=/Users/ana/Library/Application Support/Claude"
            ),
            None
        );
        // By the executable's path.
        assert_eq!(agent("", "/usr/local/bin/codex", ""), Some("codex"));
        assert_eq!(
            agent("claude.exe", r"C:\Users\ana\.local\bin\claude.exe", ""),
            Some("claude-code")
        );
        assert_eq!(
            agent(
                "Claude.exe",
                r"C:\Users\ana\AppData\Local\AnthropicClaude\Claude.exe",
                ""
            ),
            None
        );
        // Claude Code's native install runs under its version's name.
        assert_eq!(
            agent(
                "2.1.325",
                "/home/ana/.local/share/claude/versions/2.1.325",
                "--resume"
            ),
            Some("claude-code")
        );
        assert_eq!(agent("2.1.325", "/opt/other/versions/2.1.325", ""), None);
        // Installed with npm, it runs under node.
        assert_eq!(
            agent("node", "node", "/opt/homebrew/bin/claude --resume"),
            Some("claude-code")
        );
        assert_eq!(
            agent(
                "node",
                "/usr/bin/node",
                "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js -p hello"
            ),
            Some("claude-code")
        );
        assert_eq!(
            agent(
                "node",
                "/usr/bin/node",
                "/usr/lib/node_modules/@openai/codex/bin/codex.js"
            ),
            Some("codex")
        );
        assert_eq!(
            agent("node", "/usr/bin/node", "server.js --port 3000"),
            None
        );
        // Both in one process: Claude Code.
        assert_eq!(
            agent("codex", "codex", "/opt/homebrew/bin/claude"),
            Some("claude-code")
        );
        // An argument as the API documents it, or as a list.
        let listed = Process {
            argvs: Some(Argvs::List(vec!["/opt/homebrew/bin/claude".into()])),
            ..process("node", "node", "")
        };
        assert_eq!(process_agent(&listed), Some("claude-code"));
    }

    #[test]
    fn a_running_coding_agent_is_dated_by_its_latest_scan() {
        let scanned = |name: &str, time: &str| Process {
            scan: Some(Scan {
                time: Some(time.to_owned()),
            }),
            ..process(name, "", "")
        };
        assert_eq!(
            running(&[
                scanned("Claude", "2021-05-26T12:50:00Z"),
                scanned("codex", "2021-05-26T12:40:40Z"),
                scanned("claude", "2021-05-26T12:40:00Z"),
            ]),
            Sighting {
                agent: Some("claude-code"),
                running_at: Some(1_622_032_840_000),
                command: None,
            }
        );
        // The desktop app alone: nothing running, whatever its scan time.
        assert_eq!(
            running(&[scanned("Claude Helper", "2021-05-26T12:50:00Z")]),
            Sighting::default()
        );
        // A coding agent whose scan time cannot be read is still one.
        assert_eq!(
            running(&[process("codex", "", "")]),
            Sighting {
                agent: Some("codex"),
                running_at: None,
                command: None,
            }
        );
        assert_eq!(running(&[]), Sighting::default());
    }

    #[test]
    fn a_sighting_keeps_the_command_line_of_the_process_it_saw() {
        let line = |cmd: &str, argvs: Option<Argvs>| {
            command_line(&Process {
                argvs,
                ..process("claude", cmd, "")
            })
        };
        let list = |words: &[&str]| Some(Argvs::List(words.iter().map(|w| (*w).into()).collect()));
        assert_eq!(
            line("claude", list(&["-p", "고객 목록 백업해줘"])),
            Some("claude -p 고객 목록 백업해줘".into())
        );
        assert_eq!(
            line(
                "/usr/bin/node",
                Some(Argvs::Line(
                    " /opt/homebrew/bin/claude --resume 4a03 ".into()
                ))
            ),
            Some("/usr/bin/node /opt/homebrew/bin/claude --resume 4a03".into())
        );
        // Windows: the executable's path only. macOS: nothing.
        assert_eq!(
            line(r"C:\Users\ana\.local\bin\claude.exe", None),
            Some(r"C:\Users\ana\.local\bin\claude.exe".into())
        );
        assert_eq!(line("", None), None);
        assert_eq!(line(" ", list(&["", " "])), None);
        assert_eq!(line("", list(&["exec", "a\0b"])), Some("exec ab".into()));
        let long = "가".repeat(2 * COMMAND_CHARS);
        assert_eq!(
            line("codex", list(&["exec", &long])).map(|line| line.chars().count()),
            Some(COMMAND_CHARS)
        );

        // Of a scan's processes: the latest scan, the agent named, then one with arguments.
        let seen = |name: &str, cmd: &str, argvs: &str, time: &str| Process {
            scan: Some(Scan {
                time: Some(time.to_owned()),
            }),
            ..process(name, cmd, argvs)
        };
        let command = |processes: &[Process]| running(processes).command;
        assert_eq!(
            command(&[
                seen("claude", "claude", "", "2021-05-26T12:40:40Z"),
                seen("claude", "claude", "--resume 4a03", "2021-05-26T12:40:40Z"),
                seen("claude", "claude", "", "2021-05-26T12:40:40Z"),
            ]),
            Some("claude --resume 4a03".into())
        );
        assert_eq!(
            command(&[
                seen("claude", "claude", "-p old", "2021-05-26T11:40:40Z"),
                seen("claude", "claude", "", "2021-05-26T12:40:40Z"),
            ]),
            Some("claude".into())
        );
        assert_eq!(
            command(&[
                seen("codex", "codex", "exec hello", "2021-05-26T12:40:40Z"),
                seen("claude", "claude", "", "2021-05-26T12:40:40Z"),
            ]),
            Some("claude".into())
        );
        // The desktop app's command line is none of it.
        assert_eq!(
            command(&[
                seen(
                    "Claude Helper",
                    "/Applications/Claude.app/x",
                    "--type=gpu",
                    "2021-05-26T12:50:00Z"
                ),
                seen("claude", "", "", "2021-05-26T12:40:40Z"),
            ]),
            None
        );
    }

    #[test]
    fn a_package_names_the_coding_agent_unless_it_is_the_claude_desktop_app() {
        let packages = |names: &[&str]| -> Vec<Named> {
            names
                .iter()
                .map(|name| Named {
                    name: Some((*name).to_owned()),
                })
                .collect()
        };
        for (names, expected) in [
            (&["@anthropic-ai/claude-code"][..], Some("claude-code")),
            (&["claude-code"], Some("claude-code")),
            (&["Claude Code"], Some("claude-code")),
            (&["codex"], Some("codex")),
            (&["Codex CLI", "7-Zip"], Some("codex")),
            (&["codex", "@anthropic-ai/claude-code"], Some("claude-code")),
            // The desktop app.
            (&["Claude"], None),
            (&["Claude Desktop"], None),
            (&["Claude", "Codex CLI"], Some("codex")),
            (&["code", "cloud-init"], None),
            (&[], None),
        ] {
            assert_eq!(package_agent(&packages(names)), expected, "{names:?}");
        }
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
