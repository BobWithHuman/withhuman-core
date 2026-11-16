//! The EDR device sync end to end: a Wazuh manager faked in the test (login, paged agents,
//! syscollector inventory) on one side, PostgreSQL on the other.
//! Runs against `POSTGRES_INTEGRATION_URL`, like `postgres_integration.rs`; each test works in a
//! schema of its own.

use std::{
    collections::HashMap,
    process,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio_postgres::NoTls;
use withhuman_generator::{
    EdrSync, EdrSyncError, PgGraphRepository, WazuhConfig, WazuhTls, sync_edr_devices,
};

/// `withhuman:s3cret`, as HTTP basic authentication sends it.
const BASIC: &str = "Basic d2l0aGh1bWFuOnMzY3JldA==";
const HOUR: u64 = 3_600_000;
const T0: u64 = 1_800_000_000_000;

#[tokio::test]
async fn a_sync_mirrors_the_manager_and_matches_registered_clients() {
    let Some(stack) = Stack::start().await else {
        return;
    };
    stack.fake.set(|fake| {
        fake.agents = company();
        fake.hardware = HashMap::from([
            // A virtual machine reports an empty board serial.
            ("000", json!({"board_serial": "", "agent_id": "000"})),
            ("001", json!({"board_serial": "C02XK1", "agent_id": "001"})),
            ("002", json!({"board_serial": "To Be Filled By O.E.M."})),
            ("004", json!({"board_serial": " PF3ABC "})),
        ]);
        fake.processes = HashMap::from([
            // Codex installed with npm, running under node.
            (
                "000",
                vec![process(
                    "node",
                    "/usr/bin/node",
                    "/usr/lib/node_modules/@openai/codex/bin/codex.js",
                    SCANNED,
                )],
            ),
            // Claude Code next to the Claude desktop app, which the manager's match lets
            // through too.
            (
                "001",
                vec![
                    process("zsh", "", "", SCANNED),
                    process("Claude Helper (Renderer)", "", "", LATER),
                    process("claude", "", "", SCANNED),
                ],
            ),
            // The desktop app alone.
            (
                "002",
                vec![process(
                    "Claude.exe",
                    r"C:\Users\ana\AppData\Local\AnthropicClaude\Claude.exe",
                    "",
                    LATER,
                )],
            ),
            (
                "004",
                vec![process("cargo", "/usr/bin/cargo", "build", SCANNED)],
            ),
        ]);
        fake.packages = HashMap::from([
            // The desktop app's package is not Claude Code.
            ("002", vec!["Codex CLI", "7-Zip", "Claude"]),
            ("004", vec!["codex", "@anthropic-ai/claude-code"]),
        ]);
        // The manager cannot answer for this agent's inventory.
        fake.refused = vec!["005"];
    });
    stack
        .db
        .batch_execute(
            "INSERT INTO clients (client_id, hostname, serial, edr_agent_id, edr_status) VALUES \
             ('t/ana', 'work-mac', 'c02xk1', NULL, NULL), \
             ('t/ben', 'Anas-MacBook-Pro', 'C02XK1', NULL, NULL), \
             ('t/cho', 'desktop-abc.corp.example.com', NULL, NULL, NULL), \
             ('t/dan', 'anas-macbook-pro.local', 'C02ZZZ', NULL, NULL), \
             ('t/eve', 'gone', NULL, '099', 'active'), \
             ('t/fay', 'BUILD-7.local', 'PF3ABC', '001', 'active')",
        )
        .await
        .unwrap();

    let synced = sync_edr_devices(&stack.repository, &stack.config, T0)
        .await
        .unwrap();
    assert_eq!(
        synced,
        EdrSync::Synced {
            devices: 6,
            matched: 4
        }
    );
    assert_eq!(
        stack.devices().await,
        json!([
            [
                "000",
                "wazuh-manager",
                "Ubuntu 22.04.4 LTS",
                "active",
                null,
                null,
                "codex",
                T0,
                SCANNED_AT
            ],
            [
                "001",
                "Anas-MacBook-Pro.local",
                "macOS 14.5",
                "active",
                "C02XK1",
                1_622_032_840_000_u64,
                "claude-code",
                T0,
                SCANNED_AT
            ],
            [
                "002",
                "DESKTOP-ABC",
                "Microsoft Windows 11 Pro 10.0.22631",
                "disconnected",
                "To Be Filled By O.E.M.",
                1_622_032_800_000_u64,
                "codex",
                T0,
                null
            ],
            [
                "003",
                "new-laptop",
                null,
                "never_connected",
                null,
                null,
                null,
                T0,
                null
            ],
            [
                "004",
                "build-7",
                "ubuntu",
                "pending",
                "PF3ABC",
                1_622_032_840_000_u64,
                // Only a package shows it: nothing was running at the scan.
                "claude-code",
                T0,
                null
            ],
            [
                "005",
                "legacy",
                "CentOS Linux 7.9",
                "active",
                null,
                1_622_032_840_000_u64,
                null,
                T0,
                null
            ],
        ])
    );
    assert_eq!(
        stack.clients().await,
        json!([
            // The same serial under two OS accounts, whatever the hostnames.
            ["t/ana", "001", "active"],
            ["t/ben", "001", "active"],
            // No serial on the client, a placeholder on the EDR's side: the hostname.
            ["t/cho", "002", "disconnected"],
            // The hostname of 001, but another serial: another machine.
            ["t/dan", null, null],
            // Matched before, listed no longer.
            ["t/eve", null, null],
            // Matched to another device before.
            ["t/fay", "004", "pending"],
        ])
    );
    {
        let fake = stack.fake.get();
        assert_eq!(fake.logins, 1);
        // Six agents at two a page.
        let pages: Vec<&String> = fake
            .requests
            .iter()
            .filter(|request| request.starts_with("GET /agents?"))
            .collect();
        assert_eq!(pages.len(), 3, "{pages:?}");
        assert_eq!(
            pages[1].as_str(),
            "GET /agents?offset=2&limit=500&sort=%2Bid\
         &select=id%2Cname%2Cstatus%2ClastKeepAlive%2Cos.name%2Cos.version%2Cos.platform"
        );
        // An agent that never connected is not asked for an inventory it cannot have.
        assert!(
            !fake
                .requests
                .iter()
                .any(|r| r.contains("/syscollector/003/")),
            "{:?}",
            fake.requests
        );
        assert!(
            fake.requests
                .contains(&"GET /syscollector/001/hardware?select=board_serial".to_owned())
        );
        assert!(
            fake.requests.contains(
                &"GET /syscollector/001/processes?q=name%7Eclaude%2Cname%7Ecodex%2Ccmd%7Eclaude\
                  %2Ccmd%7Ecodex%2Cargvs%7Eclaude%2Cargvs%7Ecodex\
                  &select=name%2Ccmd%2Cargvs%2Cscan.time&limit=500"
                    .to_owned()
            ),
            "{:?}",
            fake.requests
        );
        // Claude Code found among the processes: the packages are not asked for.
        assert!(
            !fake
                .requests
                .iter()
                .any(|r| r.contains("/syscollector/001/packages"))
        );
        assert!(
        fake.requests.contains(
            &"GET /syscollector/002/packages?q=name%7Eclaude%2Cname%7Ecodex&select=name&limit=500"
                .to_owned()
        )
    );
    }

    // An hour later the manager has dropped 002, lost touch with 001, and a client registered.
    stack.fake.set(|fake| {
        fake.agents.retain(|agent| agent["id"] != "002");
        fake.agents[1]["status"] = json!("disconnected");
    });
    stack
        .db
        .batch_execute("INSERT INTO clients (client_id, hostname) VALUES ('t/gil', 'Legacy.lan')")
        .await
        .unwrap();
    let synced = sync_edr_devices(&stack.repository, &stack.config, T0 + HOUR)
        .await
        .unwrap();
    assert_eq!(
        synced,
        EdrSync::Synced {
            devices: 5,
            matched: 4
        }
    );
    let devices = stack.devices().await;
    let rows = devices.as_array().unwrap();
    assert_eq!(
        rows.iter().map(|row| row[0].clone()).collect::<Vec<_>>(),
        [
            json!("000"),
            json!("001"),
            json!("003"),
            json!("004"),
            json!("005")
        ]
    );
    assert!(rows.iter().all(|row| row[7] == json!(T0 + HOUR)));
    assert_eq!(rows[1][3], json!("disconnected"));
    assert_eq!(
        stack.clients().await,
        json!([
            ["t/ana", "001", "disconnected"],
            ["t/ben", "001", "disconnected"],
            ["t/cho", null, null],
            ["t/dan", null, null],
            ["t/eve", null, null],
            ["t/fay", "004", "pending"],
            ["t/gil", "005", "active"],
        ])
    );
    stack.stop().await;
}

#[tokio::test]
async fn an_expired_token_is_replaced_and_a_wrong_password_is_an_error() {
    let Some(mut stack) = Stack::start().await else {
        return;
    };
    stack.fake.set(|fake| {
        fake.agents = company();
        // The manager forgets the token after the fourth request it serves.
        fake.expire_after = Some(4);
    });
    // 20 requests a second at most.
    stack.config.requests_per_minute = 1_200;
    let started = Instant::now();
    let synced = sync_edr_devices(&stack.repository, &stack.config, T0)
        .await
        .unwrap();
    assert_eq!(
        synced,
        EdrSync::Synced {
            devices: 6,
            matched: 0
        }
    );
    {
        let fake = stack.fake.get();
        assert_eq!(fake.logins, 2);
        assert_eq!(fake.unauthorized, 1);
        // Requests the manager counts keep their distance; logins are not counted.
        let counted = fake.requests.len() - fake.logins;
        assert!(
            started.elapsed() >= Duration::from_millis(50) * (counted as u32 - 1),
            "{counted} requests in {:?}",
            started.elapsed()
        );
    }

    // A password the manager does not take: nothing is read, nothing is written.
    stack.config.password = "wrong".into();
    stack.config.requests_per_minute = 0;
    stack.fake.set(|fake| {
        fake.requests.clear();
        fake.agents.clear();
    });
    let error = sync_edr_devices(&stack.repository, &stack.config, T0 + HOUR)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        EdrSyncError::Source("Wazuh refused the login: Unauthorized: Invalid credentials".into())
    );
    assert_eq!(
        stack.fake.get().requests,
        ["POST /security/user/authenticate"]
    );
    assert_eq!(stack.devices().await.as_array().unwrap().len(), 6);
    stack.stop().await;
}

#[tokio::test]
async fn a_failed_sync_leaves_the_previous_devices_and_matches() {
    let Some(mut stack) = Stack::start().await else {
        return;
    };
    stack.fake.set(|fake| {
        fake.agents = company();
        fake.hardware = HashMap::from([("001", json!({"board_serial": "C02XK1"}))]);
    });
    stack
        .db
        .batch_execute(
            "INSERT INTO clients (client_id, hostname, serial) VALUES \
             ('t/ana', 'work-mac', 'C02XK1'), ('t/cho', 'desktop-abc', NULL)",
        )
        .await
        .unwrap();
    sync_edr_devices(&stack.repository, &stack.config, T0)
        .await
        .unwrap();
    let devices = stack.devices().await;
    let clients = stack.clients().await;
    assert_eq!(
        clients,
        json!([["t/ana", "001", "active"], ["t/cho", "002", "disconnected"]])
    );

    // The manager's list changes, but it cannot be read to the end.
    stack.fake.set(|fake| {
        fake.agents.retain(|agent| agent["id"] != "001");
        fake.agents[1]["status"] = json!("active");
    });
    let mut now = T0;
    for (path, status) in [
        ("/syscollector/004/hardware", 500),
        ("/syscollector/002/processes", 503),
        ("/agents", 500),
        // Too many requests, and a user without the permission.
        ("/syscollector/002/hardware", 429),
        ("/syscollector/002/hardware", 403),
    ] {
        stack.fake.set(|fake| fake.failing = Some((path, status)));
        now += HOUR;
        let error = sync_edr_devices(&stack.repository, &stack.config, now)
            .await
            .unwrap_err();
        let EdrSyncError::Source(message) = &error else {
            panic!("{error:?}");
        };
        assert_eq!(
            message,
            &format!("Wazuh answered HTTP {status} for {path}: Wazuh Internal Error: it broke")
        );
        assert_eq!(stack.devices().await, devices, "{path}");
        assert_eq!(stack.clients().await, clients, "{path}");
    }
    // A manager that sends something else than its API.
    stack.fake.set(|fake| fake.failing = Some(("/agents", 200)));
    let error = sync_edr_devices(&stack.repository, &stack.config, now + HOUR)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, EdrSyncError::Source(message) if message.starts_with("invalid Wazuh response")),
        "{error:?}"
    );
    // A manager that is not there.
    let reachable = stack.config.url.clone();
    stack.config.url = "http://127.0.0.1:9".into();
    let error = sync_edr_devices(&stack.repository, &stack.config, now + HOUR)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, EdrSyncError::Source(message) if message.starts_with("Wazuh unavailable")),
        "{error:?}"
    );
    // A CA file that is not there.
    stack.config.url = reachable.clone();
    stack.config.tls = WazuhTls::CaFile("/nonexistent/wazuh-ca.pem".into());
    let error = sync_edr_devices(&stack.repository, &stack.config, now + HOUR)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, EdrSyncError::Source(message) if message.starts_with("invalid Wazuh settings")),
        "{error:?}"
    );
    assert_eq!(stack.devices().await, devices);
    assert_eq!(stack.clients().await, clients);

    // Once the manager answers again, the next sync catches up.
    stack.config.tls = WazuhTls::PublicRoots;
    stack.fake.set(|fake| fake.failing = None);
    sync_edr_devices(&stack.repository, &stack.config, now + 2 * HOUR)
        .await
        .unwrap();
    assert_eq!(
        stack.clients().await,
        json!([["t/ana", null, null], ["t/cho", "002", "active"]])
    );
    stack.stop().await;
}

#[tokio::test]
async fn one_generator_syncs_at_a_time_and_not_again_too_soon() {
    let Some(stack) = Stack::start().await else {
        return;
    };
    let gate = Arc::new(Semaphore::new(0));
    stack.fake.set(|fake| {
        fake.agents = company();
        fake.gate = Some(gate.clone());
    });
    // A second Generator: its own pool on the same database.
    let other = PgGraphRepository::connect(&stack.url, 2).await.unwrap();

    let first = tokio::spawn({
        let (repository, config) = (stack.repository.clone(), stack.config.clone());
        async move { sync_edr_devices(&repository, &config, T0).await }
    });
    // The first is reading the manager...
    while stack.fake.get().requests.is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // ...so the second leaves it alone, and asks the manager nothing.
    assert_eq!(
        sync_edr_devices(&other, &stack.config, T0).await.unwrap(),
        EdrSync::Busy
    );
    gate.add_permits(100);
    assert_eq!(
        first.await.unwrap().unwrap(),
        EdrSync::Synced {
            devices: 6,
            matched: 0
        }
    );
    assert_eq!(stack.fake.get().logins, 1);

    // The other Generator's turn comes a moment later: the list is fresh (the interval is 60s).
    let asked = stack.fake.get().requests.len();
    assert_eq!(
        sync_edr_devices(&other, &stack.config, T0 + 29_000)
            .await
            .unwrap(),
        EdrSync::Fresh
    );
    assert_eq!(stack.fake.get().requests.len(), asked);
    // Half an interval on, it is due again. The lock went with the first sync's connection.
    assert_eq!(
        sync_edr_devices(&other, &stack.config, T0 + 30_000)
            .await
            .unwrap(),
        EdrSync::Synced {
            devices: 6,
            matched: 0
        }
    );
    // A sync that failed released the lock too.
    stack.fake.set(|fake| fake.failing = Some(("/agents", 500)));
    sync_edr_devices(&stack.repository, &stack.config, T0 + HOUR)
        .await
        .unwrap_err();
    stack.fake.set(|fake| fake.failing = None);
    assert!(matches!(
        sync_edr_devices(&other, &stack.config, T0 + HOUR).await,
        Ok(EdrSync::Synced { .. })
    ));
    stack.stop().await;
}

#[tokio::test]
async fn the_schema_names_what_the_viewer_reads() {
    let Some(stack) = Stack::start().await else {
        return;
    };
    let columns = |table: &'static str| {
        let db = &stack.db;
        let schema = stack.schema.clone();
        async move {
            let value: Value = db
                .query_one(
                    "SELECT jsonb_agg(column_name || ' ' || data_type ORDER BY ordinal_position) \
                     FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2",
                    &[&schema, &table],
                )
                .await
                .unwrap()
                .get(0);
            value
        }
    };
    assert_eq!(
        columns("edr_devices").await,
        json!([
            "agent_id text",
            "name text",
            "os text",
            "status text",
            "serial text",
            "last_seen bigint",
            "agent text",
            "synced_at bigint",
            "running_at bigint"
        ])
    );
    // A database from before `running_at` gains it, keeping its devices.
    stack
        .db
        .batch_execute(
            "INSERT INTO edr_devices (agent_id, agent, synced_at) VALUES ('001', 'codex', 5); \
             ALTER TABLE edr_devices DROP COLUMN running_at",
        )
        .await
        .unwrap();
    PgGraphRepository::connect(&stack.url, 1).await.unwrap();
    assert_eq!(
        columns("edr_devices").await.as_array().unwrap().last(),
        Some(&json!("running_at bigint"))
    );
    assert_eq!(
        stack.devices().await,
        json!([["001", null, null, null, null, null, "codex", 5, null]])
    );
    let clients = columns("clients").await;
    for column in ["edr_agent_id text", "edr_status text"] {
        assert!(
            clients.as_array().unwrap().contains(&json!(column)),
            "{clients}"
        );
    }
    // A database from before the EDR columns gains them, keeping its devices, and applying the
    // schema again changes nothing.
    stack
        .db
        .batch_execute(
            "INSERT INTO clients (client_id, hostname) VALUES ('t/old', 'mac-1'); \
             ALTER TABLE clients DROP COLUMN edr_agent_id, DROP COLUMN edr_status; \
             DROP TABLE edr_devices",
        )
        .await
        .unwrap();
    PgGraphRepository::connect(&stack.url, 1).await.unwrap();
    PgGraphRepository::connect(&stack.url, 1).await.unwrap();
    assert_eq!(stack.clients().await, json!([["t/old", null, null]]));
    assert_eq!(stack.devices().await, Value::Null);
    stack.stop().await;
}

/// When the process scans of the first sync ran.
const SCANNED: &str = "2021-05-26T12:30:00Z";
const SCANNED_AT: i64 = 1_622_032_200_000;
const LATER: &str = "2021-05-26T12:35:00Z";

/// A process as `GET /syscollector/{agent_id}/processes` lists it.
fn process(name: &str, cmd: &str, argvs: &str, scanned: &str) -> Value {
    json!({"name": name, "cmd": cmd, "argvs": argvs, "scan": {"id": 0, "time": scanned}})
}

/// Six agents as `GET /agents` lists them: the manager itself, and one of each status.
fn company() -> Vec<Value> {
    vec![
        json!({"id": "000", "name": "wazuh-manager", "status": "active",
               "lastKeepAlive": "9999-12-31T23:59:59Z",
               "os": {"name": "Ubuntu", "version": "22.04.4 LTS", "platform": "ubuntu"}}),
        json!({"id": "001", "name": "Anas-MacBook-Pro.local", "status": "active",
               "lastKeepAlive": "2021-05-26T12:40:40Z",
               "os": {"name": "macOS", "version": "14.5", "platform": "darwin"}}),
        json!({"id": "002", "name": "DESKTOP-ABC", "status": "disconnected",
               "lastKeepAlive": "2021-05-26T12:40:00Z",
               "os": {"name": "Microsoft Windows 11 Pro", "version": "10.0.22631",
                      "platform": "windows"}}),
        json!({"id": "003", "name": "new-laptop", "status": "never_connected"}),
        json!({"id": "004", "name": "build-7", "status": "pending",
               "lastKeepAlive": "2021-05-26T12:40:40Z", "os": {"platform": "ubuntu"}}),
        json!({"id": "005", "name": "legacy", "status": "active",
               "lastKeepAlive": "2021-05-26T12:40:40Z",
               "os": {"name": "CentOS Linux", "version": "7.9"}}),
    ]
}

/// A Wazuh manager as far as the sync talks to it, shaped after the API reference.
#[derive(Default)]
struct Fake {
    agents: Vec<Value>,
    hardware: HashMap<&'static str, Value>,
    processes: HashMap<&'static str, Vec<Value>>,
    packages: HashMap<&'static str, Vec<&'static str>>,
    /// Agents whose inventory the manager answers with HTTP 400.
    refused: Vec<&'static str>,
    /// A path that fails with this status.
    failing: Option<(&'static str, u16)>,
    /// The token is forgotten after this many requests served with it.
    expire_after: Option<usize>,
    /// `/agents` waits here for a permit.
    gate: Option<Arc<Semaphore>>,
    token: Option<String>,
    logins: usize,
    served: usize,
    unauthorized: usize,
    /// Every request, in order: `GET /agents?offset=0&...`.
    requests: Vec<String>,
}

#[derive(Clone, Default)]
struct FakeWazuh(Arc<Mutex<Fake>>);

impl FakeWazuh {
    fn set(&self, change: impl FnOnce(&mut Fake)) {
        change(&mut self.0.lock().unwrap());
    }

    fn get(&self) -> std::sync::MutexGuard<'_, Fake> {
        self.0.lock().unwrap()
    }

    async fn serve(self) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().fallback(answer).with_state(self);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}")
    }
}

fn problem(status: u16, title: &str, detail: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        Json(json!({"title": title, "detail": detail})),
    )
        .into_response()
}

fn items(items: Vec<Value>, total: usize) -> Response {
    Json(json!({
        "data": {"affected_items": items, "total_affected_items": total,
                 "total_failed_items": 0, "failed_items": []},
        "message": "All selected items were returned",
        "error": 0
    }))
    .into_response()
}

async fn answer(
    State(wazuh): State<FakeWazuh>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let path = uri.path().to_owned();
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let query: HashMap<String, String> = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    let gate = {
        let mut fake = wazuh.get();
        fake.requests.push(match uri.query() {
            Some(query) => format!("{method} {path}?{query}"),
            None => format!("{method} {path}"),
        });
        if path == "/security/user/authenticate" {
            if method != Method::POST || authorization != BASIC {
                return problem(401, "Unauthorized", "Invalid credentials");
            }
            fake.logins += 1;
            let token = format!("token-{}", fake.logins);
            fake.token = Some(token.clone());
            return Json(json!({"data": {"token": token}, "error": 0})).into_response();
        }
        if method != Method::GET
            || fake.token.is_none()
            || authorization.strip_prefix("Bearer ") != fake.token.as_deref()
        {
            fake.unauthorized += 1;
            return problem(401, "Unauthorized", "Invalid token");
        }
        fake.served += 1;
        if fake.expire_after == Some(fake.served) {
            fake.token = None;
        }
        match fake.failing {
            Some((failing, 200)) if failing == path => {
                return Json(json!({"hello": "world"})).into_response();
            }
            Some((failing, status)) if failing == path => {
                return problem(status, "Wazuh Internal Error", "it broke");
            }
            _ => {}
        }
        fake.gate.clone().filter(|_| path == "/agents")
    };
    if let Some(gate) = gate {
        gate.acquire().await.unwrap().forget();
    }
    let fake = wazuh.get();
    if path == "/agents" {
        // Never more than two a page, whatever the limit asked for.
        let offset: usize = query["offset"].parse().unwrap();
        let page = fake.agents.iter().skip(offset).take(2).cloned().collect();
        return items(page, fake.agents.len());
    }
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let ["syscollector", agent, kind] = segments[..] else {
        return problem(404, "Not Found", "no such endpoint");
    };
    if fake.refused.contains(&agent) {
        return problem(400, "Bad Request", "agent has no inventory");
    }
    // As the manager applies `q`: any of these fields holding either word, in any case.
    let like = |fields: &[&str], item: &Value| {
        fields.iter().any(|field| {
            let value = item[*field].as_str().unwrap_or_default().to_lowercase();
            value.contains("claude") || value.contains("codex")
        })
    };
    let expected = |q: &str, select: &str| {
        query.get("q").map(String::as_str) == Some(q)
            && query.get("select").map(String::as_str) == Some(select)
    };
    match kind {
        "hardware" => match fake.hardware.get(agent) {
            Some(hardware) => items(vec![hardware.clone()], 1),
            None => items(vec![], 0),
        },
        "processes" => {
            if !expected(
                "name%7Eclaude%2Cname%7Ecodex%2Ccmd%7Eclaude%2Ccmd%7Ecodex%2Cargvs%7Eclaude\
                 %2Cargvs%7Ecodex",
                "name%2Ccmd%2Cargvs%2Cscan.time",
            ) {
                return problem(400, "Bad Request", "unexpected q or select");
            }
            let found: Vec<Value> = fake
                .processes
                .get(agent)
                .into_iter()
                .flatten()
                .filter(|process| like(&["name", "cmd", "argvs"], process))
                .cloned()
                .collect();
            let total = found.len();
            items(found, total)
        }
        "packages" => {
            if !expected("name%7Eclaude%2Cname%7Ecodex", "name") {
                return problem(400, "Bad Request", "unexpected q or select");
            }
            let found: Vec<Value> = fake
                .packages
                .get(agent)
                .into_iter()
                .flatten()
                .map(|name| json!({"name": name}))
                .filter(|package| like(&["name"], package))
                .collect();
            let total = found.len();
            items(found, total)
        }
        _ => problem(404, "Not Found", "no such inventory"),
    }
}

/// A fake manager, and the engine's store in a schema of this test's own.
struct Stack {
    fake: FakeWazuh,
    config: WazuhConfig,
    repository: PgGraphRepository,
    db: tokio_postgres::Client,
    admin: tokio_postgres::Client,
    schema: String,
    url: String,
}

impl Stack {
    async fn start() -> Option<Self> {
        let base = std::env::var("POSTGRES_INTEGRATION_URL").ok()?;
        let schema = format!(
            "edr_{}_{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let admin = connect(&base).await;
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let repository = PgGraphRepository::connect(&url, 2).await.unwrap();
        let fake = FakeWazuh::default();
        let config = WazuhConfig {
            url: fake.clone().serve().await,
            user: "withhuman".into(),
            password: "s3cret".into(),
            sync_interval: Duration::from_secs(60),
            tls: WazuhTls::PublicRoots,
            requests_per_minute: 0,
        };
        Some(Self {
            fake,
            config,
            repository,
            db: connect(&url).await,
            admin,
            schema,
            url,
        })
    }

    /// Every row of `edr_devices`, by agent ID.
    async fn devices(&self) -> Value {
        self.db
            .query_one(
                "SELECT jsonb_agg(jsonb_build_array(agent_id, name, os, status, serial, \
                 last_seen, agent, synced_at, running_at) ORDER BY agent_id) FROM edr_devices",
                &[],
            )
            .await
            .unwrap()
            .get::<_, Option<Value>>(0)
            .unwrap_or(Value::Null)
    }

    /// Every client's match, by client ID.
    async fn clients(&self) -> Value {
        self.db
            .query_one(
                "SELECT jsonb_agg(jsonb_build_array(client_id, edr_agent_id, edr_status) \
                 ORDER BY client_id) FROM clients",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }

    async fn stop(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

async fn connect(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
}
