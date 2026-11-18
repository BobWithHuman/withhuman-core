//! Keys on the Hooks (the user they name, the kill switch, `WITHHUMAN_REQUIRE_KEY`), the
//! inventory API, stopping a device and the session facts the Hooks now carry.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_collector::{
    CollectorConfig, CollectorService, FailurePolicy, GeneratorError, GeneratorTransport,
    NormalizedEvent, app_with_transport, devices, keys,
};
use withhuman_common::chunking::sha256;
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionResponse},
    events::EventResponse,
    inventory::{
        ClientState, KeyDenial, KeyStatus, SessionDenial, SessionFlags, SessionStop, StopDenial,
        VerifyKeyRequest, VerifyKeyResponse,
    },
};

const ACTIVE: &str =
    "whk_00000000000000aa_1111111111111111111111111111111111111111111111111111111111111111";
const REVOKED: &str =
    "whk_00000000000000bb_2222222222222222222222222222222222222222222222222222222222222222";
const UNKNOWN: &str =
    "whk_00000000000000cc_3333333333333333333333333333333333333333333333333333333333333333";
const ADMIN: &str = "admin-secret";

/// An inventory request the Collector passed on: method, path segments and body.
type Forwarded = (String, Vec<String>, Option<Value>);

#[derive(Default)]
struct Generator {
    events: Mutex<Vec<NormalizedEvent>>,
    verified: Mutex<Vec<VerifyKeyRequest>>,
    denials: Mutex<Vec<(String, KeyDenial)>>,
    inventory: Mutex<Vec<Forwarded>>,
    keys: Mutex<HashMap<String, VerifyKeyResponse>>,
    unavailable: bool,
    /// The client IDs the security team stopped.
    stopped: Mutex<HashSet<String>>,
    /// The client IDs whose state the Collector asked for.
    states: Mutex<Vec<String>>,
    stop_denials: Mutex<Vec<(String, StopDenial)>>,
    /// The Generator cannot say whether a device is stopped.
    state_down: AtomicBool,
    /// The sessions the security team stopped.
    stopped_sessions: Mutex<Vec<String>>,
    flag_lookups: Mutex<usize>,
    session_denials: Mutex<Vec<(String, SessionDenial)>>,
}

impl Generator {
    fn with_keys() -> Self {
        let generator = Self::default();
        {
            let mut keys = generator.keys.lock().unwrap();
            keys.insert(
                sha256(ACTIVE),
                VerifyKeyResponse {
                    status: KeyStatus::Active,
                    user: Some("ana@example.com".into()),
                },
            );
            keys.insert(
                sha256(REVOKED),
                VerifyKeyResponse {
                    status: KeyStatus::Revoked,
                    user: Some("bo@example.com".into()),
                },
            );
        }
        generator
    }

    fn events(&self) -> Vec<NormalizedEvent> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait]
impl GeneratorTransport for Generator {
    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        let call = matches!(event, NormalizedEvent::PreToolUse(_));
        self.events.lock().unwrap().push(event);
        Ok(EventResponse {
            nodes: Vec::new(),
            paragraphs: None,
            version: 1,
            decision_response: call.then(|| DecisionResponse {
                decision: Decision::Allow,
                reason: String::new(),
                rule: "test".into(),
                start: CausalStart::User,
                written: true,
                jev: None,
            }),
        })
    }

    async fn verify_key(
        &self,
        request: VerifyKeyRequest,
    ) -> Result<VerifyKeyResponse, GeneratorError> {
        if self.unavailable {
            return Err(GeneratorError::Unavailable("down".into()));
        }
        let answer = self
            .keys
            .lock()
            .unwrap()
            .get(&request.hash)
            .cloned()
            .unwrap_or(VerifyKeyResponse {
                status: KeyStatus::Unknown,
                user: None,
            });
        self.verified.lock().unwrap().push(request);
        Ok(answer)
    }

    async fn record_key_denial(
        &self,
        key_id: &str,
        denial: KeyDenial,
    ) -> Result<(), GeneratorError> {
        self.denials
            .lock()
            .unwrap()
            .push((key_id.to_owned(), denial));
        Ok(())
    }

    async fn client_state(&self, client_id: &str) -> Result<ClientState, GeneratorError> {
        self.states.lock().unwrap().push(client_id.to_owned());
        if self.state_down.load(Ordering::SeqCst) {
            return Err(GeneratorError::Unavailable("down".into()));
        }
        Ok(ClientState {
            stopped: self.stopped.lock().unwrap().contains(client_id),
        })
    }

    async fn record_stop_denial(
        &self,
        client_id: &str,
        denial: StopDenial,
    ) -> Result<(), GeneratorError> {
        self.stop_denials
            .lock()
            .unwrap()
            .push((client_id.to_owned(), denial));
        Ok(())
    }

    async fn session_flags(&self, session_id: &str) -> Result<SessionFlags, GeneratorError> {
        *self.flag_lookups.lock().unwrap() += 1;
        let stopped = self
            .stopped_sessions
            .lock()
            .unwrap()
            .iter()
            .any(|s| s == session_id);
        Ok(SessionFlags {
            stop: stopped.then(|| SessionStop {
                id: 1,
                session_id: session_id.to_owned(),
                stopped_at: 1,
                stopped_by: Some("sec@example.com".into()),
                reason: None,
                released_at: None,
                released_by: None,
                release_reason: None,
                first_denied_at: None,
                last_denied_at: None,
                denied_count: 0,
            }),
        })
    }

    async fn record_session_denial(
        &self,
        session_id: &str,
        denial: SessionDenial,
    ) -> Result<(), GeneratorError> {
        self.session_denials
            .lock()
            .unwrap()
            .push((session_id.to_owned(), denial));
        Ok(())
    }

    async fn inventory(
        &self,
        method: reqwest::Method,
        segments: &[&str],
        body: Option<Value>,
    ) -> Result<(u16, Value), GeneratorError> {
        self.inventory.lock().unwrap().push((
            method.to_string(),
            segments.iter().map(|s| (*s).to_owned()).collect(),
            body.clone(),
        ));
        let answer = match segments {
            ["users", user, "keys"] if method == reqwest::Method::POST => {
                let body = body.unwrap();
                json!({"key_id": body["key_id"], "user": user, "created_at": body["created_at"],
                       "created_by": body["actor"], "denied_count": 0})
            }
            ["users", _, "revoke"] => json!([{"key_id": "00000000000000aa",
                "user": "ana@example.com", "created_at": 1, "revoked_at": 2, "denied_count": 0}]),
            ["keys", key_id, "revoke"] => {
                json!({"key_id": key_id, "user": "bo@example.com", "created_at": 1,
                       "revoked_at": 2, "revoked_by": body.unwrap()["actor"], "denied_count": 0})
            }
            ["sessions", session, change] if *change == "stop" || *change == "release" => {
                json!({"id": 1, "session_id": session, "stopped_at": 1, "denied_count": 0,
                       "released_at": if *change == "release" { json!(2) } else { Value::Null }})
            }
            ["reviews"] => {
                let body = body.unwrap();
                return Ok((
                    201,
                    json!({"id": 1, "session_id": body["session_id"],
                    "seq": body["seq"], "status": body["status"], "at": 1}),
                ));
            }
            ["clients"] if method == reqwest::Method::POST => {
                let body = body.unwrap();
                json!({"client_id": body["client_id"], "user": body["user"], "projects": []})
            }
            ["clients", client_id, "owner"] if *client_id != "team/1234" => {
                return Ok((404, json!({"error": "graph_resource_not_found"})));
            }
            ["clients", client_id, "owner"] => {
                let body = body.unwrap();
                json!({"client_id": client_id, "owner": body["owner"],
                       "owner_set_by": body["actor"], "projects": []})
            }
            ["clients", client_id, "stop"] if *client_id != "team/1234" => {
                return Ok((404, json!({"error": "graph_resource_not_found"})));
            }
            ["clients", client_id, "stop"] => {
                let body = body.unwrap();
                let mut stopped = self.stopped.lock().unwrap();
                if body["stopped"] == true {
                    stopped.insert((*client_id).to_owned());
                    json!({"client_id": client_id, "stopped_at": 5, "stopped_by": body["actor"],
                           "stop_reason": body["reason"], "stop_denied_count": 0, "projects": []})
                } else {
                    stopped.remove(*client_id);
                    json!({"client_id": client_id, "stopped_at": null, "stopped_by": null,
                           "stop_reason": null, "stop_denied_count": 0, "projects": []})
                }
            }
            _ => json!([]),
        };
        Ok((200, answer))
    }
}

fn app(generator: Arc<Generator>, configure: impl FnOnce(&mut CollectorConfig)) -> Router {
    let mut config = CollectorConfig {
        intent_capture: false,
        ..CollectorConfig::default()
    };
    configure(&mut config);
    app_with_transport(CollectorService::new(config, generator))
}

async fn post(
    app: &Router,
    path: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    read(response).await
}

async fn get(app: &Router, path: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut request = Request::get(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    read(
        app.clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap(),
    )
    .await
}

async fn read(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

fn bearer(key: &str) -> String {
    format!("Bearer {key}")
}

fn call(session: &str) -> Value {
    json!({"session_id": session, "tool_name": "Read", "tool_input": {"file_path": "/r/a"},
           "tool_use_id": "t1", "permission_mode": "acceptEdits"})
}

fn denial(body: &Value) -> (&str, &str) {
    let output = &body["hookSpecificOutput"];
    (
        output["permissionDecision"].as_str().unwrap_or_default(),
        output["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default(),
    )
}

fn user_of(event: &NormalizedEvent) -> Option<String> {
    match event {
        NormalizedEvent::SessionStart(event) => event.user.clone(),
        NormalizedEvent::UserPromptSubmit(event) => event.user.clone(),
        NormalizedEvent::PreToolUse(event) => event.event.user.clone(),
        other => panic!("unexpected event {other:?}"),
    }
}

#[tokio::test]
async fn a_valid_key_names_the_user_and_a_client_cannot_name_one() {
    let generator = Arc::new(Generator::with_keys());
    let app = app(generator.clone(), |_| {});
    let key = bearer(ACTIVE);
    let spoofed = [
        ("authorization", key.as_str()),
        ("x-withhuman-user", "mallory@example.com"),
        ("x-withhuman-client", "team/device"),
    ];
    let (status, _) = post(
        &app,
        "/v1/hooks/SessionStart",
        json!({"session_id": "s1", "source": "resume", "model": "claude-opus-5",
               "permission_mode": "plan"}),
        &spoofed,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(&app, "/v1/hooks/PreToolUse", call("s1"), &spoofed).await;
    assert_eq!((status, body), (StatusCode::OK, Value::Null));
    // Without a key the header a client sets is dropped.
    post(
        &app,
        "/v1/hooks/SessionStart",
        json!({"session_id": "s2"}),
        &[("x-withhuman-user", "mallory@example.com")],
    )
    .await;

    let events = generator.events();
    assert_eq!(user_of(&events[0]).as_deref(), Some("ana@example.com"));
    assert_eq!(user_of(&events[1]).as_deref(), Some("ana@example.com"));
    assert_eq!(user_of(&events[2]), None);
    let NormalizedEvent::SessionStart(start) = &events[0] else {
        panic!()
    };
    assert_eq!(start.payload.source.as_deref(), Some("resume"));
    assert_eq!(start.meta.model.as_deref(), Some("claude-opus-5"));
    assert_eq!(start.meta.permission_mode.as_deref(), Some("plan"));
    assert_eq!(start.client_id.as_deref(), Some("team/device"));
    let NormalizedEvent::PreToolUse(call) = &events[1] else {
        panic!()
    };
    assert_eq!(
        call.event.meta.permission_mode.as_deref(),
        Some("acceptEdits")
    );
    // The two Hooks' key was verified once (cached), by hash: the key never left.
    let verified = generator.verified.lock().unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].key_id, "00000000000000aa");
    assert_eq!(verified[0].hash, sha256(ACTIVE));
}

#[tokio::test]
async fn a_revoked_key_stops_every_call_and_records_when() {
    let generator = Arc::new(Generator::with_keys());
    // Observing modes never block a verdict; the kill switch is an administrator's decision.
    let app = app(generator.clone(), |config| {
        config.enforcement_mode = withhuman_contracts::events::EnforcementMode::Shadow;
    });
    let key = bearer(REVOKED);
    let headers = [
        ("authorization", key.as_str()),
        ("x-withhuman-client", "team/device"),
    ];
    let (status, body) = post(&app, "/v1/hooks/PreToolUse", call("s9"), &headers).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denial(&body), ("deny", keys::KEY_REVOKED));
    let (status, body) = post(
        &app,
        "/v1/hooks/codex/PreToolUse",
        json!({"session_id": "c9", "tool_name": "shell", "tool_use_id": "t",
               "tool_input": {"command": "ls"}, "cwd": "/p"}),
        &headers,
    )
    .await;
    assert_eq!(
        (status, denial(&body)),
        (StatusCode::OK, ("deny", keys::KEY_REVOKED))
    );
    // What the user still does is recorded under their name.
    let (status, _) = post(
        &app,
        "/v1/hooks/UserPromptSubmit",
        json!({"session_id": "s9", "prompt": "why?"}),
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let events = generator.events();
    assert_eq!(events.len(), 1, "no call reached the Generator");
    assert_eq!(user_of(&events[0]).as_deref(), Some("bo@example.com"));
    let denials = generator.denials.lock().unwrap();
    assert_eq!(denials.len(), 2);
    assert_eq!(denials[0].0, "00000000000000bb");
    assert_eq!(denials[0].1.session_id.as_deref(), Some("s9"));
    assert_eq!(denials[0].1.client_id.as_deref(), Some("team/device"));
    assert!(denials[0].1.denied_at > 0);
    assert_eq!(denials[1].1.session_id.as_deref(), Some("c9"));
}

#[tokio::test]
async fn hooks_without_a_key_pass_unless_one_is_required() {
    let generator = Arc::new(Generator::with_keys());
    let open = app(generator.clone(), |_| {});
    assert_eq!(
        post(&open, "/v1/hooks/PreToolUse", call("s"), &[]).await,
        (StatusCode::OK, Value::Null)
    );
    // An unknown key is ignored, as no key would be.
    let unknown = bearer(UNKNOWN);
    assert_eq!(
        post(
            &open,
            "/v1/hooks/PreToolUse",
            call("s"),
            &[("authorization", unknown.as_str())]
        )
        .await,
        (StatusCode::OK, Value::Null)
    );
    // An HTTP Hook whose WITHHUMAN_KEY is unset sends an empty bearer.
    let (status, _) = post(
        &open,
        "/v1/hooks/SessionStart",
        json!({"session_id": "s"}),
        &[("authorization", "Bearer ")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(generator.events().len(), 3);

    let required = app(generator.clone(), |config| config.require_key = true);
    let (status, body) = post(&required, "/v1/hooks/PreToolUse", call("s"), &[]).await;
    assert_eq!(
        (status, denial(&body)),
        (StatusCode::OK, ("deny", keys::KEY_MISSING))
    );
    let (status, body) = post(
        &required,
        "/v1/hooks/PreToolUse",
        call("s"),
        &[("authorization", unknown.as_str())],
    )
    .await;
    assert_eq!(
        (status, denial(&body)),
        (StatusCode::OK, ("deny", keys::KEY_INVALID))
    );
    let (status, body) = post(
        &required,
        "/v1/hooks/SessionStart",
        json!({"session_id": "s"}),
        &[("authorization", "Bearer not-a-key")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "key_invalid");
    let (status, body) = post(
        &required,
        "/v1/hooks/codex/SessionStart",
        json!({"session_id": "s"}),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["message"], keys::KEY_MISSING);
    let key = bearer(ACTIVE);
    assert_eq!(
        post(
            &required,
            "/v1/hooks/PreToolUse",
            call("s"),
            &[("authorization", key.as_str())]
        )
        .await,
        (StatusCode::OK, Value::Null)
    );
    assert_eq!(generator.events().len(), 4);
}

#[tokio::test]
async fn a_key_that_cannot_be_checked_follows_the_failure_policy() {
    let generator = Arc::new(Generator {
        unavailable: true,
        ..Generator::default()
    });
    let key = bearer(ACTIVE);
    let headers = [("authorization", key.as_str())];
    let closed = app(generator.clone(), |config| {
        config.require_key = true;
        config.failure_policy = FailurePolicy::Closed;
    });
    let (status, body) = post(&closed, "/v1/hooks/PreToolUse", call("s"), &headers).await;
    assert_eq!(
        (status, denial(&body)),
        (StatusCode::OK, ("deny", keys::KEY_UNCHECKED))
    );
    let open = app(generator.clone(), |config| {
        config.require_key = true;
        config.failure_policy = FailurePolicy::Open;
    });
    assert_eq!(
        post(&open, "/v1/hooks/PreToolUse", call("s"), &headers).await,
        (StatusCode::OK, Value::Null)
    );
    assert_eq!(user_of(&generator.events()[0]), None);
}

#[tokio::test]
async fn records_how_a_session_ended() {
    let generator = Arc::new(Generator::default());
    let app = app(generator.clone(), |_| {});
    let (status, body) = post(
        &app,
        "/v1/hooks/SessionEnd",
        json!({"session_id": "s", "hook_event_name": "SessionEnd", "reason": "prompt_input_exit",
               "cwd": "/r", "permission_mode": "default", "transcript_path": "/t.jsonl"}),
        &[("x-withhuman-client", "team/device")],
    )
    .await;
    assert_eq!((status, body), (StatusCode::OK, Value::Null));
    let events = generator.events();
    let NormalizedEvent::SessionEnd(end) = &events[0] else {
        panic!("expected SessionEnd, got {:?}", events[0]);
    };
    assert_eq!(end.payload.reason.as_deref(), Some("prompt_input_exit"));
    assert_eq!(end.meta.cwd.as_deref(), Some("/r"));
    assert_eq!(end.meta.permission_mode.as_deref(), Some("default"));
    assert_eq!(end.client_id.as_deref(), Some("team/device"));
    assert_eq!(end.order, 1);
}

#[tokio::test]
async fn administrators_issue_list_and_revoke_keys_with_the_admin_token() {
    let generator = Arc::new(Generator::with_keys());
    let disabled = app(generator.clone(), |_| {});
    let (status, _) = post(&disabled, "/v1/admin/users/a@b.c/keys", json!({}), &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let app = app(generator.clone(), |config| {
        config.admin_token = Some(ADMIN.into());
        config.key_cache = Duration::from_secs(3_600);
    });
    let admin = bearer(ADMIN);
    let admin = [("authorization", admin.as_str())];
    let (status, _) = post(
        &app,
        "/v1/admin/users/a@b.c/keys",
        json!({}),
        &[("authorization", "Bearer wrong")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = post(&app, "/v1/admin/users/not-an-email/keys", json!({}), &admin).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, issued) = post(
        &app,
        "/v1/admin/users/Ana@Example.com/keys",
        json!({"actor": "sec@example.com", "note": "laptop"}),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key = issued["key"].as_str().unwrap();
    let parsed = keys::parse(key).expect("a WithHuman key");
    assert_eq!(issued["key_id"], parsed.key_id);
    assert_eq!(issued["user"], "ana@example.com");
    {
        let calls = generator.inventory.lock().unwrap();
        let (method, path, body) = &calls[0];
        assert_eq!(
            (method.as_str(), path.join("/")),
            ("POST", "users/ana@example.com/keys".into())
        );
        let body = body.as_ref().unwrap();
        assert_eq!(body["hash"], sha256(key));
        assert_eq!(body["actor"], "sec@example.com");
        assert!(!body.to_string().contains(key), "the key itself stays here");
    }

    // A cached answer is dropped on revocation, so this replica stops the key at once.
    let active = bearer(ACTIVE);
    let user = [("authorization", active.as_str())];
    post(&app, "/v1/hooks/PreToolUse", call("s"), &user).await;
    generator.keys.lock().unwrap().insert(
        sha256(ACTIVE),
        VerifyKeyResponse {
            status: KeyStatus::Revoked,
            user: Some("ana@example.com".into()),
        },
    );
    let (status, revoked) = post(
        &app,
        "/v1/admin/keys/00000000000000aa/revoke",
        json!({"actor": "sec@example.com", "reason": "left the company"}),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked["revoked_by"], "sec@example.com");
    let (_, body) = post(&app, "/v1/hooks/PreToolUse", call("s"), &user).await;
    assert_eq!(denial(&body), ("deny", keys::KEY_REVOKED));

    let (status, revoked) = post(
        &app,
        "/v1/admin/users/ana@example.com/revoke",
        json!({"actor": "sec@example.com"}),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked[0]["revoked_at"], 2);
    for path in [
        "/v1/admin/keys",
        "/v1/admin/clients",
        "/v1/admin/users/ana@example.com/keys",
    ] {
        assert_eq!(get(&app, path, &admin).await.0, StatusCode::OK, "{path}");
        assert_eq!(
            get(&app, path, &[]).await.0,
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
}

#[tokio::test]
async fn devices_register_with_their_keys_user() {
    let generator = Arc::new(Generator::with_keys());
    let app = app(generator.clone(), |_| {});
    let registration = json!({"client_id": " team/1234 ", "team": "team", "hostname": "mac-1",
        "os": "darwin 25.1", "os_user": "ana", "hook_version": "abc", "agent": "claude",
        "project": "/Users/ana/app", "serial": " C02TEST1234 "});
    let key = bearer(ACTIVE);
    let (status, body) = post(
        &app,
        "/v1/clients/register",
        registration.clone(),
        &[("authorization", key.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["client_id"], "team/1234");
    assert_eq!(body["user"], "ana@example.com");
    {
        let calls = generator.inventory.lock().unwrap();
        let sent = calls[0].2.as_ref().unwrap();
        assert_eq!(sent["hostname"], "mac-1");
        assert_eq!(sent["project"], "/Users/ana/app");
        assert_eq!(sent["serial"], "C02TEST1234");
        assert!(sent["registered_at"].as_u64().unwrap() > 0);
    }
    // A device whose serial could not be read registers without one; a blank one is none.
    for serial in [json!(null), json!("  ")] {
        let mut without = registration.clone();
        without["serial"] = serial;
        let (status, _) = post(&app, "/v1/clients/register", without, &[]).await;
        assert_eq!(status, StatusCode::OK);
        let calls = generator.inventory.lock().unwrap();
        assert_eq!(
            calls.last().unwrap().2.as_ref().unwrap()["serial"],
            Value::Null
        );
    }
    let mut long = registration.clone();
    long["serial"] = json!("9".repeat(1_025));
    let (status, _) = post(&app, "/v1/clients/register", long, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Without a key a device still registers, with no user.
    let (status, body) = post(&app, "/v1/clients/register", registration.clone(), &[]).await;
    assert_eq!((status, &body["user"]), (StatusCode::OK, &Value::Null));

    let revoked = bearer(REVOKED);
    let (status, _) = post(
        &app,
        "/v1/clients/register",
        registration.clone(),
        &[("authorization", revoked.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let required = self::app(generator.clone(), |config| config.require_key = true);
    let (status, _) = post(&required, "/v1/clients/register", registration, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = post(&app, "/v1/clients/register", json!({"client_id": ""}), &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn administrators_name_and_clear_a_devices_owner() {
    let generator = Arc::new(Generator::with_keys());
    // The client ID is one path segment: its slash is sent as %2F.
    let path = "/v1/admin/clients/team%2F1234/owner";
    let named = json!({"owner": " Bo@Example.com ", "actor": "sec@example.com"});
    let disabled = app(generator.clone(), |_| {});
    let (status, body) = post(&disabled, path, named.clone(), &[]).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("admin_api_disabled"))
    );

    let app = app(generator.clone(), |config| {
        config.admin_token = Some(ADMIN.into())
    });
    let admin = bearer(ADMIN);
    let admin = [("authorization", admin.as_str())];
    for headers in [&[][..], &[("authorization", "Bearer wrong")][..]] {
        let (status, body) = post(&app, path, named.clone(), headers).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("admin_token_invalid"))
        );
    }
    // A user's key is not the admin token.
    let user = bearer(ACTIVE);
    let (status, _) = post(
        &app,
        path,
        named.clone(),
        &[("authorization", user.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(generator.inventory.lock().unwrap().is_empty());

    let (status, body) = post(&app, path, named, &admin).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["client_id"], "team/1234");
    assert_eq!(body["owner"], "bo@example.com");
    assert_eq!(body["owner_set_by"], "sec@example.com");
    let (status, body) = post(
        &app,
        path,
        json!({"owner": null, "actor": "sec@example.com"}),
        &admin,
    )
    .await;
    assert_eq!((status, &body["owner"]), (StatusCode::OK, &Value::Null));
    {
        let calls = generator.inventory.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for (method, segments, _) in calls.iter() {
            assert_eq!(method, "POST");
            assert_eq!(segments, &["clients", "team/1234", "owner"]);
        }
        assert_eq!(
            calls[0].2,
            Some(json!({"owner": "bo@example.com", "actor": "sec@example.com"}))
        );
        assert_eq!(
            calls[1].2,
            Some(json!({"owner": null, "actor": "sec@example.com"}))
        );
    }

    // Not an email, or a body that does not say the owner: nothing reaches the Generator.
    let (status, body) = post(&app, path, json!({"owner": "bo"}), &admin).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_email"))
    );
    let (status, _) = post(&app, path, json!({"actor": "sec@example.com"}), &admin).await;
    assert!(status.is_client_error(), "{status}");
    assert_eq!(generator.inventory.lock().unwrap().len(), 2);
    // An unencoded slash is another path, and an unknown device is the Generator's 404.
    let (status, _) = post(
        &app,
        "/v1/admin/clients/team/1234/owner",
        json!({"owner": null}),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(generator.inventory.lock().unwrap().len(), 2);
    let (status, body) = post(
        &app,
        "/v1/admin/clients/team%2Fnone/owner",
        json!({"owner": "bo@example.com"}),
        &admin,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("graph_resource_not_found"))
    );

    let (_, document) = get(&app, "/api-docs/openapi.json", &[]).await;
    let documented = &document["paths"]["/v1/admin/clients/{client_id}/owner"]["post"];
    assert!(documented.is_object());
    let schema = &document["components"]["schemas"]["SetOwnerRequest"];
    assert_eq!(schema["required"], json!(["owner"]), "{schema}");
}

/// The PreToolUse events that reached the Generator.
fn calls(generator: &Generator) -> usize {
    generator
        .events()
        .iter()
        .filter(|event| matches!(event, NormalizedEvent::PreToolUse(_)))
        .count()
}

const STOP: &str = "/v1/admin/clients/team%2F1234/stop";

#[tokio::test]
async fn a_stopped_device_is_refused_every_call_until_it_is_released() {
    let generator = Arc::new(Generator::with_keys());
    // Observing modes never block a verdict; a stop is an administrator's decision.
    let app = app(generator.clone(), |config| {
        config.enforcement_mode = withhuman_contracts::events::EnforcementMode::Shadow;
        config.admin_token = Some(ADMIN.into());
    });
    let admin = bearer(ADMIN);
    let admin = [("authorization", admin.as_str())];
    let key = bearer(ACTIVE);
    let device = [
        ("authorization", key.as_str()),
        ("x-withhuman-client", "team/1234"),
    ];
    // The same device without a key, where none is required.
    let keyless = [("x-withhuman-client", "team/1234")];
    let other = [
        ("authorization", key.as_str()),
        ("x-withhuman-client", "team/5678"),
    ];

    // Running, its calls pass; the answer is kept for the next ones.
    for headers in [&device[..], &keyless[..]] {
        let (status, body) = post(&app, "/v1/hooks/PreToolUse", call("s1"), headers).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(denial(&body).0, "deny", "{body}");
    }
    assert_eq!(calls(&generator), 2);
    assert_eq!(*generator.states.lock().unwrap(), ["team/1234"]);

    let (status, body) = post(
        &app,
        STOP,
        json!({"stopped": true, "actor": "sec@example.com", "reason": "lost laptop"}),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["client_id"], "team/1234");
    assert_eq!(body["stopped_at"], 5);
    assert_eq!(body["stopped_by"], "sec@example.com");
    assert_eq!(body["stop_reason"], "lost laptop");

    // The stop made here applies at once, not when the kept answer runs out: with a key,
    // without one, and from Codex.
    for headers in [&device[..], &keyless[..]] {
        let (status, body) = post(&app, "/v1/hooks/PreToolUse", call("s1"), headers).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(denial(&body), ("deny", devices::DEVICE_STOPPED));
        // The team's reason stays with the team.
        assert!(!body.to_string().contains("lost laptop"));
    }
    let (status, body) = post(
        &app,
        "/v1/hooks/codex/PreToolUse",
        json!({"session_id": "c1", "tool_name": "shell", "tool_use_id": "t",
               "tool_input": {"command": "ls"}, "cwd": "/p"}),
        &device,
    )
    .await;
    assert_eq!(
        (status, denial(&body)),
        (StatusCode::OK, ("deny", devices::DEVICE_STOPPED))
    );
    assert_eq!(calls(&generator), 2, "no call reached the Generator");
    {
        let denials = generator.stop_denials.lock().unwrap();
        assert_eq!(denials.len(), 3);
        assert!(denials.iter().all(|(client, _)| client == "team/1234"));
        assert!(denials[0].1.denied_at > 0);
    }

    // What the device still does is recorded, under its key's user.
    let before = generator.events().len();
    let (status, _) = post(
        &app,
        "/v1/hooks/UserPromptSubmit",
        json!({"session_id": "s1", "prompt": "why?"}),
        &device,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = generator.events();
    assert_eq!(events.len(), before + 1);
    assert_eq!(
        user_of(events.last().unwrap()).as_deref(),
        Some("ana@example.com")
    );
    // Another device of the same user, and a Hook that names no device, are not stopped.
    for headers in [&other[..], &[("authorization", key.as_str())][..]] {
        let (_, body) = post(&app, "/v1/hooks/PreToolUse", call("s2"), headers).await;
        assert_ne!(denial(&body).0, "deny", "{body}");
    }
    assert_eq!(calls(&generator), 4);

    // Released, it is allowed again at once.
    let (status, body) = post(&app, STOP, json!({"stopped": false}), &admin).await;
    assert_eq!(
        (status, &body["stopped_at"]),
        (StatusCode::OK, &Value::Null)
    );
    let (_, body) = post(&app, "/v1/hooks/PreToolUse", call("s1"), &device).await;
    assert_ne!(denial(&body).0, "deny", "{body}");
    assert_eq!(calls(&generator), 5);
    assert_eq!(generator.stop_denials.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn a_revoked_key_on_a_stopped_device_is_refused_for_its_key() {
    let generator = Arc::new(Generator::with_keys());
    generator.stopped.lock().unwrap().insert("team/1234".into());
    let app = app(generator.clone(), |_| {});
    let key = bearer(REVOKED);
    let headers = [
        ("authorization", key.as_str()),
        ("x-withhuman-client", "team/1234"),
    ];
    let (_, body) = post(&app, "/v1/hooks/PreToolUse", call("s1"), &headers).await;
    assert_eq!(denial(&body), ("deny", keys::KEY_REVOKED));
    assert_eq!(generator.denials.lock().unwrap().len(), 1);
    assert!(generator.stop_denials.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_stop_made_elsewhere_applies_when_the_kept_answer_runs_out() {
    let device = [("x-withhuman-client", "team/1234")];
    // Kept: the Generator is asked once, and a stop another replica took is not seen yet.
    let generator = Arc::new(Generator::with_keys());
    let kept = app(generator.clone(), |config| {
        config.key_cache = Duration::from_secs(60);
    });
    let (_, body) = post(&kept, "/v1/hooks/PreToolUse", call("s1"), &device).await;
    assert_ne!(denial(&body).0, "deny");
    generator.stopped.lock().unwrap().insert("team/1234".into());
    let (_, body) = post(&kept, "/v1/hooks/PreToolUse", call("s1"), &device).await;
    assert_ne!(denial(&body).0, "deny");
    assert_eq!(generator.states.lock().unwrap().len(), 1);
    // Only a call asks: the device's other Hooks pass without the question.
    post(
        &kept,
        "/v1/hooks/UserPromptSubmit",
        json!({"session_id": "s1", "prompt": "hello"}),
        &device,
    )
    .await;
    assert_eq!(generator.states.lock().unwrap().len(), 1);

    // Not kept: every call asks, so the stop is seen by the next one, and so is the release.
    let generator = Arc::new(Generator::with_keys());
    let fresh = app(generator.clone(), |config| {
        config.key_cache = Duration::ZERO;
    });
    let (_, body) = post(&fresh, "/v1/hooks/PreToolUse", call("s1"), &device).await;
    assert_ne!(denial(&body).0, "deny");
    generator.stopped.lock().unwrap().insert("team/1234".into());
    let (_, body) = post(&fresh, "/v1/hooks/PreToolUse", call("s1"), &device).await;
    assert_eq!(denial(&body), ("deny", devices::DEVICE_STOPPED));

    // While the Generator cannot answer, a device it said was stopped stays stopped, and one
    // it never answered for goes on to be decided like any other call.
    generator.state_down.store(true, Ordering::SeqCst);
    let (_, body) = post(&fresh, "/v1/hooks/PreToolUse", call("s1"), &device).await;
    assert_eq!(denial(&body), ("deny", devices::DEVICE_STOPPED));
    let before = calls(&generator);
    let unknown = [("x-withhuman-client", "team/9999")];
    let (_, body) = post(&fresh, "/v1/hooks/PreToolUse", call("s3"), &unknown).await;
    assert_ne!(denial(&body).0, "deny");
    assert_eq!(calls(&generator), before + 1);
    generator.state_down.store(false, Ordering::SeqCst);
    generator.stopped.lock().unwrap().clear();
    let (_, body) = post(&fresh, "/v1/hooks/PreToolUse", call("s1"), &device).await;
    assert_ne!(denial(&body).0, "deny");
}

#[tokio::test]
async fn administrators_stop_and_release_a_device_with_the_admin_token() {
    let generator = Arc::new(Generator::with_keys());
    let stop = json!({"stopped": true, "actor": "sec@example.com", "reason": "lost laptop"});
    let disabled = app(generator.clone(), |_| {});
    let (status, body) = post(&disabled, STOP, stop.clone(), &[]).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("admin_api_disabled"))
    );

    let app = app(generator.clone(), |config| {
        config.admin_token = Some(ADMIN.into())
    });
    let admin = bearer(ADMIN);
    let admin = [("authorization", admin.as_str())];
    for headers in [&[][..], &[("authorization", "Bearer wrong")][..]] {
        let (status, body) = post(&app, STOP, stop.clone(), headers).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("admin_token_invalid"))
        );
    }
    // A user's key is not the admin token.
    let user = bearer(ACTIVE);
    let (status, _) = post(
        &app,
        STOP,
        stop.clone(),
        &[("authorization", user.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(generator.inventory.lock().unwrap().is_empty());
    assert!(generator.stopped.lock().unwrap().is_empty());

    // A body that does not say which, or says it as something else: nothing is changed.
    for body in [
        json!({"actor": "sec@example.com"}),
        json!({"stopped": "yes"}),
        json!({"stopped": null}),
    ] {
        let (status, _) = post(&app, STOP, body, &admin).await;
        assert!(status.is_client_error(), "{status}");
    }
    assert!(generator.inventory.lock().unwrap().is_empty());

    let (status, _) = post(&app, STOP, stop.clone(), &admin).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post(&app, STOP, json!({"stopped": false}), &admin).await;
    assert_eq!(status, StatusCode::OK);
    {
        let calls = generator.inventory.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for (method, segments, _) in calls.iter() {
            assert_eq!(method, "POST");
            // The client ID reaches the Generator whole, as one segment.
            assert_eq!(segments, &["clients", "team/1234", "stop"]);
        }
        assert_eq!(calls[0].2, Some(stop.clone()));
        assert_eq!(
            calls[1].2,
            Some(json!({"stopped": false, "actor": null, "reason": null}))
        );
    }

    // An unencoded slash is another path, and an unknown device is the Generator's 404.
    let (status, _) = post(
        &app,
        "/v1/admin/clients/team/1234/stop",
        stop.clone(),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(generator.inventory.lock().unwrap().len(), 2);
    let (status, body) = post(&app, "/v1/admin/clients/team%2Fnone/stop", stop, &admin).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("graph_resource_not_found"))
    );
    assert!(generator.stopped.lock().unwrap().is_empty());

    let (_, document) = get(&app, "/api-docs/openapi.json", &[]).await;
    let documented = &document["paths"]["/v1/admin/clients/{client_id}/stop"]["post"];
    assert!(documented.is_object());
    let schema = &document["components"]["schemas"]["StopClientRequest"];
    assert_eq!(schema["required"], json!(["stopped"]), "{schema}");
    let record = &document["components"]["schemas"]["ClientRecord"]["properties"];
    for field in [
        "stopped_at",
        "stopped_by",
        "stop_reason",
        "stop_denied_count",
        "stop_last_denied_at",
    ] {
        assert!(record[field].is_object(), "{field}");
    }
}

/// Over HTTP, as the Collector reaches a real Generator: the client ID, slash and all, is one
/// path segment of each request.
#[tokio::test]
async fn asks_the_generator_for_a_devices_state_by_its_whole_client_id() {
    use axum::{Json, extract::Path, extract::State, routing};
    type Seen = Arc<Mutex<Vec<String>>>;
    let seen = Seen::default();
    let stub = Router::new()
        .route(
            "/v1/clients/{client_id}/state",
            routing::get(
                |State(seen): State<Seen>, Path(client_id): Path<String>| async move {
                    seen.lock().unwrap().push(format!("state {client_id}"));
                    Json(json!({"stopped": client_id == "team/1234"}))
                },
            ),
        )
        .route(
            "/v1/clients/{client_id}/stop-denials",
            routing::post(
                |State(seen): State<Seen>,
                 Path(client_id): Path<String>,
                 Json(body): Json<Value>| async move {
                    assert!(body["denied_at"].as_u64().unwrap() > 0);
                    seen.lock().unwrap().push(format!("denied {client_id}"));
                    StatusCode::NO_CONTENT
                },
            ),
        )
        .route(
            "/v1/clients/{client_id}/stop",
            routing::post(
                |State(seen): State<Seen>,
                 Path(client_id): Path<String>,
                 Json(body): Json<Value>| async move {
                    seen.lock().unwrap().push(format!("stop {client_id}"));
                    Json(json!({"client_id": client_id, "stopped_at": 5,
                        "stopped_by": body["actor"], "projects": []}))
                },
            ),
        )
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, stub).await.unwrap() });

    let app = withhuman_collector::app(CollectorConfig {
        generator_url: format!("http://{address}"),
        admin_token: Some(ADMIN.into()),
        intent_capture: false,
        ..CollectorConfig::default()
    });
    let device = [("x-withhuman-client", "team/1234")];
    let (status, body) = post(&app, "/v1/hooks/PreToolUse", call("s1"), &device).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denial(&body), ("deny", devices::DEVICE_STOPPED));
    let admin = bearer(ADMIN);
    let (status, body) = post(
        &app,
        STOP,
        json!({"stopped": true, "actor": "sec@example.com"}),
        &[("authorization", admin.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["client_id"], "team/1234");
    assert_eq!(
        *seen.lock().unwrap(),
        ["state team/1234", "denied team/1234", "stop team/1234"]
    );
}

#[tokio::test]
async fn a_stopped_session_has_its_calls_denied_until_released() {
    let generator = Arc::new(Generator::with_keys());
    let app = app(generator.clone(), |config| {
        config.admin_token = Some(ADMIN.into());
        config.key_cache = Duration::from_secs(3_600);
    });
    let admin = bearer(ADMIN);
    let admin = [("authorization", admin.as_str())];
    // Cached as running, then stopped here: the stop applies at once.
    assert_eq!(
        post(&app, "/v1/hooks/PreToolUse", call("s-1"), &[]).await,
        (StatusCode::OK, Value::Null)
    );
    generator
        .stopped_sessions
        .lock()
        .unwrap()
        .push("s-1".into());
    let (status, stop) = post(
        &app,
        "/v1/admin/sessions/s-1/stop",
        json!({"actor": "sec@example.com", "reason": "exfiltration"}),
        &admin,
    )
    .await;
    assert_eq!(
        (status, &stop["session_id"]),
        (StatusCode::OK, &json!("s-1"))
    );
    let (status, body) = post(&app, "/v1/hooks/PreToolUse", call("s-1"), &[]).await;
    assert_eq!(
        (status, denial(&body)),
        (StatusCode::OK, ("deny", keys::SESSION_STOPPED))
    );
    let (_, body) = post(
        &app,
        "/v1/hooks/codex/PreToolUse",
        json!({"session_id": "s-1", "tool_name": "shell", "tool_use_id": "t",
               "tool_input": {"command": "ls"}, "cwd": "/p"}),
        &[],
    )
    .await;
    assert_eq!(denial(&body), ("deny", keys::SESSION_STOPPED));
    // Other sessions and the session's other Hooks go on.
    assert_eq!(
        post(&app, "/v1/hooks/PreToolUse", call("s-2"), &[]).await,
        (StatusCode::OK, Value::Null)
    );
    let (status, _) = post(
        &app,
        "/v1/hooks/UserPromptSubmit",
        json!({"session_id": "s-1", "prompt": "go on"}),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    {
        let denials = generator.session_denials.lock().unwrap();
        assert_eq!(denials.len(), 2);
        assert_eq!(denials[0].0, "s-1");
        assert!(denials[0].1.denied_at > 0);
    }
    // A user's revoked key comes first.
    let revoked = bearer(REVOKED);
    let (_, body) = post(
        &app,
        "/v1/hooks/PreToolUse",
        call("s-1"),
        &[("authorization", revoked.as_str())],
    )
    .await;
    assert_eq!(denial(&body).1, keys::KEY_REVOKED);

    generator.stopped_sessions.lock().unwrap().clear();
    let (status, released) = post(
        &app,
        "/v1/admin/sessions/s-1/release",
        json!({"actor": "sec@example.com", "reason": "cleared"}),
        &admin,
    )
    .await;
    assert_eq!(
        (status, &released["released_at"]),
        (StatusCode::OK, &json!(2))
    );
    assert_eq!(
        post(&app, "/v1/hooks/PreToolUse", call("s-1"), &[]).await,
        (StatusCode::OK, Value::Null)
    );
    let (status, _) = post(&app, "/v1/admin/sessions/s-1/stop", json!({}), &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reviews_and_service_keys_go_through_the_admin_api() {
    let generator = Arc::new(Generator::default());
    let app = app(generator.clone(), |config| {
        config.admin_token = Some(ADMIN.into())
    });
    let admin = bearer(ADMIN);
    let admin = [("authorization", admin.as_str())];
    let (status, review) = post(
        &app,
        "/v1/admin/reviews",
        json!({"session_id": "s", "seq": 7, "status": "issue", "note": "copied .env",
               "actor": "sec@example.com"}),
        &admin,
    )
    .await;
    assert_eq!(
        (status, &review["status"]),
        (StatusCode::CREATED, &json!("issue"))
    );
    let (status, _) = post(
        &app,
        "/v1/admin/reviews",
        json!({"session_id": "s", "seq": 7, "status": "maybe"}),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        &app,
        "/v1/admin/reviews",
        json!({"session_id": "s", "seq": 7, "status": "no_issue", "note": "x".repeat(10_001)}),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, issued) = post(
        &app,
        "/v1/admin/users/CI-Deploy/keys",
        json!({"kind": "service", "actor": "sec@example.com"}),
        &admin,
    )
    .await;
    assert_eq!(
        (status, &issued["user"]),
        (StatusCode::CREATED, &json!("ci-deploy"))
    );
    let sent = generator.inventory.lock().unwrap().last().cloned().unwrap();
    assert_eq!(sent.2.unwrap()["kind"], "service");
    // A person's key needs an email.
    let (status, _) = post(&app, "/v1/admin/users/ci-deploy/keys", json!({}), &admin).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn stop_checks_are_cached_per_session() {
    let generator = Arc::new(Generator::default());
    let app = app(generator.clone(), |config| {
        config.key_cache = Duration::from_secs(3_600);
    });
    for tool in ["t1", "t2", "t3"] {
        let mut event = call("s-cache");
        event["tool_use_id"] = json!(tool);
        post(&app, "/v1/hooks/PreToolUse", event, &[]).await;
    }
    assert_eq!(*generator.flag_lookups.lock().unwrap(), 1);
}
