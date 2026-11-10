//! Keys on the Hooks (the user they name, the kill switch, `WITHHUMAN_REQUIRE_KEY`), the
//! inventory API and the session facts the Hooks now carry.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
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
    NormalizedEvent, app_with_transport, keys,
};
use withhuman_common::chunking::sha256;
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionResponse},
    events::EventResponse,
    inventory::{KeyDenial, KeyStatus, VerifyKeyRequest, VerifyKeyResponse},
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
            ["clients"] if method == reqwest::Method::POST => {
                let body = body.unwrap();
                json!({"client_id": body["client_id"], "user": body["user"], "projects": []})
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
    let open = app(generator.clone(), |config| config.require_key = true);
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
        "project": "/Users/ana/app"});
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
        assert!(sent["registered_at"].as_u64().unwrap() > 0);
    }
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
