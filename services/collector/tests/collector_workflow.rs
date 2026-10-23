use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tokio::sync::Notify;
use tower::ServiceExt as _;
use withhuman_collector::{
    CollectorConfig, CollectorService, FailurePolicy, GeneratorError, GeneratorTransport,
    NormalizedEvent, ReviewPolicy, StoredVerdict, VerdictStore, app_with_transport,
};
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionResponse},
    events::EventResponse,
};

#[tokio::test]
async fn waits_for_generator_and_forwards_trusted_normalized_context() {
    let generator = Arc::new(GatedGenerator::default());
    let app = test_app(CollectorConfig::default(), generator.clone());
    let task = tokio::spawn(app.oneshot(json_request(
        "/v1/hooks/UserPromptSubmit",
        json!({"session_id":"s1","prompt":"inspect","prompt_id":"p1","cwd":"/repo"}),
    )));

    generator.entered.notified().await;
    assert!(
        !task.is_finished(),
        "Hook response preceded Generator acknowledgement"
    );
    generator.release.notify_one();
    let response = task.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let events = generator.events.lock().unwrap();
    let NormalizedEvent::UserPromptSubmit(event) = &events[0] else {
        panic!("expected UserPromptSubmit");
    };
    assert_eq!(event.order, 1);
    assert_eq!(event.client_id.as_deref(), Some("team-a/laptop-3"));
    assert_eq!(event.meta.repo.as_deref(), Some("github.com/acme/service"));
    assert_eq!(event.meta.cwd.as_deref(), Some("/repo"));
    assert_eq!(event.meta.prompt_id.as_deref(), Some("p1"));
}

#[tokio::test]
async fn aggregates_messages_without_calling_generator_for_partial_fragments() {
    let generator = Arc::new(RecordingGenerator::allow());
    let app = test_app(CollectorConfig::default(), generator.clone());

    let partial = app
        .clone()
        .oneshot(json_request(
            "/v1/hooks/MessageDisplay",
            json!({"session_id":"s1","message_id":"m1","delta":"hello ","final":false}),
        ))
        .await
        .unwrap();
    assert_eq!(partial.status(), StatusCode::OK);
    assert!(generator.events.lock().unwrap().is_empty());

    let completed = app.oneshot(json_request(
        "/v1/hooks/MessageDisplay",
        json!({"session_id":"s1","message_id":"m1","delta":"world","final":true,"turn_id":"turn-1"}),
    )).await.unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::MessageDisplay(event) = &events[0] else {
        panic!("expected MessageDisplay");
    };
    assert_eq!(event.payload.text, "hello world");
    assert_eq!(event.meta.turn_id.as_deref(), Some("turn-1"));
}

#[tokio::test]
async fn maps_allow_deny_and_review_to_hook_responses() {
    let allow = pre_tool_response(CollectorConfig::default(), Decision::Allow, "").await;
    assert_eq!(allow.0, StatusCode::OK);
    assert!(allow.1.is_null());

    let deny = pre_tool_response(
        CollectorConfig::default(),
        Decision::Deny,
        "blocked by policy",
    )
    .await;
    assert_eq!(deny.0, StatusCode::OK);
    assert_eq!(deny.1["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        deny.1["hookSpecificOutput"]["permissionDecisionReason"],
        "blocked by policy"
    );

    let ask_config = CollectorConfig {
        review_policy: ReviewPolicy::Ask,
        ..Default::default()
    };
    let review = pre_tool_response(ask_config, Decision::Review, "human review required").await;
    assert_eq!(review.1["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[tokio::test]
async fn applies_pre_tool_failure_and_timeout_policies() {
    let open_config = CollectorConfig {
        decision_budget: Duration::from_millis(5),
        failure_policy: FailurePolicy::Open,
        ..Default::default()
    };
    let response = test_app(open_config, Arc::new(NeverGenerator))
        .oneshot(pre_tool_request("Read", "tool-open"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let closed_config = CollectorConfig {
        failure_policy: FailurePolicy::Closed,
        ..Default::default()
    };
    let response = test_app(closed_config, Arc::new(FailingGenerator))
        .oneshot(pre_tool_request("Read", "tool-closed"))
        .await
        .unwrap();
    let (_, body) = response_json(response).await;
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[tokio::test]
async fn retains_mcp_verdict_but_leaves_enforcement_to_ext_authz() {
    let generator = Arc::new(RecordingGenerator::decision(Decision::Deny, "MCP denied"));
    let service = CollectorService::new(CollectorConfig::default(), generator);
    let verdicts = service.verdicts.clone();
    let response = app_with_transport(service)
        .oneshot(pre_tool_request(
            "mcp__filesystem__write_file",
            "mcp-call-1",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        verdicts.get("mcp-call-1").unwrap().decision.decision,
        Decision::Deny
    );
}

#[test]
fn evicts_the_oldest_verdict_at_capacity() {
    let verdicts = VerdictStore::new(2);
    verdicts.insert("one".to_owned(), stored(Decision::Allow, ""));
    verdicts.insert("two".to_owned(), stored(Decision::Deny, "two"));
    verdicts.insert("three".to_owned(), stored(Decision::Review, "three"));

    assert!(verdicts.get("one").is_none());
    assert!(verdicts.get("two").is_some());
    assert!(verdicts.get("three").is_some());
}

async fn pre_tool_response(
    config: CollectorConfig,
    verdict: Decision,
    reason: &str,
) -> (StatusCode, Value) {
    let app = test_app(
        config,
        Arc::new(RecordingGenerator::decision(verdict, reason)),
    );
    response_json(
        app.oneshot(pre_tool_request("Read", "tool-1"))
            .await
            .unwrap(),
    )
    .await
}

fn test_app(config: CollectorConfig, generator: Arc<dyn GeneratorTransport>) -> axum::Router {
    app_with_transport(CollectorService::new(config, generator))
}

fn pre_tool_request(tool_name: &str, tool_use_id: &str) -> Request<Body> {
    json_request(
        "/v1/hooks/PreToolUse",
        json!({
            "session_id":"s1", "tool_name":tool_name, "tool_input":{}, "tool_use_id":tool_use_id
        }),
    )
}

fn json_request(uri: &str, body: Value) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-withhuman-client", "team-a/laptop-3")
        .header("x-withhuman-repo", "github.com/acme/service")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

fn event_response(decision_response: Option<DecisionResponse>) -> EventResponse {
    EventResponse {
        nodes: Vec::new(),
        pieces: None,
        version: 1,
        decision_response,
    }
}

fn decision(verdict: Decision, reason: &str) -> DecisionResponse {
    DecisionResponse {
        decision: verdict,
        reason: reason.to_owned(),
        rule: "test-rule".to_owned(),
        start: CausalStart::User,
        written: true,
        jev: None,
        causal: None,
    }
}

fn stored(verdict: Decision, reason: &str) -> StoredVerdict {
    StoredVerdict {
        decision: decision(verdict, reason),
        tool_name: "mcp__server__tool".to_owned(),
        arguments: json!({}),
    }
}

struct RecordingGenerator {
    events: Mutex<Vec<NormalizedEvent>>,
    response: EventResponse,
}

impl RecordingGenerator {
    fn allow() -> Self {
        Self::decision(Decision::Allow, "")
    }
    fn decision(verdict: Decision, reason: &str) -> Self {
        Self {
            events: Mutex::default(),
            response: event_response(Some(decision(verdict, reason))),
        }
    }
}

#[async_trait]
impl GeneratorTransport for RecordingGenerator {
    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        self.events.lock().unwrap().push(event);
        Ok(self.response.clone())
    }
}

#[derive(Default)]
struct GatedGenerator {
    events: Mutex<Vec<NormalizedEvent>>,
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl GeneratorTransport for GatedGenerator {
    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        self.events.lock().unwrap().push(event);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(event_response(None))
    }
}

struct FailingGenerator;

#[async_trait]
impl GeneratorTransport for FailingGenerator {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        Err(GeneratorError::Unavailable("offline".to_owned()))
    }
}

struct NeverGenerator;

#[async_trait]
impl GeneratorTransport for NeverGenerator {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        std::future::pending().await
    }
}
