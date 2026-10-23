use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt as _;
use withhuman_collector::{
    CollectorConfig, CollectorService, GeneratorError, GeneratorTransport, NormalizedEvent,
    app_with_transport,
};
use withhuman_contracts::events::EventResponse;

const HOOK_REQUESTS: [(&str, &str); 13] = [
    ("SessionStart", r#"{"session_id":"s","cwd":"/repo"}"#),
    ("UserPromptSubmit", r#"{"session_id":"s","prompt":"hello"}"#),
    (
        "PreToolUse",
        r#"{"session_id":"s","tool_name":"Read","tool_input":{},"tool_use_id":"t1"}"#,
    ),
    (
        "PostToolUse",
        r#"{"session_id":"s","tool_name":"Read","tool_response":{},"tool_use_id":"t1"}"#,
    ),
    (
        "PostToolUseFailure",
        r#"{"session_id":"s","tool_name":"Read","error":"failed","tool_use_id":"t2"}"#,
    ),
    ("SubagentStart", r#"{"session_id":"s","agent_id":"a1"}"#),
    ("SubagentStop", r#"{"session_id":"s","agent_id":"a1"}"#),
    (
        "InstructionsLoaded",
        r#"{"session_id":"s","file_path":"/repo/AGENTS.md"}"#,
    ),
    (
        "ConfigChange",
        r#"{"session_id":"s","file_path":"/repo/config.json"}"#,
    ),
    (
        "FileChanged",
        r#"{"session_id":"s","file_path":"/repo/src/lib.rs"}"#,
    ),
    (
        "MessageDisplay",
        r#"{"session_id":"s","message_id":"m1","delta":"done","final":true}"#,
    ),
    ("PostToolBatch", r#"{"session_id":"s"}"#),
    ("ToolDescriptions", r#"{"session_id":"s","tools":[]}"#),
];

#[tokio::test]
async fn exposes_every_versioned_hook_route() {
    for (event, body) in HOOK_REQUESTS {
        let response = test_app()
            .oneshot(json_request(&format!("/v1/hooks/{event}"), body))
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK, "route {event}");
    }
}

#[tokio::test]
async fn rejects_missing_json_content_type() {
    let response = test_app()
        .oneshot(
            Request::post("/v1/hooks/PreToolUse")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn maps_malformed_json_to_bad_request() {
    let response = test_app()
        .oneshot(json_request("/v1/hooks/PreToolUse", "{"))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reports_collector_health() {
    let response = test_app()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("health body should be readable");
    let json: Value = serde_json::from_slice(&body).expect("health body should be JSON");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "collector");
}

#[tokio::test]
async fn serves_collector_openapi_and_swagger_ui() {
    let specification = test_app()
        .clone()
        .oneshot(
            Request::get("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(specification.into_body(), 1_000_000)
        .await
        .unwrap();
    let document: Value = serde_json::from_slice(&body).unwrap();
    let swagger = test_app()
        .oneshot(Request::get("/swagger-ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(document["openapi"], "3.1.0");
    assert!(document["paths"]["/v1/hooks/PreToolUse"]["post"].is_object());
    assert_eq!(swagger.status(), StatusCode::OK);
}

fn json_request(uri: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-withhuman-client", "team-a/laptop-3")
        .header("x-withhuman-repo", "github.com/org/repo")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn test_app() -> axum::Router {
    app_with_transport(CollectorService::new(
        CollectorConfig::default(),
        Arc::new(AcceptingGenerator),
    ))
}

struct AcceptingGenerator;

#[async_trait]
impl GeneratorTransport for AcceptingGenerator {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        Ok(EventResponse {
            nodes: Vec::new(),
            pieces: None,
            version: 1,
            decision_response: None,
        })
    }
}
