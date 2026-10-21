use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_contracts::events::EventResponse;
use withhuman_generator::{
    GeneratorEvent, GeneratorService, GraphRepository, RepositoryError, app,
};

#[tokio::test]
async fn exposes_every_versioned_event_route() {
    let repository = Arc::new(RecordingRepository::default());
    let app = app(GeneratorService::from_shared(repository.clone()));

    for (name, body) in event_requests() {
        let response = app
            .clone()
            .oneshot(json_request(&format!("/v1/events/{name}"), body))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::OK, "route {name}");
    }

    let events = repository.events.lock().unwrap();
    assert_eq!(events.len(), 13);
    assert_eq!(events[0].event_name(), "SessionStart");
    assert_eq!(events[0].session_id(), "session-1");
    assert_eq!(events[0].order(), 1);
}

#[tokio::test]
async fn rejects_missing_content_type_and_invalid_contracts() {
    let app = app(GeneratorService::new(RecordingRepository::default()));
    let missing_content_type = app
        .clone()
        .oneshot(
            Request::post("/v1/events/SessionStart")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let invalid_contract = app
        .oneshot(json_request("/v1/events/SessionStart", json!({})))
        .await
        .unwrap();

    assert_eq!(
        missing_content_type.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(invalid_contract.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn health_reflects_neo4j_readiness() {
    let healthy = app(GeneratorService::new(RecordingRepository::default()))
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let unhealthy = app(GeneratorService::new(UnavailableRepository))
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = to_bytes(unhealthy.into_body(), 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(healthy.status(), StatusCode::OK);
    assert_eq!(json["error"], "neo4j_unavailable");
}

fn event_requests() -> Vec<(&'static str, Value)> {
    vec![
        ("SessionStart", envelope(1, json!({"source":"startup"}))),
        (
            "UserPromptSubmit",
            envelope(2, json!({"prompt":"hello","kind":"user","user_docs":[]})),
        ),
        (
            "PreToolUse",
            with_fields(
                envelope(3, json!({"tool_name":"Read","tool_input":{}})),
                json!({"mode":"enforce","deadline_ms":4000}),
            ),
        ),
        (
            "PostToolUse",
            envelope(
                4,
                json!({"tool_name":"Read","tool_input":{},"tool_response":{}}),
            ),
        ),
        (
            "PostToolUseFailure",
            envelope(
                5,
                json!({"tool_name":"Read","tool_input":{},"error":"failed"}),
            ),
        ),
        (
            "SubagentStart",
            envelope(6, json!({"agent_id":"agent-1","agent_type":"worker"})),
        ),
        ("SubagentStop", envelope(7, json!({"agent_id":"agent-1"}))),
        (
            "InstructionsLoaded",
            envelope(8, json!({"file_path":"/repo/AGENTS.md"})),
        ),
        (
            "ConfigChange",
            envelope(9, json!({"file_path":"/repo/config.json"})),
        ),
        (
            "FileChanged",
            envelope(10, json!({"file_path":"/repo/src/lib.rs"})),
        ),
        (
            "MessageDisplay",
            envelope(11, json!({"message_id":"message-1","text":"done"})),
        ),
        ("PostToolBatch", envelope(12, json!({}))),
        ("ToolDescriptions", envelope(13, json!({"tools":[]}))),
    ]
}

fn envelope(order: u64, payload: Value) -> Value {
    json!({
        "session_id":"session-1",
        "order":order,
        "observed_at":1000 + order,
        "client_id":"client-1",
        "meta":{},
        "payload":payload
    })
}

fn with_fields(mut value: Value, fields: Value) -> Value {
    value
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    value
}

fn json_request(uri: &str, body: Value) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[derive(Default)]
struct RecordingRepository {
    events: Mutex<Vec<GeneratorEvent>>,
}

#[async_trait]
impl GraphRepository for RecordingRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn commit(&self, event: GeneratorEvent) -> Result<EventResponse, RepositoryError> {
        self.events.lock().unwrap().push(event);
        Ok(EventResponse {
            nodes: Vec::new(),
            paragraphs: None,
            version: 1,
            decision_response: None,
        })
    }
}

struct UnavailableRepository;

#[async_trait]
impl GraphRepository for UnavailableRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        Err(RepositoryError::Unavailable("offline".to_owned()))
    }

    async fn commit(&self, _event: GeneratorEvent) -> Result<EventResponse, RepositoryError> {
        unreachable!()
    }
}
