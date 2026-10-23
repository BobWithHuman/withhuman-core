use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionRequest, DecisionResponse, JevActivity},
    events::{
        CreatedNode, EventResponse, PieceClassificationRequest, PieceClassificationResponse,
        RequestContinuationRequest, RequestContinuationResponse,
    },
};
use withhuman_generator::{
    DecisionClient, DecisionError, GeneratorEvent, GeneratorService, GraphRepository,
    RepositoryError, app,
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

#[tokio::test]
async fn serves_generator_openapi_and_swagger_ui() {
    let router = app(GeneratorService::new(RecordingRepository::default()));
    let specification = router
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
    let swagger = router
        .oneshot(Request::get("/swagger-ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(document["openapi"], "3.1.0");
    assert!(document["paths"]["/v1/events/PreToolUse"]["post"].is_object());
    assert!(document["paths"]["/v1/sessions/{session_id}/pieces/{hash}"]["patch"].is_object());
    assert_eq!(swagger.status(), StatusCode::OK);
}

#[tokio::test]
async fn pre_tool_use_commits_before_requesting_a_decision() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let service = GeneratorService::from_shared_with_decision(
        Arc::new(CallRepository),
        Arc::new(RecordingDecisionClient {
            requests: requests.clone(),
            fail: false,
        }),
    );
    let response = app(service)
        .oneshot(json_request(
            "/v1/events/PreToolUse",
            with_fields(
                envelope(3, json!({"tool_name":"Read","tool_input":{}})),
                json!({"mode":"enforce","deadline_ms":4000}),
            ),
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: EventResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(body.decision_response.unwrap().decision, Decision::Deny);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].call_seq, 23);
    assert_eq!(requests[0].graph_version, 57);
    assert!(requests[0].deadline_ms.unwrap() <= 4000);
}

#[tokio::test]
async fn record_mode_dispatches_without_returning_the_decision() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let service = GeneratorService::from_shared_with_decision(
        Arc::new(CallRepository),
        Arc::new(RecordingDecisionClient {
            requests: requests.clone(),
            fail: false,
        }),
    );
    let response = app(service)
        .oneshot(json_request(
            "/v1/events/PreToolUse",
            with_fields(
                envelope(3, json!({"tool_name":"Read","tool_input":{}})),
                json!({"mode":"record","deadline_ms":4000}),
            ),
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: EventResponse = serde_json::from_slice(&body).unwrap();
    for _ in 0..10 {
        if !requests.lock().unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert!(body.decision_response.is_none());
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].deadline_ms, None);
}

#[tokio::test]
async fn decision_failure_returns_a_committed_graph_with_no_decision() {
    let service = GeneratorService::from_shared_with_decision(
        Arc::new(CallRepository),
        Arc::new(RecordingDecisionClient {
            requests: Arc::default(),
            fail: true,
        }),
    );
    let response = app(service)
        .oneshot(json_request(
            "/v1/events/PreToolUse",
            with_fields(
                envelope(3, json!({"tool_name":"Read","tool_input":{}})),
                json!({"mode":"shadow","deadline_ms":4000}),
            ),
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: EventResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(body.version, 57);
    assert!(body.decision_response.is_none());
}

#[tokio::test]
async fn exposes_enrichment_patch_routes() {
    let app = app(GeneratorService::new(EnrichmentRepository));
    let piece = app
        .clone()
        .oneshot(patch_request(
            "/v1/sessions/session-1/pieces/hash-1",
            json!({
                "sentences":[{"index":0,"text":"Run it","p":0.92}],
                "jev_ms":180,
                "error":null
            }),
        ))
        .await
        .unwrap();
    let continuation = app
        .oneshot(patch_request(
            "/v1/sessions/session-1/requests/2",
            json!({
                "choice":"o1",
                "probabilities":{"o1":0.8,"none":0.2},
                "jev_ms":150,
                "error":null
            }),
        ))
        .await
        .unwrap();

    assert_eq!(piece.status(), StatusCode::OK);
    assert_eq!(continuation.status(), StatusCode::OK);
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

fn patch_request(uri: &str, body: Value) -> Request<Body> {
    Request::patch(uri)
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
            pieces: None,
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

struct CallRepository;

#[async_trait]
impl GraphRepository for CallRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn commit(&self, _event: GeneratorEvent) -> Result<EventResponse, RepositoryError> {
        Ok(EventResponse {
            nodes: vec![CreatedNode {
                seq: 23,
                node_type: "Call".to_owned(),
            }],
            pieces: None,
            version: 57,
            decision_response: None,
        })
    }
}

struct RecordingDecisionClient {
    requests: Arc<Mutex<Vec<DecisionRequest>>>,
    fail: bool,
}

struct EnrichmentRepository;

#[async_trait]
impl GraphRepository for EnrichmentRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn commit(&self, _event: GeneratorEvent) -> Result<EventResponse, RepositoryError> {
        unreachable!()
    }

    async fn classify_piece(
        &self,
        session_id: &str,
        hash: &str,
        request: PieceClassificationRequest,
    ) -> Result<PieceClassificationResponse, RepositoryError> {
        assert_eq!(session_id, "session-1");
        assert_eq!(hash, "hash-1");
        assert_eq!(request.sentences[0].p, 0.92);
        Ok(PieceClassificationResponse {
            applied: true,
            instructs: Some(0.92),
        })
    }

    async fn continue_request(
        &self,
        session_id: &str,
        order: u64,
        request: RequestContinuationRequest,
    ) -> Result<RequestContinuationResponse, RepositoryError> {
        assert_eq!(session_id, "session-1");
        assert_eq!(order, 2);
        assert_eq!(request.choice.as_deref(), Some("o1"));
        Ok(RequestContinuationResponse {
            applied: true,
            request_seq: Some(31),
        })
    }
}

#[async_trait]
impl DecisionClient for RecordingDecisionClient {
    async fn decide(&self, request: DecisionRequest) -> Result<DecisionResponse, DecisionError> {
        self.requests.lock().unwrap().push(request);
        if self.fail {
            return Err(DecisionError::Unavailable("offline".to_owned()));
        }
        Ok(DecisionResponse {
            decision: Decision::Deny,
            reason: "Blocked by WithHuman.".to_owned(),
            rule: "test".to_owned(),
            start: CausalStart::OtherDoc,
            written: true,
            jev: Some(JevActivity {
                asked: false,
                ms: None,
                reused_from: None,
                error: None,
            }),
            causal: None,
            path: None,
        })
    }
}
