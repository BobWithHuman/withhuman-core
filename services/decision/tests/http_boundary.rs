use std::{
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_contracts::decisions::{CausalStart, Decision, DecisionRequest, DecisionResponse};
use withhuman_decision::{
    DecisionProvider, DecisionRepository, DecisionService, MockDecisionProvider, ProviderError,
    RepositoryError, app,
};

#[tokio::test]
async fn returns_and_persists_each_configured_mock_decision() {
    for decision in [Decision::Allow, Decision::Deny, Decision::Review] {
        let repository = Arc::new(RecordingRepository::default());
        let router = app(DecisionService::from_shared(
            repository.clone(),
            Arc::new(MockDecisionProvider::fixed(decision)),
        ));
        let response = router
            .oneshot(json_request(decision_request(Some(100))))
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: DecisionResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.decision, decision);
        assert!(body.written);
        assert_eq!(repository.persisted.lock().unwrap().len(), 1);
        match decision {
            Decision::Allow => assert!(body.reason.is_empty()),
            Decision::Deny | Decision::Review => assert!(!body.reason.is_empty()),
        }
    }
}

#[tokio::test]
async fn reports_missing_graph_and_unavailable_neo4j() {
    let missing = app(DecisionService::new(
        FailingRepository(RepositoryError::NotFound),
        MockDecisionProvider::fixed(Decision::Allow),
    ))
    .oneshot(json_request(decision_request(Some(100))))
    .await
    .unwrap();
    let unavailable = app(DecisionService::new(
        FailingRepository(RepositoryError::Unavailable("offline".into())),
        MockDecisionProvider::fixed(Decision::Allow),
    ))
    .oneshot(json_request(decision_request(Some(100))))
    .await
    .unwrap();

    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn returns_written_false_when_verdict_persistence_fails() {
    let response = app(DecisionService::new(
        PersistFailingRepository,
        MockDecisionProvider::fixed(Decision::Deny),
    ))
    .oneshot(json_request(decision_request(Some(100))))
    .await
    .unwrap();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: DecisionResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(body.decision, Decision::Deny);
    assert!(!body.written);
}

#[tokio::test]
async fn enforces_the_remaining_decision_deadline() {
    let response = app(DecisionService::new(
        RecordingRepository::default(),
        DelayedProvider,
    ))
    .oneshot(json_request(decision_request(Some(1))))
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn validates_json_and_reports_health() {
    let router = app(DecisionService::new(
        RecordingRepository::default(),
        MockDecisionProvider::fixed(Decision::Allow),
    ));
    let health = router
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let invalid = router
        .oneshot(
            Request::post("/v1/decide")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn production_runtime_rejects_the_mock_provider() {
    let output = Command::new(env!("CARGO_BIN_EXE_withhuman-decision"))
        .env("WITHHUMAN_ENV", "production")
        .env("DECISION_PROVIDER", "mock")
        .env("NEO4J_PASSWORD", "unused")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("mock decision provider is forbidden in production")
    );
}

fn decision_request(deadline_ms: Option<u64>) -> Value {
    json!({
        "session_id":"session-1",
        "call_seq":23,
        "graph_version":57,
        "mode":"enforce",
        "deadline_ms":deadline_ms
    })
}

fn json_request(body: Value) -> Request<Body> {
    Request::post("/v1/decide")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[derive(Default)]
struct RecordingRepository {
    persisted: Mutex<Vec<(DecisionRequest, DecisionResponse)>>,
}

#[async_trait]
impl DecisionRepository for RecordingRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        Ok(())
    }
    async fn verify_graph(&self, _request: &DecisionRequest) -> Result<(), RepositoryError> {
        Ok(())
    }
    async fn persist(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), RepositoryError> {
        self.persisted
            .lock()
            .unwrap()
            .push((request.clone(), response.clone()));
        Ok(())
    }
}

struct FailingRepository(RepositoryError);

#[async_trait]
impl DecisionRepository for FailingRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        Err(self.0.clone())
    }
    async fn verify_graph(&self, _request: &DecisionRequest) -> Result<(), RepositoryError> {
        Err(self.0.clone())
    }
    async fn persist(
        &self,
        _request: &DecisionRequest,
        _response: &DecisionResponse,
    ) -> Result<(), RepositoryError> {
        unreachable!()
    }
}

struct PersistFailingRepository;

#[async_trait]
impl DecisionRepository for PersistFailingRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        Ok(())
    }
    async fn verify_graph(&self, _request: &DecisionRequest) -> Result<(), RepositoryError> {
        Ok(())
    }
    async fn persist(
        &self,
        _request: &DecisionRequest,
        _response: &DecisionResponse,
    ) -> Result<(), RepositoryError> {
        Err(RepositoryError::Unavailable("offline".into()))
    }
}

struct DelayedProvider;

#[async_trait]
impl DecisionProvider for DelayedProvider {
    async fn decide(&self, _request: &DecisionRequest) -> Result<DecisionResponse, ProviderError> {
        tokio::time::sleep(Duration::from_millis(20)).await;
        Ok(DecisionResponse {
            decision: Decision::Allow,
            reason: String::new(),
            rule: "delayed".into(),
            start: CausalStart::Unresolved,
            written: false,
            jev: None,
        })
    }
}
