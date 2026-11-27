//! A Call the engine could not judge gets the failure policy, a deny by default, on the personal
//! engine as on the enterprise one: the personal engine's shadow observes judged Calls only.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_collector::{
    CollectorConfig, CollectorService, GeneratorError, GeneratorTransport, NormalizedEvent,
    app_with_transport,
};
use withhuman_common::profile::Profile;
use withhuman_contracts::events::{EnforcementMode, EventResponse};

struct FailedGenerator;

#[async_trait]
impl GeneratorTransport for FailedGenerator {
    async fn send(&self, _: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        Err(GeneratorError::Unavailable("test outage".to_owned()))
    }
}

async fn pre_tool_use(config: CollectorConfig) -> Value {
    let router = app_with_transport(CollectorService::new(config, Arc::new(FailedGenerator)));
    let body = json!({"session_id": "s", "tool_name": "Bash",
                      "tool_input": {"command": "ls"}, "tool_use_id": "t1"});
    let response = router
        .oneshot(
            Request::post("/v1/hooks/PreToolUse")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn a_call_the_engine_could_not_judge_is_denied_on_the_personal_engine_too() {
    let personal = CollectorConfig {
        profile: Profile::Personal,
        enforcement_mode: EnforcementMode::Shadow,
        intent_capture: false,
        ..CollectorConfig::default()
    };
    let denied = pre_tool_use(personal).await;
    assert_eq!(denied["hookSpecificOutput"]["permissionDecision"], "deny");

    // Enterprise shadow observes as before.
    let shadow = CollectorConfig {
        enforcement_mode: EnforcementMode::Shadow,
        intent_capture: false,
        ..CollectorConfig::default()
    };
    assert_eq!(pre_tool_use(shadow).await, Value::Null);

    let enterprise = CollectorConfig {
        intent_capture: false,
        ..CollectorConfig::default()
    };
    let denied = pre_tool_use(enterprise).await;
    assert_eq!(denied["hookSpecificOutput"]["permissionDecision"], "deny");
}
