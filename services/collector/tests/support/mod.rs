//! Replays `fixtures/session_scenario.json` through a [`Normalizer`] and returns every emitted
//! event serialized exactly as the Collector sends it to the Generator.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde_json::{Value, json};
use withhuman_collector::{
    GeneratorError, GeneratorTransport, NormalizedEvent, Normalizer, TrustedHookContext,
};
use withhuman_contracts::{
    decisions::EnforcementMode,
    events::{EventResponse, SessionCursor, SidePending, SubGraphCursor},
};

/// Output of the scenario on the in-process Collector before shared state stores existed, plus
/// the `subgraph` field added since.
#[allow(dead_code)]
pub const GOLDEN_SESSION_ID: &str = "golden-session";
#[allow(dead_code)]
pub const GOLDEN: &str = include_str!("../fixtures/session_scenario.golden.jsonl");

/// Hooks covering how events join session-wide sequences and carry the stated intent.
#[allow(dead_code)]
pub const SUBGRAPH_SCENARIO: &str = include_str!("../fixtures/subgraph_scenario.json");

/// Hooks of a session the Collector lost, resumed from [`resume_cursor`]. The first fragment
/// arrives before the session is seeded again.
#[allow(dead_code)]
pub const RESUME_SCENARIO: &str = include_str!("../fixtures/resume_scenario.json");

/// What the Generator committed for [`RESUME_SCENARIO`]: SubGraph 3 is open with its message,
/// and call `t1` still waits for its result.
#[allow(dead_code)]
pub fn resume_cursor() -> SessionCursor {
    SessionCursor {
        last_order: 20,
        last_subgraph: Some(3),
        subgraphs: SubGraphCursor {
            current: Some(3),
            open: true,
            has_message: true,
            has_call: true,
            zero_has_request: true,
            request: Some(2),
            calls: BTreeMap::from([("t1".to_owned(), 3)]),
        },
        intent: Some("이전 의도".to_owned()),
        ..SessionCursor::default()
    }
}

/// A Generator that only reports what it committed.
#[allow(dead_code)]
pub struct Committed(pub SessionCursor);

#[async_trait]
impl GeneratorTransport for Committed {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        unreachable!("normalization never sends events")
    }

    async fn session_cursor(&self, _session_id: &str) -> Result<SessionCursor, GeneratorError> {
        Ok(self.0.clone())
    }
}

pub async fn run_scenario(normalizer: Normalizer, session_id: &str) -> Vec<String> {
    run_steps(
        normalizer,
        session_id,
        include_str!("../fixtures/session_scenario.json"),
    )
    .await
}

/// Replays `[hook, request]` steps (JSON) and returns the serialized emitted events.
pub async fn run_steps(normalizer: Normalizer, session_id: &str, steps: &str) -> Vec<String> {
    let steps: Vec<(String, Value)> = serde_json::from_str(steps).unwrap();
    let mut emitted = Vec::new();
    for (index, (hook, mut request)) in steps.into_iter().enumerate() {
        let observed_at = 1_000 + u64::try_from(index).unwrap();
        if hook == "SidePending" {
            let pending: SidePending = serde_json::from_value(request).unwrap();
            normalizer
                .sessions()
                .set_side_pending(session_id, pending)
                .await
                .unwrap();
            continue;
        }
        request["session_id"] = json!(session_id);
        let ctx = context();
        let event = match hook.as_str() {
            "SessionStart" => {
                normalizer
                    .session_start(&ctx, from(request), observed_at)
                    .await
            }
            "UserPromptSubmit" => {
                normalizer
                    .user_prompt_submit(&ctx, from(request), observed_at)
                    .await
            }
            "PreToolUse" => {
                normalizer
                    .pre_tool_use(
                        &ctx,
                        from(request),
                        observed_at,
                        EnforcementMode::Enforce,
                        Some(4_200),
                    )
                    .await
            }
            "PostToolUse" => {
                normalizer
                    .post_tool_use(&ctx, from(request), observed_at)
                    .await
            }
            "PostToolUseFailure" => {
                normalizer
                    .post_tool_use_failure(&ctx, from(request), observed_at)
                    .await
            }
            "SubagentStart" => {
                normalizer
                    .subagent_start(&ctx, from(request), observed_at)
                    .await
            }
            "SubagentStop" => {
                normalizer
                    .subagent_stop(&ctx, from(request), observed_at)
                    .await
            }
            "ConfigChange" => {
                normalizer
                    .config_change(&ctx, from(request), observed_at)
                    .await
            }
            "PostToolBatch" => {
                normalizer
                    .post_tool_batch(&ctx, from(request), observed_at)
                    .await
            }
            "ToolDescriptions" => {
                normalizer
                    .tool_descriptions(&ctx, from(request), observed_at)
                    .await
            }
            "MessageDisplay" => {
                let events = normalizer
                    .message_display(&ctx, from(request), observed_at)
                    .await
                    .unwrap();
                emitted.extend(events.iter().map(serialize));
                continue;
            }
            other => panic!("unknown hook {other}"),
        };
        emitted.push(serialize(&event.unwrap()));
    }
    emitted
}

pub fn from<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

pub fn serialize(event: &NormalizedEvent) -> String {
    match event {
        NormalizedEvent::SessionStart(value) => serde_json::to_string(value),
        NormalizedEvent::UserPromptSubmit(value) => serde_json::to_string(value),
        NormalizedEvent::PreToolUse(value) => serde_json::to_string(value),
        NormalizedEvent::PostToolUse(value) => serde_json::to_string(value),
        NormalizedEvent::PostToolUseFailure(value) => serde_json::to_string(value),
        NormalizedEvent::SubagentStart(value) => serde_json::to_string(value),
        NormalizedEvent::SubagentStop(value) => serde_json::to_string(value),
        NormalizedEvent::ConfigChange(value) => serde_json::to_string(value),
        NormalizedEvent::MessageDisplay(value) => serde_json::to_string(value),
        NormalizedEvent::Intent(value) => serde_json::to_string(value),
        NormalizedEvent::PostToolBatch(value) => serde_json::to_string(value),
        NormalizedEvent::ToolDescriptions(value) => serde_json::to_string(value),
    }
    .unwrap()
}

pub fn context() -> TrustedHookContext {
    TrustedHookContext {
        client_id: Some("team-a/laptop-3".to_owned()),
        repository: Some("github.com/acme/service".to_owned()),
    }
}
