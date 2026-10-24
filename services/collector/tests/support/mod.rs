//! Replays `fixtures/session_scenario.json` through a [`Normalizer`] and returns every emitted
//! event serialized exactly as the Collector sends it to the Generator.

use serde_json::{Value, json};
use withhuman_collector::{NormalizedEvent, Normalizer, TrustedHookContext};
use withhuman_contracts::{decisions::EnforcementMode, events::SidePending};

/// Output of the scenario on the in-process Collector before shared state stores existed, plus
/// the `session_sequence` field added since.
#[allow(dead_code)]
pub const GOLDEN_SESSION_ID: &str = "golden-session";
#[allow(dead_code)]
pub const GOLDEN: &str = include_str!("../fixtures/session_scenario.golden.jsonl");

/// Hooks covering how events join session-wide sequences and carry the stated intent.
#[allow(dead_code)]
pub const SEQUENCE_SCENARIO: &str = include_str!("../fixtures/sequence_scenario.json");

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
            "InstructionsLoaded" => {
                normalizer
                    .instructions_loaded(&ctx, from(request), observed_at)
                    .await
            }
            "ConfigChange" => {
                normalizer
                    .config_change(&ctx, from(request), observed_at)
                    .await
            }
            "FileChanged" => {
                normalizer
                    .file_changed(&ctx, from(request), observed_at)
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
                match normalizer
                    .message_display(&ctx, from(request), observed_at)
                    .await
                    .unwrap()
                {
                    Some(event) => Ok(event),
                    None => continue,
                }
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
        NormalizedEvent::InstructionsLoaded(value) => serde_json::to_string(value),
        NormalizedEvent::ConfigChange(value) => serde_json::to_string(value),
        NormalizedEvent::FileChanged(value) => serde_json::to_string(value),
        NormalizedEvent::MessageDisplay(value) => serde_json::to_string(value),
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
