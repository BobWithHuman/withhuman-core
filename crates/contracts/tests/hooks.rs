use serde_json::json;
use withhuman_contracts::hooks::{
    HookEventName, HookSpecificResponse, MessageDisplayOutput, PermissionDecision,
    PostToolUseRequest, PreToolUseOutput, PreToolUseRequest, SessionStartOutput,
    UserPromptSubmitOutput,
};

#[test]
fn deserializes_pre_tool_use_with_additive_fields() {
    let request: PreToolUseRequest = serde_json::from_value(json!({
        "session_id": "8e789b84",
        "cwd": "/app",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "npm install" },
        "tool_use_id": "toolu_01",
        "permission_mode": "default"
    }))
    .expect("the final-spec request should deserialize");

    assert_eq!(request.hook_event_name, Some(HookEventName::PreToolUse));
    assert_eq!(request.tool_input["command"], "npm install");
}

#[test]
fn rejects_pre_tool_use_without_required_tool_id() {
    let error = serde_json::from_value::<PreToolUseRequest>(json!({
        "session_id": "8e789b84",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "npm install" }
    }))
    .expect_err("tool_use_id is required");

    assert!(error.to_string().contains("tool_use_id"));
}

#[test]
fn accepts_nullable_post_tool_input() {
    let request: PostToolUseRequest = serde_json::from_value(json!({
        "session_id": "8e789b84",
        "tool_name": "Read",
        "tool_response": "done",
        "tool_use_id": "toolu_01"
    }))
    .expect("nullable fields and ignored event name should be optional");

    assert_eq!(request.tool_input, None);
    assert_eq!(request.hook_event_name, None);
}

#[test]
fn serializes_deny_response_with_claude_wire_names() {
    let response = HookSpecificResponse {
        hook_specific_output: PreToolUseOutput {
            hook_event_name: HookEventName::PreToolUse,
            permission_decision: PermissionDecision::Deny,
            permission_decision_reason: "Blocked by WithHuman.".into(),
        },
    };

    assert_eq!(
        serde_json::to_value(response).expect("response should serialize"),
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Blocked by WithHuman."
            }
        })
    );
}

#[test]
fn serializes_session_start_watch_paths() {
    let response = HookSpecificResponse {
        hook_specific_output: SessionStartOutput {
            hook_event_name: HookEventName::SessionStart,
            watch_paths: vec!["/app/CLAUDE.md".into()],
        },
    };

    assert_eq!(
        serde_json::to_value(response).expect("response should serialize"),
        json!({
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "watchPaths": ["/app/CLAUDE.md"]
            }
        })
    );
}

#[test]
fn serializes_prompt_context_and_display_content_with_claude_wire_names() {
    let context = HookSpecificResponse {
        hook_specific_output: UserPromptSubmitOutput {
            hook_event_name: HookEventName::UserPromptSubmit,
            additional_context: "context".into(),
        },
    };
    let display = HookSpecificResponse {
        hook_specific_output: MessageDisplayOutput {
            hook_event_name: HookEventName::MessageDisplay,
            display_content: "shown".into(),
        },
    };

    assert_eq!(
        serde_json::to_value(context).expect("response should serialize"),
        json!({"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"context"}})
    );
    assert_eq!(
        serde_json::to_value(display).expect("response should serialize"),
        json!({"hookSpecificOutput":{"hookEventName":"MessageDisplay","displayContent":"shown"}})
    );
}
