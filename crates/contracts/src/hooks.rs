//! Claude Code Hook HTTP contracts exposed by the Collector.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Headers supplied by the Hook client and authenticated AgentGateway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookHeaders {
    pub repository: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum HookEventName {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    SubagentStart,
    SubagentStop,
    InstructionsLoaded,
    ConfigChange,
    FileChanged,
    MessageDisplay,
    PostToolBatch,
    ToolDescriptions,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SessionStartRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    #[serde(default)]
    pub transcript_path: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UserPromptSubmitRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub prompt: String,
    #[serde(default)]
    pub prompt_id: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PreToolUseRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_use_id: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub prompt_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PostToolUseRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Option<Value>,
    pub tool_response: Value,
    pub tool_use_id: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub prompt_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PostToolUseFailureRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Option<Value>,
    pub error: String,
    pub tool_use_id: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub prompt_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SubagentLifecycleRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub agent_id: String,
    #[serde(default)]
    pub agent_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InstructionsLoadedRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub file_path: String,
    #[serde(default)]
    pub memory_type: Option<String>,
    #[serde(default)]
    pub load_reason: Option<String>,
    #[serde(default)]
    pub trigger_file_path: Option<String>,
    #[serde(default)]
    pub parent_file_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConfigChangeRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub file_path: String,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FileChangedRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub file_path: String,
    #[serde(default)]
    pub event: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MessageDisplayRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub message_id: String,
    pub delta: String,
    #[serde(rename = "final")]
    pub final_: bool,
    #[serde(default)]
    pub turn_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PostToolBatchRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ToolDescription {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ToolDescriptionsRequest {
    pub session_id: String,
    pub tools: Vec<ToolDescription>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionDecision {
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseOutput {
    pub hook_event_name: HookEventName,
    pub permission_decision: PermissionDecision,
    pub permission_decision_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartOutput {
    pub hook_event_name: HookEventName,
    pub watch_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificResponse<T> {
    pub hook_specific_output: T,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn preserves_instruction_relationship_paths() {
        let request: InstructionsLoadedRequest = serde_json::from_value(json!({
            "session_id": "8e789b84",
            "hook_event_name": "InstructionsLoaded",
            "file_path": "/app/.claude/rules/security.md",
            "trigger_file_path": "/app/CLAUDE.md",
            "parent_file_path": "/app/.claude/rules"
        }))
        .expect("instruction relationship paths should deserialize");

        assert_eq!(request.trigger_file_path.as_deref(), Some("/app/CLAUDE.md"));
        assert_eq!(
            request.parent_file_path.as_deref(),
            Some("/app/.claude/rules")
        );
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
}
