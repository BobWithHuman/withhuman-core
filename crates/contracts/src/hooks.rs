//! Claude Code Hook HTTP contracts exposed by the Collector.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Headers supplied by the Hook client and authenticated AgentGateway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookHeaders {
    pub repository: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct PreToolUseRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub tool_name: String,
    #[schema(value_type = Object)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct PostToolUseRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub tool_name: String,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub tool_input: Option<Value>,
    #[schema(value_type = Object)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct PostToolUseFailureRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub tool_name: String,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SubagentLifecycleRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub agent_id: String,
    #[serde(default)]
    pub agent_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ConfigChangeRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub file_path: String,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct FileChangedRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub file_path: String,
    #[serde(default)]
    pub event: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct PostToolBatchRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ToolDescription {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ToolDescriptionsRequest {
    pub session_id: String,
    pub tools: Vec<ToolDescription>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PermissionDecision {
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseOutput {
    pub hook_event_name: HookEventName,
    pub permission_decision: PermissionDecision,
    pub permission_decision_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartOutput {
    pub hook_event_name: HookEventName,
    pub watch_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificResponse<T> {
    pub hook_specific_output: T,
}
