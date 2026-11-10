//! Claude Code Hook HTTP contracts exposed by the Collector.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Headers supplied by the Hook client and authenticated AgentGateway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookHeaders {
    pub repository: Option<String>,
    pub client_id: Option<String>,
    /// The user of the client's WithHuman key, set by the engine once it has verified the key;
    /// never taken from the client.
    pub user: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub enum HookEventName {
    SessionStart,
    SessionEnd,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    SubagentStart,
    SubagentStop,
    ConfigChange,
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
    /// Claude Code's permission mode when the Hook fired (`default`, `plan`, `acceptEdits`,
    /// `auto`, `dontAsk`, `bypassPermissions`); not every event carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    /// The model the session runs; only SessionStart carries it, and not always.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// The session ended. Claude Code gives SessionEnd Hooks a short budget (1.5 s by default) and
/// does not wait for their answer.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct SessionEndRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    #[serde(default)]
    pub transcript_path: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// Claude Code's permission mode when the Hook fired (`default`, `plan`, `acceptEdits`,
    /// `auto`, `dontAsk`, `bypassPermissions`); not every event carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    /// Why it ended: `clear`, `resume`, `logout`, `prompt_input_exit` or `other`.
    #[serde(default)]
    pub reason: Option<String>,
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
    /// Claude Code's permission mode when the Hook fired (`default`, `plan`, `acceptEdits`,
    /// `auto`, `dontAsk`, `bypassPermissions`); not every event carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
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
    /// Claude Code's permission mode when the Hook fired (`default`, `plan`, `acceptEdits`,
    /// `auto`, `dontAsk`, `bypassPermissions`); not every event carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    /// The local program files a Bash command may run, read by the WithHuman command hook
    /// just before the Call, so the code a run executes can be judged; Claude Code's own event
    /// has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withhuman_programs: Vec<ProgramFile>,
}

/// A local program file as the client read it just before the Call.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ProgramFile {
    /// Absolute path.
    pub path: String,
    /// Its text, possibly cut short (`truncated`).
    pub content: String,
    /// SHA-256 of the whole file, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Size of the whole file in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
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
    /// Claude Code's permission mode when the Hook fired (`default`, `plan`, `acceptEdits`,
    /// `auto`, `dontAsk`, `bypassPermissions`); not every event carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
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
    /// Claude Code's permission mode when the Hook fired (`default`, `plan`, `acceptEdits`,
    /// `auto`, `dontAsk`, `bypassPermissions`); not every event carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
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
pub struct ConfigChangeRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub file_path: String,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct MessageDisplayRequest {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<HookEventName>,
    pub message_id: String,
    /// Zero-based flush index within the message; Claude Code increments it once per flush.
    #[serde(default)]
    pub index: Option<u64>,
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
    /// Set when the batch ran in a subagent.
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    /// The calls of the batch; only their ids are read.
    #[serde(default)]
    pub tool_calls: Vec<BatchedToolCall>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct BatchedToolCall {
    pub tool_use_id: String,
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

/// Context Claude Code adds to the prompt it sends to the model.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserPromptSubmitOutput {
    pub hook_event_name: HookEventName,
    pub additional_context: String,
}

/// Context Claude Code adds to a tool result it shows the model.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseOutput {
    pub hook_event_name: HookEventName,
    pub additional_context: String,
}

/// Text Claude Code displays in place of a streamed delta. Display-only: the stored message and
/// what the model sees are unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MessageDisplayOutput {
    pub hook_event_name: HookEventName,
    pub display_content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificResponse<T> {
    pub hook_specific_output: T,
}
