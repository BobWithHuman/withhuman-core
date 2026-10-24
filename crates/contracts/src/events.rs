//! Normalized Collector-to-Generator HTTP contracts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::decisions::DecisionResponse;

pub use crate::decisions::EnforcementMode;

pub type AdditionalFields = BTreeMap<String, Value>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub enum EventName {
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

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct EventMetadata {
    #[serde(default)]
    pub prompt_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SidePending {
    #[serde(default)]
    pub paragraphs: Vec<String>,
    #[serde(default)]
    pub requests: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct ParagraphChunk {
    pub index: u64,
    pub text: String,
    pub hash: String,
    pub source: String,
    pub hidden: bool,
    #[serde(default)]
    pub from_user_doc: Option<bool>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct EventRequest<T> {
    pub session_id: String,
    pub order: u64,
    pub observed_at: u64,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub sequence: Option<u64>,
    pub meta: EventMetadata,
    #[serde(default)]
    pub side_pending: Option<SidePending>,
    pub payload: T,
    #[serde(default)]
    pub chunks: Option<Vec<ParagraphChunk>>,
    #[serde(default)]
    pub flags: Option<Vec<String>>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct PreToolUseEventRequest {
    #[serde(flatten)]
    pub event: EventRequest<PreToolUsePayload>,
    pub mode: EnforcementMode,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct SessionStartPayload {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct UserDocumentReference {
    pub kind: String,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub number: Option<u64>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct UserPromptSubmitPayload {
    pub prompt: String,
    pub kind: String,
    #[serde(default)]
    pub user_docs: Vec<UserDocumentReference>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct PreToolUsePayload {
    pub tool_name: String,
    #[schema(value_type = Object)]
    pub tool_input: Value,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct PostToolUsePayload {
    pub tool_name: String,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub tool_input: Option<Value>,
    #[schema(value_type = Object)]
    pub tool_response: Value,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct PostToolUseFailurePayload {
    pub tool_name: String,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub tool_input: Option<Value>,
    pub error: String,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct SubagentStartPayload {
    pub agent_id: String,
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct SubagentStopPayload {
    pub agent_id: String,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct InstructionsLoadedPayload {
    pub file_path: String,
    #[serde(default)]
    pub memory_type: Option<String>,
    #[serde(default)]
    pub load_reason: Option<String>,
    #[serde(default)]
    pub trigger_file_path: Option<String>,
    #[serde(default)]
    pub parent_file_path: Option<String>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct ConfigChangePayload {
    pub file_path: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct FileChangedPayload {
    pub file_path: String,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct MessageDisplayPayload {
    pub message_id: String,
    pub text: String,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct PostToolBatchPayload {
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ToolDescription {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct ToolDescriptionsPayload {
    pub tools: Vec<ToolDescription>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: AdditionalFields,
}

pub type SessionStartEventRequest = EventRequest<SessionStartPayload>;
pub type UserPromptSubmitEventRequest = EventRequest<UserPromptSubmitPayload>;
pub type PostToolUseEventRequest = EventRequest<PostToolUsePayload>;
pub type PostToolUseFailureEventRequest = EventRequest<PostToolUseFailurePayload>;
pub type SubagentStartEventRequest = EventRequest<SubagentStartPayload>;
pub type SubagentStopEventRequest = EventRequest<SubagentStopPayload>;
pub type InstructionsLoadedEventRequest = EventRequest<InstructionsLoadedPayload>;
pub type ConfigChangeEventRequest = EventRequest<ConfigChangePayload>;
pub type FileChangedEventRequest = EventRequest<FileChangedPayload>;
pub type MessageDisplayEventRequest = EventRequest<MessageDisplayPayload>;
pub type PostToolBatchEventRequest = EventRequest<PostToolBatchPayload>;
pub type ToolDescriptionsEventRequest = EventRequest<ToolDescriptionsPayload>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct CreatedNode {
    pub seq: u64,
    #[serde(rename = "type")]
    pub node_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ParagraphReference {
    pub hash: String,
    pub seq: u64,
    pub new: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct EventResponse<D = DecisionResponse> {
    pub nodes: Vec<CreatedNode>,
    pub paragraphs: Option<Vec<ParagraphReference>>,
    pub version: u64,
    pub decision_response: Option<D>,
}

/// The highest order and per-agent sequence the Generator committed for a session. A Collector
/// that holds no state for the session (restart, expired or lost shared state) continues the
/// numbering after them instead of reusing committed orders.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SessionCursor {
    pub last_order: u64,
    #[serde(default)]
    pub agent_sequences: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct SentenceProbability {
    pub index: u64,
    pub text: String,
    pub p: f64,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct ParagraphClassificationRequest {
    pub sentences: Vec<SentenceProbability>,
    #[serde(default)]
    pub jev_ms: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct ParagraphClassificationResponse {
    pub applied: bool,
    #[serde(default)]
    pub instructs: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct RequestContinuationRequest {
    #[serde(default)]
    pub choice: Option<String>,
    #[serde(default)]
    pub probabilities: BTreeMap<String, f64>,
    #[serde(default)]
    pub jev_ms: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct RequestContinuationResponse {
    pub applied: bool,
    #[serde(default)]
    pub request_seq: Option<u64>,
}
