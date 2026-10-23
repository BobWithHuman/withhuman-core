//! Generator-to-Decision HTTP contracts.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Record,
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct DecisionRequest {
    pub session_id: String,
    pub call_seq: u64,
    pub graph_version: u64,
    pub mode: EnforcementMode,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_context: Option<CausalContext>,
    /// The path as already stored before this decision; filled in by Decision itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_path: Option<CausalPath>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CausalCandidate {
    pub key: String,
    pub node_seq: i64,
    pub body: String,
    /// The piece is flagged but its sentence classification has not arrived yet.
    #[serde(default)]
    pub pending: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CausalContext {
    pub sequence: u64,
    pub call_seq: u64,
    pub tool_use_id: Option<String>,
    pub current: String,
    pub action: String,
    pub parent_state: String,
    pub plans: Vec<CausalCandidate>,
    pub texts: Vec<CausalCandidate>,
    pub value_match: Option<ValueMatch>,
    pub seq_window: u64,
    pub prompt_window: u64,
    #[serde(default)]
    pub risk: Option<f64>,
    /// Values in risky argument positions of the Call and where each first appeared.
    #[serde(default)]
    pub value_findings: Vec<ValueFinding>,
}

/// A value taken from a risky position of a Call's arguments and looked up in the Token Index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ValueFinding {
    /// `send_target`, `exec_target` or `credential`.
    pub position: String,
    /// `url`, `email`, `ip`, `path` or `script`.
    pub kind: String,
    pub value: String,
    /// `percent` or `base64` when the argument carried the value encoded.
    #[serde(default)]
    pub encoding: Option<String>,
    /// `ok` (first seen from the user), `injected` (first seen in text the agent read),
    /// `observed` (first seen in a listing), `ambiguous` (first said by the agent itself),
    /// `derived` (only the URL's host was seen before) or `agent_new` (never seen before).
    pub status: String,
    /// Slot of the first occurrence: `user`, `agent`, `external` or `observed`.
    #[serde(default)]
    pub slot: Option<String>,
    #[serde(default)]
    pub source_seq: Option<i64>,
    #[serde(default)]
    pub source_sequence: Option<i64>,
    #[serde(default)]
    pub source_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ValueMatch {
    pub piece_seq: i64,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CausalChoice {
    pub choice: Option<String>,
    pub probability: Option<f64>,
    pub accepted: Option<bool>,
    pub candidates: Vec<String>,
    pub state: String,
    pub fact: bool,
    pub basis: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CausalResolution {
    pub sequence: u64,
    pub seq_window: u64,
    pub prompt_window: u64,
    pub parent: Option<CausalChoice>,
    pub from_text: Option<CausalChoice>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
/// One edge followed from the judged Call towards its cause. `kind` is `member`, `from_text`,
/// `parent` or `inherited_from_text`; `accepted = false` marks a guessed edge.
pub struct CausalPathEdge {
    pub from_seq: i64,
    pub to_seq: i64,
    pub kind: String,
    pub accepted: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathStop {
    ReachedRoot,
    None,
    Unresolved,
    LoopGuard,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CausalPath {
    pub edges: Vec<CausalPathEdge>,
    /// The piece that told the Call (or the inherited plan) what to do, when there is one.
    pub cause_seq: Option<i64>,
    pub stop: PathStop,
    /// The last depth 1 node reached.
    pub root_seq: Option<i64>,
    pub root_type: Option<String>,
    pub seq_window: u64,
    pub prompt_window: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Deny,
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CausalStart {
    User,
    UserDoc,
    OtherDoc,
    Error,
    #[serde(rename = "SELF")]
    Self_,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct JevActivity {
    pub asked: bool,
    #[serde(default)]
    pub ms: Option<u64>,
    #[serde(default)]
    pub reused_from: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct DecisionResponse {
    pub decision: Decision,
    pub reason: String,
    pub rule: String,
    pub start: CausalStart,
    pub written: bool,
    #[serde(default)]
    pub jev: Option<JevActivity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal: Option<CausalResolution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<CausalPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<ValueFinding>,
}

impl DecisionResponse {
    pub fn validate(&self) -> Result<(), DecisionContractError> {
        match self.decision {
            Decision::Allow if !self.reason.is_empty() => {
                Err(DecisionContractError::AllowReasonMustBeEmpty)
            }
            Decision::Deny | Decision::Review if self.reason.trim().is_empty() => {
                Err(DecisionContractError::BlockingReasonRequired)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionContractError {
    AllowReasonMustBeEmpty,
    BlockingReasonRequired,
}

impl fmt::Display for DecisionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AllowReasonMustBeEmpty => "ALLOW decisions must have an empty reason",
            Self::BlockingReasonRequired => {
                "DENY and REVIEW decisions must include a non-empty reason"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for DecisionContractError {}
