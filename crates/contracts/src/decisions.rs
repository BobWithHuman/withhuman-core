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
