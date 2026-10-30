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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct DecisionRequest {
    pub session_id: String,
    pub call_seq: u64,
    pub graph_version: u64,
    pub mode: EnforcementMode,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// The user intent the model stated for the current turn, compared with the Call's cause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct DecisionResponse {
    pub decision: Decision,
    pub reason: String,
    pub rule: String,
    pub start: CausalStart,
    pub written: bool,
    #[serde(default)]
    pub jev: Option<JevActivity>,
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
