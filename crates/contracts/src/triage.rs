//! Triage contracts: what the security team decided about a session it looked at, the sources
//! it distrusts, and one Call's evidence as an export for other systems.
//!
//! The Collector serves these to administrators (`/v1/admin/...`) and the Generator stores
//! them. They record the team's judgement; none of them changes how a Call is decided.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// The value of [`Evidence::schema`]. Fields may be added to this version; a field removed or
/// a meaning changed makes a new one.
pub const EVIDENCE_SCHEMA: &str = "withhuman.evidence/v1";

/// Where the team stands on a session; a session without a mark was not handled yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MarkState {
    /// Someone is looking at it.
    Reviewing,
    Attack,
    Benign,
    /// Done with, whatever it was.
    Closed,
}

impl MarkState {
    pub const ALL: [Self; 4] = [Self::Reviewing, Self::Attack, Self::Benign, Self::Closed];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reviewing => "reviewing",
            Self::Attack => "attack",
            Self::Benign => "benign",
            Self::Closed => "closed",
        }
    }

    pub fn parse(state: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|known| known.as_str() == state)
    }
}

/// `POST /v1/admin/sessions/{session_id}/mark`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct MarkSessionRequest {
    /// `reviewing`, `attack`, `benign` or `closed`, or null to take the mark off. Required,
    /// so a body without it changes nothing.
    #[serde(deserialize_with = "stated")]
    #[schema(required = true)]
    pub state: Option<MarkState>,
    /// Who marks the session, for the record (the administrator's email).
    #[serde(default)]
    pub actor: Option<String>,
}

/// A value or an explicit null; unlike a plain `Option`, a missing field is an error.
fn stated<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<MarkState>, D::Error> {
    Option::deserialize(deserializer)
}

/// A session's mark: who set it last and when.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SessionMark {
    pub state: MarkState,
    #[serde(default)]
    pub set_by: Option<String>,
    /// Epoch milliseconds.
    pub set_at: u64,
}

/// A session and its mark after a change; `mark` is null once it is taken off.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct MarkedSession {
    pub session_id: String,
    #[schema(required = true)]
    pub mark: Option<SessionMark>,
}

/// `POST /v1/admin/sources/distrust`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct DistrustSourceRequest {
    /// A document's path, a URL or a tool's name, compared as written.
    pub source: String,
    /// True distrusts the source; false trusts it again.
    pub on: bool,
    /// Who decides, for the record (the administrator's email).
    #[serde(default)]
    pub actor: Option<String>,
    /// The Call that showed the source, when there is one.
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub seq: Option<u64>,
}

/// A source and whether the team distrusts it. The rest is null for a source it trusts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SourceTrust {
    pub source: String,
    pub distrusted: bool,
    #[serde(default)]
    pub set_by: Option<String>,
    /// Epoch milliseconds.
    #[serde(default)]
    pub set_at: Option<u64>,
    /// The Call that showed the source, when the team named one.
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub seq: Option<u64>,
}

/// `GET /v1/admin/sessions/{session_id}/calls/{seq}/evidence`: one Call, what decided it and
/// what led the agent to it, as the engine recorded them. Text is as stored: with the
/// sensitive values the engine found already replaced. A field the engine has no value for is
/// null, never left out.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct Evidence {
    /// `withhuman.evidence/v1`.
    pub schema: String,
    pub session_id: String,
    /// The Call's number in its session.
    pub seq: u64,
    pub call: EvidenceCall,
    /// The engine's verdict; null for a Call it has not judged.
    #[schema(required = true)]
    pub decision: Option<EvidenceDecision>,
    /// The person's latest request before the Call; null when the session has none.
    #[schema(required = true)]
    pub request: Option<EvidenceRequest>,
    pub cause: EvidenceCause,
    /// The team's mark on the session; null when it has none.
    #[schema(required = true)]
    pub mark: Option<SessionMark>,
}

/// The Call itself.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct EvidenceCall {
    #[schema(required = true)]
    pub tool_use_id: Option<String>,
    #[schema(required = true)]
    pub tool: Option<String>,
    /// The tool's input, whole.
    #[schema(value_type = Object, required = true)]
    pub input: Value,
    /// What the Call acts on: the first of the input's `command`, `file_path`, `url`, `path`,
    /// `pattern` and `query`.
    #[schema(required = true)]
    pub target: Option<String>,
    /// The directory the Call was made in.
    #[schema(required = true)]
    pub cwd: Option<String>,
    /// When the Hook saw the Call, epoch milliseconds.
    #[schema(required = true)]
    pub at: Option<u64>,
    /// The device, `<team>/<uuid>`.
    #[schema(required = true)]
    pub client_id: Option<String>,
    /// The user of the key the session's Hooks presented.
    #[schema(required = true)]
    pub user: Option<String>,
    /// The subagent that made the Call; null for the main agent.
    #[schema(required = true)]
    pub agent_id: Option<String>,
    /// The agent's permission mode at the Call (`default`, `acceptEdits`, ...).
    #[schema(required = true)]
    pub permission_mode: Option<String>,
    #[schema(required = true)]
    pub model: Option<String>,
}

/// The verdict as it was written on the Call.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct EvidenceDecision {
    /// `ALLOW`, `DENY` or `REVIEW`.
    pub decision: String,
    /// Empty for an `ALLOW`.
    #[schema(required = true)]
    pub reason: Option<String>,
    #[schema(required = true)]
    pub rule: Option<String>,
    /// The enforcement mode the Call was judged in: `record`, `shadow` or `enforce`.
    #[schema(required = true)]
    pub mode: Option<String>,
    /// Where the Call's causes start: `USER`, `USER_DOC`, `OTHER_DOC`, `ERROR`, `SELF` or
    /// `UNRESOLVED`.
    #[schema(required = true)]
    pub start: Option<String>,
    /// Epoch milliseconds.
    #[schema(required = true)]
    pub decided_at: Option<u64>,
}

/// A request of the person.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct EvidenceRequest {
    pub seq: u64,
    /// The prompt's text.
    #[schema(required = true)]
    pub text: Option<String>,
    /// Epoch milliseconds.
    #[schema(required = true)]
    pub at: Option<u64>,
}

/// What led the agent to the Call, as the engine traced it.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct EvidenceCause {
    /// Whether the engine traced the Call. When false, only `error` may say something.
    pub traced: bool,
    /// `request` (the next step of the person's request), `segment` (the content of a tool
    /// result) or `none` (neither); null for a Call not traced, or whose trace kept no link.
    #[schema(required = true)]
    pub link: Option<String>,
    /// Whether the model picked the cause; false when it is the nearest one walking back.
    #[schema(required = true)]
    pub picked: Option<bool>,
    /// Why the trace failed, when it did.
    #[schema(required = true)]
    pub error: Option<String>,
    /// The request the Call was traced to, with the cause's probability; null when the trace
    /// points at none, and whenever `link` is `segment`.
    #[schema(required = true)]
    pub request: Option<CausedByRequest>,
    /// The tool results the Call was traced to, the most probable first; empty unless `link`
    /// is `segment`.
    pub told_by: Vec<CausedByResult>,
    /// Whether the team distrusts the source of any of `told_by`.
    pub source_distrusted: bool,
    /// How far the Call departs from what the person asked; null when no intent was stated.
    #[schema(required = true)]
    pub deviation: Option<EvidenceDeviation>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct CausedByRequest {
    pub seq: u64,
    #[schema(required = true)]
    pub probability: Option<f64>,
}

/// A tool result that told the agent to make the Call, and the Call whose result it was.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct CausedByResult {
    /// The result's number in the session.
    pub result_seq: u64,
    /// `Segment` (a tool's output) or `Error` (a tool's failure).
    pub result_kind: String,
    /// The Call whose result it was; null when the session does not hold it.
    #[schema(required = true)]
    pub call_seq: Option<u64>,
    #[schema(required = true)]
    pub tool: Option<String>,
    #[schema(value_type = Object, required = true)]
    pub input: Value,
    /// As [`EvidenceCall::target`], of that Call.
    #[schema(required = true)]
    pub target: Option<String>,
    /// The paragraph of the result the Call was traced to; null for the result whole.
    #[schema(required = true)]
    pub paragraph: Option<u64>,
    /// The paragraph's text; null for the result whole.
    #[schema(required = true)]
    pub quote: Option<String>,
    /// Whether the paragraph was hidden where it appeared.
    #[schema(required = true)]
    pub hidden: Option<bool>,
    #[schema(required = true)]
    pub probability: Option<f64>,
    /// Rank among the Call's causes, from 1.
    #[schema(required = true)]
    pub rank: Option<u64>,
    /// What the result came from: the entry of `distrusted_sources` that names it when there
    /// is one, else that Call's `file_path`, `url` or `path`, else its tool's name.
    #[schema(required = true)]
    pub source: Option<String>,
    /// Whether the team distrusts it: one of that Call's target, its target below `cwd`, its
    /// `file_path`, `url` or `path`, or its tool's name is in `distrusted_sources`.
    pub source_distrusted: bool,
}

/// The engine's measure of the Call against the person's intents.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct EvidenceDeviation {
    /// From 0 (keeps to them) to 1.
    #[schema(required = true)]
    pub score: Option<f64>,
    /// The worst breach: `explicit`, an expectation's key (`exfiltration`, `hijacked_goal`,
    /// ...) or `none`.
    #[schema(required = true)]
    pub worst: Option<String>,
}
