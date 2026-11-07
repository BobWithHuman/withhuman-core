//! Codex CLI Hook input as the Collector's Codex route receives it.
//!
//! Codex sends one JSON object per Hook on stdin; the WithHuman bridge forwards it unchanged and
//! may add the `withhuman_*` fields only the client can know. The Collector translates it into
//! the Claude Code Hook requests of [`crate::hooks`], so the same engine logic judges both.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::hooks::ProgramFile;

/// Codex Hook events the Collector's Codex route accepts. `MessageDisplay` and `PostToolBatch`
/// have no Codex Hook: the bridge makes them from the session transcript, in their Claude Code
/// form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub enum CodexHookEvent {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    Stop,
    SessionEnd,
    SubagentStart,
    SubagentStop,
    MessageDisplay,
    PostToolBatch,
}

impl CodexHookEvent {
    pub fn from_path(name: &str) -> Option<Self> {
        Some(match name {
            "SessionStart" => Self::SessionStart,
            "UserPromptSubmit" => Self::UserPromptSubmit,
            "PreToolUse" => Self::PreToolUse,
            "PostToolUse" => Self::PostToolUse,
            "Stop" => Self::Stop,
            "SessionEnd" => Self::SessionEnd,
            "SubagentStart" => Self::SubagentStart,
            "SubagentStop" => Self::SubagentStop,
            "MessageDisplay" => Self::MessageDisplay,
            "PostToolBatch" => Self::PostToolBatch,
            _ => return None,
        })
    }
}

/// One Codex Hook's stdin, with what the bridge added.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct CodexHookInput {
    pub session_id: String,
    #[serde(default)]
    pub hook_event_name: Option<String>,
    /// Codex's turn, the counterpart of Claude Code's `prompt_id`.
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<String>,
    /// The project directory; for a shell call not the directory it runs in (`workdir`).
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub permission_mode: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub tool_input: Option<Value>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub tool_response: Option<Value>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(default)]
    pub last_assistant_message: Option<String>,
    #[serde(default)]
    pub stop_hook_active: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Set by the bridge: the directory a shell call runs in, read from the transcript since
    /// the Hook leaves it out.
    #[serde(default)]
    pub withhuman_workdir: Option<String>,
    /// Set by the bridge when the transcript shows the call failed (Codex's PostToolUse has no
    /// exit code): the failure text.
    #[serde(default)]
    pub withhuman_failure: Option<String>,
    /// Set by the bridge on a call Codex ran without a Hook (a web search found later in the
    /// transcript): it is recorded, not judged before it runs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub withhuman_record: bool,
    /// Local program files a shell call may run, read by the bridge just before the call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withhuman_programs: Vec<ProgramFile>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: BTreeMap<String, Value>,
}

/// The shell a Codex client runs commands in, as the bridge reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CodexShell {
    #[default]
    Posix,
    PowerShell,
}

impl CodexShell {
    pub fn from_header(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(value) if value.eq_ignore_ascii_case("powershell") => Self::PowerShell,
            _ => Self::Posix,
        }
    }

    /// The Claude Code tool a shell call becomes.
    pub fn tool_name(self) -> &'static str {
        match self {
            Self::Posix => "Bash",
            Self::PowerShell => "PowerShell",
        }
    }
}
