//! Cursor CLI Hook input as the Collector's Cursor route receives it.
//!
//! Cursor runs one process per Hook with the event's JSON on stdin; the WithHuman bridge
//! forwards it and may add the `withhuman_*` fields only the client can know. The Collector
//! translates it into the Claude Code Hook requests of [`crate::hooks`], so the same engine
//! logic judges Cursor sessions as it judges Claude Code's.
//!
//! What Cursor's Hooks give, verified against Cursor CLI 2026.11.22 (fixtures under
//! `tests/fixtures/cursor/`):
//!
//! - [`CursorHookEvent::PreToolUse`] covers every tool, with the directory already filled in,
//!   so a shell call needs nothing read back from the transcript. Its name for an MCP call is
//!   `MCP:<tool>`, which does not say which server: those are judged on
//!   [`CursorHookEvent::BeforeMcpExecution`], which carries `mcp_server_name`, and the
//!   `MCP:`-named PreToolUse is passed over.
//! - [`CursorHookEvent::PostToolUse`] carries `tool_output` as a JSON **string**. For a shell
//!   call and an MCP call it holds what the tool printed, `exitCode` included, so a failed
//!   call is known without reading a transcript. For a file read it holds only the path and a
//!   length — **the file's text arrives on [`CursorHookEvent::BeforeReadFile`] instead**, under
//!   the same `tool_use_id`, which is why the bridge carries it over to the result. A `Grep`
//!   answers with neither its matches nor their text, so a grep's content cannot be judged.
//! - `generation_id` is the turn: a prompt and every event it leads to share it, and only
//!   thought events add a `-<n>-<suffix>`. It becomes Claude Code's `prompt_id`.
//! - Prompt text, the model's answer and the turn's end arrive as
//!   [`CursorHookEvent::BeforeSubmitPrompt`], [`CursorHookEvent::AfterAgentResponse`] and
//!   [`CursorHookEvent::Stop`] — but **only in an interactive session**. A `cursor-agent -p`
//!   run fires none of the three, so such a session reaches the engine without a prompt or an
//!   intent line.
//! - A subagent runs under a `session_id` of its own; its `transcript_path` sits in the parent
//!   session's folder (`…/<parent>/subagents/<child>.jsonl`), which is where the bridge finds
//!   the parent it belongs to. Cursor's own `subagentStart` / `subagentStop` Hooks do not fire.
//!
//! Every Hook Cursor can send is named here, including those the engine has nothing to do
//! with: a client is set up with `failClosed`, so an event the route turned away as unknown
//! would block the call behind it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::hooks::ProgramFile;

/// Cursor Hook events the Collector's Cursor route accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub enum CursorHookEvent {
    // ---- what the engine judges or records ----
    SessionStart,
    SessionEnd,
    BeforeSubmitPrompt,
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    BeforeMcpExecution,
    AfterAgentResponse,
    Stop,
    // ---- accepted and passed over ----
    /// Duplicates [`Self::PreToolUse`] for a shell call.
    BeforeShellExecution,
    /// The call's result is in [`Self::PostToolUse`] already.
    AfterShellExecution,
    /// The result is in [`Self::PostToolUse`]; the server name came with
    /// [`Self::BeforeMcpExecution`].
    AfterMcpExecution,
    /// Carries the file's text, which the result leaves out; the bridge keeps it for the
    /// result rather than sending an event of its own.
    BeforeReadFile,
    /// The edit is in the call's own result.
    AfterFileEdit,
    /// The model's reasoning, which the engine does not keep.
    AfterAgentThought,
    /// Context compaction, which changes nothing the engine judges.
    PreCompact,
    /// Opening a folder; it carries no session.
    WorkspaceOpen,
    /// Cursor does not fire these — a subagent arrives as a session of its own.
    SubagentStart,
    SubagentStop,
    /// Cursor Tab's own file access, which is not an agent Call.
    BeforeTabFileRead,
    AfterTabFileEdit,
}

impl CursorHookEvent {
    /// The event as Cursor names it in `hooks.json` and on the route.
    pub fn from_path(name: &str) -> Option<Self> {
        Some(match name {
            "sessionStart" => Self::SessionStart,
            "sessionEnd" => Self::SessionEnd,
            "beforeSubmitPrompt" => Self::BeforeSubmitPrompt,
            "preToolUse" => Self::PreToolUse,
            "postToolUse" => Self::PostToolUse,
            "postToolUseFailure" => Self::PostToolUseFailure,
            "beforeMCPExecution" => Self::BeforeMcpExecution,
            "afterAgentResponse" => Self::AfterAgentResponse,
            "stop" => Self::Stop,
            "beforeShellExecution" => Self::BeforeShellExecution,
            "afterShellExecution" => Self::AfterShellExecution,
            "afterMCPExecution" => Self::AfterMcpExecution,
            "beforeReadFile" => Self::BeforeReadFile,
            "afterFileEdit" => Self::AfterFileEdit,
            "afterAgentThought" => Self::AfterAgentThought,
            "preCompact" => Self::PreCompact,
            "workspaceOpen" => Self::WorkspaceOpen,
            "subagentStart" => Self::SubagentStart,
            "subagentStop" => Self::SubagentStop,
            "beforeTabFileRead" => Self::BeforeTabFileRead,
            "afterTabFileEdit" => Self::AfterTabFileEdit,
            _ => return None,
        })
    }

    /// Whether the client reads this Hook's answer to decide a Call. Only these need an answer
    /// in time; the rest are reported and forgotten.
    pub fn blocks_a_call(self) -> bool {
        matches!(self, Self::PreToolUse | Self::BeforeMcpExecution)
    }
}

/// One Cursor Hook's stdin, with what the bridge added.
///
/// Every field is optional: one Hook carries a handful of them, and Cursor adds fields between
/// versions. What this type does not name is kept in `additional_fields` and travels with the
/// event as evidence.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct CursorHookInput {
    /// The thread the event belongs to; Cursor sets it to the conversation's id, and a
    /// subagent's is its own. Absent on `workspaceOpen`.
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub conversation_id: Option<String>,
    /// The turn, and so Claude Code's `prompt_id`. Thought events add a `-<n>-<suffix>` that
    /// the Collector strips.
    #[serde(default)]
    pub generation_id: Option<String>,
    #[serde(default)]
    pub hook_event_name: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<String>,
    /// The directory the call runs in — filled in, unlike Codex's.
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub is_background_agent: Option<bool>,

    // ---- a prompt and an answer ----
    /// `beforeSubmitPrompt`: the prompt as the user submitted it.
    #[serde(default)]
    pub prompt: Option<String>,
    /// `beforeSubmitPrompt` and `beforeReadFile`: what came with the prompt or the file.
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub attachments: Option<Vec<Value>>,
    /// `afterAgentResponse`: the answer the model gave, which opens with the `[의도]` line.
    /// Also `afterAgentThought`, whose text the engine does not keep.
    #[serde(default)]
    pub text: Option<String>,
    /// `stop`: how the turn ended.
    #[serde(default)]
    pub status: Option<String>,

    // ---- a call ----
    /// `MCP:<tool>` for an MCP call, else Cursor's own tool name (`Shell`, `Read`, `Grep`,
    /// `Write`, `Task`, …). On the MCP Hooks it is the tool alone, without the server.
    #[serde(default)]
    pub tool_name: Option<String>,
    /// An object on the tool Hooks, a JSON string on the MCP ones.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub tool_input: Option<Value>,
    /// `postToolUse`: the tool's own result as a JSON string (a shell call's `exitCode` too).
    #[serde(default)]
    pub tool_output: Option<String>,
    pub tool_use_id: Option<String>,
    /// `postToolUseFailure`: why the call did not finish.
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub failure_type: Option<String>,
    #[serde(default)]
    pub is_interrupt: Option<bool>,

    // ---- what only a tool's own Hook says ----
    /// `beforeMCPExecution` / `afterMCPExecution`: the server the call goes to.
    #[serde(default)]
    pub mcp_server_name: Option<String>,
    /// `afterMCPExecution`: the server's answer, as a JSON string.
    #[serde(default)]
    pub result_json: Option<String>,
    /// `before/afterShellExecution`: the command, and whether it ran sandboxed.
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub sandbox: Option<bool>,
    #[serde(default)]
    pub output: Option<String>,
    /// `beforeReadFile` / `afterFileEdit`: the file, its text, and the edit made to it.
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub edits: Option<Vec<CursorEdit>>,

    // ---- a session's end ----
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub final_status: Option<String>,

    // ---- what the bridge added ----
    /// Set by the bridge on a `postToolUse` of an MCP call: the server it went to, remembered
    /// from `beforeMCPExecution`, since Cursor leaves it out of the tool Hooks.
    #[serde(default)]
    pub withhuman_mcp_server: Option<String>,
    /// Set by the bridge on a subagent's event: the session it belongs to, read from the
    /// transcript path. The event's own `session_id` then becomes the agent's id.
    #[serde(default)]
    pub withhuman_parent_session: Option<String>,
    /// Set by the bridge on the `postToolUse` of a file read: the file's text, which Cursor
    /// sends on `beforeReadFile` and leaves out of the result. Without it the engine would
    /// judge a read whose content it never saw.
    #[serde(default)]
    pub withhuman_read_content: Option<String>,
    /// Local program files a shell call may run, read by the bridge just before the call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withhuman_programs: Vec<ProgramFile>,

    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: BTreeMap<String, Value>,
}

/// One change `afterFileEdit` reports, in the shape Claude Code's `MultiEdit` uses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct CursorEdit {
    #[serde(default)]
    pub old_string: String,
    #[serde(default)]
    pub new_string: String,
}

/// The turn an event belongs to: `generation_id` without the suffix a thought event adds
/// (`<uuid>-3-r7ev` is the same turn as `<uuid>`).
pub fn turn_of(generation_id: &str) -> &str {
    // A bare id is 36 characters (`8-4-4-4-12`); anything past that is the suffix.
    match generation_id.len() > 36 && generation_id.as_bytes().get(36) == Some(&b'-') {
        true => &generation_id[..36],
        false => generation_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thought_belongs_to_the_turn_it_interrupts() {
        let turn = "8c9af799-b8a9-4f87-85d1-fbe03912cc92";
        assert_eq!(turn_of(turn), turn);
        assert_eq!(turn_of(&format!("{turn}-0-778f")), turn);
        assert_eq!(turn_of(&format!("{turn}-13-zonj")), turn);
        // Nothing is assumed of an id that is not Cursor's shape.
        assert_eq!(turn_of("short"), "short");
    }
}
