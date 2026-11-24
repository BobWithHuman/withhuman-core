//! GitHub Copilot CLI Hook input as the Collector's Copilot route receives it.
//!
//! Copilot runs one process per Hook with the event's JSON on stdin; the WithHuman bridge
//! forwards it and may add the `withhuman_*` fields only the client can know. The Collector
//! translates it into the Claude Code Hook requests of [`crate::hooks`], so the same engine
//! logic judges Copilot sessions as it judges Claude Code's.
//!
//! Copilot names every event twice. Its own names are camelCase (`preToolUse`), and under
//! Claude Code's names (`PreToolUse`) it sends **Claude Code's field names and Claude Code's
//! tool names** — `bash` arrives as `Bash`, `view` as `Read`, `task` as `Agent`. The bridge
//! therefore registers the Claude Code name wherever one exists, and the translation has
//! almost nothing left to do. Three events have no Claude Code name and keep the camelCase
//! fields even under a Claude Code one: [`CopilotHookEvent::SubagentStart`],
//! [`CopilotHookEvent::PermissionRequest`] and [`CopilotHookEvent::Notification`]. Both
//! spellings of every field are accepted here, so a Hook registered either way parses.
//!
//! What Copilot's Hooks give, measured against Copilot CLI 1.0.115-7 (fixtures under
//! `tests/fixtures/copilot/`):
//!
//! - **[`CopilotHookEvent::PreToolUse`] is the only Hook that can stop a Call.** A
//!   `preMcpToolCall` or `permissionRequest` command Hook that answers `deny` is ignored and
//!   the call runs, so MCP calls are judged on `PreToolUse` as every other call is.
//! - A Hook that **times out lets the call run** (30 seconds by default, `timeoutSec` to
//!   change), which is why the bridge denies on its own deadline rather than letting
//!   Copilot's pass. A Hook that **fails** denies the call, and a Hook that prints nothing
//!   allows it. `ask` denies where there is no terminal to ask at.
//! - An MCP call's `tool_name` is `<server>-<tool>`, which cannot be split: the server's own
//!   name holds hyphens (`github-mcp-server-get_file_contents`). The server arrives, after
//!   the call was already judged, on `preMcpToolCall` (`serverName`) and
//!   `permissionRequest` (`<server>/<tool>`); the bridge keeps what it learns there in
//!   `withhuman_mcp_server` so later calls to the same server are named
//!   `mcp__<server>__<tool>`. A call to a server it has not seen yet is judged under the raw
//!   name — named differently, never unjudged.
//! - **No event carries a turn.** `turnId` is in the session transcript
//!   (`transcript_path`, `~/.copilot/session-state/<session>/events.jsonl`), which is also
//!   where the model's answer is, so the bridge reads both from there and sends the turn as
//!   `withhuman_turn` and the answer as a Claude Code `MessageDisplay`.
//! - The intent instruction reaches the model as a top-level `{"additionalContext": "…"}`
//!   from `UserPromptSubmit`. Claude Code's nested `hookSpecificOutput` form is ignored.
//! - Parallel calls run **one Hook process each, at the same time**, so the bridge's state
//!   file is only safe behind its lock.
//! - A subagent's events carry its own `session_id` with `parent_agent_id` holding the real
//!   session, which is the session the Collector folds them into. `SubagentStop` carries
//!   `last_assistant_message`; the main turn's `Stop` does not.
//! - `apply_patch` arrives as `Edit` whose `tool_input` is the **patch itself, as a string**
//!   rather than an object, which is Codex's shape and is translated by Codex's parser.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::hooks::ProgramFile;

/// Copilot Hook events the Collector's Copilot route accepts, under either spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub enum CopilotHookEvent {
    // ---- what the engine judges or records ----
    SessionStart,
    SessionEnd,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    SubagentStart,
    SubagentStop,
    Stop,
    /// No Copilot Hook: the bridge makes it from the session transcript, in its Claude Code
    /// form, because the answer carrying the `[의도]` line is nowhere in a Hook.
    MessageDisplay,
    // ---- accepted and passed over ----
    /// Copilot's own MCP gate, which cannot stop a call. The bridge reads the server name off
    /// it and sends nothing.
    PreMcpToolCall,
    /// A permission prompt, which cannot stop a call either. Its `<server>/<tool>` is a
    /// second place the bridge can learn a server name.
    PermissionRequest,
    /// The prompt as the runtime rewrote it for the model; the engine judges what the user
    /// submitted.
    UserPromptTransformed,
    /// An error inside the agent, which is not a Call.
    ErrorOccurred,
    /// Context compaction, which changes nothing the engine judges.
    PreCompact,
    /// A message for the user.
    Notification,
}

impl CopilotHookEvent {
    /// The event as the bridge names it on the route: Claude Code's name where Copilot has
    /// one, Copilot's own otherwise. Both spellings parse, since a Hook file written by hand
    /// may use either.
    pub fn from_path(name: &str) -> Option<Self> {
        Some(match name {
            "SessionStart" | "sessionStart" => Self::SessionStart,
            "SessionEnd" | "sessionEnd" => Self::SessionEnd,
            "UserPromptSubmit" | "userPromptSubmitted" => Self::UserPromptSubmit,
            "PreToolUse" | "preToolUse" => Self::PreToolUse,
            "PostToolUse" | "postToolUse" => Self::PostToolUse,
            "PostToolUseFailure" | "postToolUseFailure" => Self::PostToolUseFailure,
            "SubagentStart" | "subagentStart" => Self::SubagentStart,
            "SubagentStop" | "subagentStop" => Self::SubagentStop,
            "Stop" | "agentStop" => Self::Stop,
            "MessageDisplay" => Self::MessageDisplay,
            "PreMcpToolCall" | "preMcpToolCall" => Self::PreMcpToolCall,
            "PermissionRequest" | "permissionRequest" => Self::PermissionRequest,
            "UserPromptTransformed" | "userPromptTransformed" => Self::UserPromptTransformed,
            "ErrorOccurred" | "errorOccurred" => Self::ErrorOccurred,
            "PreCompact" | "preCompact" => Self::PreCompact,
            "Notification" | "notification" => Self::Notification,
            _ => return None,
        })
    }

    /// Whether Copilot reads this Hook's answer to decide a Call. Only `PreToolUse` does:
    /// `preMcpToolCall` and `permissionRequest` command Hooks are consulted and their answer
    /// discarded.
    pub fn blocks_a_call(self) -> bool {
        matches!(self, Self::PreToolUse)
    }
}

/// One Copilot Hook's stdin, with what the bridge added.
///
/// Every field is optional: one Hook carries a handful of them, and Copilot adds fields
/// between versions. What this type does not name is kept in `additional_fields` and travels
/// with the event as evidence. Each field accepts both of Copilot's spellings, since the
/// same event sends snake_case under Claude Code's name and camelCase under its own — and
/// `SubagentStart` mixes the two in one payload.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct CopilotHookInput {
    /// The session the event belongs to. A subagent's own id stands here instead, with the
    /// real session in `parent_agent_id`.
    #[serde(default, alias = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub hook_event_name: Option<String>,
    /// An ISO-8601 string under Claude Code's names, milliseconds since the epoch under
    /// Copilot's own.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub timestamp: Option<Value>,
    /// The directory the session runs in.
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default, alias = "transcriptPath")]
    pub transcript_path: Option<String>,

    // ---- a prompt and an answer ----
    /// `SessionStart`: the prompt a `-p` run started with.
    #[serde(default, alias = "initialPrompt")]
    pub initial_prompt: Option<String>,
    /// How the session started (`new`, `resume`, …).
    #[serde(default)]
    pub source: Option<String>,
    /// `UserPromptSubmit`: the prompt as the user submitted it.
    #[serde(default)]
    pub prompt: Option<String>,
    /// `UserPromptTransformed`: the prompt the model was given instead.
    #[serde(default, alias = "transformedPrompt")]
    pub transformed_prompt: Option<String>,
    /// `SubagentStop`: the subagent's answer. The main turn's `Stop` carries none, which is
    /// why the bridge reads the answer from the transcript.
    #[serde(default, alias = "response")]
    pub last_assistant_message: Option<String>,
    /// `Stop` / `SubagentStop`: how the turn ended.
    #[serde(default, alias = "stopReason")]
    pub stop_reason: Option<String>,
    #[serde(default)]
    pub stop_hook_active: Option<bool>,
    /// `SessionEnd`: why the session ended.
    #[serde(default)]
    pub reason: Option<String>,

    // ---- a call ----
    /// Claude Code's name for one of Copilot's own tools (`bash` arrives as `Bash`), or
    /// `<server>-<tool>` for an MCP call. On `PreMcpToolCall` it is the tool alone, and on
    /// `PermissionRequest` it is `<server>/<tool>`.
    #[serde(default, alias = "toolName")]
    pub tool_name: Option<String>,
    /// The call's arguments: an object, or for `Edit` the patch itself as a string.
    #[serde(default, alias = "toolArgs", alias = "toolInput")]
    #[schema(value_type = Option<Object>)]
    pub tool_input: Option<Value>,
    /// `PostToolUse`: what the tool answered, as `result_type` and `text_result_for_llm`.
    #[serde(default, alias = "toolResult")]
    #[schema(value_type = Option<Object>)]
    pub tool_result: Option<Value>,
    #[serde(default, alias = "toolCallId")]
    pub tool_use_id: Option<String>,
    /// `PostToolUseFailure`: why the call failed, as a string. `ErrorOccurred` sends an
    /// object here instead.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub error: Option<Value>,
    /// `ErrorOccurred`: where the error came from, and whether the agent carried on.
    #[serde(default, alias = "errorContext")]
    pub error_context: Option<String>,
    #[serde(default)]
    pub recoverable: Option<bool>,

    // ---- a subagent ----
    #[serde(default, alias = "agentId")]
    pub agent_id: Option<String>,
    #[serde(default, alias = "agentType")]
    pub agent_type: Option<String>,
    /// The session a subagent belongs to, which is the session the Collector folds its events
    /// into.
    #[serde(default, alias = "parentAgentId")]
    pub parent_agent_id: Option<String>,
    #[serde(default, alias = "agentName")]
    pub agent_name: Option<String>,

    // ---- what only Copilot's own MCP and permission Hooks say ----
    /// `PreMcpToolCall`: the server the call goes to.
    #[serde(default, alias = "serverName")]
    pub server_name: Option<String>,
    /// `PreMcpToolCall`: the call's arguments, under a name of its own.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub arguments: Option<Value>,
    /// `PreMcpToolCall`: the call id, under MCP's own `_meta`.
    #[serde(default, rename = "_meta")]
    #[schema(value_type = Option<Object>)]
    pub meta: Option<Value>,
    /// `PermissionRequest`: what Copilot would offer the user, and which Hook asked.
    #[serde(default, alias = "permissionSuggestions")]
    #[schema(value_type = Option<Vec<Object>>)]
    pub permission_suggestions: Option<Value>,
    #[serde(default, alias = "hookName")]
    pub hook_name: Option<String>,

    // ---- what the bridge added ----
    /// Set by the bridge from the session transcript: the turn the event belongs to, and so
    /// Claude Code's `prompt_id`. No Copilot Hook carries one.
    #[serde(default)]
    pub withhuman_turn: Option<String>,
    /// Set by the bridge on an MCP call whose server it knows, from Copilot's MCP
    /// configuration or from a `PreMcpToolCall` it saw earlier: `tool_name` is
    /// `<server>-<tool>` and cannot be split without it.
    #[serde(default)]
    pub withhuman_mcp_server: Option<String>,
    /// Local program files a shell call may run, read by the bridge just before the call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withhuman_programs: Vec<ProgramFile>,

    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: BTreeMap<String, Value>,
}

impl CopilotHookInput {
    /// The session the event belongs to: a subagent's events carry their own id in
    /// `session_id` and the session they run under in `parent_agent_id`.
    pub fn session(&self) -> Option<&str> {
        self.parent_agent_id
            .as_deref()
            .filter(|parent| Some(*parent) != self.session_id.as_deref())
            .or(self.session_id.as_deref())
    }

    /// The server and tool of an MCP call, given what the bridge knows of the server.
    /// `<server>-<tool>` cannot be split on its own, so without a known server there is
    /// nothing to take apart and the call keeps the name Copilot gave it. The server the
    /// bridge reports is what tells an MCP call from one of Copilot's own tools: nothing is
    /// assumed of a name the bridge said nothing about.
    pub fn mcp_call(&self) -> Option<(&str, &str)> {
        let name = self.tool_name.as_deref()?;
        let server = self.withhuman_mcp_server.as_deref()?;
        let tool = name
            .strip_prefix(server)
            .and_then(|rest| rest.strip_prefix('-'))?;
        Some((server, tool))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_subagents_events_belong_to_the_session_it_runs_under() {
        let mut input: CopilotHookInput = serde_json::from_value(json!({
            "session_id": "agent-1",
            "parent_agent_id": "session-1",
        }))
        .unwrap();
        assert_eq!(input.session(), Some("session-1"));

        // The main agent's own events name the session in both fields, or in one.
        input.parent_agent_id = Some("session-1".into());
        input.session_id = Some("session-1".into());
        assert_eq!(input.session(), Some("session-1"));
        input.parent_agent_id = None;
        assert_eq!(input.session(), Some("session-1"));
    }

    #[test]
    fn an_mcp_call_is_split_only_where_the_server_is_known() {
        let call = |name: &str, server: Option<&str>| {
            let mut input: CopilotHookInput = serde_json::from_value(json!({
                "session_id": "session-1",
                "tool_name": name,
            }))
            .unwrap();
            input.withhuman_mcp_server = server.map(str::to_owned);
            input
        };

        // A server's own name holds hyphens, so only the known server splits it.
        let input = call(
            "github-mcp-server-get_file_contents",
            Some("github-mcp-server"),
        );
        assert_eq!(
            input.mcp_call(),
            Some(("github-mcp-server", "get_file_contents"))
        );
        assert_eq!(
            call("github-mcp-server-get_file_contents", None).mcp_call(),
            None
        );
        // One of Copilot's own tools matches no server's name.
        assert_eq!(call("Bash", Some("github-mcp-server")).mcp_call(), None);
        // A server that does not match the name leaves it alone.
        assert_eq!(call("other-write_file", Some("fixture")).mcp_call(), None);
    }

    /// Both spellings reach the same fields, including the one payload that mixes them.
    #[test]
    fn either_spelling_of_a_field_parses() {
        let claude: CopilotHookInput = serde_json::from_value(json!({
            "session_id": "s", "tool_name": "Bash", "tool_use_id": "call_1",
            "tool_input": {"command": "ls"}, "transcript_path": "/t",
        }))
        .unwrap();
        let copilot: CopilotHookInput = serde_json::from_value(json!({
            "sessionId": "s", "toolName": "bash", "toolCallId": "call_1",
            "toolArgs": {"command": "ls"}, "transcriptPath": "/t",
        }))
        .unwrap();
        assert_eq!(claude.session_id, copilot.session_id);
        assert_eq!(claude.tool_use_id, copilot.tool_use_id);
        assert_eq!(claude.tool_input, copilot.tool_input);
        assert_eq!(claude.transcript_path, copilot.transcript_path);
        assert!(claude.additional_fields.is_empty());
        assert!(copilot.additional_fields.is_empty());

        // SubagentStart sends camelCase and snake_case together.
        let mixed: CopilotHookInput = serde_json::from_value(json!({
            "sessionId": "s", "agentName": "explore",
            "agent_id": "a", "agent_type": "explore", "parent_agent_id": "s",
        }))
        .unwrap();
        assert_eq!(mixed.agent_name.as_deref(), Some("explore"));
        assert_eq!(mixed.agent_id.as_deref(), Some("a"));
        assert!(mixed.additional_fields.is_empty());
    }
}
