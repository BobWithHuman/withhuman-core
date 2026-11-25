//! Antigravity CLI Hook input as the Collector's Antigravity route receives it.
//!
//! Antigravity runs one process per Hook with the event's JSON on stdin; the WithHuman bridge
//! forwards it and may add the `withhuman_*` fields only the client can know. The Collector
//! translates it into the Claude Code Hook requests of [`crate::hooks`], so the same engine
//! logic judges Antigravity sessions as it judges Claude Code's.
//!
//! Antigravity's Hooks are its own, not Claude Code's: every field is camelCase (protojson),
//! a call arrives as one `toolCall` object, and the answer a Hook prints is a protobuf message
//! parsed **strictly** — an unknown field is an error, and an error blocks the call. So the
//! answer carries nothing but the fields the event's own result message names.
//!
//! What Antigravity's Hooks give, measured against Antigravity CLI 1.5.16 (fixtures under
//! `tests/fixtures/antigravity/`, and the reference the client itself ships):
//!
//! - **Every way a Hook can fail blocks the Call.** A `deny` blocks it with the reason on the
//!   user's screen; a Hook that exits non-zero blocks it; a Hook that runs past its timeout is
//!   killed and blocks it (30 seconds by default, `timeout` in **seconds** to change); an
//!   answer that does not parse blocks it. Only an empty answer allows the Call. No other
//!   agent WithHuman supports fails closed on all four.
//! - `decision` takes `allow`, `deny`, `ask` and `force_ask`, but **`ask` is not a block**: a
//!   session run with `--dangerously-skip-permissions` answers it itself, so a REVIEW is
//!   carried out as a deny.
//! - **An MCP call names its server and tool in the open**: `call_mcp_tool` with `ServerName`,
//!   `ToolName` and `Arguments`, so `mcp__<server>__<tool>` needs nothing guessed or
//!   remembered.
//! - **No Hook carries a turn**, and `invocation_num` is not one. It counts the model's
//!   invocations and starts again at 0 for the next loop — which happens **within one
//!   prompt** as well: a turn that waits for a subagent stops and re-enters at 0 with the
//!   same `last_user_input`. So the prompt is the turn: the bridge mints one when
//!   `last_user_input` changes, sends it as `withhuman_turn`, and marks the event it minted it
//!   on with `withhuman_new_turn`.
//! - **A Call's result is in no Hook.** `PostToolUse` says only whether it failed (`error`).
//!   What the call brought in is in the session transcript (`transcript_path`), under the
//!   `step_idx` the Hook carries; the bridge reads it there, with the model's answer.
//! - **A subagent runs under a conversation of its own.** `invoke_subagent` hands work to one,
//!   and the subagent's Hooks arrive under their own `conversation_id` with an empty
//!   `last_user_input` — nobody typed a prompt for it — and nothing in the payload names the
//!   session that spawned it. Its own transcript does: the message the parent sent it opens
//!   with `sender=<conversation id>`. The bridge reads it there and sends it as
//!   `withhuman_parent_session`, so the subagent's Calls are judged inside the session and the
//!   turn they were delegated from, against the intent that turn stated. Without it they are
//!   judged against no intent at all, which denied a subagent's own messaging as a deviation.
//! - The intent instruction reaches the model as an injected system message, which
//!   `SessionStart` and the invocation events answer with (`injectSteps`). It persists in the
//!   conversation, and the client renders it as a row the user can fold away.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::hooks::ProgramFile;

/// Antigravity Hook events the Collector's Antigravity route accepts. Antigravity has six, and
/// the bridge makes the two the engine needs and Antigravity has no Hook for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub enum AntigravityHookEvent {
    // ---- what the engine judges or records ----
    SessionStart,
    /// Before the model is called. The first of a turn (`invocation_num` 0) is where the turn
    /// opens, and so where the prompt is sent.
    PreInvocation,
    PreToolUse,
    PostToolUse,
    /// When the execution loop ends, which closes the turn's open tool batch.
    Stop,
    // ---- what the bridge makes from the transcript ----
    /// No Antigravity Hook carries the model's answer, which is where the `[의도]` line is.
    MessageDisplay,
    // ---- accepted and passed over ----
    /// After the model answered. The turn's calls are judged on their own Hooks, and the
    /// answer arrives as [`Self::MessageDisplay`].
    PostInvocation,
}

impl AntigravityHookEvent {
    /// The event as Antigravity names it in `hooks.json` and on the route.
    pub fn from_path(name: &str) -> Option<Self> {
        Some(match name {
            "SessionStart" => Self::SessionStart,
            "PreInvocation" => Self::PreInvocation,
            "PostInvocation" => Self::PostInvocation,
            "PreToolUse" => Self::PreToolUse,
            "PostToolUse" => Self::PostToolUse,
            "Stop" => Self::Stop,
            "MessageDisplay" => Self::MessageDisplay,
            _ => return None,
        })
    }

    /// Whether Antigravity reads this Hook's answer to decide a Call. Only `PreToolUse` does;
    /// `PostToolUse` is answered with an empty object.
    pub fn blocks_a_call(self) -> bool {
        matches!(self, Self::PreToolUse)
    }
}

/// Antigravity's name for a call to an MCP server's tool. The server and the tool are in its
/// arguments, so an MCP call is named without anything being guessed.
pub const MCP_TOOL: &str = "call_mcp_tool";

/// One Antigravity Hook's stdin, with what the bridge added.
///
/// Antigravity sends camelCase (protojson); the names here are the engine's own, with the
/// client's spelling as an alias. Every field is optional: one Hook carries a handful of them,
/// and Antigravity adds fields between versions. What this type does not name is kept in
/// `additional_fields` and travels with the event as evidence.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct AntigravityHookInput {
    /// The conversation, which is the session: it holds across the turns of one run.
    #[serde(default, alias = "conversationId")]
    pub conversation_id: Option<String>,
    #[serde(default, alias = "hookEventName")]
    pub hook_event_name: Option<String>,
    /// The directory the agent's own commands run in — not the Hook process's.
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default, alias = "workspacePaths")]
    pub workspace_paths: Option<Vec<String>>,
    /// The session transcript, which holds the model's answers and what each Call brought in.
    #[serde(default, alias = "transcriptPath")]
    pub transcript_path: Option<String>,
    #[serde(default, alias = "artifactDirectoryPath")]
    pub artifact_directory_path: Option<String>,
    #[serde(default, alias = "modelName")]
    pub model_name: Option<String>,
    /// The prompt of the turn the event belongs to, on every event of that turn.
    #[serde(default, alias = "lastUserInput")]
    pub last_user_input: Option<String>,

    // ---- a call ----
    /// `PreToolUse` and `PostToolUse`: the call, as Antigravity's own tool and arguments.
    #[serde(default, alias = "toolCall")]
    pub tool_call: Option<AntigravityToolCall>,
    /// Where the call sits in the conversation's steps, which is how its result is found in
    /// the transcript. It counts across the whole conversation, not within a turn.
    #[serde(default, alias = "stepIdx")]
    pub step_idx: Option<i64>,
    /// `PostToolUse`: why the call failed, when it did. `Stop` carries one of its own.
    #[serde(default)]
    pub error: Option<String>,

    // ---- a turn ----
    /// The invocation within the turn. `0` opens a turn: it starts again at `0` for the next
    /// one.
    #[serde(default, alias = "invocationNum")]
    pub invocation_num: Option<i64>,
    #[serde(default, alias = "initialNumSteps")]
    pub initial_num_steps: Option<i64>,

    // ---- a turn's end ----
    #[serde(default, alias = "executionNum")]
    pub execution_num: Option<i64>,
    /// Why the loop ended (`NO_TOOL_CALL`, `ERROR`, `USER_CANCELED`, …).
    #[serde(default, alias = "terminationReason")]
    pub termination_reason: Option<String>,
    #[serde(default, alias = "fullyIdle")]
    pub fully_idle: Option<bool>,
    /// Whether the agent is still doing work a `Stop` Hook asked for.
    #[serde(default, alias = "continuationActive")]
    pub continuation_active: Option<bool>,

    // ---- what the bridge added ----
    /// Set by the bridge: the turn the event belongs to, and so Claude Code's `prompt_id`. No
    /// Antigravity Hook carries one.
    #[serde(default)]
    pub withhuman_turn: Option<String>,
    /// Set by the bridge on the one event that opened the turn: the prompt is new here, so
    /// this is where it is sent. An invocation of 0 is not enough — it comes again within one
    /// prompt.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub withhuman_new_turn: bool,
    /// Set by the bridge on a `PostToolUse`: what the call brought in, read from the
    /// transcript, since the Hook carries only whether it failed.
    #[serde(default)]
    pub withhuman_result: Option<String>,
    /// Set by the bridge on a subagent's event: the conversation it was delegated from, read
    /// from the `sender=` of the message that started it. `conversation_id` then names the
    /// subagent itself.
    #[serde(default)]
    pub withhuman_parent_session: Option<String>,
    /// Local program files a shell call may run, read by the bridge just before the call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withhuman_programs: Vec<ProgramFile>,

    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: BTreeMap<String, Value>,
}

/// One call, as Antigravity sends it. Its `args` are the tool's own, in the tool's own
/// spelling (`CommandLine`, `Path`, …).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct AntigravityToolCall {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub args: Option<Value>,
}

impl AntigravityToolCall {
    /// An argument of this call, by the name the tool gives it.
    pub fn arg(&self, name: &str) -> Option<&Value> {
        self.args.as_ref()?.get(name)
    }

    /// An argument as text.
    pub fn text(&self, name: &str) -> Option<&str> {
        self.arg(name)?.as_str()
    }

    /// The server and tool of an MCP call, which Antigravity names in the open.
    pub fn mcp_call(&self) -> Option<(&str, &str)> {
        if self.name.as_deref() != Some(MCP_TOOL) {
            return None;
        }
        Some((self.text("ServerName")?, self.text("ToolName")?))
    }
}

impl AntigravityHookInput {
    /// The session the event belongs to, and the agent inside it when a subagent raised it.
    ///
    /// A subagent's events carry its own conversation; the engine keeps them inside the
    /// session they were delegated from, as Claude Code's subagents are.
    pub fn session(&self) -> Option<(String, Option<String>)> {
        let own = self.conversation_id.clone()?;
        Some(match self.withhuman_parent_session.as_deref() {
            Some(parent) if parent != own => (parent.to_owned(), Some(own)),
            _ => (own, None),
        })
    }

    /// Whether this event could open a turn: the first invocation of a loop. It is not a turn
    /// on its own — the loop re-enters at 0 within one prompt — so the bridge decides by the
    /// prompt and marks what it decided in `withhuman_new_turn`.
    pub fn opens_a_loop(&self) -> bool {
        self.hook_event_name.as_deref() == Some("PreInvocation") && self.invocation_num == Some(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_mcp_call_names_its_server_and_tool_in_the_open() {
        let call: AntigravityToolCall = serde_json::from_value(json!({
            "id": "call_1", "name": "call_mcp_tool",
            "args": {"ServerName": "withhuman-fixture", "ToolName": "write_file",
                     "Arguments": {"path": "a.txt"}},
        }))
        .unwrap();
        assert_eq!(call.mcp_call(), Some(("withhuman-fixture", "write_file")));

        // One of Antigravity's own tools is not an MCP call.
        let shell: AntigravityToolCall = serde_json::from_value(json!({
            "name": "run_command", "args": {"CommandLine": "ls"},
        }))
        .unwrap();
        assert_eq!(shell.mcp_call(), None);
        assert_eq!(shell.text("CommandLine"), Some("ls"));
    }

    /// A turn opens on the first invocation of one. Without this the calls of every turn of a
    /// session would be judged against one turn.
    #[test]
    fn a_loop_opens_on_the_first_invocation_of_one() {
        let event = |name: &str, invocation: Option<i64>| -> AntigravityHookInput {
            let mut input: AntigravityHookInput = serde_json::from_value(json!({
                "conversationId": "c1", "hookEventName": name,
            }))
            .unwrap();
            input.invocation_num = invocation;
            input
        };
        assert!(event("PreInvocation", Some(0)).opens_a_loop());
        assert!(!event("PreInvocation", Some(1)).opens_a_loop());
        assert!(!event("PostInvocation", Some(0)).opens_a_loop());
        assert!(!event("PreToolUse", None).opens_a_loop());
    }

    /// A subagent's events belong to the session it was delegated from, with the subagent
    /// itself as the agent inside it.
    #[test]
    fn a_subagents_events_belong_to_the_session_it_was_delegated_from() {
        let mut input: AntigravityHookInput = serde_json::from_value(json!({
            "conversationId": "agent-1",
        }))
        .unwrap();
        assert_eq!(input.session(), Some(("agent-1".to_owned(), None)));
        input.withhuman_parent_session = Some("session-1".to_owned());
        assert_eq!(
            input.session(),
            Some(("session-1".to_owned(), Some("agent-1".to_owned())))
        );
        // A session that names itself as its own parent is nobody's subagent.
        input.withhuman_parent_session = Some("agent-1".to_owned());
        assert_eq!(input.session(), Some(("agent-1".to_owned(), None)));
    }

    #[test]
    fn the_clients_spelling_parses_into_the_engines_names() {
        let input: AntigravityHookInput = serde_json::from_value(json!({
            "conversationId": "c1", "hookEventName": "PreToolUse",
            "lastUserInput": "fix the build", "stepIdx": 7,
            "transcriptPath": "/t.jsonl", "workspacePaths": ["/repo"],
            "artifactDirectoryPath": "/a", "modelName": "auto",
            "toolCall": {"id": "call_1", "name": "run_command", "args": {"CommandLine": "ls"}},
            "cwd": "/repo",
        }))
        .unwrap();
        assert_eq!(input.conversation_id.as_deref(), Some("c1"));
        assert_eq!(input.last_user_input.as_deref(), Some("fix the build"));
        assert_eq!(input.step_idx, Some(7));
        assert_eq!(
            input.workspace_paths.as_deref(),
            Some(&["/repo".to_owned()][..])
        );
        assert_eq!(
            input
                .tool_call
                .as_ref()
                .and_then(|call| call.name.as_deref()),
            Some("run_command")
        );
        assert!(
            input.additional_fields.is_empty(),
            "unmodelled: {:?}",
            input.additional_fields
        );
    }
}
