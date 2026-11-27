//! OpenClaw Hook input as the Collector's OpenClaw route receives it.
//!
//! OpenClaw has two Hook systems and only one of them can hold a Call back. Its automation
//! Hooks (`openclaw hooks`, a workspace's `hooks/` folder) carry no tool event at all and
//! cannot abort what they observe. Its **plugin** Hooks do: a plugin registered in the Gateway
//! (`api.on("before_tool_call", …)`) is handed the Call before it runs and blocks it by
//! returning `{ block: true, blockReason }`, or asks the user with `requireApproval`. So the
//! WithHuman client is a plugin, and what reaches this route is what that plugin posts: the
//! Hook's own event, with the fields of its context that only the context carries. The
//! Collector translates it into the Claude Code Hook requests of [`crate::hooks`], so the same
//! engine logic judges OpenClaw sessions as it judges Claude Code's.
//!
//! What OpenClaw's Hooks give, verified against OpenClaw 2026.11.7 (captures under
//! `tests/fixtures/openclaw/`):
//!
//! - [`OpenClawHookEvent::BeforeToolCall`] covers every tool, **with the directory already
//!   filled in** (`params.workdir`), so a shell call needs nothing read back from a
//!   transcript. [`OpenClawHookEvent::AfterToolCall`] carries the tool's whole result, a shell
//!   call's `exitCode` and a file edit's unified `patch` included.
//! - A failed call still arrives with `error: null`: what failed is in `result.details`
//!   (`exitCode`, or a `status` of its own such as `not_found`), and `details.status` of
//!   `completed` means the program ran, not that it succeeded.
//! - **The conversation Hooks are refused unless the plugin is allowed them.** Without
//!   `plugins.entries.<id>.hooks.allowConversationAccess = true` OpenClaw blocks
//!   [`OpenClawHookEvent::BeforeAgentRun`] and the rest of the turn's Hooks, so a setup
//!   without it reaches the engine with Calls but no prompt and no intent line.
//! - `runId` is the turn: a prompt and every Call it leads to share it. It becomes Claude
//!   Code's `prompt_id`.
//! - **A Call may run another Call.** `dispatch_action` names an action in its `params.id`
//!   ([`dispatched_action`]) and passes its arguments in `params.args`; the action then
//!   arrives a second time as a Call of its own, whose `toolCallId` holds the dispatching
//!   call's ([`dispatched_by`]). Both carry the real tool and the real arguments, so the
//!   **dispatching call is the one judged** and the Call it runs is passed over as the
//!   duplicate it is: blocking a `dispatch_action` keeps the action from being dispatched at
//!   all, while what blocking the dispatched Call does is not known — the engine does not put
//!   its only gate on the one of the two whose answer may arrive too late to matter.
//! - **An MCP call reaches the same Hook**, so the Hook judges MCP as it judges any other
//!   Call. Its tool is named `<server>__<tool>` and its action id `mcp:<server>:<server>__<tool>`,
//!   so Claude Code's name for it is `mcp__` and the tool name as it stands; the result adds
//!   `details.mcpServer` and `details.mcpTool`. Nothing has to be remembered from an earlier
//!   Hook, as Cursor's server name does.
//! - OpenClaw's tool surface is not fixed: `tool_search` and `tool_describe` let the model
//!   look tools up mid-turn, so what an agent can call cannot be read off the session's start.
//! - `session_start` and `session_end` did not fire in any captured session, resumed or not,
//!   so the client opens a session itself (`withhuman_synthesized`) rather than wait for them.
//!
//! Every Hook the plugin can register is named here, including those the engine has nothing to
//! do with: a Hook the route turned away as unknown would, on the events that decide a Call,
//! be answered as a failure and block it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::hooks::ProgramFile;

/// OpenClaw plugin Hook events the Collector's OpenClaw route accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub enum OpenClawHookEvent {
    // ---- what the engine judges or records ----
    SessionStart,
    SessionEnd,
    BeforeAgentRun,
    BeforeToolCall,
    AfterToolCall,
    AgentEnd,
    BeforeAgentFinalize,
    /// Every message the transcript is about to keep, the agent's own among them, and the
    /// agent's arrives **before the Calls it announces run**. That is what makes it the
    /// answer the engine judges a first Call against: [`Self::BeforeAgentFinalize`] carries
    /// the answer the turn settled on, which is the last one, so a turn whose last answer is
    /// a tool's output has no `[의도]` line in it at all. See [`announced_answer`].
    ///
    /// It is synchronous: a handler that returns a promise is ignored and the host says so.
    /// A plugin can therefore keep what it carries, but cannot reach the engine from it.
    BeforeMessageWrite,
    SubagentSpawned,
    SubagentEnded,
    SkillChanged,
    BeforeInstall,
    CronChanged,
    // ---- accepted and passed over ----
    /// The prompt as the host assembled it, not as the user wrote it; the user's is on
    /// [`Self::BeforeAgentRun`].
    BeforePromptBuild,
    /// Fires at the turn's start, before [`Self::BeforeAgentRun`], and carries the inbound
    /// text alone (`cleanedBody`) — not the model's answer its name suggests.
    BeforeAgentReply,
    /// A channel's own delivery, which is not an agent Call.
    MessageReceived,
    MessageSending,
    /// The model's output and token counts; the answer the engine keeps arrives on
    /// [`Self::BeforeAgentFinalize`].
    LlmOutput,
}

impl OpenClawHookEvent {
    /// The event as OpenClaw names it to a plugin, and so on the route.
    pub fn from_path(name: &str) -> Option<Self> {
        Some(match name {
            "session_start" => Self::SessionStart,
            "session_end" => Self::SessionEnd,
            "before_agent_run" => Self::BeforeAgentRun,
            "before_tool_call" => Self::BeforeToolCall,
            "after_tool_call" => Self::AfterToolCall,
            "agent_end" => Self::AgentEnd,
            "before_agent_finalize" => Self::BeforeAgentFinalize,
            "before_message_write" => Self::BeforeMessageWrite,
            "subagent_spawned" => Self::SubagentSpawned,
            "subagent_ended" => Self::SubagentEnded,
            "skill_changed" => Self::SkillChanged,
            "before_install" => Self::BeforeInstall,
            "cron_changed" => Self::CronChanged,
            "before_prompt_build" => Self::BeforePromptBuild,
            "before_agent_reply" => Self::BeforeAgentReply,
            "message_received" => Self::MessageReceived,
            "message_sending" => Self::MessageSending,
            "llm_output" => Self::LlmOutput,
            _ => return None,
        })
    }

    /// Whether the plugin reads this Hook's answer to decide a Call. Only these need an answer
    /// in time; the rest are reported and forgotten.
    pub fn blocks_a_call(self) -> bool {
        matches!(self, Self::BeforeToolCall)
    }

    /// Whether OpenClaw refuses this Hook to a plugin that was not allowed the conversation
    /// (`plugins.entries.<id>.hooks.allowConversationAccess`). A setup without it keeps the
    /// Calls and loses the turn around them.
    ///
    /// [`Self::BeforeMessageWrite`] is not among them, although it carries the agent's own
    /// words: a capture made with the setting off holds it beside the Call Hooks and nothing
    /// else. It is the only way an answer reaches the engine in a setup that never turns the
    /// setting on.
    pub fn needs_conversation_access(self) -> bool {
        matches!(
            self,
            Self::BeforeAgentRun
                | Self::BeforePromptBuild
                | Self::BeforeAgentReply
                | Self::BeforeAgentFinalize
                | Self::AgentEnd
                | Self::LlmOutput
        )
    }
}

/// One OpenClaw Hook as the plugin posts it, with what the client added.
///
/// Every field is optional: one Hook carries a handful of them, and OpenClaw adds fields
/// between versions. What this type does not name is kept in `additional_fields` and travels
/// with the event as evidence.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenClawHookInput {
    /// The session the event belongs to. `session_key` is the same session as a name
    /// (`agent:main:main`); `session_id` is the one that changes when a session is replaced.
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub session_key: Option<String>,
    /// The turn, and so Claude Code's `prompt_id`: a prompt and every Call it leads to share
    /// it.
    #[serde(default)]
    pub run_id: Option<String>,
    /// The agent the event belongs to; a subagent has one of its own.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// The directory the agent works in. The turn's Hooks carry it; **the tool Hooks do
    /// not**, so the client fills it in from the turn it kept — without it a relative path in
    /// a Call resolves against nothing.
    #[serde(default)]
    pub workspace_dir: Option<String>,
    #[serde(default, rename = "hook_event_name")]
    pub hook_event_name: Option<String>,
    #[serde(default)]
    pub model_provider_id: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub sandboxed: Option<bool>,
    /// `before_agent_finalize`: the directory the turn ran in, and the session's transcript.
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<String>,

    // ---- who asked ----
    /// What set the turn going (`user`, and the host's own triggers).
    #[serde(default)]
    pub trigger: Option<String>,
    /// The channel the prompt came in on. OpenClaw takes work from chat channels as well as a
    /// terminal, so a prompt is not always the device owner's.
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub sender_id: Option<String>,
    /// Whether the sender owns this OpenClaw. False for anyone else who can reach it.
    #[serde(default)]
    pub sender_is_owner: Option<bool>,
    /// `before_tool_call`: who the Call is run for, as the host resolved it.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub requester: Option<Value>,

    // ---- a prompt and an answer ----
    /// `before_agent_run`: the prompt as the user submitted it.
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub images: Option<Vec<Value>>,
    /// `before_agent_reply`: the inbound text, cleaned.
    #[serde(default)]
    pub cleaned_body: Option<String>,
    /// `before_agent_finalize`: the answer the turn settled on, which opens with the `[의도]`
    /// line. This is the one the engine keeps.
    #[serde(default)]
    pub last_assistant_message: Option<String>,
    /// `before_message_write`: the message the transcript is about to keep. `role` is
    /// `user`, `assistant` or `toolResult`, and `content` is either a string or the parts the
    /// message is made of (`text`, `thinking`, `toolCall`). [`announced_answer`] reads an
    /// agent's out of it.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub message: Option<Value>,
    /// `llm_output`: the provider's last message as it came back — the whole message, its
    /// thinking blocks included, not the text alone. `assistant_texts` holds that.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub last_assistant: Option<Value>,
    #[serde(default)]
    pub assistant_texts: Option<Vec<String>>,

    // ---- a call ----
    /// OpenClaw's own tool name (`exec`, `read`, `write`, `edit`, `apply_patch`, `ls`,
    /// `ripgrep`, `web_search`, `dispatch_action`, …), or an MCP tool's.
    #[serde(default)]
    pub tool_name: Option<String>,
    /// The call's arguments, as the tool names them.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub params: Option<Value>,
    /// The call's id. A dispatched call's holds the call that dispatched it; see
    /// [`dispatched_by`].
    #[serde(default)]
    pub tool_call_id: Option<String>,
    /// Set only for tools that share a name; absent otherwise.
    #[serde(default)]
    pub tool_kind: Option<String>,
    #[serde(default)]
    pub tool_input_kind: Option<String>,
    /// `after_tool_call`: the tool's whole result — `content` as the model sees it, and
    /// `details` as the tool reports it (`exitCode`, a file edit's `patch`, a read's `kind`).
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub result: Option<Value>,
    /// `after_tool_call`: set only when the host itself failed the call. A program that exited
    /// non-zero leaves this null and says so in `result.details`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub error: Option<Value>,
    #[serde(default)]
    pub duration_ms: Option<u64>,

    // ---- a turn's end ----
    /// `agent_end`: that the run finished, **not** that it succeeded — a turn whose model
    /// failed still ends with `success: true` and says so in its last message.
    #[serde(default)]
    pub success: Option<bool>,

    // ---- a subagent ----
    #[serde(default)]
    pub child_session_key: Option<String>,
    #[serde(default)]
    pub target_session_key: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub outcome: Option<Value>,

    // ---- what the capture reduced ----
    /// The size of what the plugin does not send: the system prompt and the message history
    /// the Hook carried. Present in a capture, not in what a client posts.
    #[serde(default)]
    pub system_prompt_chars: Option<u64>,
    #[serde(default)]
    pub message_count: Option<u64>,

    // ---- what the client added ----
    /// Set by the client on the first event of a session OpenClaw never announced: it opens
    /// the session itself rather than lose the events before one.
    #[serde(
        default,
        rename = "withhuman_synthesized",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub withhuman_synthesized: bool,
    /// Set by the client on a Call it found after it ran: it is recorded, not judged before
    /// it runs.
    #[serde(
        default,
        rename = "withhuman_record",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub withhuman_record: bool,
    /// Local program files a shell call may run, read by the client just before the call.
    #[serde(
        default,
        rename = "withhuman_programs",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub withhuman_programs: Vec<ProgramFile>,

    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: BTreeMap<String, Value>,
}

/// The call that dispatched this one, as its id holds it: `dispatch_action` runs an action,
/// and the action arrives as a Call of its own named `tool_call:<caller>:<tool>:<n>`. None when
/// the Call is the agent's own.
///
/// This is what tells a dispatched Call apart from a Call the agent made itself, and so which
/// of the two Calls of one dispatch is the duplicate to pass over — the dispatching call is
/// the one judged, since blocking it is what keeps the action from running.
///
/// The caller is written with `_` where its own id has `|`, so [`dispatch_key`] puts a
/// dispatching call's id into the same form before the two are compared.
pub fn dispatched_by(tool_call_id: &str) -> Option<&str> {
    let rest = tool_call_id.strip_prefix("tool_call:")?;
    // `<caller>:<tool>:<n>` — the tool name and the index are taken off the end, since the
    // caller's own id may hold anything but a colon.
    let index = rest.rfind(':')?;
    let tool = rest[..index].rfind(':')?;
    match tool {
        0 => None,
        _ => Some(&rest[..tool]),
    }
}

/// A call's id in the form a call it dispatches writes it.
pub fn dispatch_key(tool_call_id: &str) -> String {
    tool_call_id.replace('|', "_")
}

/// The action a `dispatch_action` call runs, as its `params.id` names it:
/// `<namespace>:<group>:<tool>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchedAction<'a> {
    /// Where the action comes from: `openclaw` for one of the host's own, `mcp` for a server's.
    pub namespace: &'a str,
    /// What it belongs to within that namespace: `core`, or the MCP server's name.
    pub group: &'a str,
    /// The tool as the Call that runs it names it, `<server>__<tool>` for an MCP tool.
    pub tool: &'a str,
}

impl<'a> DispatchedAction<'a> {
    /// The MCP server this action goes to, or none when the host runs it itself. Claude Code's
    /// name for the tool is then `mcp__` and [`Self::tool`] as it stands, since that already
    /// holds the server.
    pub fn mcp_server(&self) -> Option<&'a str> {
        (self.namespace == "mcp").then_some(self.group)
    }
}

/// The action `dispatch_action` was given, read off its `params.id`
/// (`openclaw:core:agents_list`, `mcp:<server>:<server>__<tool>`). None when the id is not
/// three parts, so nothing is assumed of an id this host writes differently.
pub fn dispatched_action(id: &str) -> Option<DispatchedAction<'_>> {
    let mut parts = id.splitn(3, ':');
    let namespace = parts.next()?;
    let group = parts.next()?;
    // The tool keeps any colon of its own; only the first two parts are taken off.
    let tool = parts.next()?;
    match namespace.is_empty() || group.is_empty() || tool.is_empty() {
        true => None,
        false => Some(DispatchedAction {
            namespace,
            group,
            tool,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ids of one dispatch, as OpenClaw 2026.11.7 wrote them.
    const CALLER: &str =
        "call_feJSzSOKqbkMiGe16ECTW41s|fc_092f1d97530e9dc1006b04fa8474dc87d0a16726bda08c38c0";
    const DISPATCHED: &str = "tool_call:call_feJSzSOKqbkMiGe16ECTW41s_fc_092f1d97530e9dc1006b04fa8474dc87d0a16726bda08c38c0:agents_list:1";

    #[test]
    fn a_dispatched_call_names_the_call_that_ran_it() {
        assert_eq!(
            dispatched_by(DISPATCHED),
            Some(dispatch_key(CALLER).as_str())
        );
        // A call the agent made itself belongs to no other.
        assert_eq!(dispatched_by(CALLER), None);
    }

    #[test]
    fn nothing_is_assumed_of_an_id_that_is_not_a_dispatch() {
        assert_eq!(dispatched_by("tool_call:"), None);
        assert_eq!(dispatched_by("tool_call:only-one-part"), None);
        assert_eq!(dispatched_by("tool_call::tool:1"), None);
        assert_eq!(dispatched_by("call_plain"), None);
    }

    /// The two kinds of action one dispatch can name, as OpenClaw 2026.11.7 wrote them.
    #[test]
    fn a_dispatch_names_where_its_action_comes_from() {
        let own = dispatched_action("openclaw:core:agents_list").expect("the host's own action");
        assert_eq!(own.namespace, "openclaw");
        assert_eq!(own.group, "core");
        assert_eq!(own.tool, "agents_list");
        assert_eq!(own.mcp_server(), None);

        let mcp = dispatched_action("mcp:wh-probe:wh-probe__echo_back").expect("an MCP action");
        assert_eq!(mcp.mcp_server(), Some("wh-probe"));
        // Claude Code's name for it is `mcp__` and the tool as it stands.
        assert_eq!(format!("mcp__{}", mcp.tool), "mcp__wh-probe__echo_back");
    }

    #[test]
    fn nothing_is_assumed_of_an_action_id_of_another_shape() {
        assert_eq!(dispatched_action("agents_list"), None);
        assert_eq!(dispatched_action("openclaw:core"), None);
        assert_eq!(dispatched_action(":core:agents_list"), None);
        assert_eq!(dispatched_action("openclaw::agents_list"), None);
        assert_eq!(dispatched_action("openclaw:core:"), None);
    }

    #[test]
    fn a_hook_the_conversation_is_needed_for_is_known_as_one() {
        assert!(OpenClawHookEvent::BeforeAgentRun.needs_conversation_access());
        assert!(OpenClawHookEvent::AgentEnd.needs_conversation_access());
        // A Call is judged whether or not the plugin was allowed the conversation.
        assert!(!OpenClawHookEvent::BeforeToolCall.needs_conversation_access());
        assert!(OpenClawHookEvent::BeforeToolCall.blocks_a_call());
        assert!(!OpenClawHookEvent::AfterToolCall.blocks_a_call());
    }
}

/// An agent's answer as [`OpenClawHookEvent::BeforeMessageWrite`] carries it: the words it
/// wrote, and the Calls that same message announces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnnouncedAnswer {
    /// The message's own text, its `text` parts joined by a blank line. A `thinking` part is
    /// left out: it is the model's reasoning, which the engine does not keep.
    pub text: String,
    /// The ids of the Calls this answer announces, in the order it names them. Each arrives
    /// again as [`OpenClawHookEvent::BeforeToolCall`] with that id as its `toolCallId` —
    /// whole and unchanged, the `|` composite an OpenAI model's id carries included.
    pub calls: Vec<String>,
}

/// Reads an agent's answer out of a message `before_message_write` is about to keep. None
/// unless the message is the agent's own, so a prompt and a tool's output are passed over.
///
/// A message that announces Calls is the answer those Calls were made in: it reaches the
/// plugin before they run, which is what lets the turn's intent be known while the first one
/// is still being judged. Whether the agent puts any words there is the model's own habit —
/// some write the `[의도]` line beside the Call, others only in the answer that ends the turn.
pub fn announced_answer(message: &Value) -> Option<AnnouncedAnswer> {
    if message.get("role")?.as_str()? != "assistant" {
        return None;
    }
    let content = message.get("content");
    // A message with nothing but text carries it as a string rather than as parts.
    if let Some(text) = content.and_then(Value::as_str) {
        return Some(AnnouncedAnswer {
            text: text.trim().to_owned(),
            calls: Vec::new(),
        });
    }
    let mut texts = Vec::new();
    let mut calls = Vec::new();
    for part in content.and_then(Value::as_array).into_iter().flatten() {
        match part.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    let text = text.trim();
                    if !text.is_empty() {
                        texts.push(text.to_owned());
                    }
                }
            }
            Some("toolCall") => {
                if let Some(id) = part.get("id").and_then(Value::as_str) {
                    calls.push(id.to_owned());
                }
            }
            _ => {}
        }
    }
    Some(AnnouncedAnswer {
        text: texts.join("\n\n"),
        calls,
    })
}
