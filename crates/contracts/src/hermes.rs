//! Hermes Agent Hook input as the Collector's Hermes route receives it.
//!
//! Hermes calls a plugin's hook callbacks in its own process with keyword arguments; the
//! WithHuman plugin sends them as one JSON object, named by the hook, and adds the `withhuman_*`
//! fields only the client can know (the directory a command runs in, the MCP server of a tool).
//! The Collector translates it into the Claude Code Hook requests of [`crate::hooks`], so the
//! same engine logic judges both.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::hooks::ProgramFile;

/// Hermes hooks the Collector's Hermes route accepts, by the name Hermes gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HermesHookEvent {
    /// A new session's first turn.
    OnSessionStart,
    /// Once per turn, before the model is asked: the user's message.
    PreLlmCall,
    /// After each model response, before any tool it asked for runs: the assistant's text.
    PostApiRequest,
    /// Before a tool runs; its answer can block the call.
    PreToolCall,
    /// After a tool ran, failed or was blocked.
    PostToolCall,
    /// At each turn's end.
    OnSessionEnd,
    /// When the client closes the session.
    OnSessionFinalize,
    SubagentStart,
    SubagentStop,
}

impl HermesHookEvent {
    pub fn from_path(name: &str) -> Option<Self> {
        Some(match name {
            "on_session_start" => Self::OnSessionStart,
            "pre_llm_call" => Self::PreLlmCall,
            "post_api_request" => Self::PostApiRequest,
            "pre_tool_call" => Self::PreToolCall,
            "post_tool_call" => Self::PostToolCall,
            "on_session_end" => Self::OnSessionEnd,
            "on_session_finalize" => Self::OnSessionFinalize,
            "subagent_start" => Self::SubagentStart,
            "subagent_stop" => Self::SubagentStop,
            _ => return None,
        })
    }
}

/// The `platform` Hermes gives a delegated subagent's own hooks.
pub const SUBAGENT_PLATFORM: &str = "subagent";

/// One Hermes hook's keyword arguments, with what the plugin added. Hermes leaves out the
/// fields a hook does not have, so all are optional here; the translation names the ones each
/// hook needs.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize, ToSchema)]
pub struct HermesHookInput {
    /// The hook, as Hermes names it; the route's `<event>` decides, this is kept for the record.
    #[serde(default)]
    pub hook_event_name: Option<String>,
    /// The Hermes session the hook ran in. A delegated subagent has a session of its own.
    #[serde(default)]
    pub session_id: Option<String>,
    /// The conversation's first session: the same across compression and, for a subagent, its
    /// delegator's. Tool hooks only.
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    /// For a subagent's tool hooks, its subagent ID (`sa-…`).
    #[serde(default)]
    pub task_id: Option<String>,
    /// Where the session runs: `cli`, `tui`, `desktop`, a messaging platform, or `subagent`.
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    /// Set by the plugin: the session's working directory (`ctx.session_cwd()`), never the
    /// gateway process's own.
    #[serde(default)]
    pub cwd: Option<String>,
    /// `pre_llm_call`: the user's message, a string or, for a multimodal turn, content parts.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub user_message: Option<Value>,
    /// `pre_llm_call`: the delegator's session, for a subagent's turn.
    #[serde(default)]
    pub parent_session_id: Option<String>,
    /// `post_api_request`: the model call this response answered.
    #[serde(default)]
    pub api_request_id: Option<String>,
    #[serde(default)]
    pub api_call_count: Option<u64>,
    /// `post_api_request`: the response, with `assistant_message.content` and `.tool_calls`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub response: Option<Value>,
    #[serde(default)]
    pub tool_name: Option<String>,
    /// The tool's arguments as the model gave them (after any plugin rewrite).
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub args: Option<Value>,
    /// The model's ID for the call. Empty for a call a script made through `execute_code`; the
    /// plugin then gives it one of its own.
    #[serde(default)]
    pub tool_call_id: Option<String>,
    /// `post_tool_call`: the tool's result, a JSON string.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub result: Option<Value>,
    /// `post_tool_call`: `ok`, `error` or `blocked`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error_type: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    /// `on_session_finalize`: why the session closed.
    #[serde(default)]
    pub reason: Option<String>,
    /// `subagent_start` / `subagent_stop`: the subagent's own session.
    #[serde(default)]
    pub child_session_id: Option<String>,
    #[serde(default)]
    pub child_role: Option<String>,
    /// Set by the plugin: the engine's session for this hook. Hermes gives a session a new ID
    /// when it compresses the context, and only tool hooks carry the conversation's first ID,
    /// so the plugin follows `post_compaction` and `subagent_start` and names the conversation
    /// every hook belongs to.
    #[serde(default)]
    pub withhuman_session_id: Option<String>,
    /// Set by the plugin on a delegated subagent's hooks: the subagent, as the engine's
    /// `agent_id`.
    #[serde(default)]
    pub withhuman_agent_id: Option<String>,
    /// Set by the plugin: the directory a `terminal` command runs in. Hermes keeps a `cd` for
    /// the session's later commands, so the plugin follows the directory each result reports.
    #[serde(default)]
    pub withhuman_workdir: Option<String>,
    /// Set by the plugin for an MCP tool (`mcp_<server>_<tool>`): its server, which the name
    /// alone cannot tell apart from the tool.
    #[serde(default)]
    pub withhuman_mcp_server: Option<String>,
    /// Local program files a `terminal` command may run, read by the plugin just before the call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withhuman_programs: Vec<ProgramFile>,
    #[serde(flatten)]
    #[schema(ignore)]
    pub additional_fields: BTreeMap<String, Value>,
}

fn named(value: Option<&String>) -> Option<&str> {
    value.map(String::as_str).filter(|id| !id.is_empty())
}

impl HermesHookInput {
    /// The engine's session: the plugin's, else the conversation a tool hook names, else the
    /// hook's own. Without the plugin's, a session Hermes compressed starts over in the engine.
    pub fn engine_session(&self) -> Option<&str> {
        named(self.withhuman_session_id.as_ref())
            .or_else(|| named(self.conversation_id.as_ref()))
            .or_else(|| named(self.session_id.as_ref()))
    }

    /// The subagent this hook belongs to: the plugin's, else, for a tool hook, its own session
    /// when that differs from the conversation's.
    pub fn agent_id(&self) -> Option<&str> {
        if self.withhuman_session_id.is_some() {
            return named(self.withhuman_agent_id.as_ref());
        }
        let session = named(self.session_id.as_ref())?;
        let conversation = named(self.conversation_id.as_ref())?;
        (session != conversation).then_some(session)
    }

    /// A delegated subagent's own hook: its turns state no intent of their own. Hermes also
    /// gives a session it rotates or resets a parent, so a parent alone tells a subagent only
    /// when the plugin, which sees the delegation, has not said.
    pub fn is_subagent(&self) -> bool {
        if self.platform.as_deref() == Some(SUBAGENT_PLATFORM) || self.agent_id().is_some() {
            return true;
        }
        self.withhuman_session_id.is_none() && named(self.parent_session_id.as_ref()).is_some()
    }
}
