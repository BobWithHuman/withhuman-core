//! Antigravity CLI's adapter: translates its Hooks into the Claude Code Hook requests the
//! Collector already handles. [`crate::agent`] is the seam it is plugged into; everything here
//! is Antigravity's own.
//!
//! Antigravity's tools and their arguments are its own — a call arrives as one `toolCall` whose
//! arguments are spelled the way that tool spells them (`CommandLine`, `Path`, `Content`) — so
//! the translation renames both:
//!
//! | Antigravity | Claude Code |
//! |---|---|
//! | `run_command` | `Bash`, or `PowerShell` when the bridge reports that shell; `CommandLine` becomes `command` |
//! | `read_file` | `Read`, with `Path` under the name the rules read it by (`file_path`) |
//! | `write_file` | `Write`, with `Path` / `Content` under `file_path` / `content` |
//! | `edit_file` | `Edit`, with `Path` / `Target` / `Replacement` under `file_path` / `old_string` / `new_string` |
//! | `invoke_subagent` | `Task`, with `Prompt` / `TypeName` under `prompt` / `subagent_type` |
//! | `call_mcp_tool` | `mcp__<server>__<tool>`, from the `ServerName` and `ToolName` it carries |
//! | any other | the same name and arguments, marked [`UNTRANSLATED`] |
//!
//! Antigravity has over a hundred step types it can run as tools, and only the four above have
//! been seen in a real session. The rest are passed through under their own names rather than
//! translated from their documentation: a guessed argument name would have the engine judge a
//! file write whose path it cannot read. [`UNTRANSLATED`] says which Calls those were, so the
//! next capture turns them into translations instead of guesses.
//!
//! What the Hooks leave out and the bridge supplies: the turn (`withhuman_turn`, minted on the
//! invocation that opens one, since no Hook carries a turn), what a Call brought in
//! (`withhuman_result`, read from the session transcript, since `PostToolUse` says only
//! whether the Call failed), the program files a shell command may run
//! (`withhuman_programs`), and the model's answer, which the bridge sends as a Claude Code
//! `MessageDisplay` of its own.

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};
use withhuman_contracts::{
    antigravity::{AntigravityHookEvent, AntigravityHookInput, AntigravityToolCall, MCP_TOOL},
    hooks::{
        ClientShell, HookEventName, PostToolBatchRequest, PostToolUseFailureRequest,
        PostToolUseRequest, PreToolUseRequest, SessionStartRequest, UserPromptSubmitRequest,
    },
};

use crate::{
    FailurePolicy, HookPolicy, ReviewPolicy,
    agent::{Agent, Incoming, Rejection, SHELL_HEADER, Translated},
    http::header_value,
};

/// Marks every event of an Antigravity session, and the `<kind>` of its route.
pub const AGENT_KIND: &str = "antigravity";
/// Set on a Call whose tool this adapter has no translation for: the engine has the Call, but
/// the rules for the tool it stands for are not the ones judging it.
pub const UNTRANSLATED: &str = "antigravity_untranslated";
/// Antigravity's own names for the tools this adapter translates.
const SHELL_TOOL: &str = "run_command";
const READ_TOOL: &str = "read_file";
const WRITE_TOOL: &str = "write_file";
const EDIT_TOOL: &str = "edit_file";
const SUBAGENT_TOOL: &str = "invoke_subagent";

/// Antigravity's adapter.
pub struct Antigravity;

impl Agent for Antigravity {
    fn kind(&self) -> &'static str {
        AGENT_KIND
    }

    /// Antigravity blocks a Call on every way a Hook can fail — a `deny`, a non-zero exit, a
    /// timeout, an answer that does not parse — so a Call that cannot be judged is blocked
    /// whatever goes wrong. Its `ask` is not a block: a session run with
    /// `--dangerously-skip-permissions` answers it itself, which would turn a REVIEW into an
    /// allow, so a REVIEW denies. MCP calls are judged on the Hook rather than by
    /// AgentGateway, which reads an id only Claude Code stamps.
    fn policy(&self) -> HookPolicy {
        HookPolicy {
            review: ReviewPolicy::Deny,
            mcp_at_hook: true,
            failure: FailurePolicy::Closed,
            resends: true,
        }
    }

    fn request_headers(&self) -> &'static [&'static str] {
        &[SHELL_HEADER]
    }

    fn translate(
        &self,
        event: &str,
        raw: Value,
        headers: &HeaderMap,
    ) -> Result<Incoming, Rejection> {
        let Some(event) = AntigravityHookEvent::from_path(event) else {
            return Err(Rejection::unknown_event());
        };
        // The bridge makes this one from the session transcript, in its Claude Code form: the
        // model's answer is in no Antigravity Hook. Antigravity cannot hide text it has shown,
        // so only the event matters, and there is no Hook to keep with it.
        if event == AntigravityHookEvent::MessageDisplay {
            let request = serde_json::from_value(raw).map_err(|_| Rejection::invalid_json())?;
            return Ok(Incoming::new(Translated::MessageDisplay(request)));
        }
        let input: AntigravityHookInput =
            serde_json::from_value(raw.clone()).map_err(|_| Rejection::invalid_json())?;
        let shell = ClientShell::from_header(header_value(headers, SHELL_HEADER).as_deref());
        let request = translate(event, &input, shell)?;
        // Program files are kept with the Call already; the copy keeps the rest as sent.
        let mut payload = raw;
        if let Some(fields) = payload.as_object_mut() {
            fields.remove("withhuman_programs");
        }
        let mut incoming = Incoming::new(request).with_payload(payload);
        if untranslated(event, &input) {
            incoming = incoming.with_flag(UNTRANSLATED, json!(true));
        }
        Ok(incoming)
    }
}

/// A Call whose tool this adapter passes through under Antigravity's own name.
fn untranslated(event: AntigravityHookEvent, input: &AntigravityHookInput) -> bool {
    if !matches!(
        event,
        AntigravityHookEvent::PreToolUse | AntigravityHookEvent::PostToolUse
    ) {
        return false;
    }
    let Some(name) = input
        .tool_call
        .as_ref()
        .and_then(|call| call.name.as_deref())
    else {
        return false;
    };
    !matches!(
        name,
        SHELL_TOOL | READ_TOOL | WRITE_TOOL | EDIT_TOOL | SUBAGENT_TOOL | MCP_TOOL
    )
}

fn missing(field: &'static str) -> Rejection {
    // The field names are the client's; the code is the one its self-check knows.
    let _ = field;
    Rejection::new(StatusCode::BAD_REQUEST, "invalid_antigravity_hook")
}

/// One Antigravity Hook as the Claude Code request doing the same thing.
pub fn translate(
    event: AntigravityHookEvent,
    input: &AntigravityHookInput,
    shell: ClientShell,
) -> Result<Translated, Rejection> {
    use AntigravityHookEvent as Event;
    // A subagent's events carry its own conversation and the one it was delegated from; the
    // engine keeps them inside the session they came from, with the subagent as the agent.
    let session = || -> Result<(String, Option<String>), Rejection> {
        input.session().ok_or_else(|| missing("conversationId"))
    };
    let session_id = || -> Result<String, Rejection> { Ok(session()?.0) };
    Ok(match event {
        Event::SessionStart => Translated::SessionStart(SessionStartRequest {
            session_id: session_id()?,
            hook_event_name: Some(HookEventName::SessionStart),
            transcript_path: input.transcript_path.clone(),
            cwd: input.cwd.clone(),
            // Antigravity says what model the session runs, not where the session came from.
            source: None,
            permission_mode: None,
            model: input.model_name.clone(),
        }),
        // The invocation that opens a turn is the turn's prompt: Antigravity has no Hook for a
        // prompt, and carries the prompt on every event instead. A later invocation of the
        // same turn is the model being called again, which the engine has nothing to do with.
        //
        // A subagent's session opens with no prompt at all — nobody typed one — so there is
        // nothing to send and its Calls are judged under a turn of their own. The bridge marks
        // the one invocation the prompt is new on: an invocation of 0 comes again within one
        // prompt, and sending it twice would split one turn into two.
        Event::PreInvocation
            if input.withhuman_new_turn
                && !input.last_user_input.as_deref().unwrap_or("").is_empty() =>
        {
            Translated::UserPromptSubmit(UserPromptSubmitRequest {
                session_id: session_id()?,
                hook_event_name: Some(HookEventName::UserPromptSubmit),
                prompt: input
                    .last_user_input
                    .clone()
                    .ok_or_else(|| missing("lastUserInput"))?,
                prompt_id: input.withhuman_turn.clone(),
                transcript_path: input.transcript_path.clone(),
                cwd: input.cwd.clone(),
                permission_mode: None,
            })
        }
        Event::PreToolUse => {
            let (session_id, agent_id) = session()?;
            let (tool_name, tool_input) = call(input, shell)?;
            Translated::PreToolUse(PreToolUseRequest {
                session_id,
                hook_event_name: Some(HookEventName::PreToolUse),
                tool_name,
                tool_input,
                tool_use_id: tool_use_id(input)?,
                cwd: input.cwd.clone(),
                prompt_id: input.withhuman_turn.clone(),
                agent_id,
                agent_type: None,
                permission_mode: None,
                withhuman_programs: input.withhuman_programs.clone(),
                withhuman_instructions: Vec::new(),
            })
        }
        Event::PostToolUse => {
            let (session_id, agent_id) = session()?;
            let (tool_name, tool_input) = call(input, shell)?;
            let tool_use_id = tool_use_id(input)?;
            // Antigravity reports a failure as the text of the error, and an empty string when
            // the Call succeeded.
            match input
                .error
                .as_deref()
                .map(str::trim)
                .filter(|e| !e.is_empty())
            {
                Some(error) => Translated::PostToolUseFailure(PostToolUseFailureRequest {
                    session_id: session_id.clone(),
                    hook_event_name: Some(HookEventName::PostToolUseFailure),
                    tool_name,
                    tool_input: Some(tool_input),
                    error: error.to_owned(),
                    tool_use_id,
                    cwd: input.cwd.clone(),
                    prompt_id: input.withhuman_turn.clone(),
                    agent_id: agent_id.clone(),
                    agent_type: None,
                    permission_mode: None,
                }),
                None => Translated::PostToolUse(PostToolUseRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PostToolUse),
                    tool_response: response(&tool_name, input),
                    tool_name,
                    tool_input: Some(tool_input),
                    tool_use_id,
                    cwd: input.cwd.clone(),
                    prompt_id: input.withhuman_turn.clone(),
                    agent_id,
                    agent_type: None,
                    permission_mode: None,
                }),
            }
        }
        // The loop ended, which closes the turn's open tool batch.
        Event::Stop => {
            let (session_id, agent_id) = session()?;
            Translated::PostToolBatch(PostToolBatchRequest {
                session_id,
                hook_event_name: Some(HookEventName::PostToolBatch),
                agent_id,
                agent_type: None,
                tool_calls: Vec::new(),
            })
        }
        // A later invocation of a turn, and the model's answer, which arrives as a
        // `MessageDisplay` the bridge made.
        Event::PreInvocation | Event::PostInvocation => Translated::Nothing,
        // Handled before the translation, which has no Antigravity Hook to read.
        Event::MessageDisplay => Translated::Nothing,
    })
}

/// The id the Call and its result share. Antigravity gives every call one.
fn tool_use_id(input: &AntigravityHookInput) -> Result<String, Rejection> {
    input
        .tool_call
        .as_ref()
        .and_then(|call| call.id.clone())
        .ok_or_else(|| missing("toolCall.id"))
}

/// The call as its Claude Code counterpart: the tool doing the same thing, and its arguments
/// under the names the rules for that tool read.
fn call(input: &AntigravityHookInput, shell: ClientShell) -> Result<(String, Value), Rejection> {
    let call = input
        .tool_call
        .as_ref()
        .ok_or_else(|| missing("toolCall"))?;
    let name = call
        .name
        .as_deref()
        .ok_or_else(|| missing("toolCall.name"))?;
    let arguments = call.args.clone().unwrap_or(Value::Null);
    // An MCP call names its server and tool in its own arguments, so the name the engine
    // knows MCP by needs nothing guessed and the server's arguments travel as the input.
    if let Some((server, tool)) = call.mcp_call() {
        let inner = call.arg("Arguments").cloned().unwrap_or(Value::Null);
        return Ok((format!("mcp__{server}__{tool}"), inner));
    }
    Ok(match name {
        SHELL_TOOL => (
            shell.tool_name().to_owned(),
            json!({ "command": call.text("CommandLine").unwrap_or_default() }),
        ),
        // The rules read a file's path as `file_path`.
        READ_TOOL => ("Read".to_owned(), json!({ "file_path": path(call, input) })),
        WRITE_TOOL => (
            "Write".to_owned(),
            json!({
                "file_path": path(call, input),
                "content": call.text("Content").unwrap_or_default(),
            }),
        ),
        // One replacement in a file, which is Claude Code's `Edit`. Without this the engine
        // sees a tool it does not know, and the rules that deny a change to the agent's own
        // hooks never read the file it names — a Call that switched the supervision off was
        // allowed before it was translated.
        EDIT_TOOL => (
            "Edit".to_owned(),
            json!({
                "file_path": path(call, input),
                "old_string": call.text("Target").unwrap_or_default(),
                "new_string": call.text("Replacement").unwrap_or_default(),
            }),
        ),
        // Handing work to a subagent, which the engine judges as the delegation it is. The
        // subagent then runs as a session of its own; see the contract for why it is not
        // folded into this one.
        SUBAGENT_TOOL => (
            "Task".to_owned(),
            json!({
                "prompt": call.text("Prompt").unwrap_or_default(),
                "subagent_type": call.text("TypeName").unwrap_or_default(),
                "description": call.text("Role").unwrap_or_default(),
            }),
        ),
        other => (other.to_owned(), arguments),
    })
}

/// The file a Call names, as the key file reads and writes share: a relative path is resolved
/// against the directory the agent runs in, so a file one Call read is the file another wrote.
fn path(call: &AntigravityToolCall, input: &AntigravityHookInput) -> String {
    let named = call.text("Path").unwrap_or_default();
    crate::patch::file_key(input.cwd.as_deref(), named)
}

/// The result in the shape the rules for that tool read it by: a command's output as
/// `{stdout, stderr}`, a file's text as `{file: {content}}`, anything else as `{content}`.
/// Antigravity carries no result on the Hook, so this is what the bridge read from the
/// transcript; a result it could not read leaves the response empty rather than claiming the
/// Call brought in nothing.
fn response(tool_name: &str, input: &AntigravityHookInput) -> Value {
    let Some(text) = input.withhuman_result.as_deref() else {
        return Value::Object(Map::new());
    };
    match tool_name {
        "Bash" | "PowerShell" => json!({"stdout": text, "stderr": ""}),
        "Read" => json!({"file": {"content": text}}),
        _ => json!({"content": text}),
    }
}
