//! Cursor CLI's adapter: translates its Hooks into the Claude Code Hook requests the Collector
//! already handles. [`crate::agent`] is the seam it is plugged into; everything here is
//! Cursor's own.
//!
//! Cursor's tool inputs are nearly Claude Code's already — it reads Claude Code hook settings
//! itself — so the translation is mostly a matter of names:
//!
//! | Cursor | Claude Code |
//! |---|---|
//! | `Shell` | `Bash`, or `PowerShell` when the bridge reports that shell |
//! | `Read` / `Write` / `Task` / `Glob` | the same name and input |
//! | `Grep` | `Grep`, with `file_path` under the name the rules read it by (`path`) |
//! | `MCP:<tool>` on a tool Hook | nothing: the server is unknown there |
//! | a tool on `beforeMCPExecution` | `mcp__<server>__<tool>`, the form the engine knows MCP by |
//! | any other | the same name and input |
//!
//! What the Hooks leave out and the bridge supplies: the server of an MCP result
//! (`withhuman_mcp_server`), the text of a file read (`withhuman_read_content`), the session a
//! subagent belongs to (`withhuman_parent_session`), and the program files a shell command may
//! run (`withhuman_programs`).

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};
use withhuman_contracts::{
    cursor::{CursorHookEvent, CursorHookInput, turn_of},
    hooks::{
        ClientShell, HookEventName, MessageDisplayRequest, PostToolBatchRequest,
        PostToolUseFailureRequest, PostToolUseRequest, PreToolUseRequest, SessionEndRequest,
        SessionStartRequest, UserPromptSubmitRequest,
    },
};

use crate::{
    FailurePolicy, HookPolicy, ReviewPolicy,
    agent::{Agent, Incoming, Rejection, SHELL_HEADER, Translated},
    http::header_value,
};

/// Marks every event of a Cursor session, and the `<kind>` of its route.
pub const AGENT_KIND: &str = "cursor";
/// Set on a file read whose text never reached the engine, so a read nobody could judge is
/// visible as such rather than looking like a read of nothing.
pub const READ_CONTENT_MISSING: &str = "missing";
/// What Cursor calls its shell tool.
const SHELL_TOOL: &str = "Shell";
/// Cursor's name for an MCP call on the tool Hooks, which does not say which server.
const MCP_PREFIX: &str = "MCP:";

/// Cursor's adapter.
pub struct Cursor;

impl Agent for Cursor {
    fn kind(&self) -> &'static str {
        AGENT_KIND
    }

    /// Cursor's `preToolUse` takes `deny` but its `ask` is not carried through to a real
    /// approval, so a REVIEW denies. MCP calls are judged on their own Hook rather than by
    /// AgentGateway, which reads an id only Claude Code stamps. A Call that cannot be judged is
    /// blocked — the client's `failClosed: true` blocks it even when this hook never answers.
    fn policy(&self) -> HookPolicy {
        HookPolicy {
            review: ReviewPolicy::Deny,
            mcp_at_hook: true,
            failure: FailurePolicy::Closed,
            resends: false,
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
        let Some(event) = CursorHookEvent::from_path(event) else {
            return Err(Rejection::unknown_event());
        };
        let input: CursorHookInput =
            serde_json::from_value(raw.clone()).map_err(|_| Rejection::invalid_json())?;
        let shell = ClientShell::from_header(header_value(headers, SHELL_HEADER).as_deref());
        let request = translate(event, &input, shell)?;
        // Program files are kept with the Call already; the copy keeps the rest as sent.
        let mut payload = raw;
        if let Some(fields) = payload.as_object_mut() {
            fields.remove("withhuman_programs");
        }
        let mut incoming = Incoming::new(request).with_payload(payload);
        if read_content_missing(event, &input) {
            incoming = incoming.with_flag("cursor_read_content", json!(READ_CONTENT_MISSING));
        }
        Ok(incoming)
    }
}

/// A file read whose text the bridge could not carry over: the engine has the call but not what
/// it brought in.
fn read_content_missing(event: CursorHookEvent, input: &CursorHookInput) -> bool {
    event == CursorHookEvent::PostToolUse
        && input.tool_name.as_deref() == Some("Read")
        && input.withhuman_read_content.is_none()
}

fn missing(field: &'static str) -> Rejection {
    // The field names are the client's; the code is the one its self-check knows.
    let _ = field;
    Rejection::new(StatusCode::BAD_REQUEST, "invalid_cursor_hook")
}

/// One Cursor Hook as the Claude Code request doing the same thing.
pub fn translate(
    event: CursorHookEvent,
    input: &CursorHookInput,
    shell: ClientShell,
) -> Result<Translated, Rejection> {
    use CursorHookEvent as Event;
    Ok(match event {
        Event::SessionStart => Translated::SessionStart(SessionStartRequest {
            session_id: session(input)?.0,
            hook_event_name: Some(HookEventName::SessionStart),
            transcript_path: input.transcript_path.clone(),
            cwd: input.cwd.clone(),
            // Cursor says whether the session is a background agent's, not where it came from.
            source: None,
            permission_mode: None,
            model: input.model.clone(),
        }),
        Event::SessionEnd => Translated::SessionEnd(SessionEndRequest {
            session_id: session(input)?.0,
            hook_event_name: Some(HookEventName::SessionEnd),
            transcript_path: input.transcript_path.clone(),
            cwd: input.cwd.clone(),
            permission_mode: None,
            reason: input.reason.clone().or_else(|| input.final_status.clone()),
        }),
        Event::BeforeSubmitPrompt => Translated::UserPromptSubmit(UserPromptSubmitRequest {
            session_id: session(input)?.0,
            hook_event_name: Some(HookEventName::UserPromptSubmit),
            prompt: input.prompt.clone().ok_or_else(|| missing("prompt"))?,
            prompt_id: turn(input),
            transcript_path: input.transcript_path.clone(),
            cwd: input.cwd.clone(),
            permission_mode: None,
        }),
        // An MCP call is judged on `beforeMCPExecution`, which is the only Hook that says which
        // server it goes to; this one would judge a call whose target is unknown.
        Event::PreToolUse if is_mcp_tool(input) => Translated::Nothing,
        Event::PreToolUse | Event::BeforeMcpExecution => {
            let (session_id, agent_id) = session(input)?;
            let (tool_name, tool_input) = call(event, input, shell)?;
            Translated::PreToolUse(PreToolUseRequest {
                session_id,
                hook_event_name: Some(HookEventName::PreToolUse),
                tool_name,
                tool_input,
                tool_use_id: tool_use_id(input)?,
                cwd: input.cwd.clone(),
                prompt_id: turn(input),
                agent_id,
                agent_type: None,
                permission_mode: None,
                withhuman_programs: input.withhuman_programs.clone(),
                withhuman_instructions: Vec::new(),
            })
        }
        Event::PostToolUse => {
            let (session_id, agent_id) = session(input)?;
            let (tool_name, tool_input) = call(event, input, shell)?;
            let tool_use_id = tool_use_id(input)?;
            let result = parsed_output(input);
            match failed_shell(&tool_name, &result) {
                // A shell call that exited non-zero: what it printed is kept, as Claude Code
                // keeps a failing command's output, so the text it brought in is still judged.
                Some((code, printed)) if !printed.is_empty() => {
                    Translated::PostToolUse(PostToolUseRequest {
                        session_id,
                        hook_event_name: Some(HookEventName::PostToolUse),
                        tool_name,
                        tool_input: Some(tool_input),
                        tool_response: json!({"stdout": printed, "stderr": format!("(exit code {code})")}),
                        tool_use_id,
                        cwd: input.cwd.clone(),
                        prompt_id: turn(input),
                        agent_id,
                        agent_type: None,
                        permission_mode: None,
                    })
                }
                Some((code, _)) => Translated::PostToolUseFailure(PostToolUseFailureRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PostToolUseFailure),
                    tool_name,
                    tool_input: Some(tool_input),
                    error: format!("exit code {code}"),
                    tool_use_id,
                    cwd: input.cwd.clone(),
                    prompt_id: turn(input),
                    agent_id,
                    agent_type: None,
                    permission_mode: None,
                }),
                None => Translated::PostToolUse(PostToolUseRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PostToolUse),
                    tool_response: response(&tool_name, input, result),
                    tool_name,
                    tool_input: Some(tool_input),
                    tool_use_id,
                    cwd: input.cwd.clone(),
                    prompt_id: turn(input),
                    agent_id,
                    agent_type: None,
                    permission_mode: None,
                }),
            }
        }
        Event::PostToolUseFailure => {
            let (session_id, agent_id) = session(input)?;
            let (tool_name, tool_input) = call(event, input, shell)?;
            Translated::PostToolUseFailure(PostToolUseFailureRequest {
                session_id,
                hook_event_name: Some(HookEventName::PostToolUseFailure),
                tool_name,
                tool_input: Some(tool_input),
                error: failure(input),
                tool_use_id: tool_use_id(input)?,
                cwd: input.cwd.clone(),
                prompt_id: turn(input),
                agent_id,
                agent_type: None,
                permission_mode: None,
            })
        }
        // The answer the model gave, whole. Cursor shows it before this Hook runs, so the
        // `[의도]` line stays on the user's screen; the engine keeps it as the turn's intent
        // either way.
        //
        // A turn has as many answers as the model had passes — a Call turned back for its
        // intent is followed by another answer — and Cursor names none of them. The turn's own
        // id would make the engine take them for flushes of one message and join them, which
        // swallowed the intent line of the first into a run-on first line. So each answer is a
        // message of its own, named after the turn and what it says.
        Event::AfterAgentResponse => {
            let turn = turn(input).ok_or_else(|| missing("generation_id"))?;
            let text = passes(input.text.as_deref().ok_or_else(|| missing("text"))?);
            Translated::MessageDisplay(MessageDisplayRequest {
                session_id: session(input)?.0,
                hook_event_name: Some(HookEventName::MessageDisplay),
                message_id: message_id(&turn, &text),
                index: Some(0),
                delta: text,
                final_: true,
                turn_id: Some(turn),
            })
        }
        // The turn ended, which closes its open tool batch.
        Event::Stop => {
            let (session_id, agent_id) = session(input)?;
            Translated::PostToolBatch(PostToolBatchRequest {
                session_id,
                hook_event_name: Some(HookEventName::PostToolBatch),
                agent_id,
                agent_type: None,
                tool_calls: Vec::new(),
            })
        }
        // Accepted and passed over; `withhuman_contracts::cursor` says why for each.
        Event::BeforeShellExecution
        | Event::AfterShellExecution
        | Event::AfterMcpExecution
        | Event::BeforeReadFile
        | Event::AfterFileEdit
        | Event::AfterAgentThought
        | Event::PreCompact
        | Event::WorkspaceOpen
        | Event::SubagentStart
        | Event::SubagentStop
        | Event::BeforeTabFileRead
        | Event::AfterTabFileEdit => Translated::Nothing,
    })
}

/// The session the event belongs to, and the agent inside it when a subagent raised it.
fn session(input: &CursorHookInput) -> Result<(String, Option<String>), Rejection> {
    let own = input
        .session_id
        .clone()
        .or_else(|| input.conversation_id.clone())
        .ok_or_else(|| missing("session_id"))?;
    Ok(match input.withhuman_parent_session.clone() {
        // A subagent runs under a session of its own; the engine keeps it inside the session it
        // was spawned from, as Claude Code's subagents are.
        Some(parent) if parent != own => (parent, Some(own)),
        _ => (own, None),
    })
}

/// Puts back the line breaks Cursor dropped between a turn's passes.
///
/// A turn has as many passes as the model took, and `afterAgentResponse` reports the text of
/// all of them joined with nothing in between. Newlines inside one pass survive, so the only
/// line that gets lost is the last of a pass — and when that is the `[의도]` line of a pass a
/// Call interrupted, the intent runs into the next pass's text and stops being a line, which
/// left the engine judging the turn against its whole answer instead of its intent.
///
/// Every pass the model opens with the marker is a line of its own, so a newline before each
/// marker but the first restores what the engine reads.
fn passes(text: &str) -> String {
    let mut restored = String::with_capacity(text.len() + 8);
    for (index, part) in text.split(withhuman_common::intent::MARKER).enumerate() {
        if index > 0 {
            if !restored.is_empty() && !restored.ends_with('\n') {
                restored.push('\n');
            }
            restored.push_str(withhuman_common::intent::MARKER);
        }
        restored.push_str(part);
    }
    restored
}

/// Names one answer of a turn. Cursor gives an answer no id of its own, so it is named after
/// the turn it belongs to and what it says: two answers of one turn stay two messages, and the
/// same answer reported twice stays one.
fn message_id(turn: &str, text: &str) -> String {
    let digest = withhuman_common::chunking::sha256(text);
    format!("{turn}-{}", &digest[..12])
}

/// The turn, as Claude Code's `prompt_id`.
fn turn(input: &CursorHookInput) -> Option<String> {
    input
        .generation_id
        .as_deref()
        .map(|id| turn_of(id).to_owned())
}

/// Cursor's ids for a tool call hold a newline. Keys, logs and traces read better without it,
/// and both the Call and its result are renamed the same way.
fn tool_use_id(input: &CursorHookInput) -> Result<String, Rejection> {
    let id = input
        .tool_use_id
        .as_deref()
        .ok_or_else(|| missing("tool_use_id"))?;
    Ok(id.split_whitespace().collect::<Vec<_>>().join("+"))
}

fn is_mcp_tool(input: &CursorHookInput) -> bool {
    input
        .tool_name
        .as_deref()
        .is_some_and(|name| name.starts_with(MCP_PREFIX))
}

/// The call as its Claude Code counterpart: the tool doing the same thing, and its input under
/// the names the rules for that tool read.
fn call(
    event: CursorHookEvent,
    input: &CursorHookInput,
    shell: ClientShell,
) -> Result<(String, Value), Rejection> {
    let name = input
        .tool_name
        .as_deref()
        .ok_or_else(|| missing("tool_name"))?;
    let arguments = input.tool_input.clone().unwrap_or(Value::Null);
    // The MCP Hooks send the arguments as a JSON string.
    let arguments = match &arguments {
        Value::String(text) => serde_json::from_str(text).unwrap_or(Value::Null),
        _ => arguments,
    };
    if event == CursorHookEvent::BeforeMcpExecution {
        let server = input
            .mcp_server_name
            .as_deref()
            .ok_or_else(|| missing("mcp_server_name"))?;
        return Ok((mcp_name(server, name), arguments));
    }
    if let Some(tool) = name.strip_prefix(MCP_PREFIX) {
        // A finished MCP call: the bridge remembered which server it went to.
        let server = input.withhuman_mcp_server.as_deref().unwrap_or("unknown");
        return Ok((mcp_name(server, tool), arguments));
    }
    Ok(match name {
        // Cursor puts an empty `cwd` in a shell call's input and the real one beside it.
        SHELL_TOOL => (
            shell.tool_name().to_owned(),
            json!({ "command": field(&arguments, "command") }),
        ),
        // The rules read a grep's target as `path`.
        "Grep" => {
            let mut fields = object(&arguments);
            if let Some(path) = fields.remove("file_path") {
                fields.insert("path".to_owned(), path);
            }
            ("Grep".to_owned(), Value::Object(fields))
        }
        other => (other.to_owned(), arguments),
    })
}

/// Why a call did not finish, as Cursor reports it: the message, and the kind of failure when
/// it says something the message does not (an interrupted call is not a failed one).
fn failure(input: &CursorHookInput) -> String {
    let message = input.error_message.clone().unwrap_or_default();
    let kind = match input.is_interrupt {
        Some(true) => "interrupted",
        _ => input.failure_type.as_deref().unwrap_or_default(),
    };
    match (message.trim(), kind) {
        ("", "") => "the call did not finish".to_owned(),
        ("", kind) => kind.to_owned(),
        (message, "" | "error") => message.to_owned(),
        (message, kind) => format!("{message} ({kind})"),
    }
}

/// The name the engine knows an MCP call by.
fn mcp_name(server: &str, tool: &str) -> String {
    format!("mcp__{server}__{tool}")
}

fn field(input: &Value, name: &str) -> String {
    input
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn object(input: &Value) -> Map<String, Value> {
    input.as_object().cloned().unwrap_or_default()
}

/// Cursor sends a result as a JSON string; what it holds differs by tool.
fn parsed_output(input: &CursorHookInput) -> Value {
    match input.tool_output.as_deref() {
        Some(text) => serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned())),
        None => Value::Null,
    }
}

/// The exit code and output of a shell call that failed, if this is one.
fn failed_shell(tool_name: &str, result: &Value) -> Option<(i64, String)> {
    if !matches!(tool_name, "Bash" | "PowerShell") {
        return None;
    }
    let code = result.get("exitCode").and_then(Value::as_i64)?;
    (code != 0).then(|| (code, field(result, "output")))
}

/// The result in the shape the rules for that tool read it by: a command's output as
/// `{stdout, stderr}`, a file's text as `{file: {content}}`, and anything else as it came.
fn response(tool_name: &str, input: &CursorHookInput, result: Value) -> Value {
    match tool_name {
        "Bash" | "PowerShell" => json!({"stdout": field(&result, "output"), "stderr": ""}),
        // Cursor's own result holds the path and a length; the text came with `beforeReadFile`.
        "Read" => match &input.withhuman_read_content {
            Some(content) => json!({"file": {"content": content}}),
            None => result,
        },
        _ => result,
    }
}
