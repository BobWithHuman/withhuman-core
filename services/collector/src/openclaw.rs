//! OpenClaw's adapter: translates its plugin Hooks into the Claude Code Hook requests the
//! Collector already handles. [`crate::agent`] is the seam it is plugged into; everything here
//! is OpenClaw's own.
//!
//! OpenClaw's tools have names and inputs of their own, so unlike Cursor's — which are Claude
//! Code's already — every one of them has to be translated or the rules written against Claude
//! Code's tools do not reach it. An untranslated `exec` is classified by the words in its name
//! alone, and `exec` is not `execute`, so it would be judged as an ordinary step rather than as
//! a program run:
//!
//! | OpenClaw | Claude Code |
//! |---|---|
//! | `exec` | `Bash`, or `PowerShell` when the client reports that shell; `workdir` becomes the Call's directory |
//! | `ls` | `Bash` `ls -- <path>`: listing a directory is the agent running a program, not a search |
//! | `read`, `view_image`, `pdf` | `Read`, with `path` under the name the rules read it by (`file_path`) |
//! | `write` | `Write` |
//! | `edit` | `MultiEdit`, with `oldText` / `newText` under `old_string` / `new_string` |
//! | `ripgrep` / `fd` | `Grep` / `Glob` |
//! | `web_search`, `x_search` / `browser` | `WebSearch` / `WebFetch` |
//! | `sessions_spawn` | `Task` |
//! | `<server>__<tool>` (MCP) | `mcp__<server>__<tool>`, the form the engine knows MCP by |
//! | `dispatch_action` | the tool its `params.id` names, with `params.args` as the input |
//! | any other | the same name and input, marked [`UNTRANSLATED`] |
//!
//! Two of OpenClaw's own ways of working decide the rest:
//!
//! - **A Call may run another Call.** `dispatch_action` names an action and the action arrives a
//!   second time as a Call of its own. Blocking the dispatching call keeps the action from
//!   running at all — verified against OpenClaw 2026.11.7, where the dispatched Call never
//!   reached the Hook once the dispatch was blocked — while what blocking the dispatched Call
//!   does is not known. So the dispatching call is judged and the Call it runs is passed over.
//! - **The tool Hooks name no directory.** Only the turn's Hooks carry `workspaceDir`, so the
//!   client fills it in from the turn it kept; a shell call carries its own `workdir` as well.
//!
//! What the Hooks leave out and the client supplies: the session OpenClaw never announced
//! (`withhuman_synthesized`), the directory of a Call (`workspaceDir`), and the program files a
//! shell command may run (`withhuman_programs`).

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};
use withhuman_contracts::{
    hooks::{
        ClientShell, HookEventName, PostToolUseFailureRequest, PostToolUseRequest,
        PreToolUseRequest, SessionEndRequest, SessionStartRequest, UserPromptSubmitRequest,
    },
    openclaw::{OpenClawHookEvent, OpenClawHookInput, dispatched_action, dispatched_by},
};

use crate::{
    FailurePolicy, HookPolicy, ReviewPolicy,
    agent::{Agent, Incoming, Rejection, SHELL_HEADER, Translated},
    http::header_value,
};

/// Marks every event of an OpenClaw session, and the `<kind>` of its route.
pub const AGENT_KIND: &str = "openclaw";
/// Set on a Call whose tool this adapter has no translation for: the engine has the Call, but
/// the rules for the tool it stands for are not the ones judging it.
pub const UNTRANSLATED: &str = "openclaw_untranslated";
/// OpenClaw's own name for a tool that runs another tool.
const DISPATCH_TOOL: &str = "dispatch_action";
/// What separates an MCP server from its tool in OpenClaw's name for the call.
const MCP_SEPARATOR: &str = "__";

/// OpenClaw's adapter.
pub struct OpenClaw;

impl Agent for OpenClaw {
    fn kind(&self) -> &'static str {
        AGENT_KIND
    }

    /// OpenClaw's `before_tool_call` takes `requireApproval`, which pauses the Call until the
    /// user answers and blocks it on a deny or a timeout, so a REVIEW can be asked rather than
    /// denied — the first client of the engine's that can. MCP calls reach the same Hook, so
    /// the Hook enforces them rather than AgentGateway. A Call that cannot be judged is
    /// blocked, and the client sends every event with a delivery ID.
    fn policy(&self) -> HookPolicy {
        HookPolicy {
            review: ReviewPolicy::Ask,
            mcp_at_hook: true,
            failure: FailurePolicy::Closed,
            resends: true,
        }
    }

    fn request_headers(&self) -> &'static [&'static str] {
        &[SHELL_HEADER]
    }

    /// A finished Call's Hook carries the tool's whole result, a program's exit code included,
    /// so a failed Call is known from its own Hook.
    fn reads_failure_output(&self) -> bool {
        true
    }

    fn translate(
        &self,
        event: &str,
        raw: Value,
        headers: &HeaderMap,
    ) -> Result<Incoming, Rejection> {
        let Some(event) = OpenClawHookEvent::from_path(event) else {
            return Err(Rejection::unknown_event());
        };
        let input: OpenClawHookInput =
            serde_json::from_value(raw.clone()).map_err(|_| Rejection::invalid_json())?;
        let shell = ClientShell::from_header(header_value(headers, SHELL_HEADER).as_deref());
        let translation = translate(event, &input, shell)?;
        // Program files are kept with the Call already; the copy keeps the rest as sent.
        let mut payload = raw;
        if let Some(fields) = payload.as_object_mut() {
            fields.remove("withhuman_programs");
        }
        let mut incoming = Incoming::new(translation.request).with_payload(payload);
        if translation.untranslated {
            incoming = incoming.with_flag(UNTRANSLATED, json!(true));
        }
        Ok(incoming)
    }
}

/// One OpenClaw Hook as the engine reads it, and whether its tool had a translation.
#[derive(Debug, Clone, PartialEq)]
pub struct Translation {
    pub request: Translated,
    /// The Call's tool is not one this adapter knows; see [`UNTRANSLATED`].
    pub untranslated: bool,
}

impl Translation {
    fn of(request: Translated) -> Self {
        Self {
            request,
            untranslated: false,
        }
    }
}

fn missing(field: &'static str) -> Rejection {
    // The field names are the client's; the code is the one its self-check knows.
    let _ = field;
    Rejection::new(StatusCode::BAD_REQUEST, "invalid_openclaw_hook")
}

/// One OpenClaw Hook as the Claude Code request doing the same thing.
pub fn translate(
    event: OpenClawHookEvent,
    input: &OpenClawHookInput,
    shell: ClientShell,
) -> Result<Translation, Rejection> {
    use OpenClawHookEvent as Event;
    Ok(match event {
        Event::SessionStart => Translation::of(Translated::SessionStart(SessionStartRequest {
            session_id: session(input)?,
            hook_event_name: Some(HookEventName::SessionStart),
            transcript_path: input.transcript_path.clone(),
            cwd: input.workspace_dir.clone(),
            // A session the client opened itself, rather than one OpenClaw announced.
            source: input.withhuman_synthesized.then(|| "resume".to_owned()),
            permission_mode: None,
            model: input.model_id.clone(),
        })),
        Event::SessionEnd => Translation::of(Translated::SessionEnd(SessionEndRequest {
            session_id: session(input)?,
            hook_event_name: Some(HookEventName::SessionEnd),
            transcript_path: input.transcript_path.clone(),
            cwd: input.workspace_dir.clone(),
            permission_mode: None,
            reason: input.reason.clone(),
        })),
        Event::BeforeAgentRun => {
            Translation::of(Translated::UserPromptSubmit(UserPromptSubmitRequest {
                session_id: session(input)?,
                hook_event_name: Some(HookEventName::UserPromptSubmit),
                prompt: input.prompt.clone().ok_or_else(|| missing("prompt"))?,
                prompt_id: input.run_id.clone(),
                transcript_path: input.transcript_path.clone(),
                cwd: input.workspace_dir.clone(),
                permission_mode: None,
            }))
        }
        // The second Call of one dispatch: the dispatching call was judged already, and
        // judging this one would put the turn's record and the user's prompt on the same work
        // twice.
        Event::BeforeToolCall | Event::AfterToolCall if dispatched(input) => {
            Translation::of(Translated::Nothing)
        }
        Event::BeforeToolCall => {
            let call = call(input, shell)?;
            Translation {
                request: Translated::PreToolUse(PreToolUseRequest {
                    session_id: session(input)?,
                    hook_event_name: Some(HookEventName::PreToolUse),
                    tool_name: call.tool_name,
                    tool_input: call.tool_input,
                    tool_use_id: tool_use_id(input)?,
                    cwd: call.cwd.or_else(|| input.workspace_dir.clone()),
                    prompt_id: input.run_id.clone(),
                    agent_id: None,
                    agent_type: None,
                    permission_mode: None,
                    withhuman_programs: input.withhuman_programs.clone(),
                }),
                untranslated: call.untranslated,
            }
        }
        Event::AfterToolCall => {
            let call = call(input, shell)?;
            let session_id = session(input)?;
            let tool_use_id = tool_use_id(input)?;
            let cwd = call.cwd.clone().or_else(|| input.workspace_dir.clone());
            let request = match failure(input, &call.tool_name) {
                // A program that exited non-zero: what it printed is kept, as Claude Code keeps
                // a failing command's output, so the text it brought in is still judged.
                Some(reason) if printed(input).is_some() => {
                    Translated::PostToolUse(PostToolUseRequest {
                        session_id,
                        hook_event_name: Some(HookEventName::PostToolUse),
                        tool_response: json!({
                            "stdout": printed(input).unwrap_or_default(),
                            "stderr": reason,
                        }),
                        tool_name: call.tool_name,
                        tool_input: Some(call.tool_input),
                        tool_use_id,
                        cwd,
                        prompt_id: input.run_id.clone(),
                        agent_id: None,
                        agent_type: None,
                        permission_mode: None,
                    })
                }
                Some(reason) => Translated::PostToolUseFailure(PostToolUseFailureRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PostToolUseFailure),
                    tool_name: call.tool_name,
                    tool_input: Some(call.tool_input),
                    error: reason,
                    tool_use_id,
                    cwd,
                    prompt_id: input.run_id.clone(),
                    agent_id: None,
                    agent_type: None,
                    permission_mode: None,
                }),
                None => Translated::PostToolUse(PostToolUseRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PostToolUse),
                    tool_response: response(&call.tool_name, input),
                    tool_name: call.tool_name,
                    tool_input: Some(call.tool_input),
                    tool_use_id,
                    cwd,
                    prompt_id: input.run_id.clone(),
                    agent_id: None,
                    agent_type: None,
                    permission_mode: None,
                }),
            };
            Translation {
                request,
                untranslated: call.untranslated,
            }
        }
        // Accepted and passed over. The turn's end, the messages it showed, its subagents and
        // the changes to what the agent can do are translated where their captures are;
        // turning them away here would, on an event that decides a Call, block it.
        Event::AgentEnd
        | Event::BeforeAgentFinalize
        | Event::SubagentSpawned
        | Event::SubagentEnded
        | Event::SkillChanged
        | Event::BeforeInstall
        | Event::CronChanged
        | Event::BeforePromptBuild
        | Event::BeforeAgentReply
        | Event::MessageReceived
        | Event::MessageSending
        | Event::LlmOutput => Translation::of(Translated::Nothing),
    })
}

/// The session the event belongs to. `session_id` is the one that changes when a session is
/// replaced, so it is the engine's; `session_key` names the same session and stands in when a
/// Hook carries only that.
fn session(input: &OpenClawHookInput) -> Result<String, Rejection> {
    input
        .session_id
        .clone()
        .or_else(|| input.session_key.clone())
        .ok_or_else(|| missing("sessionId"))
}

fn tool_use_id(input: &OpenClawHookInput) -> Result<String, Rejection> {
    input
        .tool_call_id
        .clone()
        .ok_or_else(|| missing("toolCallId"))
}

/// Whether this Call is one another Call dispatched, and so the duplicate of a Call the engine
/// judged already.
fn dispatched(input: &OpenClawHookInput) -> bool {
    input
        .tool_call_id
        .as_deref()
        .is_some_and(|id| dispatched_by(id).is_some())
}

/// A Call as its Claude Code counterpart.
#[derive(Debug, Clone, PartialEq)]
struct Call {
    tool_name: String,
    tool_input: Value,
    /// The directory the Call runs in, when the Call itself names one.
    cwd: Option<String>,
    untranslated: bool,
}

/// The Call as the Claude Code tool doing the same thing, with its input under the names the
/// rules for that tool read.
fn call(input: &OpenClawHookInput, shell: ClientShell) -> Result<Call, Rejection> {
    let name = input
        .tool_name
        .as_deref()
        .ok_or_else(|| missing("toolName"))?;
    let params = input.params.clone().unwrap_or(Value::Null);
    // A dispatch runs the action its id names, with its arguments; it carries both, so the
    // Call the engine judges is the real one even though the dispatch is the Hook it answers.
    if name == DISPATCH_TOOL {
        if let Some(action) = params.get("id").and_then(Value::as_str) {
            let arguments = params.get("args").cloned().unwrap_or(Value::Null);
            if let Some(action) = dispatched_action(action) {
                return Ok(tool(
                    action.tool,
                    arguments,
                    shell,
                    action.mcp_server().is_some(),
                ));
            }
        }
    }
    Ok(tool(name, params, shell, mcp_tool(name)))
}

/// Whether a tool's name is an MCP server's and its tool (`<server>__<tool>`). OpenClaw's own
/// tools hold no `__`, so the separator is what tells them apart.
fn mcp_tool(name: &str) -> bool {
    match name.split_once(MCP_SEPARATOR) {
        Some((server, tool)) => !server.is_empty() && !tool.is_empty(),
        None => false,
    }
}

/// One tool of OpenClaw's as the Claude Code tool doing the same thing.
fn tool(name: &str, params: Value, shell: ClientShell, mcp: bool) -> Call {
    let plain = |tool_name: &str, tool_input: Value| Call {
        tool_name: tool_name.to_owned(),
        tool_input,
        cwd: None,
        untranslated: false,
    };
    // An MCP tool keeps the server its name already holds; `mcp__` is what the engine's MCP
    // rules read it by.
    if mcp {
        return plain(&format!("mcp__{name}"), params);
    }
    let text = |field: &str| {
        params
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    match name {
        "exec" => Call {
            tool_name: shell.tool_name().to_owned(),
            tool_input: json!({ "command": text("command") }),
            // A shell call says which directory it runs in; the turn's is only the fallback.
            cwd: params
                .get("workdir")
                .and_then(Value::as_str)
                .map(str::to_owned),
            untranslated: false,
        },
        // Listing a directory is the agent running a program over it, not a search for a
        // pattern, so it is judged as the command it stands for. The path is quoted: a
        // directory whose name holds a space would otherwise read as two arguments, and the
        // command the engine judges would not be the one the agent ran.
        "ls" => plain(
            shell.tool_name(),
            json!({ "command": format!("ls -- {}", quote(&text("path"))) }),
        ),
        "read" | "view_image" | "pdf" => {
            let mut fields = Map::new();
            fields.insert("file_path".to_owned(), json!(text("path")));
            for field in ["offset", "limit"] {
                if let Some(value) = params.get(field) {
                    fields.insert(field.to_owned(), value.clone());
                }
            }
            plain("Read", Value::Object(fields))
        }
        "write" => plain(
            "Write",
            json!({ "file_path": text("path"), "content": text("content") }),
        ),
        "edit" => plain(
            "MultiEdit",
            json!({ "file_path": text("path"), "edits": edits(&params) }),
        ),
        // Named from the host's tool registry; their inputs are passed through as sent, since
        // no captured session has run one.
        "ripgrep" => plain("Grep", params),
        "fd" => plain("Glob", params),
        "web_search" | "x_search" => plain("WebSearch", params),
        "browser" => plain("WebFetch", params),
        "sessions_spawn" => plain("Task", params),
        other => Call {
            tool_name: other.to_owned(),
            tool_input: params,
            cwd: None,
            untranslated: true,
        },
    }
}

/// `word` quoted for a POSIX shell when it needs it.
///
/// The same rule as the one Codex's adapter applies to the commands its patches become; both
/// are moved to one place when that translation is shared.
fn quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,\\".contains(c));
    match plain {
        true => word.to_owned(),
        false => format!("'{}'", word.replace('\'', "'\\''")),
    }
}

/// The changes an `edit` makes, in the shape Claude Code's `MultiEdit` takes.
fn edits(params: &Value) -> Vec<Value> {
    params
        .get("edits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|edit| {
            let side = |name: &str| edit.get(name).and_then(Value::as_str).unwrap_or_default();
            json!({ "old_string": side("oldText"), "new_string": side("newText") })
        })
        .collect()
}

/// What a finished Call printed, if it printed anything.
fn printed(input: &OpenClawHookInput) -> Option<String> {
    let result = input.result.as_ref()?;
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    (!text.trim().is_empty()).then_some(text)
}

/// Why a Call did not do what it was asked, as OpenClaw reports it.
///
/// `error` is set only when the host itself failed the Call. A program that exited non-zero
/// leaves it null and says so in `result.details`, where `status` of `completed` means the
/// program ran rather than that it succeeded — so the exit code is what decides.
fn failure(input: &OpenClawHookInput, tool_name: &str) -> Option<String> {
    if let Some(error) = input.error.as_ref().filter(|error| !error.is_null()) {
        return Some(match error.as_str() {
            Some(text) => text.to_owned(),
            None => error.to_string(),
        });
    }
    let details = input.result.as_ref()?.get("details")?;
    if matches!(tool_name, "Bash" | "PowerShell") {
        let code = details.get("exitCode").and_then(Value::as_i64)?;
        return (code != 0).then(|| format!("exit code {code}"));
    }
    None
}

/// The result in the shape the rules for that tool read it by: a command's output as
/// `{stdout, stderr}`, a file's text as `{file: {content}}`, and anything else as it came.
fn response(tool_name: &str, input: &OpenClawHookInput) -> Value {
    let printed = printed(input).unwrap_or_default();
    match tool_name {
        "Bash" | "PowerShell" => json!({ "stdout": printed, "stderr": "" }),
        "Read" => json!({ "file": { "content": printed } }),
        _ => match input.result.clone() {
            Some(result) => result,
            None => Value::Null,
        },
    }
}
