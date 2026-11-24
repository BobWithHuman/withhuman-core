//! GitHub Copilot CLI's adapter: translates its Hooks into the Claude Code Hook requests the
//! Collector already handles. [`crate::agent`] is the seam it is plugged into; everything here
//! is Copilot's own.
//!
//! Copilot sends every event under its own camelCase name and again under Claude Code's, and
//! under Claude Code's it uses **Claude Code's field names and Claude Code's tool names**. The
//! bridge registers those, so there is barely a translation left to make:
//!
//! | Copilot | Claude Code |
//! |---|---|
//! | `bash` → `Bash` | `Bash`, or `PowerShell` when the bridge reports that shell |
//! | `view` → `Read`, `task` → `Agent` | the same name and input, both of which the engine knows |
//! | `apply_patch` → `Edit`, whose input is the patch itself | the calls the patch makes, by the shared patch translation |
//! | `<server>-<tool>` for an MCP call | `mcp__<server>__<tool>`, once the bridge knows the server |
//! | any other | the same name and input |
//!
//! What the Hooks leave out and the bridge supplies: the turn (`withhuman_turn`, read from the
//! session transcript, since no Hook carries one), the server of an MCP call
//! (`withhuman_mcp_server`), the program files a shell command may run
//! (`withhuman_programs`), and the model's answer, which the bridge sends as a Claude Code
//! `MessageDisplay` of its own.

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};
use withhuman_contracts::{
    copilot::{CopilotHookEvent, CopilotHookInput},
    hooks::{
        ClientShell, HookEventName, PostToolBatchRequest, PostToolUseFailureRequest,
        PostToolUseRequest, PreToolUseRequest, SessionEndRequest, SessionStartRequest,
        SubagentLifecycleRequest, UserPromptSubmitRequest,
    },
};

use crate::{
    FailurePolicy, HookPolicy, ReviewPolicy,
    agent::{Agent, Incoming, Rejection, SHELL_HEADER, Translated},
    http::header_value,
};

/// Marks every event of a Copilot session, and the `<kind>` of its route.
pub const AGENT_KIND: &str = "copilot";
/// Claude Code's name for Copilot's `bash`.
const SHELL_TOOL: &str = "Bash";
/// Claude Code's name for Copilot's `apply_patch`, whose input is a patch rather than an edit.
const PATCH_TOOL: &str = "Edit";

/// Copilot's adapter.
pub struct Copilot;

impl Agent for Copilot {
    fn kind(&self) -> &'static str {
        AGENT_KIND
    }

    /// `PreToolUse` is the only Hook Copilot lets stop a Call: a `deny` on `preMcpToolCall` or
    /// `permissionRequest` is discarded and the call runs, so MCP calls are judged on the same
    /// Hook as every other call. Copilot's `ask` denies where there is no terminal to ask at
    /// and has not been seen to reach a real approval, so a REVIEW denies. A Call that cannot
    /// be judged is blocked, and because a Hook that merely times out lets the call run, the
    /// bridge answers on a deadline of its own rather than waiting for Copilot's.
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
        let Some(event) = CopilotHookEvent::from_path(event) else {
            return Err(Rejection::unknown_event());
        };
        // The bridge makes this one from the session transcript, in its Claude Code form: the
        // model's answer is in no Copilot Hook. Copilot cannot hide text it has shown, so only
        // the event matters, and there is no Copilot Hook to keep with it.
        if event == CopilotHookEvent::MessageDisplay {
            let request = serde_json::from_value(raw).map_err(|_| Rejection::invalid_json())?;
            return Ok(Incoming::new(Translated::MessageDisplay(request)));
        }
        let input: CopilotHookInput =
            serde_json::from_value(raw.clone()).map_err(|_| Rejection::invalid_json())?;
        let shell = ClientShell::from_header(header_value(headers, SHELL_HEADER).as_deref());
        let request = translate(event, &input, shell)?;
        // Program files are kept with the Call already; the copy keeps the rest as sent.
        let mut payload = raw;
        if let Some(fields) = payload.as_object_mut() {
            fields.remove("withhuman_programs");
        }
        Ok(Incoming::new(request).with_payload(payload))
    }
}

fn missing(field: &'static str) -> Rejection {
    // The field names are the client's; the code is the one its self-check knows.
    let _ = field;
    Rejection::new(StatusCode::BAD_REQUEST, "invalid_copilot_hook")
}

/// One Copilot Hook as the Claude Code request doing the same thing.
pub fn translate(
    event: CopilotHookEvent,
    input: &CopilotHookInput,
    shell: ClientShell,
) -> Result<Translated, Rejection> {
    use CopilotHookEvent as Event;
    Ok(match event {
        Event::SessionStart => Translated::SessionStart(SessionStartRequest {
            session_id: session(input)?.0,
            hook_event_name: Some(HookEventName::SessionStart),
            transcript_path: input.transcript_path.clone(),
            cwd: input.cwd.clone(),
            source: input.source.clone(),
            permission_mode: None,
            model: None,
        }),
        Event::SessionEnd => Translated::SessionEnd(SessionEndRequest {
            session_id: session(input)?.0,
            hook_event_name: Some(HookEventName::SessionEnd),
            transcript_path: input.transcript_path.clone(),
            cwd: input.cwd.clone(),
            permission_mode: None,
            reason: input.reason.clone(),
        }),
        Event::UserPromptSubmit => Translated::UserPromptSubmit(UserPromptSubmitRequest {
            session_id: session(input)?.0,
            hook_event_name: Some(HookEventName::UserPromptSubmit),
            prompt: input.prompt.clone().ok_or_else(|| missing("prompt"))?,
            prompt_id: input.withhuman_turn.clone(),
            transcript_path: input.transcript_path.clone(),
            cwd: input.cwd.clone(),
            permission_mode: None,
        }),
        Event::PreToolUse => {
            let (session_id, agent_id) = session(input)?;
            let (tool_name, tool_input) = call(input, shell)?;
            Translated::PreToolUse(PreToolUseRequest {
                session_id,
                hook_event_name: Some(HookEventName::PreToolUse),
                tool_name,
                tool_input,
                tool_use_id: input
                    .tool_use_id
                    .clone()
                    .ok_or_else(|| missing("tool_use_id"))?,
                cwd: input.cwd.clone(),
                prompt_id: input.withhuman_turn.clone(),
                agent_id,
                agent_type: input.agent_type.clone(),
                permission_mode: None,
                withhuman_programs: input.withhuman_programs.clone(),
            })
        }
        Event::PostToolUse => {
            let (session_id, agent_id) = session(input)?;
            let (tool_name, tool_input) = call(input, shell)?;
            Translated::PostToolUse(PostToolUseRequest {
                session_id,
                hook_event_name: Some(HookEventName::PostToolUse),
                tool_response: response(&tool_name, input),
                tool_name,
                tool_input: Some(tool_input),
                tool_use_id: input
                    .tool_use_id
                    .clone()
                    .ok_or_else(|| missing("tool_use_id"))?,
                cwd: input.cwd.clone(),
                prompt_id: input.withhuman_turn.clone(),
                agent_id,
                agent_type: input.agent_type.clone(),
                permission_mode: None,
            })
        }
        Event::PostToolUseFailure => {
            let (session_id, agent_id) = session(input)?;
            let (tool_name, tool_input) = call(input, shell)?;
            Translated::PostToolUseFailure(PostToolUseFailureRequest {
                session_id,
                hook_event_name: Some(HookEventName::PostToolUseFailure),
                tool_name,
                tool_input: Some(tool_input),
                error: failure(input),
                tool_use_id: input
                    .tool_use_id
                    .clone()
                    .ok_or_else(|| missing("tool_use_id"))?,
                cwd: input.cwd.clone(),
                prompt_id: input.withhuman_turn.clone(),
                agent_id,
                agent_type: input.agent_type.clone(),
                permission_mode: None,
            })
        }
        Event::SubagentStart | Event::SubagentStop => {
            let request = SubagentLifecycleRequest {
                session_id: session(input)?.0,
                hook_event_name: Some(match event {
                    Event::SubagentStart => HookEventName::SubagentStart,
                    _ => HookEventName::SubagentStop,
                }),
                agent_id: input.agent_id.clone().ok_or_else(|| missing("agent_id"))?,
                agent_type: input
                    .agent_type
                    .clone()
                    .or_else(|| input.agent_name.clone()),
            };
            match event {
                Event::SubagentStart => Translated::SubagentStart(request),
                _ => Translated::SubagentStop(request),
            }
        }
        // The turn ended, which closes its open tool batch. The answer it ended with is not
        // here: the bridge reads it from the transcript this Hook names.
        Event::Stop => {
            let (session_id, agent_id) = session(input)?;
            Translated::PostToolBatch(PostToolBatchRequest {
                session_id,
                hook_event_name: Some(HookEventName::PostToolBatch),
                agent_id,
                agent_type: input.agent_type.clone(),
                tool_calls: Vec::new(),
            })
        }
        // Accepted and passed over; `withhuman_contracts::copilot` says why for each. The
        // bridge reads an MCP server's name off `PreMcpToolCall` and a permission prompt
        // without sending either on.
        Event::PreMcpToolCall
        | Event::PermissionRequest
        | Event::UserPromptTransformed
        | Event::ErrorOccurred
        | Event::PreCompact
        | Event::Notification => Translated::Nothing,
        // Handled before the translation, which has no Copilot Hook to read.
        Event::MessageDisplay => Translated::Nothing,
    })
}

/// The session the event belongs to, and the agent inside it when a subagent raised it.
///
/// A subagent's events carry its own id as the session and the session it runs under beside
/// it, which is the session the engine keeps it in — as Claude Code's subagents are.
fn session(input: &CopilotHookInput) -> Result<(String, Option<String>), Rejection> {
    let session = input
        .session()
        .ok_or_else(|| missing("session_id"))?
        .to_owned();
    let agent_id = input
        .agent_id
        .clone()
        .or_else(|| input.session_id.clone())
        .filter(|agent| *agent != session);
    Ok((session, agent_id))
}

/// The call as its Claude Code counterpart. Copilot already sends Claude Code's tool names, so
/// only two calls need anything done to them: a shell call takes the name of the shell the
/// client runs, and a patch becomes the calls it makes.
fn call(input: &CopilotHookInput, shell: ClientShell) -> Result<(String, Value), Rejection> {
    let name = input
        .tool_name
        .as_deref()
        .ok_or_else(|| missing("tool_name"))?;
    let arguments = input.tool_input.clone().unwrap_or(Value::Null);
    // An MCP call is named `<server>-<tool>`, which only the server the bridge reports takes
    // apart. Without one the call keeps the name Copilot gave it and is judged under that.
    if let Some((server, tool)) = input.mcp_call() {
        return Ok((format!("mcp__{server}__{tool}"), arguments));
    }
    Ok(match name {
        SHELL_TOOL => (shell.tool_name().to_owned(), arguments),
        // `apply_patch` arrives as `Edit` whose input is the patch itself, which no rule for
        // `Edit` can read. Codex and OpenClaw send the same patches, so the shared translation
        // turns this one into the calls it makes.
        PATCH_TOOL if arguments.is_string() => {
            crate::patch::translate(&arguments, input.cwd.as_deref())
        }
        other => (other.to_owned(), arguments),
    })
}

/// The result in the shape the rules for that tool read it by: a command's output as
/// `{stdout, stderr}`, a file's text as `{file: {content}}`, anything else as `{content}`.
/// Copilot answers every call alike, with `text_result_for_llm`.
fn response(tool_name: &str, input: &CopilotHookInput) -> Value {
    let text = input
        .tool_result
        .as_ref()
        .and_then(|result| result.get("text_result_for_llm"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    match tool_name {
        "Bash" | "PowerShell" => json!({"stdout": text, "stderr": ""}),
        "Read" => json!({"file": {"content": text}}),
        _ => json!({"content": text}),
    }
}

/// Why a call did not finish. Copilot sends a sentence on `PostToolUseFailure` and an object
/// holding one on `ErrorOccurred`.
fn failure(input: &CopilotHookInput) -> String {
    let error = match input.error.as_ref() {
        Some(Value::String(message)) => message.trim().to_owned(),
        Some(Value::Object(fields)) => fields
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned(),
        _ => String::new(),
    };
    match error.is_empty() {
        true => "the call did not finish".to_owned(),
        false => error,
    }
}
