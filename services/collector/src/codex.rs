//! Codex CLI's adapter: translates its Hooks into the Claude Code Hook requests the Collector
//! already handles, so the same normalization, graph and judgment apply to Codex sessions
//! unchanged. [`crate::agent`] is the seam it is plugged into and has what adding another
//! agent takes; everything here is Codex's own.
//!
//! Tools are translated to the Claude Code tool doing the same thing, so the engine's rules for
//! that tool (external origin, program runs, file changes, safeguards) apply as they are:
//!
//! | Codex | Claude Code |
//! |---|---|
//! | shell (`Bash`, `exec_command`, `shell`, …) | `Bash`, or `PowerShell` when the bridge reports that shell |
//! | `apply_patch` adding one file | `Write` |
//! | `apply_patch` updating one file in place | `MultiEdit`, one edit per hunk |
//! | `apply_patch` deleting one file | `Bash` `rm -- <path>` |
//! | `apply_patch` touching several files or moving one | `apply_patch` with `changes`: the calls above, one per step |
//! | `webrun` searching | `WebSearch` |
//! | `webrun` opening or finding in a page | `WebFetch` |
//! | `update_plan` / `spawn_agent` / `view_image` | `TodoWrite` / `Task` / `Read` |
//! | any other, MCP tools included | the same name and input |

use std::fmt;

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};
use withhuman_contracts::{
    codex::{CodexHookEvent, CodexHookInput, CodexShell},
    hooks::{
        HookEventName, PostToolBatchRequest, PostToolUseFailureRequest, PostToolUseRequest,
        PreToolUseRequest, SessionEndRequest, SessionStartRequest, SubagentLifecycleRequest,
        UserPromptSubmitRequest,
    },
};

pub use crate::agent::Translated;
use crate::{
    FailurePolicy, HookPolicy, ReviewPolicy,
    agent::{Agent, Incoming, Rejection},
    http::header_value,
};

/// Marks every event of a Codex session, and the `<kind>` of its route.
pub const AGENT_KIND: &str = "codex";
/// Every agent reports its shell the same way; see [`crate::agent::SHELL_HEADER`].
pub use crate::agent::SHELL_HEADER;
/// Set on a shell call whose directory the bridge could not tell: it was judged as running in
/// the project directory.
pub const WORKDIR_UNKNOWN: &str = "unknown";

/// Only recognized native web operations may use the post-hoc record exception.
pub fn valid_record(event: CodexHookEvent, input: &CodexHookInput) -> bool {
    if event != CodexHookEvent::PreToolUse || input.tool_name.as_deref() != Some("webrun") {
        return false;
    }
    let Some(fields) = input.tool_input.as_ref().and_then(Value::as_object) else {
        return false;
    };
    !fields.is_empty()
        && fields.iter().all(|(name, value)| {
            let key = match name.as_str() {
                "search_query" | "image_query" => "q",
                "open" | "find" | "click" => "ref_id",
                _ => return false,
            };
            value.as_array().is_some_and(|items| {
                !items.is_empty()
                    && items.iter().all(|item| {
                        item.get(key)
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.trim().is_empty())
                    })
            })
        })
}

/// Codex names for its shell tool, across versions.
const SHELL_TOOLS: &[&str] = &[
    "Bash",
    "exec_command",
    "shell",
    "local_shell",
    "shell_command",
    "unified_exec",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Translation {
    pub request: Translated,
    /// A shell call ran in a directory the Hook and the bridge left unknown.
    pub workdir_unknown: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslateError {
    /// The Hook lacks a field its Claude Code counterpart needs.
    Missing(&'static str),
    /// This route takes the event in its Claude Code form.
    NotCodexHook,
}

impl fmt::Display for TranslateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(formatter, "codex hook without {field}"),
            Self::NotCodexHook => formatter.write_str("event is not a codex hook"),
        }
    }
}

impl std::error::Error for TranslateError {}

/// The text a shell command printed, as Codex reports it; none when it printed nothing.
fn printed(response: Option<&Value>) -> Option<String> {
    let text = match response? {
        Value::String(output) => output.clone(),
        other => withhuman_common::origin::tool_output(other)?,
    };
    (!text.trim().is_empty()).then_some(text)
}

/// The Claude Code request for one Codex Hook. A shell command that ran and exited non-zero is
/// sent as a PostToolUse carrying its output, as Claude Code reports a Bash command: a third of
/// Codex's shell commands end non-zero (a missing test runner at the end of a reading command),
/// and what they printed (an injected instruction included) never reached the graph.
pub fn translate(
    event: CodexHookEvent,
    input: CodexHookInput,
    shell: CodexShell,
) -> Result<Translation, TranslateError> {
    let mut workdir_unknown = false;
    let request = match event {
        CodexHookEvent::SessionStart => Translated::SessionStart(SessionStartRequest {
            session_id: input.session_id,
            hook_event_name: Some(HookEventName::SessionStart),
            transcript_path: input.transcript_path,
            cwd: input.cwd,
            source: input.source,
            permission_mode: input.permission_mode,
            model: input.model,
        }),
        CodexHookEvent::UserPromptSubmit => Translated::UserPromptSubmit(UserPromptSubmitRequest {
            session_id: input.session_id,
            hook_event_name: Some(HookEventName::UserPromptSubmit),
            prompt: input.prompt.ok_or(TranslateError::Missing("prompt"))?,
            prompt_id: input.turn_id,
            transcript_path: input.transcript_path,
            cwd: input.cwd,
            permission_mode: input.permission_mode,
        }),
        CodexHookEvent::PreToolUse => {
            let call = tool_call(&input, shell)?;
            workdir_unknown = call.workdir_unknown;
            Translated::PreToolUse(PreToolUseRequest {
                session_id: input.session_id,
                hook_event_name: Some(HookEventName::PreToolUse),
                tool_name: call.tool_name,
                tool_input: call.tool_input,
                tool_use_id: input
                    .tool_use_id
                    .ok_or(TranslateError::Missing("tool_use_id"))?,
                cwd: call.cwd,
                prompt_id: input.turn_id,
                agent_id: input.agent_id,
                agent_type: input.agent_type,
                permission_mode: input.permission_mode,
                withhuman_programs: input.withhuman_programs,
            })
        }
        CodexHookEvent::PostToolUse => {
            let call = tool_call(&input, shell)?;
            workdir_unknown = call.workdir_unknown;
            let tool_use_id = input
                .tool_use_id
                .ok_or(TranslateError::Missing("tool_use_id"))?;
            let kept_output = match &input.withhuman_failure {
                Some(_)
                    if call.shell && matches!(call.tool_name.as_str(), "Bash" | "PowerShell") =>
                {
                    printed(input.tool_response.as_ref())
                }
                _ => None,
            };
            match input.withhuman_failure {
                Some(error) if kept_output.is_some() => {
                    Translated::PostToolUse(PostToolUseRequest {
                        session_id: input.session_id,
                        hook_event_name: Some(HookEventName::PostToolUse),
                        tool_response: json!({
                            "stdout": kept_output.unwrap_or_default(),
                            "stderr": format!("({error})"),
                        }),
                        tool_name: call.tool_name,
                        tool_input: Some(call.tool_input),
                        tool_use_id,
                        cwd: call.cwd,
                        prompt_id: input.turn_id,
                        agent_id: input.agent_id,
                        agent_type: input.agent_type,
                        permission_mode: input.permission_mode,
                    })
                }
                Some(error) => Translated::PostToolUseFailure(PostToolUseFailureRequest {
                    session_id: input.session_id,
                    hook_event_name: Some(HookEventName::PostToolUseFailure),
                    tool_name: call.tool_name,
                    tool_input: Some(call.tool_input),
                    error,
                    tool_use_id,
                    cwd: call.cwd,
                    prompt_id: input.turn_id,
                    agent_id: input.agent_id,
                    agent_type: input.agent_type,
                    permission_mode: input.permission_mode,
                }),
                None => Translated::PostToolUse(PostToolUseRequest {
                    session_id: input.session_id,
                    hook_event_name: Some(HookEventName::PostToolUse),
                    tool_response: tool_response(
                        call.shell,
                        &call.tool_name,
                        &call.tool_input,
                        input.tool_response.unwrap_or(Value::Null),
                    ),
                    tool_name: call.tool_name,
                    tool_input: Some(call.tool_input),
                    tool_use_id,
                    cwd: call.cwd,
                    prompt_id: input.turn_id,
                    agent_id: input.agent_id,
                    agent_type: input.agent_type,
                    permission_mode: input.permission_mode,
                }),
            }
        }
        CodexHookEvent::Stop => Translated::PostToolBatch(PostToolBatchRequest {
            session_id: input.session_id,
            hook_event_name: Some(HookEventName::PostToolBatch),
            agent_id: input.agent_id,
            agent_type: input.agent_type,
            tool_calls: Vec::new(),
        }),
        CodexHookEvent::SessionEnd => Translated::SessionEnd(SessionEndRequest {
            session_id: input.session_id,
            hook_event_name: Some(HookEventName::SessionEnd),
            transcript_path: input.transcript_path,
            cwd: input.cwd,
            permission_mode: input.permission_mode,
            reason: input.reason,
        }),
        CodexHookEvent::SubagentStart | CodexHookEvent::SubagentStop => {
            let request = SubagentLifecycleRequest {
                session_id: input.session_id,
                hook_event_name: Some(match event {
                    CodexHookEvent::SubagentStart => HookEventName::SubagentStart,
                    _ => HookEventName::SubagentStop,
                }),
                agent_id: input.agent_id.ok_or(TranslateError::Missing("agent_id"))?,
                agent_type: input.agent_type,
            };
            match event {
                CodexHookEvent::SubagentStart => Translated::SubagentStart(request),
                _ => Translated::SubagentStop(request),
            }
        }
        CodexHookEvent::MessageDisplay | CodexHookEvent::PostToolBatch => {
            return Err(TranslateError::NotCodexHook);
        }
    };
    Ok(Translation {
        request,
        workdir_unknown,
    })
}

/// A Codex tool call as its Claude Code counterpart.
struct ToolCall {
    tool_name: String,
    tool_input: Value,
    /// The directory the call runs in.
    cwd: Option<String>,
    shell: bool,
    workdir_unknown: bool,
}

fn tool_call(input: &CodexHookInput, shell: CodexShell) -> Result<ToolCall, TranslateError> {
    let name = input
        .tool_name
        .as_deref()
        .ok_or(TranslateError::Missing("tool_name"))?;
    let tool_input = input.tool_input.clone().unwrap_or(Value::Null);
    let is_shell = SHELL_TOOLS.contains(&name);
    // A shell call runs where its `workdir` says; the Hook leaves it out, so the bridge reads it
    // from the transcript. A path in it, or in a patch, is relative to that directory.
    let workdir = input.withhuman_workdir.as_deref().or_else(|| {
        tool_input
            .get("workdir")
            .and_then(Value::as_str)
            .filter(|_| is_shell)
    });
    let cwd = match workdir {
        Some(workdir) => Some(resolve(input.cwd.as_deref(), workdir)),
        None => input.cwd.clone(),
    };
    let (tool_name, tool_input) = translate_tool(name, &tool_input, cwd.as_deref(), shell);
    Ok(ToolCall {
        tool_name,
        tool_input,
        cwd,
        shell: is_shell,
        workdir_unknown: is_shell && workdir.is_none(),
    })
}

/// A Codex tool's name and input as the Claude Code tool doing the same; `cwd` is the directory
/// the call runs in.
pub fn translate_tool(
    name: &str,
    input: &Value,
    cwd: Option<&str>,
    shell: CodexShell,
) -> (String, Value) {
    if SHELL_TOOLS.contains(&name) {
        let command = input
            .get("command")
            .or_else(|| input.get("cmd"))
            .map(shell_command)
            .unwrap_or_default();
        if let Some(read) = simple_read(&command, shell, cwd) {
            return ("Read".to_owned(), read);
        }
        // Codex 0.167 writes files with shell commands; one that only writes literal text into
        // one file is judged as Claude Code's Write (or Edit, when it appends) is.
        if let Some(write) =
            crate::codex_write::simple_write(&command, shell, |path| file_key(cwd, path))
        {
            return write;
        }
        return (shell.tool_name().to_owned(), json!({ "command": command }));
    }
    match name {
        "apply_patch" => crate::patch::translate(input, cwd),
        "webrun" => web(input),
        "update_plan" => {
            let todos: Vec<Value> = input
                .get("plan")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|item| {
                    json!({
                        "content": item.get("step").cloned().unwrap_or(Value::Null),
                        "status": item.get("status").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect();
            ("TodoWrite".to_owned(), json!({ "todos": todos }))
        }
        "spawn_agent" => {
            let prompt = ["message", "prompt", "task"]
                .iter()
                .find_map(|field| input.get(*field).and_then(Value::as_str))
                .unwrap_or_default();
            let mut task = json!({ "prompt": prompt });
            if let Some(agent_type) = input.get("agent_type").and_then(Value::as_str) {
                task["subagent_type"] = json!(agent_type);
            }
            ("Task".to_owned(), task)
        }
        "view_image" => {
            let path = input
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            (
                "Read".to_owned(),
                json!({ "file_path": file_key(cwd, path) }),
            )
        }
        _ => (name.to_owned(), input.clone()),
    }
}

/// A shell result in the form Claude Code's tool reports it: a shell's `{stdout, stderr}`, or,
/// for a command translated to `Read`, the file content as Read gives it. Codex gives the
/// output alone.
fn tool_response(shell: bool, tool_name: &str, tool_input: &Value, response: Value) -> Value {
    if shell && tool_name == "Read" {
        return read_response(tool_input, response);
    }
    if shell && matches!(tool_name, "Write" | "Edit") {
        return crate::codex_write::write_response(tool_name, tool_input);
    }
    match response {
        Value::String(output) if shell => json!({ "stdout": output, "stderr": "" }),
        response => response,
    }
}

/// PowerShell's `Get-Content` and its aliases.
const POWERSHELL_READERS: &[&str] = &["get-content", "gc", "cat", "type"];
/// POSIX commands that print one file.
const POSIX_READERS: &[&str] = &["cat", "head", "tail"];
/// Characters that make a command more than one plain read: pipes, separators, redirections,
/// subexpressions and variables, wildcards, escapes, arrays and splatting, comments, line
/// breaks, home expansion.
const NOT_PLAIN: &[char] = &[
    '|', ';', '&', '>', '<', '`', '$', '(', ')', '{', '}', '*', '?', '[', ']', ',', '@', '#', '\n',
    '\r', '~', '!',
];

/// The `Read` input for a shell command that only prints one file (`Get-Content -LiteralPath
/// 'vendor\note.md'`, `cat notes.md`, `head -n 5 x`), with the path resolved against the
/// directory it runs in; none for anything else, which stays a shell call. Reading a file this
/// way is what Claude Code does with Read, so its result is classified (a vendored or outside
/// file is external, so hidden content in it is looked for) and remembered the same way.
///
/// The path uses `/` separators: the engine judges paths by `/`-separated parts.
pub fn simple_read(command: &str, shell: CodexShell, cwd: Option<&str>) -> Option<Value> {
    if command.contains(NOT_PLAIN) || (shell == CodexShell::Posix && command.contains('\\')) {
        return None;
    }
    let words = plain_words(command)?;
    let (program, arguments) = words.split_first()?;
    let program = program.to_ascii_lowercase();
    let mut path: Option<String> = None;
    let mut limit: Option<u64> = None;
    let mut arguments = arguments.iter();
    let number = |word: Option<&String>| word.and_then(|word| word.parse::<u64>().ok());
    match shell {
        CodexShell::PowerShell if POWERSHELL_READERS.contains(&program.as_str()) => {
            while let Some(word) = arguments.next() {
                if !word.starts_with('-') {
                    set_path(&mut path, word)?;
                    continue;
                }
                match word.to_ascii_lowercase().as_str() {
                    "-path" | "-literalpath" => {
                        let value = arguments.next().filter(|value| !value.starts_with('-'))?;
                        set_path(&mut path, value)?;
                    }
                    "-raw" => {}
                    "-encoding" => {
                        arguments.next().filter(|value| !value.starts_with('-'))?;
                    }
                    "-totalcount" | "-head" | "-tail" => limit = Some(number(arguments.next())?),
                    _ => return None,
                }
            }
        }
        CodexShell::Posix if POSIX_READERS.contains(&program.as_str()) => {
            while let Some(word) = arguments.next() {
                if !word.starts_with('-') {
                    set_path(&mut path, word)?;
                } else if program != "cat" && word == "-n" {
                    limit = Some(number(arguments.next())?);
                } else if program != "cat"
                    && word.len() > 1
                    && word[1..].bytes().all(|b| b.is_ascii_digit())
                {
                    limit = Some(word[1..].parse().ok()?);
                } else {
                    return None;
                }
            }
        }
        _ => return None,
    }
    let path = file_key(cwd, &path?);
    let mut read = json!({ "file_path": path });
    if let Some(limit) = limit {
        // A part of the file: the engine then does not take it as the whole content.
        read["limit"] = json!(limit);
    }
    Some(read)
}

/// Takes `word` as the one file read; none when a file was already named.
fn set_path(path: &mut Option<String>, word: &str) -> Option<()> {
    if path.is_some() || word.is_empty() {
        return None;
    }
    *path = Some(word.to_owned());
    Some(())
}

/// The words of a command with quotes removed; none when a quote is left open.
fn plain_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                quoted = true;
                loop {
                    match chars.next() {
                        Some(end) if end == c => break,
                        Some(inner) => word.push(inner),
                        None => return None,
                    }
                }
            }
            c if c.is_whitespace() => {
                if !word.is_empty() || quoted {
                    words.push(std::mem::take(&mut word));
                }
                quoted = false;
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() || quoted {
        words.push(word);
    }
    Some(words)
}

/// A shell's output of a file as Read's result. Codex may wrap a command's output in run
/// details (`Chunk ID: …`, `Wall time: …`, `Process exited with code …`, then `Output:`); only
/// what follows `Output:` is the file.
fn read_response(tool_input: &Value, response: Value) -> Value {
    let text = match &response {
        Value::String(text) => text.clone(),
        Value::Object(fields) => match ["stdout", "output"]
            .iter()
            .find_map(|name| fields.get(*name).and_then(Value::as_str))
        {
            Some(text) => text.to_owned(),
            None => return response,
        },
        _ => return response,
    };
    let details = [
        "Chunk ID:",
        "Wall time:",
        "Exit code:",
        "Process exited",
        "Output:",
    ];
    let content = match text.split_once("Output:\n") {
        Some((head, rest))
            if details
                .iter()
                .any(|detail| head.trim_start().starts_with(detail))
                || head.trim().is_empty() =>
        {
            rest.to_owned()
        }
        _ => text,
    };
    let lines = content.lines().count();
    let mut file = json!({
        "filePath": tool_input.get("file_path").cloned().unwrap_or(Value::Null),
        "content": content,
        "numLines": lines,
        "startLine": 1,
    });
    if tool_input.get("limit").is_none() {
        file["totalLines"] = json!(lines);
    }
    json!({ "type": "text", "file": file })
}

/// A command given as words joins into one line. A shell running a script (`bash -lc …`,
/// `powershell -Command …`) is the script itself, so the engine reads what it runs.
fn shell_command(command: &Value) -> String {
    let words: Vec<&str> = match command {
        Value::String(command) => return command.clone(),
        Value::Array(words) => words.iter().filter_map(Value::as_str).collect(),
        _ => return String::new(),
    };
    let program = words
        .first()
        .map(|word| {
            word.rsplit(['/', '\\'])
                .next()
                .unwrap_or(word)
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let program = program.strip_suffix(".exe").unwrap_or(&program);
    let shells = ["bash", "sh", "zsh", "powershell", "pwsh", "cmd"];
    let script_flags = ["-c", "-lc", "-command", "/c"];
    if let [_, flag, script @ ..] = words.as_slice() {
        if shells.contains(&program)
            && script_flags.contains(&flag.to_ascii_lowercase().as_str())
            && !script.is_empty()
        {
            return script.join(" ");
        }
    }
    words
        .iter()
        .map(|word| crate::patch::quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The patch translation and the path keys both this adapter and OpenClaw's read files by
/// live in [`crate::patch`]; the names Codex's own code and tests use are kept here.
pub use crate::patch::{Hunk, PatchStep, file_key, parse_patch, resolve};

/// Codex's web tool as Claude Code's: a search as `WebSearch`, opening or searching a page as
/// `WebFetch`, so its results count as external.
fn web(input: &Value) -> (String, Value) {
    let field = |name: &str, key: &str| -> Vec<String> {
        input
            .get(name)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get(key).and_then(Value::as_str).map(str::to_owned))
            .collect()
    };
    let queries: Vec<String> = field("search_query", "q")
        .into_iter()
        .chain(field("image_query", "q"))
        .collect();
    if !queries.is_empty() {
        return (
            "WebSearch".to_owned(),
            json!({ "query": queries.join("\n") }),
        );
    }
    let urls: Vec<String> = field("open", "ref_id")
        .into_iter()
        .chain(field("find", "ref_id"))
        .chain(field("click", "ref_id"))
        .collect();
    let Some(url) = urls.first() else {
        // A request of a shape not seen yet still counts as a web call.
        return (
            "WebSearch".to_owned(),
            json!({ "query": input.to_string() }),
        );
    };
    let mut fetch = Map::from_iter([("url".to_owned(), json!(url))]);
    let patterns = field("find", "pattern");
    if !patterns.is_empty() {
        fetch.insert("prompt".to_owned(), json!(patterns.join("\n")));
    }
    if urls.len() > 1 {
        fetch.insert("urls".to_owned(), json!(urls));
    }
    ("WebFetch".to_owned(), Value::Object(fetch))
}

/// Codex's adapter: the Hooks of the Codex CLI, as the Claude Code requests the engine judges.
pub struct Codex;

impl Agent for Codex {
    fn kind(&self) -> &'static str {
        AGENT_KIND
    }

    /// Codex has no way to ask the user, and an `ask` it receives fails the Hook and lets the
    /// call run; MCP calls do not pass AgentGateway. So a REVIEW denies, the Hook enforces MCP
    /// calls, and a Call that cannot be judged is blocked.
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
        let Some(event) = CodexHookEvent::from_path(event) else {
            return Err(Rejection::unknown_event());
        };
        // The bridge makes these from the session transcript, in their Claude Code form:
        // Codex has no Hook for either. Codex cannot hide text it shows, so only the events
        // matter, and there is no Codex Hook to keep with them.
        match event {
            CodexHookEvent::MessageDisplay => {
                let request = serde_json::from_value(raw).map_err(|_| Rejection::invalid_json())?;
                return Ok(Incoming::new(Translated::MessageDisplay(request)));
            }
            CodexHookEvent::PostToolBatch => {
                let request = serde_json::from_value(raw).map_err(|_| Rejection::invalid_json())?;
                return Ok(Incoming::new(Translated::PostToolBatch(request)));
            }
            _ => {}
        }
        let input = serde_json::from_value::<CodexHookInput>(raw.clone())
            .map_err(|_| Rejection::invalid_json())?;
        let shell = CodexShell::from_header(header_value(headers, SHELL_HEADER).as_deref());
        let record = input.withhuman_record;
        if record && !valid_record(event, &input) {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "invalid_record_tool",
            ));
        }
        let translation = translate(event, input, shell)
            .map_err(|_| Rejection::new(StatusCode::BAD_REQUEST, "invalid_codex_hook"))?;
        // Program files are kept with the Call already; the copy keeps the rest as sent.
        let mut payload = raw;
        if let Some(fields) = payload.as_object_mut() {
            fields.remove("withhuman_programs");
        }
        let mut incoming = Incoming::new(translation.request).with_payload(payload);
        if record {
            incoming = incoming.recorded();
        }
        if translation.workdir_unknown {
            // The call was judged as running in the project directory.
            incoming = incoming.with_flag("codex_workdir", json!(WORKDIR_UNKNOWN));
        }
        Ok(incoming)
    }
}
