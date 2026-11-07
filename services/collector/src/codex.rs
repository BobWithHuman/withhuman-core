//! Translates Codex CLI Hooks into the Claude Code Hook requests the Collector already handles,
//! so the same normalization, graph and judgment apply to Codex sessions unchanged.
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

use serde_json::{Map, Value, json};
use withhuman_contracts::{
    codex::{CodexHookEvent, CodexHookInput, CodexShell},
    hooks::{
        HookEventName, PostToolBatchRequest, PostToolUseFailureRequest, PostToolUseRequest,
        PreToolUseRequest, SessionStartRequest, SubagentLifecycleRequest, UserPromptSubmitRequest,
    },
};

use crate::NormalizedEvent;

/// Marks every event of a Codex session.
pub const AGENT_KIND: &str = "codex";
/// Set on a shell call whose directory the bridge could not tell: it was judged as running in
/// the project directory.
pub const WORKDIR_UNKNOWN: &str = "unknown";

/// Codex names for its shell tool, across versions.
const SHELL_TOOLS: &[&str] = &[
    "Bash",
    "exec_command",
    "shell",
    "local_shell",
    "shell_command",
    "unified_exec",
];

/// What a Codex Hook becomes.
#[derive(Debug, Clone, PartialEq)]
pub enum Translated {
    SessionStart(SessionStartRequest),
    UserPromptSubmit(UserPromptSubmitRequest),
    PreToolUse(PreToolUseRequest),
    PostToolUse(PostToolUseRequest),
    PostToolUseFailure(PostToolUseFailureRequest),
    /// A turn's end closes the open tool batch, as Claude Code's PostToolBatch does.
    PostToolBatch(PostToolBatchRequest),
    SubagentStart(SubagentLifecycleRequest),
    SubagentStop(SubagentLifecycleRequest),
    /// Nothing for the engine (SessionEnd).
    Nothing,
}

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

/// The Claude Code request for one Codex Hook.
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
        }),
        CodexHookEvent::UserPromptSubmit => Translated::UserPromptSubmit(UserPromptSubmitRequest {
            session_id: input.session_id,
            hook_event_name: Some(HookEventName::UserPromptSubmit),
            prompt: input.prompt.ok_or(TranslateError::Missing("prompt"))?,
            prompt_id: input.turn_id,
            transcript_path: input.transcript_path,
            cwd: input.cwd,
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
                withhuman_programs: input.withhuman_programs,
            })
        }
        CodexHookEvent::PostToolUse => {
            let call = tool_call(&input, shell)?;
            workdir_unknown = call.workdir_unknown;
            let tool_use_id = input
                .tool_use_id
                .ok_or(TranslateError::Missing("tool_use_id"))?;
            match input.withhuman_failure {
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
        CodexHookEvent::SessionEnd => Translated::Nothing,
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
        return (shell.tool_name().to_owned(), json!({ "command": command }));
    }
    match name {
        "apply_patch" => apply_patch(input, cwd),
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
                json!({ "file_path": resolve(cwd, path) }),
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
    let path = resolve(cwd, &path?).replace('\\', "/");
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
        .map(|word| quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `word` quoted for a POSIX shell when it needs it.
fn quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,\\".contains(c));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// `path` resolved against `cwd`, with `.` and `..` steps taken out; separators follow `cwd`.
pub fn resolve(cwd: Option<&str>, path: &str) -> String {
    let absolute =
        path.starts_with('/') || path.starts_with('\\') || path.as_bytes().get(1) == Some(&b':');
    let Some(cwd) = cwd.filter(|_| !absolute) else {
        return path.to_owned();
    };
    let separator = if cwd.contains('\\') { '\\' } else { '/' };
    let (root, base) = if cwd.as_bytes().get(1) == Some(&b':') {
        (format!("{}{separator}", &cwd[..2]), &cwd[2..])
    } else if cwd.starts_with(['/', '\\']) {
        (separator.to_string(), cwd)
    } else {
        (String::new(), cwd)
    };
    let mut steps: Vec<&str> = Vec::new();
    for step in base.split(['/', '\\']).chain(path.split(['/', '\\'])) {
        match step {
            "" | "." => {}
            ".." => {
                steps.pop();
            }
            step => steps.push(step),
        }
    }
    format!("{root}{}", steps.join(&separator.to_string()))
}

/// One step of a Codex patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchStep {
    Add {
        path: String,
        lines: Vec<String>,
    },
    Update {
        path: String,
        move_to: Option<String>,
        hunks: Vec<Hunk>,
    },
    Delete {
        path: String,
    },
}

/// A hunk as the lines it replaces and the lines it leaves, context included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hunk {
    pub old: Vec<String>,
    pub new: Vec<String>,
}

/// The steps of a Codex patch (`*** Begin Patch` … `*** End Patch`); none when it does not
/// parse, so a malformed patch is never taken for less than it is.
pub fn parse_patch(patch: &str) -> Option<Vec<PatchStep>> {
    // Headers are matched without a trailing `\r`; added and removed lines keep theirs.
    let mut lines = patch.split('\n');
    // Codex accepts the patch wrapped in a here-document; only its body counts.
    lines
        .by_ref()
        .find(|line| line.trim() == "*** Begin Patch")?;
    let mut steps: Vec<PatchStep> = Vec::new();
    let mut ended = false;
    for line in lines {
        let header = line.trim_end();
        if header == "*** End Patch" {
            ended = true;
            break;
        }
        if let Some(path) = header.strip_prefix("*** Add File: ") {
            steps.push(PatchStep::Add {
                path: path.trim().to_owned(),
                lines: Vec::new(),
            });
        } else if let Some(path) = header.strip_prefix("*** Update File: ") {
            steps.push(PatchStep::Update {
                path: path.trim().to_owned(),
                move_to: None,
                hunks: Vec::new(),
            });
        } else if let Some(path) = header.strip_prefix("*** Delete File: ") {
            steps.push(PatchStep::Delete {
                path: path.trim().to_owned(),
            });
        } else if let Some(target) = header.strip_prefix("*** Move to: ") {
            match steps.last_mut() {
                Some(PatchStep::Update { move_to, hunks, .. })
                    if move_to.is_none() && hunks.is_empty() =>
                {
                    *move_to = Some(target.trim().to_owned());
                }
                _ => return None,
            }
        } else if header == "*** End of File" {
            if !matches!(steps.last(), Some(PatchStep::Update { .. })) {
                return None;
            }
        } else if header.starts_with("***") {
            return None;
        } else {
            match steps.last_mut()? {
                PatchStep::Add { lines, .. } => lines.push(line.strip_prefix('+')?.to_owned()),
                PatchStep::Update { hunks, .. } => {
                    if line.starts_with("@@") {
                        hunks.push(Hunk::default());
                        continue;
                    }
                    if hunks.is_empty() {
                        hunks.push(Hunk::default());
                    }
                    let hunk = hunks.last_mut()?;
                    let line = if line.trim_end_matches('\r').is_empty() {
                        ""
                    } else {
                        line
                    };
                    match line.chars().next() {
                        Some('+') => hunk.new.push(line[1..].to_owned()),
                        Some('-') => hunk.old.push(line[1..].to_owned()),
                        Some(' ') => {
                            hunk.old.push(line[1..].to_owned());
                            hunk.new.push(line[1..].to_owned());
                        }
                        // An empty context line whose leading space was trimmed.
                        None => {
                            hunk.old.push(String::new());
                            hunk.new.push(String::new());
                        }
                        Some(_) => return None,
                    }
                }
                PatchStep::Delete { .. } => return None,
            }
        }
    }
    (ended && !steps.is_empty()).then_some(steps)
}

fn patch_text(input: &Value) -> Option<&str> {
    match input {
        Value::String(patch) => Some(patch),
        _ => ["command", "input", "patch"]
            .iter()
            .find_map(|field| input.get(*field).and_then(Value::as_str)),
    }
}

/// A patch as the Claude Code calls making the same changes: one when it makes one change,
/// else an `apply_patch` call listing them in `changes`. A patch that does not parse keeps its
/// name and text, judged as written.
fn apply_patch(input: &Value, cwd: Option<&str>) -> (String, Value) {
    let Some(patch) = patch_text(input) else {
        return ("apply_patch".to_owned(), input.clone());
    };
    let Some(steps) = parse_patch(patch) else {
        return ("apply_patch".to_owned(), json!({ "command": patch }));
    };
    let mut changes: Vec<(String, Value)> = Vec::new();
    for step in steps {
        match step {
            PatchStep::Add { path, lines } => {
                let content = if lines.is_empty() {
                    String::new()
                } else {
                    format!("{}\n", lines.join("\n"))
                };
                changes.push((
                    "Write".to_owned(),
                    json!({ "file_path": resolve(cwd, &path), "content": content }),
                ));
            }
            PatchStep::Update {
                path,
                move_to,
                hunks,
            } => {
                let mut target = resolve(cwd, &path);
                if let Some(move_to) = move_to {
                    let destination = resolve(cwd, &move_to);
                    changes.push((
                        "Bash".to_owned(),
                        json!({ "command": format!("mv -- {} {}", quote(&target), quote(&destination)) }),
                    ));
                    target = destination;
                    if hunks.is_empty() {
                        continue;
                    }
                }
                let edits: Vec<Value> = hunks
                    .into_iter()
                    .map(|hunk| {
                        json!({ "old_string": hunk.old.join("\n"), "new_string": hunk.new.join("\n") })
                    })
                    .collect();
                changes.push((
                    "MultiEdit".to_owned(),
                    json!({ "file_path": target, "edits": edits }),
                ));
            }
            PatchStep::Delete { path } => changes.push((
                "Bash".to_owned(),
                json!({ "command": format!("rm -- {}", quote(&resolve(cwd, &path))) }),
            )),
        }
    }
    if let [(tool_name, tool_input)] = changes.as_slice() {
        return (tool_name.clone(), tool_input.clone());
    }
    let changes: Vec<Value> = changes
        .into_iter()
        .map(|(tool_name, tool_input)| json!({ "tool_name": tool_name, "tool_input": tool_input }))
        .collect();
    (
        "apply_patch".to_owned(),
        json!({ "command": patch, "changes": changes }),
    )
}

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

/// Marks `event` as coming from Codex, keeping the Hook as Codex sent it (`payload`), and
/// whether a shell call's directory was unknown.
pub fn tag(event: &mut NormalizedEvent, payload: Option<&Value>, workdir_unknown: bool) {
    macro_rules! mark {
        ($envelope:expr) => {{
            let envelope = $envelope;
            envelope
                .meta
                .additional_fields
                .insert("agent_kind".to_owned(), json!(AGENT_KIND));
            if workdir_unknown {
                envelope
                    .meta
                    .additional_fields
                    .insert("codex_workdir".to_owned(), json!(WORKDIR_UNKNOWN));
            }
            if let Some(payload) = payload {
                envelope
                    .additional_fields
                    .insert("codex_payload".to_owned(), payload.clone());
            }
        }};
    }
    match event {
        NormalizedEvent::SessionStart(event) => mark!(event),
        NormalizedEvent::UserPromptSubmit(event) => mark!(event),
        NormalizedEvent::PreToolUse(event) => mark!(&mut event.event),
        NormalizedEvent::PostToolUse(event) => mark!(event),
        NormalizedEvent::PostToolUseFailure(event) => mark!(event),
        NormalizedEvent::SubagentStart(event) => mark!(event),
        NormalizedEvent::SubagentStop(event) => mark!(event),
        NormalizedEvent::ConfigChange(event) => mark!(event),
        NormalizedEvent::MessageDisplay(event) => mark!(event),
        NormalizedEvent::Intent(event) => mark!(event),
        NormalizedEvent::PostToolBatch(event) => mark!(event),
        NormalizedEvent::ToolDescriptions(event) => mark!(event),
    }
}
