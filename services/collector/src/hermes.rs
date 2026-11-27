//! Hermes Agent's adapter: translates its plugin hooks into the Claude Code Hook requests the
//! Collector already handles, so the same normalization, graph and judgment apply to Hermes
//! sessions unchanged. [`crate::agent`] is the seam it is plugged into.
//!
//! | Hermes hook | Claude Code |
//! |---|---|
//! | `on_session_start` | `SessionStart` |
//! | `pre_llm_call` | `UserPromptSubmit` (its answer is injected into the user's message) |
//! | `post_api_request` | `MessageDisplay` of the assistant's text, before the tools it asked for run |
//! | `pre_tool_call` | `PreToolUse` |
//! | `post_tool_call` | `PostToolUse`, or `PostToolUseFailure`; nothing for a blocked call |
//! | `on_session_end` (each turn's end) | `PostToolBatch` |
//! | `on_session_finalize` | `SessionEnd` |
//! | `subagent_start` / `subagent_stop` | `SubagentStart` / `SubagentStop` |
//!
//! A delegated subagent's own turns state no intent (the engine asks none of a subagent), so its
//! `on_session_start`, `pre_llm_call`, `post_api_request` and `on_session_end` are nothing here;
//! its calls are judged in the delegating conversation under its `agent_id`.
//!
//! Tools become the Claude Code tool doing the same thing, so the engine's rules for that tool
//! apply as they are:
//!
//! | Hermes | Claude Code |
//! |---|---|
//! | `terminal` | as a Codex shell call: `Read` or `Write` when it only prints or writes one file, else `Bash` (Hermes runs commands in bash, Git Bash on Windows) |
//! | `read_file` / `write_file` | `Read` / `Write` |
//! | `patch` replacing a string / with a V4A patch | `Edit` / the shared patch translation (`crate::patch`) |
//! | `search_files` in contents / by name | `Grep` / `Glob` |
//! | `web_search` / `web_extract` | `WebSearch` / `WebFetch` |
//! | `vision_analyze` | `WebFetch` for a URL, else `Read` |
//! | `todo_list` | `TodoWrite` |
//! | `delegate_task` spawning | `Task` |
//! | `execute_code` / `browser_exec` | `Bash` running the script with `python3` |
//! | `process_manage` writing into a running process | `Bash` with that input as the command |
//! | `cronjob_manage` creating / removing / listing | `CronCreate` / `CronDelete` / `CronList` |
//! | `mcp_<server>_<tool>` (server named by the plugin) | `mcp__<server>__<tool>` |
//! | any other | the same name and input |

use std::fmt;

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};
use withhuman_contracts::{
    hermes::{HermesHookEvent, HermesHookInput},
    hooks::{
        ClientShell, HookEventName, MessageDisplayRequest, PostToolBatchRequest,
        PostToolUseFailureRequest, PostToolUseRequest, PreToolUseRequest, SessionEndRequest,
        SessionStartRequest, SubagentLifecycleRequest, UserPromptSubmitRequest,
    },
};

pub use crate::agent::Translated;
use crate::{
    FailurePolicy, HookPolicy, ReviewPolicy,
    agent::{Agent, Incoming, Rejection},
    codex,
    patch::{self, file_key, resolve},
};

/// Marks every event of a Hermes session, and the `<kind>` of its route.
pub const AGENT_KIND: &str = "hermes";
/// Set on a `terminal` call whose directory the plugin did not report: it was judged as
/// running in the session's directory.
pub const WORKDIR_UNKNOWN: &str = "unknown";
/// Delimits an `execute_code` script in the `Bash` command it is judged as.
const SCRIPT_END: &str = "WITHHUMAN_HERMES_SCRIPT";

#[derive(Debug, Clone, PartialEq)]
pub struct Translation {
    pub request: Translated,
    /// A `terminal` call ran in a directory the plugin left unknown.
    pub workdir_unknown: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslateError {
    /// The hook lacks a field its Claude Code counterpart needs.
    Missing(&'static str),
}

impl fmt::Display for TranslateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(formatter, "hermes hook without {field}"),
        }
    }
}

impl std::error::Error for TranslateError {}

fn named(value: Option<&String>) -> Option<String> {
    value.filter(|text| !text.is_empty()).cloned()
}

/// The Claude Code request for one Hermes hook.
pub fn translate(
    event: HermesHookEvent,
    input: HermesHookInput,
) -> Result<Translation, TranslateError> {
    let mut workdir_unknown = false;
    let request = match event {
        HermesHookEvent::SubagentStart | HermesHookEvent::SubagentStop => {
            // Hermes names the delegator and the subagent; the plugin names the conversation.
            let session_id = named(input.withhuman_session_id.as_ref())
                .or_else(|| named(input.parent_session_id.as_ref()))
                .ok_or(TranslateError::Missing("parent_session_id"))?;
            let request = SubagentLifecycleRequest {
                session_id,
                hook_event_name: Some(match event {
                    HermesHookEvent::SubagentStart => HookEventName::SubagentStart,
                    _ => HookEventName::SubagentStop,
                }),
                agent_id: named(input.withhuman_agent_id.as_ref())
                    .or_else(|| named(input.child_session_id.as_ref()))
                    .ok_or(TranslateError::Missing("child_session_id"))?,
                agent_type: input.child_role,
            };
            match event {
                HermesHookEvent::SubagentStart => Translated::SubagentStart(request),
                _ => Translated::SubagentStop(request),
            }
        }
        _ if input.is_subagent()
            && event != HermesHookEvent::PreToolCall
            && event != HermesHookEvent::PostToolCall =>
        {
            Translated::Nothing
        }
        _ => {
            let session_id = input
                .engine_session()
                .ok_or(TranslateError::Missing("session_id"))?
                .to_owned();
            match event {
                HermesHookEvent::OnSessionStart => Translated::SessionStart(SessionStartRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::SessionStart),
                    transcript_path: None,
                    cwd: input.cwd,
                    source: input.platform,
                    permission_mode: None,
                    model: input.model,
                    withhuman_exception: None,
                }),
                HermesHookEvent::PreLlmCall => {
                    Translated::UserPromptSubmit(UserPromptSubmitRequest {
                        session_id,
                        hook_event_name: Some(HookEventName::UserPromptSubmit),
                        prompt: prompt_text(input.user_message.as_ref())
                            .ok_or(TranslateError::Missing("user_message"))?,
                        prompt_id: input.turn_id,
                        transcript_path: None,
                        cwd: input.cwd,
                        permission_mode: None,
                    })
                }
                HermesHookEvent::PostApiRequest => {
                    match assistant_text(input.response.as_ref()) {
                        // Every response is a message of its own, shown whole.
                        Some(delta) => Translated::MessageDisplay(MessageDisplayRequest {
                            session_id,
                            hook_event_name: Some(HookEventName::MessageDisplay),
                            message_id: named(input.api_request_id.as_ref()).unwrap_or_else(|| {
                                format!(
                                    "{}:{}",
                                    input.turn_id.clone().unwrap_or_default(),
                                    input.api_call_count.unwrap_or_default()
                                )
                            }),
                            index: Some(0),
                            delta,
                            final_: true,
                            turn_id: input.turn_id,
                        }),
                        None => Translated::Nothing,
                    }
                }
                HermesHookEvent::PreToolCall => {
                    let call = tool_call(&input)?;
                    workdir_unknown = call.workdir_unknown;
                    Translated::PreToolUse(PreToolUseRequest {
                        session_id,
                        hook_event_name: Some(HookEventName::PreToolUse),
                        tool_name: call.tool_name,
                        tool_input: call.tool_input,
                        tool_use_id: named(input.tool_call_id.as_ref())
                            .ok_or(TranslateError::Missing("tool_call_id"))?,
                        cwd: call.cwd,
                        prompt_id: input.turn_id.clone(),
                        agent_id: input.agent_id().map(str::to_owned),
                        agent_type: None,
                        permission_mode: None,
                        withhuman_programs: input.withhuman_programs.clone(),
                    })
                }
                HermesHookEvent::PostToolCall => {
                    return tool_result(session_id, input);
                }
                HermesHookEvent::OnSessionEnd => Translated::PostToolBatch(PostToolBatchRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PostToolBatch),
                    agent_id: None,
                    agent_type: None,
                    tool_calls: Vec::new(),
                }),
                HermesHookEvent::OnSessionFinalize => Translated::SessionEnd(SessionEndRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::SessionEnd),
                    transcript_path: None,
                    cwd: input.cwd,
                    permission_mode: None,
                    reason: input.reason,
                }),
                HermesHookEvent::SubagentStart | HermesHookEvent::SubagentStop => {
                    unreachable!("handled above")
                }
            }
        }
    };
    Ok(Translation {
        request,
        workdir_unknown,
    })
}

/// The text of the user's message: a string, or the text parts of a multimodal one.
fn prompt_text(message: Option<&Value>) -> Option<String> {
    match message? {
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => {
            let texts: Vec<&str> = parts
                .iter()
                .filter_map(|part| match part {
                    Value::String(text) => Some(text.as_str()),
                    part => part.get("text").and_then(Value::as_str),
                })
                .collect();
            Some(texts.join("\n"))
        }
        _ => None,
    }
}

/// The assistant's text in a model response; none when it only called tools.
fn assistant_text(response: Option<&Value>) -> Option<String> {
    let content = response?.pointer("/assistant_message/content")?;
    let text = prompt_text(Some(content))?;
    (!text.trim().is_empty()).then_some(text)
}

/// The finished call's request: a blocked call never ran, so there is nothing to record.
fn tool_result(session_id: String, input: HermesHookInput) -> Result<Translation, TranslateError> {
    let status = input.status.clone().unwrap_or_default();
    if status == "blocked" {
        return Ok(Translation {
            request: Translated::Nothing,
            workdir_unknown: false,
        });
    }
    let call = tool_call(&input)?;
    let tool_use_id =
        named(input.tool_call_id.as_ref()).ok_or(TranslateError::Missing("tool_call_id"))?;
    let result = parsed(input.result.clone().unwrap_or(Value::Null));
    let terminal = input.tool_name.as_deref() == Some("terminal");
    let exit_code = result.get("exit_code").and_then(Value::as_i64);
    let agent_id = input.agent_id().map(str::to_owned);
    let request = match status.as_str() {
        "error" => {
            let output = result
                .get("output")
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty());
            let error = match exit_code {
                Some(code) if code != 0 => format!("exit code {code}"),
                _ => named(input.error_message.as_ref())
                    .or_else(|| named(input.error_type.as_ref()))
                    .unwrap_or_else(|| "failed".to_owned()),
            };
            match output {
                // What a failed command printed still reaches the graph, as Claude Code
                // reports a Bash command that exited non-zero.
                Some(output) if terminal => Translated::PostToolUse(PostToolUseRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PostToolUse),
                    tool_response: json!({ "stdout": output, "stderr": format!("({error})") }),
                    tool_name: call.tool_name,
                    tool_input: Some(call.tool_input),
                    tool_use_id,
                    cwd: call.cwd,
                    prompt_id: input.turn_id,
                    agent_id,
                    agent_type: None,
                    permission_mode: None,
                }),
                _ => Translated::PostToolUseFailure(PostToolUseFailureRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PostToolUseFailure),
                    tool_name: call.tool_name,
                    tool_input: Some(call.tool_input),
                    error,
                    tool_use_id,
                    cwd: call.cwd,
                    prompt_id: input.turn_id,
                    agent_id,
                    agent_type: None,
                    permission_mode: None,
                }),
            }
        }
        _ => Translated::PostToolUse(PostToolUseRequest {
            session_id,
            hook_event_name: Some(HookEventName::PostToolUse),
            tool_response: tool_response(terminal, &call.tool_name, &call.tool_input, result),
            tool_name: call.tool_name,
            tool_input: Some(call.tool_input),
            tool_use_id,
            cwd: call.cwd,
            prompt_id: input.turn_id,
            agent_id,
            agent_type: None,
            permission_mode: None,
        }),
    };
    Ok(Translation {
        request,
        workdir_unknown: call.workdir_unknown,
    })
}

/// Hermes hands a tool's result over as the JSON text the model reads.
fn parsed(result: Value) -> Value {
    match result {
        Value::String(text) => serde_json::from_str(&text).unwrap_or(Value::String(text)),
        result => result,
    }
}

/// A result in the form the Claude Code tool reports it, so the engine reads its text: a
/// command's or script's `{stdout, stderr}`, a write as Write reports it, a command that only
/// printed a file as Read gives it, anything else as Hermes gave it when the engine can read
/// its text, else that text whole.
fn tool_response(terminal: bool, tool_name: &str, tool_input: &Value, result: Value) -> Value {
    let output = || {
        result
            .get("output")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    match tool_name {
        "Read" if terminal => json!({
            "type": "text",
            "file": { "filePath": tool_input["file_path"], "content": output() },
        }),
        // A `patch` replacing a string; a command's append is reported as Codex reports it.
        "Edit" if !terminal => json!({
            "filePath": tool_input["file_path"], "oldString": tool_input["old_string"],
            "newString": tool_input["new_string"],
            "replaceAll": tool_input.get("replace_all").cloned().unwrap_or(json!(false)),
            "structuredPatch": [], "userModified": false,
        }),
        "Write" | "Edit" => crate::codex_write::write_response(tool_name, tool_input),
        "Bash" => json!({ "stdout": output(), "stderr": "" }),
        _ if withhuman_common::origin::tool_output(&result).is_some() => result,
        _ => Value::String(result.to_string()),
    }
}

/// A Hermes tool call as its Claude Code counterpart.
struct ToolCall {
    tool_name: String,
    tool_input: Value,
    /// The directory the call runs in.
    cwd: Option<String>,
    workdir_unknown: bool,
}

fn tool_call(input: &HermesHookInput) -> Result<ToolCall, TranslateError> {
    let name = input
        .tool_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .ok_or(TranslateError::Missing("tool_name"))?;
    let args = input.args.clone().unwrap_or_else(|| json!({}));
    let session_cwd = input.cwd.as_deref();
    // A command runs where its `workdir` says (for that command only), else where the session's
    // last `cd` left it, which the plugin follows. File tools resolve against the session's
    // directory.
    let terminal = name == "terminal";
    let workdir = args
        .get("workdir")
        .and_then(Value::as_str)
        .filter(|path| terminal && !path.trim().is_empty());
    let base = input.withhuman_workdir.as_deref().or(session_cwd);
    let cwd = match workdir {
        Some(workdir) => Some(resolve(base, workdir)),
        None if terminal => base.map(str::to_owned),
        None => session_cwd.map(str::to_owned),
    };
    let (tool_name, tool_input) = translate_tool(
        name,
        &args,
        session_cwd,
        cwd.as_deref(),
        input.withhuman_mcp_server.as_deref(),
    );
    Ok(ToolCall {
        tool_name,
        tool_input,
        cwd,
        workdir_unknown: terminal && workdir.is_none() && input.withhuman_workdir.is_none(),
    })
}

fn text<'a>(args: &'a Value, field: &str) -> Option<&'a str> {
    args.get(field).and_then(Value::as_str)
}

/// Copies the fields of `args` that are set into `target`, under Claude Code's names.
fn carry(target: &mut Map<String, Value>, args: &Value, fields: &[(&str, &str)]) {
    for (from, to) in fields {
        if let Some(value) = args.get(*from).filter(|value| !value.is_null()) {
            target.insert((*to).to_owned(), value.clone());
        }
    }
}

/// A Hermes tool's name and arguments as the Claude Code tool doing the same. `session_cwd` is
/// the session's directory, `cwd` the one the call runs in, `mcp_server` the server the plugin
/// named for an MCP tool.
pub fn translate_tool(
    name: &str,
    args: &Value,
    session_cwd: Option<&str>,
    cwd: Option<&str>,
    mcp_server: Option<&str>,
) -> (String, Value) {
    let path = |field: &str| file_key(session_cwd, text(args, field).unwrap_or("."));
    match name {
        // A Hermes command is one `bash -c` string, as a Codex shell call is.
        "terminal" => {
            let command = text(args, "command").unwrap_or_default();
            let (tool_name, mut tool_input) = codex::translate_tool(
                "shell",
                &json!({ "command": command }),
                cwd,
                ClientShell::Posix,
            );
            if tool_name == "Bash" && args.get("background") == Some(&Value::Bool(true)) {
                tool_input["run_in_background"] = json!(true);
            }
            (tool_name, tool_input)
        }
        "read_file" => {
            let mut read = Map::from_iter([("file_path".to_owned(), json!(path("path")))]);
            carry(&mut read, args, &[("offset", "offset"), ("limit", "limit")]);
            ("Read".to_owned(), Value::Object(read))
        }
        "write_file" => (
            "Write".to_owned(),
            json!({ "file_path": path("path"), "content": text(args, "content").unwrap_or_default() }),
        ),
        "patch" if text(args, "patch").is_some() => patch::translate(args, session_cwd),
        "patch" => {
            let mut edit = Map::from_iter([("file_path".to_owned(), json!(path("path")))]);
            carry(
                &mut edit,
                args,
                &[
                    ("old_string", "old_string"),
                    ("new_string", "new_string"),
                    ("replace_all", "replace_all"),
                ],
            );
            ("Edit".to_owned(), Value::Object(edit))
        }
        "search_files" => {
            let pattern = text(args, "pattern").unwrap_or_default();
            if text(args, "target") == Some("files") {
                return (
                    "Glob".to_owned(),
                    json!({ "pattern": pattern, "path": path("path") }),
                );
            }
            let mut grep = Map::from_iter([
                ("pattern".to_owned(), json!(pattern)),
                ("path".to_owned(), json!(path("path"))),
            ]);
            carry(&mut grep, args, &[("file_glob", "glob")]);
            let mode = match text(args, "output_mode") {
                Some("files_only") => "files_with_matches",
                Some("count") => "count",
                _ => "content",
            };
            grep.insert("output_mode".to_owned(), json!(mode));
            if let Some(context) = args
                .get("context")
                .and_then(Value::as_u64)
                .filter(|n| *n > 0)
            {
                grep.insert("-C".to_owned(), json!(context));
            }
            ("Grep".to_owned(), Value::Object(grep))
        }
        "web_search" => (
            "WebSearch".to_owned(),
            json!({ "query": text(args, "query").unwrap_or_default() }),
        ),
        "web_extract" => {
            let urls: Vec<String> = args
                .get("urls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|url| url.as_str().map(str::to_owned))
                .collect();
            let Some(url) = urls.first() else {
                // A request of a shape not seen yet still counts as a web call.
                return ("WebFetch".to_owned(), json!({ "url": args.to_string() }));
            };
            let mut fetch = Map::from_iter([("url".to_owned(), json!(url))]);
            if urls.len() > 1 {
                fetch.insert("urls".to_owned(), json!(urls));
            }
            ("WebFetch".to_owned(), Value::Object(fetch))
        }
        "vision_analyze" => {
            let image = text(args, "image_url").unwrap_or_default();
            if image.starts_with("http://") || image.starts_with("https://") {
                ("WebFetch".to_owned(), json!({ "url": image }))
            } else {
                (
                    "Read".to_owned(),
                    json!({ "file_path": file_key(session_cwd, image) }),
                )
            }
        }
        "todo_list" if args.get("todos").is_some() => {
            let todos: Vec<Value> = args["todos"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|item| json!({ "content": item["content"], "status": item["status"] }))
                .collect();
            ("TodoWrite".to_owned(), json!({ "todos": todos }))
        }
        "delegate_task"
            if matches!(text(args, "action"), None | Some("spawn"))
                && args.get("tasks").is_some() =>
        {
            let tasks: Vec<String> = args["tasks"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|task| {
                    let goal = task["goal"].as_str().unwrap_or_default();
                    match task["context"].as_str().filter(|text| !text.is_empty()) {
                        Some(context) => format!("{goal}\n\n{context}"),
                        None => goal.to_owned(),
                    }
                })
                .collect();
            let description = args["tasks"][0]["goal"].as_str().unwrap_or_default();
            (
                "Task".to_owned(),
                json!({ "description": description, "prompt": tasks.join("\n\n---\n\n") }),
            )
        }
        // Both run a Python script of the model's on this machine (`browser_exec` drives the
        // browser from it).
        "execute_code" | "browser_exec" => {
            let code = text(args, "code").unwrap_or_default();
            (
                "Bash".to_owned(),
                json!({ "command": format!("python3 - <<'{SCRIPT_END}'\n{code}\n{SCRIPT_END}") }),
            )
        }
        // Input written into a running background process (a shell or REPL started with
        // `pty`) is a command run there.
        "process_manage" if matches!(text(args, "action"), Some("write" | "submit")) => (
            "Bash".to_owned(),
            json!({ "command": text(args, "data").unwrap_or_default() }),
        ),
        "cronjob_manage" => match text(args, "action") {
            Some("create") => {
                let mut cron = Map::from_iter([
                    (
                        "cron".to_owned(),
                        json!(text(args, "schedule").unwrap_or_default()),
                    ),
                    (
                        "prompt".to_owned(),
                        json!(text(args, "prompt").unwrap_or_default()),
                    ),
                ]);
                carry(&mut cron, args, &[("repeat", "repeat"), ("name", "name")]);
                ("CronCreate".to_owned(), Value::Object(cron))
            }
            Some("remove") => ("CronDelete".to_owned(), json!({ "id": args["job_id"] })),
            Some("list") => ("CronList".to_owned(), json!({})),
            _ => ("cronjob_manage".to_owned(), args.clone()),
        },
        name => match mcp_server.and_then(|server| {
            name.strip_prefix(&format!("mcp_{server}_"))
                .map(|tool| (server, tool))
        }) {
            Some((server, tool)) => (format!("mcp__{server}__{tool}"), args.clone()),
            None => (name.to_owned(), args.clone()),
        },
    }
}

/// Fields of a hook kept out of the copy stored with its event: kept elsewhere already, or too
/// large and private to keep.
const NOT_KEPT: &[&str] = &[
    "withhuman_programs",
    "conversation_history",
    "request_messages",
    "request",
];

/// Hermes Agent's adapter: its plugin hooks, as the Claude Code requests the engine judges.
pub struct Hermes;

impl Agent for Hermes {
    fn kind(&self) -> &'static str {
        AGENT_KIND
    }

    /// Hermes can ask its user, but `--yolo`, `approvals.mode: off` and an unattended run
    /// trusted with `approvals.single_query_mode: approve` approve every escalation unseen,
    /// while a block holds in all of them. So a REVIEW denies, as for Codex. MCP calls do not
    /// pass AgentGateway, and a call that cannot be judged is blocked. The plugin sends every
    /// hook as it happens, with no delivery ID to resend it under.
    fn policy(&self) -> HookPolicy {
        HookPolicy {
            review: ReviewPolicy::Deny,
            mcp_at_hook: true,
            failure: FailurePolicy::Closed,
            resends: false,
        }
    }

    fn translate(
        &self,
        event: &str,
        raw: Value,
        _headers: &HeaderMap,
    ) -> Result<Incoming, Rejection> {
        let Some(event) = HermesHookEvent::from_path(event) else {
            return Err(Rejection::unknown_event());
        };
        let input = serde_json::from_value::<HermesHookInput>(raw.clone())
            .map_err(|_| Rejection::invalid_json())?;
        let translation = translate(event, input)
            .map_err(|_| Rejection::new(StatusCode::BAD_REQUEST, "invalid_hermes_hook"))?;
        let mut payload = raw;
        if let Some(fields) = payload.as_object_mut() {
            for field in NOT_KEPT {
                fields.remove(*field);
            }
        }
        let mut incoming = Incoming::new(translation.request).with_payload(payload);
        if translation.workdir_unknown {
            // The call was judged as running in the session's directory.
            incoming = incoming.with_flag("hermes_workdir", json!(WORKDIR_UNKNOWN));
        }
        Ok(incoming)
    }
}
