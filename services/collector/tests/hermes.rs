//! The Hermes route: Hermes Agent plugin hooks translated into the Claude Code requests the
//! Collector handles, checked against hooks recorded from Hermes Agent 0.23.3 on Windows.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_collector::{
    CollectorConfig, CollectorService, GeneratorError, GeneratorTransport, INTENT_INSTRUCTION,
    INTENT_REQUIRED, NormalizedEvent, ReviewPolicy, app_with_transport,
    hermes::{Translated, translate, translate_tool},
};
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionResponse},
    events::EventResponse,
    hermes::{HermesHookEvent, HermesHookInput},
};

const H0: &str = include_str!("../../../crates/contracts/tests/fixtures/hermes/h0-windows.json");
const H0_TRANSLATED: &str =
    include_str!("../../../crates/contracts/tests/fixtures/hermes/h0-windows.translated.json");

fn event_of(input: &Value) -> HermesHookEvent {
    let name = input["hook_event_name"].as_str().unwrap();
    HermesHookEvent::from_path(name).unwrap_or_else(|| panic!("unknown hook {name}"))
}

fn request_json(translated: &Translated) -> Value {
    match translated {
        Translated::SessionStart(request) => serde_json::to_value(request),
        Translated::UserPromptSubmit(request) => serde_json::to_value(request),
        Translated::PreToolUse(request) => serde_json::to_value(request),
        Translated::PostToolUse(request) => serde_json::to_value(request),
        Translated::PostToolUseFailure(request) => serde_json::to_value(request),
        Translated::PostToolBatch(request) => serde_json::to_value(request),
        Translated::MessageDisplay(request) => serde_json::to_value(request),
        Translated::ConfigChange(request) => serde_json::to_value(request),
        Translated::SubagentStart(request) | Translated::SubagentStop(request) => {
            serde_json::to_value(request)
        }
        Translated::SessionEnd(request) => serde_json::to_value(request),
        Translated::Nothing => Ok(Value::Null),
    }
    .unwrap()
}

fn claude_event(translated: &Translated) -> &'static str {
    match translated {
        Translated::SessionStart(_) => "SessionStart",
        Translated::UserPromptSubmit(_) => "UserPromptSubmit",
        Translated::PreToolUse(_) => "PreToolUse",
        Translated::PostToolUse(_) => "PostToolUse",
        Translated::PostToolUseFailure(_) => "PostToolUseFailure",
        Translated::PostToolBatch(_) => "PostToolBatch",
        Translated::MessageDisplay(_) => "MessageDisplay",
        Translated::ConfigChange(_) => "ConfigChange",
        Translated::SubagentStart(_) => "SubagentStart",
        Translated::SubagentStop(_) => "SubagentStop",
        Translated::SessionEnd(_) => "SessionEnd",
        Translated::Nothing => "",
    }
}

fn h0() -> Vec<(String, Value, Translated)> {
    let h0: Value = serde_json::from_str(H0).unwrap();
    assert_eq!(h0["platform"], "windows");
    h0["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|fixture| {
            let input = fixture["input"].clone();
            let translation = translate(
                event_of(&input),
                serde_json::from_value(input.clone()).unwrap(),
            )
            .unwrap_or_else(|error| panic!("{}: {error}", fixture["scenario"]));
            (
                fixture["scenario"].as_str().unwrap().to_owned(),
                input,
                translation.request,
            )
        })
        .collect()
}

/// Every recorded hook translates into the Claude Code request kept in the snapshot.
/// `UPDATE_HERMES_SNAPSHOT=1` rewrites the snapshot.
#[test]
fn h0_hooks_translate_into_the_recorded_claude_requests() {
    let translated: Vec<Value> = h0()
        .into_iter()
        .map(|(scenario, input, request)| {
            json!({
                "scenario": scenario,
                "hermes_hook": input["hook_event_name"],
                "claude_event": claude_event(&request),
                "request": request_json(&request),
            })
        })
        .collect();
    if std::env::var_os("UPDATE_HERMES_SNAPSHOT").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/contracts/tests/fixtures/hermes/h0-windows.translated.json"
        );
        let mut text = serde_json::to_string_pretty(&translated).unwrap();
        text.push('\n');
        std::fs::write(path, text).unwrap();
        return;
    }
    let expected: Vec<Value> = serde_json::from_str(H0_TRANSLATED).unwrap();
    assert_eq!(translated.len(), expected.len());
    for (index, (actual, expected)) in translated.iter().zip(&expected).enumerate() {
        assert_eq!(actual, expected, "fixture {index}");
    }
}

fn scenario_of<'a>(
    fixtures: &'a [(String, Value, Translated)],
    scenario: &'a str,
) -> impl Iterator<Item = (&'a Value, &'a Translated)> + 'a {
    fixtures
        .iter()
        .filter(move |(name, _, _)| name == scenario)
        .map(|(_, input, request)| (input, request))
}

/// What the recorded sessions must come to, whatever the snapshot says.
#[test]
fn h0_translations_keep_the_engines_view_of_each_session() {
    let fixtures = h0();
    let of = |scenario: &'static str| scenario_of(&fixtures, scenario);

    // A turn: the prompt, the intent line before the first call, then calls and results.
    let basic: Vec<&str> = of("s1_basic").map(|(_, r)| claude_event(r)).collect();
    let prompt = basic.iter().position(|e| *e == "UserPromptSubmit").unwrap();
    let message = basic.iter().position(|e| *e == "MessageDisplay").unwrap();
    let call = basic.iter().position(|e| *e == "PreToolUse").unwrap();
    assert!(prompt < message && message < call, "{basic:?}");
    let intent = of("s1_basic")
        .find_map(|(_, request)| match request {
            Translated::MessageDisplay(message) => Some(message.delta.clone()),
            _ => None,
        })
        .unwrap();
    assert!(intent.starts_with("[의도]"), "{intent}");

    // `cd sub` is kept for the next command, which runs there; a file path stays the session's.
    let calls: Vec<_> = of("s1_basic")
        .filter_map(|(_, request)| match request {
            Translated::PreToolUse(call) => Some(call.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(calls[0].tool_name, "Bash");
    assert_eq!(calls[0].cwd.as_deref(), Some("C:\\work\\project"));
    assert_eq!(calls[1].tool_input["command"], "pwd");
    assert_eq!(calls[1].cwd.as_deref(), Some("C:\\work\\project\\sub"));
    assert_eq!(calls[2].tool_name, "Write");
    assert_eq!(
        calls[2].tool_input["file_path"],
        "C:/work/project/probe.txt"
    );

    // A command that exited 3 with nothing printed is a failure.
    assert!(of("s1_basic").any(|(_, request)| matches!(
        request,
        Translated::PostToolUseFailure(failure) if failure.error == "exit code 3"
    )));

    // A blocked call never ran: nothing is recorded for its result.
    for (input, request) in of("s3_block") {
        if input["hook_event_name"] == "post_tool_call" {
            assert_eq!(input["status"], "blocked");
            assert_eq!(request, &Translated::Nothing);
        }
    }

    // A script's calls are judged with an ID the plugin gave them.
    let script: Vec<_> = of("s5_execute_code")
        .filter_map(|(_, request)| match request {
            Translated::PreToolUse(call) => Some(call.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(script[0].tool_name, "Bash");
    assert!(
        script[0].tool_input["command"]
            .as_str()
            .unwrap()
            .starts_with("python3 - <<")
    );
    assert_eq!(script[1].tool_use_id, "withhuman-script-1");
    assert!(
        script[1].tool_input["command"]
            .as_str()
            .unwrap()
            .contains("NESTED-BLOCKME")
    );

    // A subagent's calls belong to the delegating session, under its agent ID; its own turn
    // states no intent.
    let delegating = of("s6_delegate")
        .find_map(|(input, _)| {
            (input["hook_event_name"] == "subagent_start")
                .then(|| input["parent_session_id"].as_str().unwrap().to_owned())
        })
        .unwrap();
    let child_call = of("s6_delegate")
        .find_map(|(input, request)| match request {
            Translated::PreToolUse(call) if input["tool_name"] == "terminal" => Some(call.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(child_call.session_id, delegating);
    assert!(child_call.agent_id.is_some());
    for (input, request) in of("s6_delegate") {
        if input["platform"] == "subagent" {
            assert_eq!(
                request,
                &Translated::Nothing,
                "{}",
                input["hook_event_name"]
            );
        }
    }
    let delegate = of("s6_delegate")
        .find_map(|(_, request)| match request {
            Translated::PreToolUse(call) if call.tool_name == "Task" => Some(call.clone()),
            _ => None,
        })
        .unwrap();
    assert!(delegate.agent_id.is_none());

    // A deferred tool reached through `tool_call` is judged by its own name.
    assert!(of("s8_tool_call").any(|(_, request)| matches!(
        request,
        Translated::PreToolUse(call) if call.tool_name == "withhuman_poc_echo"
    )));
}

#[test]
fn translates_hermes_tools_into_claude_code_tools() {
    let tool = |name: &str, args: Value| {
        translate_tool(name, &args, Some("C:\\proj"), Some("C:\\proj\\sub"), None)
    };
    assert_eq!(
        tool(
            "terminal",
            json!({"command": "npm test", "background": true})
        ),
        (
            "Bash".to_owned(),
            json!({"command": "npm test", "run_in_background": true})
        )
    );
    // A command that only prints one file is a Read of it, where the command runs.
    assert_eq!(
        tool("terminal", json!({"command": "cat notes.md"})).0,
        "Read"
    );
    assert_eq!(
        tool(
            "read_file",
            json!({"path": "src/main.rs", "offset": 10, "limit": null})
        ),
        (
            "Read".to_owned(),
            json!({"file_path": "C:/proj/src/main.rs", "offset": 10})
        )
    );
    assert_eq!(
        tool("write_file", json!({"path": "a.txt", "content": "x"})),
        (
            "Write".to_owned(),
            json!({"file_path": "C:/proj/a.txt", "content": "x"})
        )
    );
    assert_eq!(
        tool(
            "patch",
            json!({"path": "a.txt", "old_string": "x", "new_string": "y", "replace_all": false})
        ),
        (
            "Edit".to_owned(),
            json!({"file_path": "C:/proj/a.txt", "old_string": "x", "new_string": "y", "replace_all": false})
        )
    );
    assert_eq!(
        tool(
            "patch",
            json!({"mode": "patch", "patch": "*** Begin Patch\n*** Add File: new.txt\n+hi\n*** End Patch"})
        ),
        (
            "Write".to_owned(),
            json!({"file_path": "C:/proj/new.txt", "content": "hi\n"})
        )
    );
    assert_eq!(
        tool(
            "search_files",
            json!({"pattern": "*.rs", "target": "files", "path": "src"})
        ),
        (
            "Glob".to_owned(),
            json!({"pattern": "*.rs", "path": "C:/proj/src"})
        )
    );
    assert_eq!(
        tool(
            "search_files",
            json!({"pattern": "todo", "file_glob": "*.py", "output_mode": "files_only", "context": 2})
        ),
        (
            "Grep".to_owned(),
            json!({"pattern": "todo", "path": "C:/proj", "glob": "*.py", "output_mode": "files_with_matches", "-C": 2})
        )
    );
    assert_eq!(
        tool("web_search", json!({"query": "rust"})),
        ("WebSearch".to_owned(), json!({"query": "rust"}))
    );
    assert_eq!(
        tool(
            "web_extract",
            json!({"urls": ["https://a.example", "https://b.example"]})
        ),
        (
            "WebFetch".to_owned(),
            json!({"url": "https://a.example", "urls": ["https://a.example", "https://b.example"]})
        )
    );
    assert_eq!(
        tool(
            "vision_analyze",
            json!({"image_url": "https://a.example/x.png"})
        )
        .0,
        "WebFetch"
    );
    assert_eq!(
        tool("vision_analyze", json!({"image_url": "shot.png"})),
        ("Read".to_owned(), json!({"file_path": "C:/proj/shot.png"}))
    );
    assert_eq!(
        tool(
            "delegate_task",
            json!({"tasks": [{"goal": "fix tests", "context": "in crate a"}]})
        ),
        (
            "Task".to_owned(),
            json!({"description": "fix tests", "prompt": "fix tests\n\nin crate a"})
        )
    );
    // Steering a running subagent is no spawn: it keeps its name.
    assert_eq!(
        tool(
            "delegate_task",
            json!({"action": "steer", "subagent_id": "sa-1", "message": "stop"})
        )
        .0,
        "delegate_task"
    );
    assert_eq!(
        translate_tool(
            "mcp_github_tools_create_issue",
            &json!({"title": "x"}),
            None,
            None,
            Some("github_tools")
        ),
        (
            "mcp__github_tools__create_issue".to_owned(),
            json!({"title": "x"})
        )
    );
    assert_eq!(
        tool("memory", json!({"operations": []})),
        ("memory".to_owned(), json!({"operations": []}))
    );
    // A script that drives the browser runs on this machine as execute_code's does.
    let (name, input) = tool(
        "browser_exec",
        json!({"code": "page.goto('https://x.example')"}),
    );
    assert_eq!(name, "Bash");
    assert!(input["command"].as_str().unwrap().contains("page.goto"));
    // Typing into a running shell is running that command; reading its output is not.
    assert_eq!(
        tool(
            "process_manage",
            json!({"action": "submit", "session_id": "p1", "data": "rm -rf build"})
        ),
        ("Bash".to_owned(), json!({"command": "rm -rf build"}))
    );
    assert_eq!(
        tool(
            "process_manage",
            json!({"action": "poll", "session_id": "p1"})
        )
        .0,
        "process_manage"
    );
    assert_eq!(
        tool(
            "cronjob_manage",
            json!({"action": "create", "schedule": "every 2h", "prompt": "sync", "repeat": null})
        ),
        (
            "CronCreate".to_owned(),
            json!({"cron": "every 2h", "prompt": "sync"})
        )
    );
    assert_eq!(
        tool(
            "cronjob_manage",
            json!({"action": "remove", "job_id": "j1"})
        ),
        ("CronDelete".to_owned(), json!({"id": "j1"}))
    );
    assert_eq!(
        tool("cronjob_manage", json!({"action": "pause", "job_id": "j1"})).0,
        "cronjob_manage"
    );
}

#[test]
fn follows_the_plugins_session_through_a_compression() {
    // After a compression Hermes gives the session a new ID; the plugin names the first.
    let input: HermesHookInput = serde_json::from_value(json!({
        "session_id": "s-2", "conversation_id": "s-1", "withhuman_session_id": "s-1",
        "tool_name": "read_file", "args": {"path": "a"}, "tool_call_id": "c1", "cwd": "/p",
    }))
    .unwrap();
    let Translated::PreToolUse(call) = translate(HermesHookEvent::PreToolCall, input)
        .unwrap()
        .request
    else {
        panic!("expected PreToolUse");
    };
    assert_eq!(call.session_id, "s-1");
    assert_eq!(call.agent_id, None);

    let prompt: HermesHookInput = serde_json::from_value(json!({
        "session_id": "s-2", "withhuman_session_id": "s-1", "platform": "cli",
        "user_message": [{"type": "text", "text": "look"}, {"type": "image_url"}],
    }))
    .unwrap();
    let Translated::UserPromptSubmit(prompt) = translate(HermesHookEvent::PreLlmCall, prompt)
        .unwrap()
        .request
    else {
        panic!("expected UserPromptSubmit");
    };
    assert_eq!(
        (prompt.session_id.as_str(), prompt.prompt.as_str()),
        ("s-1", "look")
    );
}

#[test]
fn asks_a_rotated_session_for_its_intent() {
    // The gateway gives a session it rotates or resets a parent too; the plugin says it is no
    // subagent, so its turn is asked for the intent line as any other.
    let prompt: HermesHookInput = serde_json::from_value(json!({
        "session_id": "s-3", "withhuman_session_id": "s-3", "parent_session_id": "s-2",
        "platform": "cli", "user_message": "go on",
    }))
    .unwrap();
    assert!(matches!(
        translate(HermesHookEvent::PreLlmCall, prompt)
            .unwrap()
            .request,
        Translated::UserPromptSubmit(_)
    ));
    // A delegated subagent's turn, as Hermes names it, is still nothing to ask.
    let child: HermesHookInput = serde_json::from_value(json!({
        "session_id": "c", "withhuman_session_id": "s-3", "withhuman_agent_id": "c",
        "parent_session_id": "s-3", "platform": "subagent", "user_message": "TASK: x",
    }))
    .unwrap();
    assert_eq!(
        translate(HermesHookEvent::PreLlmCall, child)
            .unwrap()
            .request,
        Translated::Nothing
    );
}

#[test]
fn turns_away_a_call_it_cannot_identify() {
    let input: HermesHookInput = serde_json::from_value(json!({
        "session_id": "s", "tool_name": "terminal", "args": {"command": "ls"}, "tool_call_id": "",
    }))
    .unwrap();
    assert!(translate(HermesHookEvent::PreToolCall, input).is_err());
}

#[tokio::test]
async fn judges_a_hermes_turn_as_a_claude_code_turn() {
    let generator = Arc::new(Recording::decision(Decision::Allow, ""));
    let app = app(CollectorConfig::default(), generator.clone());
    let session = json!({"session_id": "h1", "withhuman_session_id": "h1", "cwd": "C:\\proj", "platform": "cli"});
    let with = |extra: Value| {
        let mut body = session.clone();
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    assert_eq!(
        send(&app, "on_session_start", with(json!({"model": "m"}))).await,
        (StatusCode::OK, Value::Null)
    );
    let (_, body) = send(
        &app,
        "pre_llm_call",
        with(json!({"turn_id": "t1", "user_message": "fix it", "conversation_history": [1, 2]})),
    )
    .await;
    assert_eq!(
        body["hookSpecificOutput"]["additionalContext"],
        INTENT_INSTRUCTION
    );
    send(
        &app,
        "post_api_request",
        with(json!({"turn_id": "t1", "api_request_id": "r1",
                    "response": {"assistant_message": {"content": "[의도] 테스트를 고치고 싶음", "tool_calls": [{"id": "c1"}]}}})),
    )
    .await;
    assert_eq!(
        send(
            &app,
            "pre_tool_call",
            with(
                json!({"turn_id": "t1", "conversation_id": "h1", "tool_name": "terminal",
                        "tool_call_id": "c1", "args": {"command": "cargo test"},
                        "withhuman_workdir": "C:\\proj\\crate"})
            ),
        )
        .await,
        (StatusCode::OK, Value::Null)
    );

    let events = generator.events.lock().unwrap();
    let NormalizedEvent::UserPromptSubmit(prompt) = &events[1] else {
        panic!("expected UserPromptSubmit");
    };
    assert_eq!(prompt.meta.additional_fields["agent_kind"], "hermes");
    let kept = &prompt.additional_fields["hermes_payload"];
    assert_eq!(kept["user_message"], "fix it");
    assert!(kept.get("conversation_history").is_none());
    let NormalizedEvent::PreToolUse(call) = events.last().unwrap() else {
        panic!("expected PreToolUse");
    };
    assert_eq!(call.event.payload.tool_name, "Bash");
    assert_eq!(call.event.meta.additional_fields["agent_kind"], "hermes");
    assert!(
        !call
            .event
            .meta
            .additional_fields
            .contains_key("hermes_workdir")
    );
}

#[tokio::test]
async fn denies_a_review_on_hermes_even_where_claude_code_asks() {
    let config = CollectorConfig {
        review_policy: ReviewPolicy::Ask,
        intent_capture: false,
        ..Default::default()
    };
    let generator = Arc::new(Recording::decision(Decision::Review, "needs a look"));
    let app = app(config, generator);
    let (status, body) = send(
        &app,
        "pre_tool_call",
        json!({"session_id": "h2", "tool_name": "write_file", "tool_call_id": "c1",
               "args": {"path": "a.txt", "content": "x"}, "cwd": "/p"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecisionReason"],
        "needs a look"
    );
}

#[tokio::test]
async fn sends_a_call_back_for_its_intent_and_spares_a_subagent() {
    let config = CollectorConfig {
        intent_wait: Duration::from_millis(50),
        ..Default::default()
    };
    let generator = Arc::new(Recording::decision(Decision::Allow, ""));
    let app = app(config, generator);
    send(
        &app,
        "pre_llm_call",
        json!({"session_id": "h3", "turn_id": "t", "user_message": "go", "platform": "cli"}),
    )
    .await;
    let call = json!({"session_id": "h3", "conversation_id": "h3", "tool_name": "read_file",
                      "tool_call_id": "c1", "args": {"path": "a"}, "cwd": "/p"});
    let (_, body) = send(&app, "pre_tool_call", call).await;
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecisionReason"],
        INTENT_REQUIRED
    );

    // A subagent's turn states no intent of its own and is not sent back for one.
    let (_, body) = send(
        &app,
        "pre_llm_call",
        json!({"session_id": "child", "parent_session_id": "h3", "platform": "subagent",
               "user_message": "CONTEXT: x"}),
    )
    .await;
    assert_eq!(body, Value::Null);
    let child = json!({"session_id": "child", "conversation_id": "h3", "task_id": "sa-0",
                       "tool_name": "read_file", "tool_call_id": "c2", "args": {"path": "a"}, "cwd": "/p"});
    assert_eq!(
        send(&app, "pre_tool_call", child).await,
        (StatusCode::OK, Value::Null)
    );
}

#[tokio::test]
async fn turns_away_hooks_it_does_not_know() {
    let app = app(
        CollectorConfig::default(),
        Arc::new(Recording::decision(Decision::Allow, "")),
    );
    let (status, _) = send(&app, "on_stream_delta", json!({"session_id": "s"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&app, "pre_tool_call", json!(["not", "an", "object"])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

fn app(config: CollectorConfig, generator: Arc<Recording>) -> axum::Router {
    app_with_transport(CollectorService::new(config, generator))
}

async fn send(app: &axum::Router, hook: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::post(format!("/v1/hooks/hermes/{hook}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-withhuman-client", "team-a/laptop-3")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

struct Recording {
    events: Mutex<Vec<NormalizedEvent>>,
    response: EventResponse,
}

impl Recording {
    fn decision(verdict: Decision, reason: &str) -> Self {
        Self {
            events: Mutex::default(),
            response: EventResponse {
                nodes: Vec::new(),
                paragraphs: None,
                version: 1,
                decision_response: Some(DecisionResponse {
                    decision: verdict,
                    reason: reason.to_owned(),
                    rule: "test-rule".to_owned(),
                    start: CausalStart::User,
                    written: true,
                    jev: None,
                }),
            },
        }
    }
}

#[async_trait]
impl GeneratorTransport for Recording {
    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        self.events.lock().unwrap().push(event);
        Ok(self.response.clone())
    }
}
