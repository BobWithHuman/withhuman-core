//! OpenClaw Hooks, as the engine receives them.
//!
//! The captures under `crates/contracts/tests/fixtures/openclaw/` are whole sessions of
//! OpenClaw 2026.11.7. Every one of them is replayed through the route here, so the
//! translation is checked against what OpenClaw actually sends rather than against its
//! documentation.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_collector::{
    CollectorConfig, CollectorService, GeneratorError, GeneratorTransport, NormalizedEvent,
    app_with_transport, openclaw::UNTRANSLATED,
};
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionResponse},
    events::EventResponse,
};

const CAPTURES: [&str; 5] = [
    include_str!("../../../crates/contracts/tests/fixtures/openclaw/capture-session-1.jsonl"),
    include_str!("../../../crates/contracts/tests/fixtures/openclaw/capture-session-2-tools.jsonl"),
    include_str!(
        "../../../crates/contracts/tests/fixtures/openclaw/capture-session-3-failure.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/openclaw/capture-session-4-nested.jsonl"
    ),
    include_str!("../../../crates/contracts/tests/fixtures/openclaw/capture-session-5-mcp.jsonl"),
];

/// Every captured Hook of every captured session, in the order OpenClaw sent it. The harness's
/// own registration line is not a Hook and is left out.
fn captured() -> Vec<(String, Value)> {
    CAPTURES
        .iter()
        .flat_map(|text| text.lines())
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: Value = serde_json::from_str(line).expect("capture holds JSON");
            (
                row["_event"].as_str().expect("_event").to_owned(),
                row["payload"].clone(),
            )
        })
        .filter(|(event, _)| event != "capture:registered")
        .collect()
}

/// A recorded OpenClaw session reaches the engine without one Hook being turned away. The
/// client blocks a Call whose Hook failed, so a Hook the route refuses blocks the call behind
/// it.
#[tokio::test]
async fn every_hook_of_a_recorded_session_is_accepted() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    for (event, payload) in captured() {
        let (status, _) = send(&app, &event, payload.clone()).await;
        assert_eq!(status, StatusCode::OK, "{event} was turned away: {payload}");
    }
    let events = generator.events.lock().unwrap();
    assert!(
        events.len() > 20,
        "the sessions should have reached the engine, got {}",
        events.len()
    );
}

/// OpenClaw's tools become the Claude Code tool doing the same thing, with their input under
/// the names the rules for that tool read, so those rules apply as they are. Left untranslated,
/// `exec` would be classified by the words in its name — and `exec` is not `execute`.
#[tokio::test]
async fn tools_become_their_claude_code_counterparts() {
    for (shell, expected) in [(None, "Bash"), (Some("powershell"), "PowerShell")] {
        let (name, input, cwd) = translated_call(
            call(
                "exec",
                json!({
                    "title": "List workspace files", "command": "ls -1A",
                    "workdir": "/work/project", "yieldMs": 10000, "awaitResults": true
                }),
            ),
            shell,
        )
        .await;
        assert_eq!(name, expected);
        assert_eq!(input, json!({"command": "ls -1A"}));
        // A shell call says which directory it runs in; the turn's is only the fallback.
        assert_eq!(cwd.as_deref(), Some("/work/project"));
    }

    // Listing a directory is the agent running a program over it, not a search.
    let (name, input, _) =
        translated_call(call("ls", json!({"path": "/work", "limit": 100})), None).await;
    assert_eq!(
        (name.as_str(), input),
        ("Bash", json!({"command": "ls -- /work"}))
    );

    // A directory whose name holds a space is one argument, not two: unquoted, the command the
    // engine judges would not be the one the agent ran.
    let (_, input, _) = translated_call(
        call("ls", json!({"path": "/work/my notes; rm -rf ."})),
        None,
    )
    .await;
    assert_eq!(
        input,
        json!({"command": "ls -- '/work/my notes; rm -rf .'"})
    );

    // The rules read a file by `file_path`; OpenClaw names it `path`.
    let (name, input, _) = translated_call(
        call(
            "read",
            json!({"path": "/work/a.md", "offset": 1, "limit": 20}),
        ),
        None,
    )
    .await;
    assert_eq!(name, "Read");
    assert_eq!(
        input,
        json!({"file_path": "/work/a.md", "offset": 1, "limit": 20})
    );

    let (name, input, _) = translated_call(
        call("write", json!({"path": "/work/a.md", "content": "hello"})),
        None,
    )
    .await;
    assert_eq!(name, "Write");
    assert_eq!(
        input,
        json!({"file_path": "/work/a.md", "content": "hello"})
    );

    // An edit is Claude Code's MultiEdit, one edit per change, under the names the file-change
    // check reads them by.
    let (name, input, _) = translated_call(
        call(
            "edit",
            json!({
                "path": "/work/a.md",
                "edits": [{"oldText": "one", "newText": "one\ntwo"}]
            }),
        ),
        None,
    )
    .await;
    assert_eq!(name, "MultiEdit");
    assert_eq!(
        input,
        json!({
            "file_path": "/work/a.md",
            "edits": [{"old_string": "one", "new_string": "one\ntwo"}]
        })
    );
}

/// An `apply_patch` becomes the Claude Code calls making its changes, so the file-change check
/// reads the lines rather than a patch it would have to parse itself. OpenClaw sends the same
/// text Codex does, under a field of its own name (`input`), which is why the translation is
/// shared.
#[tokio::test]
async fn a_patch_becomes_the_calls_making_its_changes() {
    // One file updated in place: a MultiEdit with one edit per hunk.
    let (name, input, _) = translated_call(
        call(
            "apply_patch",
            json!({"input": "*** Begin Patch\n*** Update File: /work/alpha.md\n@@\n-alpha\n+alpha patched\n*** End Patch"}),
        ),
        None,
    )
    .await;
    assert_eq!(name, "MultiEdit");
    assert_eq!(input["file_path"], "/work/alpha.md");
    assert_eq!(input["edits"][0]["old_string"], "alpha");
    assert_eq!(input["edits"][0]["new_string"], "alpha patched");

    // One file added: a Write.
    let (name, input, _) = translated_call(
        call(
            "apply_patch",
            json!({"input": "*** Begin Patch\n*** Add File: /work/new.md\n+hello\n*** End Patch"}),
        ),
        None,
    )
    .await;
    assert_eq!(name, "Write");
    assert_eq!(input["file_path"], "/work/new.md");
    assert_eq!(input["content"], "hello\n");

    // More than one file: the calls are listed, so each change is still judged as its own.
    let (name, input, _) = translated_call(
        call(
            "apply_patch",
            json!({"input": "*** Begin Patch\n*** Add File: /work/a.md\n+a\n*** Delete File: /work/b.md\n*** End Patch"}),
        ),
        None,
    )
    .await;
    assert_eq!(name, "apply_patch");
    let changes = input["changes"].as_array().expect("the calls it became");
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0]["tool_name"], "Write");
    assert_eq!(changes[1]["tool_name"], "Bash");

    // A patch whose paths are relative resolves against the turn's directory, which the client
    // fills in: `call` above sends `/work` as the workspace.
    let (_, input, _) = translated_call(
        call(
            "apply_patch",
            json!({"input": "*** Begin Patch\n*** Add File: nested/c.md\n+c\n*** End Patch"}),
        ),
        None,
    )
    .await;
    assert_eq!(input["file_path"], "/work/nested/c.md");
}

/// OpenClaw runs a Call for another: `dispatch_action` names an action, and the action arrives
/// a second time as a Call of its own. Blocking the dispatch keeps the action from running at
/// all, so the dispatch is the Call the engine judges — and the one that follows it is the
/// same work, which would otherwise be recorded and judged twice.
#[tokio::test]
async fn a_dispatch_is_judged_once_at_the_call_that_runs_it() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());

    // The dispatching call, judged as the action it names.
    let (status, _) = send(
        &app,
        "before_tool_call",
        json!({
            "sessionId": "s-1", "runId": "r-1", "agentId": "main",
            "workspaceDir": "/work",
            "toolName": "dispatch_action",
            "toolCallId": "call_outer|fc_outer",
            "params": {"id": "openclaw:core:agents_list", "args": {}}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The Call the dispatch ran, named after it: the engine has it already.
    let (status, _) = send(
        &app,
        "before_tool_call",
        json!({
            "sessionId": "s-1", "runId": "r-1", "agentId": "main",
            "toolName": "agents_list",
            "toolCallId": "tool_call:call_outer_fc_outer:agents_list:1",
            "params": {}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let events = generator.events.lock().unwrap();
    let calls: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            NormalizedEvent::PreToolUse(call) => Some(call.event.payload.tool_name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        calls,
        ["agents_list"],
        "one dispatch must reach the engine as one Call"
    );
}

/// An MCP call reaches the same Hook as any other, so the Hook judges MCP rather than leaving
/// it to AgentGateway. Its tool already holds the server it goes to, so the engine's name for
/// it is `mcp__` and the tool as it stands.
#[tokio::test]
async fn an_mcp_call_becomes_the_name_the_engine_knows_mcp_by() {
    // Dispatched, as OpenClaw runs one.
    let (name, input, _) = translated_call(
        json!({
            "sessionId": "s-1", "runId": "r-1", "workspaceDir": "/work",
            "toolName": "dispatch_action", "toolCallId": "call_outer|fc_outer",
            "params": {
                "id": "mcp:wh-probe:wh-probe__echo_back",
                "args": {"text": "withhuman mcp test"}
            }
        }),
        None,
    )
    .await;
    assert_eq!(name, "mcp__wh-probe__echo_back");
    assert_eq!(input, json!({"text": "withhuman mcp test"}));

    // Called directly, should a server's tool be on the model's surface already.
    let (name, input, _) =
        translated_call(call("wh-probe__echo_back", json!({"text": "hello"})), None).await;
    assert_eq!(name, "mcp__wh-probe__echo_back");
    assert_eq!(input, json!({"text": "hello"}));
}

/// A result reaches the engine in the shape the rules for that tool read it by.
#[tokio::test]
async fn results_carry_what_the_call_brought_in() {
    let response = result_of(json!({
        "sessionId": "s-1", "runId": "r-1", "toolName": "exec",
        "toolCallId": "c1", "params": {"command": "cat note", "workdir": "/work"},
        "result": {
            "content": [{"type": "text", "text": "from the file\n"}],
            "details": {"status": "completed", "exitCode": 0}
        },
        "error": null, "durationMs": 12
    }))
    .await;
    assert_eq!(response["stdout"], "from the file\n");
    assert_eq!(response["stderr"], "");

    // A file read answers with the text it brought in, where the rules look for it.
    let response = result_of(json!({
        "sessionId": "s-1", "runId": "r-1", "toolName": "read",
        "toolCallId": "c2", "params": {"path": "/work/a.md"},
        "result": {
            "content": [{"type": "text", "text": "hello withhuman\n"}],
            "details": {"kind": "text"}
        },
        "error": null
    }))
    .await;
    assert_eq!(response["file"]["content"], "hello withhuman\n");
}

/// A program that exited non-zero is known from its own Hook, with no transcript to read back.
/// `error` stays null and `details.status` says `completed`, so the exit code is what decides —
/// reading either of the other two would take a failed command for a successful one.
#[tokio::test]
async fn a_failed_command_is_known_from_its_own_hook() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "after_tool_call",
        json!({
            "sessionId": "s-1", "runId": "r-1", "toolName": "exec", "toolCallId": "c1",
            "params": {"command": "cat /nonexistent/path", "workdir": "/work"},
            "result": {
                "content": [{"type": "text", "text": "No such file\n\n(Command exited with code 1)"}],
                "details": {"status": "completed", "exitCode": 1, "exitReason": "exit"}
            },
            "error": null, "durationMs": 1421
        }),
    )
    .await;
    let events = generator.events.lock().unwrap();
    // What the command printed is kept, as Claude Code keeps a failing command's output, so the
    // text it brought in is still judged.
    let NormalizedEvent::PostToolUse(event) = &events[0] else {
        panic!("expected a result, got {:?}", events[0]);
    };
    assert_eq!(event.payload.tool_response["stderr"], "exit code 1");
    assert!(
        event.payload.tool_response["stdout"]
            .as_str()
            .is_some_and(|text| text.contains("No such file"))
    );
}

/// A command that printed nothing and failed is a failure, not a result of nothing.
#[tokio::test]
async fn a_failed_command_without_output_is_a_failure() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "after_tool_call",
        json!({
            "sessionId": "s-1", "runId": "r-1", "toolName": "exec", "toolCallId": "c1",
            "params": {"command": "false", "workdir": "/work"},
            "result": {"content": [], "details": {"status": "completed", "exitCode": 1}},
            "error": null
        }),
    )
    .await;
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PostToolUseFailure(event) = &events[0] else {
        panic!("expected a failure, got {:?}", events[0]);
    };
    assert_eq!(event.payload.error, "exit code 1");
}

/// OpenClaw can ask the user about a Call and blocks it on a deny or a timeout, so a REVIEW is
/// asked rather than denied. Every other client of the engine's has to deny one.
#[tokio::test]
async fn a_review_is_asked_of_the_user_rather_than_denied() {
    let generator = Arc::new(Recording::reviewing());
    let app = app(generator.clone());
    let (status, body) = send(
        &app,
        "before_tool_call",
        call(
            "exec",
            json!({"command": "rm -rf /work/build", "workdir": "/work"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecision"], "ask",
        "a REVIEW must reach OpenClaw as a question for the user"
    );
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecisionReason"],
        "the user has not asked for this"
    );
}

/// A tool this adapter has no translation for still reaches the engine, marked as what it is:
/// the Call is judged, but not by the rules of the tool it stands for.
#[tokio::test]
async fn a_tool_without_a_translation_is_marked() {
    let generator = Arc::new(Recording::allowing());
    let unknown = app(generator.clone());
    send(
        &unknown,
        "before_tool_call",
        call("canvas", json!({"action": "open"})),
    )
    .await;
    {
        let events = generator.events.lock().unwrap();
        let NormalizedEvent::PreToolUse(recorded) = &events[0] else {
            panic!("expected a call, got {:?}", events[0]);
        };
        assert_eq!(recorded.event.payload.tool_name, "canvas");
        assert_eq!(
            recorded.event.meta.additional_fields[UNTRANSLATED],
            json!(true)
        );
    }

    // A tool with a translation is not marked.
    let translated = Arc::new(Recording::allowing());
    let route = app(translated.clone());
    send(
        &route,
        "before_tool_call",
        call("read", json!({"path": "/work/a.md"})),
    )
    .await;
    let events = translated.events.lock().unwrap();
    let NormalizedEvent::PreToolUse(recorded) = &events[0] else {
        panic!("expected a call, got {:?}", events[0]);
    };
    assert!(
        !recorded
            .event
            .meta
            .additional_fields
            .contains_key(UNTRANSLATED)
    );
}

/// The prompt opens the turn every Call of it belongs to, so the engine has the turn's intent
/// before it judges the first Call.
#[tokio::test]
async fn a_prompt_opens_the_turn_its_calls_belong_to() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "before_agent_run",
        json!({
            "sessionId": "s-1", "sessionKey": "agent:main:main", "runId": "r-1",
            "agentId": "main", "workspaceDir": "/work",
            "prompt": "sample.txt 를 읽어줘", "senderIsOwner": false,
            "channelId": "webchat", "trigger": "user"
        }),
    )
    .await;
    send(
        &app,
        "before_tool_call",
        call("read", json!({"path": "/work/sample.txt"})),
    )
    .await;
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::UserPromptSubmit(prompt) = &events[0] else {
        panic!("expected a prompt, got {:?}", events[0]);
    };
    assert_eq!(prompt.payload.prompt, "sample.txt 를 읽어줘");
    assert_eq!(prompt.meta.prompt_id.as_deref(), Some("r-1"));
    let NormalizedEvent::PreToolUse(read) = &events[1] else {
        panic!("expected a call, got {:?}", events[1]);
    };
    assert_eq!(read.event.meta.prompt_id.as_deref(), Some("r-1"));
    assert_eq!(read.event.meta.additional_fields["agent_kind"], "openclaw");
}

/// A turn's answer reaches the engine as the message OpenClaw showed, named after the turn it
/// belongs to, so the `[의도]` line it opens with is the intent of that turn and not of another.
#[tokio::test]
async fn a_turn_s_answer_reaches_the_engine_as_the_message_it_showed() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "before_agent_finalize",
        json!({
            "sessionId": "s-1", "runId": "r-1", "agentId": "main", "cwd": "/work",
            "lastAssistantMessage": "[의도] sample.txt 를 읽는다\n읽었어."
        }),
    )
    .await;
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::MessageDisplay(message) = &events[0] else {
        panic!("expected a message, got {:?}", events[0]);
    };
    // Intent capture is off here, so the whole answer arrives as the message's text; the line
    // the engine reads the turn's intent from is its first.
    assert!(message.payload.text.starts_with("[의도]"));
    // Named after the turn, so two answers of one turn stay two messages and the same answer
    // reported twice stays one.
    assert!(
        message.payload.message_id.starts_with("r-1-"),
        "a message says which turn it is of: {}",
        message.payload.message_id
    );
}

/// Two answers of one turn are two messages; the same answer twice is one.
#[tokio::test]
async fn an_answer_is_named_by_the_turn_and_by_what_it_says() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    for answer in ["first pass", "second pass", "first pass"] {
        send(
            &app,
            "before_agent_finalize",
            json!({"sessionId": "s-1", "runId": "r-1", "lastAssistantMessage": answer}),
        )
        .await;
    }
    let events = generator.events.lock().unwrap();
    let ids: std::collections::BTreeSet<_> = events
        .iter()
        .filter_map(|event| match event {
            NormalizedEvent::MessageDisplay(message) => Some(message.payload.message_id.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 2, "got {ids:?}");
}

/// The turn's end closes its open tool batch. `agent_end` says only that the run finished — a
/// turn whose model failed still ends with `success: true` — so nothing is read from it but the
/// turn it belongs to.
#[tokio::test]
async fn the_turn_s_end_closes_its_tool_batch() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "agent_end",
        json!({
            "sessionId": "s-1", "runId": "r-1", "agentId": "main",
            "success": true, "error": null, "durationMs": 7176, "messageCount": 27
        }),
    )
    .await;
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PostToolBatch(batch) = &events[0] else {
        panic!("expected a batch, got {:?}", events[0]);
    };
    assert_eq!(batch.meta.additional_fields["agent_kind"], "openclaw");
}

/// Every captured turn ends in one answer and one batch, in that order: the captures hold
/// eleven turns and no turn ends twice.
#[tokio::test]
async fn every_captured_turn_ends_once() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    for (event, payload) in captured() {
        send(&app, &event, payload).await;
    }
    let events = generator.events.lock().unwrap();
    let ends: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            NormalizedEvent::MessageDisplay(_) => Some("message"),
            NormalizedEvent::PostToolBatch(_) => Some("batch"),
            _ => None,
        })
        .collect();
    assert_eq!(
        ends.len(),
        22,
        "eleven captured turns should end in one answer and one batch each, got {ends:?}"
    );
    // The answer comes before the end, as OpenClaw sends them.
    for pair in ends.chunks(2) {
        assert_eq!(pair, ["message", "batch"]);
    }
}

/// A Call hard to undo that nothing could judge is put to the user rather than blocked. The
/// engine does that only for a client that both asks and loses no event to a resend, which
/// OpenClaw's does: its plugin runs the bridge once per Hook and reads the answer in the same
/// breath.
#[tokio::test]
async fn a_hard_to_undo_call_the_engine_could_not_judge_is_put_to_the_user() {
    let failing = Arc::new(Failing);
    let app = app_with_transport(CollectorService::new(
        CollectorConfig {
            intent_capture: false,
            failure_policy: withhuman_collector::FailurePolicy::Closed,
            ..CollectorConfig::default()
        },
        failing.clone(),
    ));
    let (status, body) = send(
        &app,
        "before_tool_call",
        call(
            "exec",
            json!({"command": "rm -rf /work/build", "workdir": "/work"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecision"], "ask",
        "a call the engine could not judge, and that is hard to undo, is the user's to decide"
    );

    // A call nothing graded that highly is still blocked: no judgment stands behind it.
    let (_, body) = send(
        &app,
        "before_tool_call",
        call("read", json!({"path": "/work/a.md"})),
    )
    .await;
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
}

// ---- the harness ----

/// One Call's Hook, as OpenClaw sends it. The tool Hooks name no workspace, so the client fills
/// it in from the turn it kept.
fn call(tool_name: &str, params: Value) -> Value {
    json!({
        "sessionId": "s-1", "sessionKey": "agent:main:main", "runId": "r-1",
        "agentId": "main", "workspaceDir": "/work",
        "toolName": tool_name, "toolCallId": "call_1|fc_1", "params": params
    })
}

/// The tool name, input and directory one Hook became.
async fn translated_call(payload: Value, shell: Option<&str>) -> (String, Value, Option<String>) {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    let request = post("/v1/hooks/openclaw/before_tool_call", payload, shell);
    app.oneshot(request).await.unwrap();
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PreToolUse(recorded) = &events[0] else {
        panic!("expected a call, got {:?}", events[0]);
    };
    (
        recorded.event.payload.tool_name.clone(),
        recorded.event.payload.tool_input.clone(),
        recorded.event.meta.cwd.clone(),
    )
}

/// The result one finished Call's Hook became.
async fn result_of(payload: Value) -> Value {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(&app, "after_tool_call", payload).await;
    let events = generator.events.lock().unwrap();
    match &events[0] {
        NormalizedEvent::PostToolUse(event) => event.payload.tool_response.clone(),
        other => panic!("expected a result, got {other:?}"),
    }
}

/// Intent capture off: these tests are about the translation, and the intent gate would turn
/// back the first Call of every turn before it reached the engine.
fn app(generator: Arc<Recording>) -> axum::Router {
    app_with_transport(CollectorService::new(
        CollectorConfig {
            intent_capture: false,
            ..CollectorConfig::default()
        },
        generator,
    ))
}

fn post(uri: &str, body: Value, shell: Option<&str>) -> Request<Body> {
    let mut request = Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-withhuman-client", "team-a/laptop-3");
    if let Some(shell) = shell {
        request = request.header("x-withhuman-shell", shell);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

async fn send(app: &axum::Router, event: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(post(&format!("/v1/hooks/openclaw/{event}"), body, None))
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let body = match bytes.is_empty() {
        true => Value::Null,
        false => serde_json::from_slice(&bytes).unwrap(),
    };
    (status, body)
}

/// A generator nothing reaches, for the failure policies.
struct Failing;

#[async_trait]
impl GeneratorTransport for Failing {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        Err(GeneratorError::InvalidResponse(
            "engine unavailable".to_owned(),
        ))
    }

    async fn session_cursor(
        &self,
        _session_id: &str,
    ) -> Result<withhuman_contracts::events::SessionCursor, GeneratorError> {
        Ok(withhuman_contracts::events::SessionCursor::default())
    }
}

struct Recording {
    events: Mutex<Vec<NormalizedEvent>>,
    response: EventResponse,
}

impl Recording {
    /// An ALLOW carries no reason; the contract rejects one that does, and with `resends` the
    /// route would answer 503 rather than let the Call through.
    fn allowing() -> Self {
        Self::answering(Decision::Allow, "")
    }

    fn reviewing() -> Self {
        Self::answering(Decision::Review, "the user has not asked for this")
    }

    fn answering(decision: Decision, reason: &str) -> Self {
        Self {
            events: Mutex::default(),
            response: EventResponse {
                nodes: Vec::new(),
                paragraphs: None,
                version: 1,
                decision_response: Some(DecisionResponse {
                    decision,
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
