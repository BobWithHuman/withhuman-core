//! Antigravity Hooks, as the engine receives them.
//!
//! The captures under `crates/contracts/tests/fixtures/antigravity/` are whole sessions of
//! Antigravity CLI 1.5.16. Every one of them is replayed through the route here, so the
//! translation is checked against what Antigravity actually sends rather than against the
//! reference the client ships.

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
    app_with_transport,
};
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionResponse},
    events::EventResponse,
};

const CAPTURES: [&str; 6] = [
    include_str!(
        "../../../crates/contracts/tests/fixtures/antigravity/capture-session-1-shell.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/antigravity/capture-session-2-edit.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/antigravity/capture-session-3-failure.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/antigravity/capture-session-4-mcp.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/antigravity/capture-session-5-web-subagent.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/antigravity/capture-session-6-subagent-own.jsonl"
    ),
];

/// Every captured Hook of every captured session, in the order Antigravity sent it.
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
        .collect()
}

/// G: a recorded Antigravity session reaches the engine without one Hook being turned away. A
/// Hook the route refuses answers nothing, and Antigravity blocks the call behind it.
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
        events.len() > 15,
        "the sessions should have reached the engine, got {}",
        events.len()
    );
}

/// G: a shell call is judged as the shell the client actually runs, with the command under the
/// name the rules read it by.
#[tokio::test]
async fn a_shell_call_takes_the_name_of_the_clients_shell() {
    let call = tool_call(
        "run_command",
        json!({
            "CommandLine": "rm -rf build", "WaitMsBeforeAsync": 5000, "toolSummary": "clean"
        }),
    );
    assert_eq!(
        translated_call(call.clone(), None).await,
        ("Bash".to_owned(), json!({"command": "rm -rf build"}))
    );
    assert_eq!(
        translated_call(call, Some("powershell")).await.0,
        "PowerShell"
    );
}

/// G: a file a Call names reaches the engine under the key file reads and writes share, so a
/// file one Call read is the file another Call wrote.
#[tokio::test]
async fn a_file_call_is_judged_by_the_path_key_every_call_shares() {
    assert_eq!(
        translated_call(tool_call("read_file", json!({"Path": "src/main.rs"})), None).await,
        ("Read".to_owned(), json!({"file_path": "/repo/src/main.rs"}))
    );
    assert_eq!(
        translated_call(
            tool_call(
                "write_file",
                json!({
                    "Path": "/repo/a.txt", "Content": "hi", "Overwrite": true
                })
            ),
            None
        )
        .await,
        (
            "Write".to_owned(),
            json!({"file_path": "/repo/a.txt", "content": "hi"})
        )
    );
}

/// G: one replacement in a file is Claude Code's `Edit`, so the rules that deny a change to
/// the agent's own hooks read the file it names.
///
/// Found against the real client: before this translation a session asked to lower the hook
/// timeout in `.agents/hooks.json` did it — the call arrived as the tool `edit_file`, which no
/// rule knows, so the safeguard check never saw the file and the model judged the change as
/// the one the user had asked for.
#[tokio::test]
async fn an_edit_is_judged_as_a_change_to_the_file_it_names() {
    assert_eq!(
        translated_call(
            tool_call(
                "edit_file",
                json!({
                    "Path": "/repo/.agents/hooks.json",
                    "Target": "\"timeout\": 25",
                    "Replacement": "\"timeout\": 1"
                })
            ),
            None
        )
        .await,
        (
            "Edit".to_owned(),
            json!({
                "file_path": "/repo/.agents/hooks.json",
                "old_string": "\"timeout\": 25",
                "new_string": "\"timeout\": 1"
            })
        )
    );
}

/// G: an MCP call reaches the engine under the name it knows MCP by, with the server's own
/// arguments as the input. Antigravity names both in the open, so nothing is guessed.
#[tokio::test]
async fn an_mcp_call_is_named_by_the_server_and_tool_it_carries() {
    assert_eq!(
        translated_call(
            tool_call(
                "call_mcp_tool",
                json!({
                    "ServerName": "withhuman-fixture", "ToolName": "write_file",
                    "Arguments": {"path": "a.txt"}
                })
            ),
            None
        )
        .await,
        (
            "mcp__withhuman-fixture__write_file".to_owned(),
            json!({"path": "a.txt"})
        )
    );
}

/// G: a tool this adapter has no translation for still reaches the engine, under its own name
/// and marked as untranslated — judged, never silently dropped, and never judged by the rules
/// of a tool it was guessed to be.
#[tokio::test]
async fn an_unknown_tool_is_passed_through_and_marked() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "PreToolUse",
        tool_call("browser_click_element", json!({"ElementId": "7"})),
    )
    .await;
    {
        let events = generator.events.lock().unwrap();
        let NormalizedEvent::PreToolUse(call) = &events[0] else {
            panic!("expected a call, got {:?}", events[0]);
        };
        assert_eq!(call.event.payload.tool_name, "browser_click_element");
        assert_eq!(
            call.event
                .meta
                .additional_fields
                .get("antigravity_untranslated"),
            Some(&json!(true))
        );
    }
    // A tool it does translate is not marked.
    assert_eq!(
        translated_call(tool_call("read_file", json!({"Path": "a"})), None)
            .await
            .0,
        "Read"
    );
}

/// G: the prompt is sent on the one invocation the bridge marked as opening a turn. An
/// invocation of 0 is not enough: the loop re-enters at 0 within one prompt, and sending it
/// again would split one turn into two Requests.
#[tokio::test]
async fn the_prompt_is_sent_on_the_invocation_that_opened_the_turn() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    let invocation = |number: i64, opened: bool| {
        let mut payload = json!({
            "conversationId": "c1", "hookEventName": "PreInvocation", "cwd": "/repo",
            "invocationNum": number, "initialNumSteps": 1,
            "lastUserInput": "fix the build", "withhuman_turn": "turn-1",
        });
        if opened {
            payload["withhuman_new_turn"] = json!(true);
        }
        payload
    };
    send(&app, "PreInvocation", invocation(0, true)).await;
    // The loop coming back at 0 within the same turn, which the bridge did not mark.
    send(&app, "PreInvocation", invocation(0, false)).await;
    send(&app, "PreInvocation", invocation(1, false)).await;
    let events = generator.events.lock().unwrap();
    assert_eq!(events.len(), 1, "one turn is one prompt");
    match &events[0] {
        NormalizedEvent::UserPromptSubmit(event) => {
            assert_eq!(event.payload.prompt, "fix the build");
            assert_eq!(event.meta.prompt_id.as_deref(), Some("turn-1"));
        }
        other => panic!("expected the prompt, got {other:?}"),
    }
}

/// G: a subagent's Calls are judged inside the session and the turn they were delegated from,
/// so the intent that turn stated is what they are judged against.
///
/// Found against the real client: judged on their own, with no prompt and so no intent, a
/// subagent's own messaging was denied as a deviation.
#[tokio::test]
async fn a_subagents_call_is_judged_inside_the_session_it_came_from() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    let mut call = tool_call("run_command", json!({"CommandLine": "wc -l data.txt"}));
    call["conversationId"] = json!("agent-1");
    call["withhuman_parent_session"] = json!("session-1");
    send(&app, "PreToolUse", call).await;
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PreToolUse(judged) = &events[0] else {
        panic!("expected a call, got {:?}", events[0]);
    };
    assert_eq!(judged.event.session_id, "session-1");
    assert_eq!(judged.event.meta.agent_id.as_deref(), Some("agent-1"));
}

/// G: a failed Call reaches the engine as a failure with what Antigravity said went wrong, and
/// a Call that succeeded does not. Antigravity reports both in one field, an empty string
/// meaning it worked.
#[tokio::test]
async fn a_failed_call_is_told_from_one_that_worked() {
    let result = |error: &str| {
        let mut payload = tool_call("read_file", json!({"Path": "/nope"}));
        payload["hookEventName"] = json!("PostToolUse");
        payload["error"] = json!(error);
        payload
    };
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(&app, "PostToolUse", result("file not found")).await;
    send(&app, "PostToolUse", result("")).await;
    let events = generator.events.lock().unwrap();
    match &events[0] {
        NormalizedEvent::PostToolUseFailure(event) => {
            assert_eq!(event.payload.error, "file not found");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
    assert!(
        matches!(events[1], NormalizedEvent::PostToolUse(_)),
        "an empty error is a Call that worked, got {:?}",
        events[1]
    );
}

/// G: what a Call brought in reaches the engine in the shape the rules for that tool read,
/// since the Hook carries no result and the bridge read it from the transcript.
#[tokio::test]
async fn a_result_the_bridge_read_arrives_in_the_shape_its_tool_is_read_by() {
    let result = |tool: &str, args: Value, text: Option<&str>| {
        let mut payload = tool_call(tool, args);
        payload["hookEventName"] = json!("PostToolUse");
        payload["error"] = json!("");
        if let Some(text) = text {
            payload["withhuman_result"] = json!(text);
        }
        payload
    };
    assert_eq!(
        result_of(result(
            "run_command",
            json!({"CommandLine": "ls"}),
            Some("a.txt")
        ))
        .await,
        json!({"stdout": "a.txt", "stderr": ""})
    );
    assert_eq!(
        result_of(result(
            "read_file",
            json!({"Path": "a"}),
            Some("brought in")
        ))
        .await,
        json!({"file": {"content": "brought in"}})
    );
    // A result the bridge could not read is empty, not a Call that brought in nothing.
    assert_eq!(
        result_of(result("read_file", json!({"Path": "a"}), None)).await,
        json!({})
    );
}

/// G: the turn's end closes the batch of calls it opened.
#[tokio::test]
async fn the_loops_end_closes_the_turns_batch() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "Stop",
        json!({
            "conversationId": "c1", "hookEventName": "Stop", "cwd": "/repo",
            "executionNum": 0, "terminationReason": "NO_TOOL_CALL", "fullyIdle": true,
            "continuationActive": false, "error": "", "lastUserInput": "x",
        }),
    )
    .await;
    let events = generator.events.lock().unwrap();
    assert!(
        matches!(events[0], NormalizedEvent::PostToolBatch(_)),
        "expected the batch to close, got {:?}",
        events[0]
    );
}

/// G: the answer the bridge read from the transcript reaches the engine as a message, which is
/// where the turn's intent line is. No Antigravity Hook carries the answer.
#[tokio::test]
async fn the_answer_the_bridge_read_reaches_the_engine_as_a_message() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    let (status, _) = send(
        &app,
        "MessageDisplay",
        json!({
            "session_id": "c1", "message_id": "step-2", "index": 0,
            "delta": "[의도] 빌드를 고치고 싶음", "final": true, "turn_id": "turn-1",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = generator.events.lock().unwrap();
    match &events[0] {
        NormalizedEvent::MessageDisplay(event) => {
            assert_eq!(event.payload.text, "[의도] 빌드를 고치고 싶음");
            assert_eq!(event.meta.turn_id.as_deref(), Some("turn-1"));
        }
        other => panic!("expected a message, got {other:?}"),
    }
}

/// G: a Hook this agent does not have, and a Call with no id, are turned away under codes the
/// client's self-check knows.
#[tokio::test]
async fn an_unknown_hook_is_turned_away() {
    let app = app(Arc::new(Recording::allowing()));
    let (status, body) = send(&app, "BeforeTool", json!({"conversationId": "c1"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], json!("unknown_event"));
    // Nothing would key the verdict of a Call with no id.
    let mut call = tool_call("read_file", json!({"Path": "a"}));
    call["toolCall"]["id"] = Value::Null;
    assert_eq!(
        send(&app, "PreToolUse", call).await.0,
        StatusCode::BAD_REQUEST
    );
}

// ---- harness ----

fn tool_call(name: &str, args: Value) -> Value {
    json!({
        "conversationId": "c1", "hookEventName": "PreToolUse", "cwd": "/repo",
        "lastUserInput": "do it", "withhuman_turn": "turn-1", "stepIdx": 3,
        "toolCall": {"id": "call_1", "name": name, "args": args},
    })
}

/// The tool name and input one Hook became.
async fn translated_call(payload: Value, shell: Option<&str>) -> (String, Value) {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    let request = post("/v1/hooks/antigravity/PreToolUse", payload, shell);
    app.oneshot(request).await.unwrap();
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PreToolUse(call) = &events[0] else {
        panic!("expected a call, got {:?}", events[0]);
    };
    (
        call.event.payload.tool_name.clone(),
        call.event.payload.tool_input.clone(),
    )
}

/// The result one `PostToolUse` became.
async fn result_of(payload: Value) -> Value {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(&app, "PostToolUse", payload).await;
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
        .oneshot(post(&format!("/v1/hooks/antigravity/{event}"), body, None))
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

struct Recording {
    events: Mutex<Vec<NormalizedEvent>>,
    response: EventResponse,
}

impl Recording {
    fn allowing() -> Self {
        Self {
            events: Mutex::default(),
            response: EventResponse {
                nodes: Vec::new(),
                paragraphs: None,
                version: 1,
                decision_response: Some(DecisionResponse {
                    decision: Decision::Allow,
                    // An ALLOW carries no reason; one makes the response invalid and every
                    // Call would be answered as unjudged instead of allowed.
                    reason: String::new(),
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
    async fn session_flags(
        &self,
        _session_id: &str,
    ) -> Result<withhuman_contracts::inventory::SessionFlags, withhuman_collector::GeneratorError>
    {
        Ok(withhuman_contracts::inventory::SessionFlags::default())
    }

    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        self.events.lock().unwrap().push(event);
        Ok(self.response.clone())
    }
}
