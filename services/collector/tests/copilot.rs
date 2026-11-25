//! Copilot Hooks, as the engine receives them.
//!
//! The captures under `crates/contracts/tests/fixtures/copilot/` are whole sessions of
//! Copilot CLI 1.0.115-7, recorded under both of Copilot's spellings. Every one of them is
//! replayed through the route here, so the translation is checked against what Copilot
//! actually sends rather than against its documentation.

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

const CAPTURES: [&str; 5] = [
    include_str!("../../../crates/contracts/tests/fixtures/copilot/capture-session-1-shell.jsonl"),
    include_str!(
        "../../../crates/contracts/tests/fixtures/copilot/capture-session-2-edit-failure.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/copilot/capture-session-3-mcp-subagent.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/copilot/capture-session-4-mcp-gate-premcp.jsonl"
    ),
    include_str!(
        "../../../crates/contracts/tests/fixtures/copilot/capture-session-5-mcp-gate-permission.jsonl"
    ),
];

/// Every captured Hook of every captured session, in the order Copilot sent it.
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

/// G: a recorded Copilot session reaches the engine without one Hook being turned away, under
/// either of Copilot's spellings. A `PreToolUse` the route refuses would block the call.
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
        events.len() > 40,
        "the sessions should have reached the engine, got {}",
        events.len()
    );
}

/// G: a shell call is judged as the shell the client actually runs, so a Windows client's
/// commands are not read as bash.
#[tokio::test]
async fn a_shell_call_takes_the_name_of_the_clients_shell() {
    let call = pre_tool_use("Bash", json!({"command": "ls -la", "description": "list"}));
    assert_eq!(
        translated_call(call.clone(), None).await,
        (
            "Bash".to_owned(),
            json!({"command": "ls -la", "description": "list"})
        )
    );
    assert_eq!(
        translated_call(call, Some("powershell")).await.0,
        "PowerShell"
    );
}

/// G: `apply_patch` arrives as `Edit` whose input is the patch itself, which no rule for `Edit`
/// could read. It is translated into the calls the patch makes, so the file it writes is
/// judged as a file write.
#[tokio::test]
async fn a_patch_becomes_the_calls_it_makes() {
    let patch = "*** Begin Patch\n*** Add File: hello.txt\n+hi\n*** End Patch\n";
    let (tool_name, tool_input) = translated_call(pre_tool_use("Edit", json!(patch)), None).await;
    assert_eq!(tool_name, "Write");
    assert_eq!(tool_input["file_path"], json!("/repo/hello.txt"));
    assert_eq!(tool_input["content"], json!("hi\n"));

    // A patch touching two files keeps its own name and lists the calls it makes.
    let two = "*** Begin Patch\n*** Add File: a.txt\n+a\n*** Delete File: b.txt\n*** End Patch\n";
    let (tool_name, tool_input) = translated_call(pre_tool_use("Edit", json!(two)), None).await;
    assert_eq!(tool_name, "apply_patch");
    let changes = tool_input["changes"].as_array().expect("changes");
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0]["tool_name"], json!("Write"));
    assert_eq!(changes[1]["tool_name"], json!("Bash"));
}

/// G: an `Edit` whose input is an object is left alone — only Copilot's patch form needs
/// taking apart, and a future `Edit` that sends real fields must not be rewritten.
#[tokio::test]
async fn an_edit_with_real_fields_is_left_alone() {
    let fields = json!({"file_path": "/repo/a.txt", "old_string": "a", "new_string": "b"});
    assert_eq!(
        translated_call(pre_tool_use("Edit", fields.clone()), None).await,
        ("Edit".to_owned(), fields)
    );
}

/// G: an MCP call reaches the engine under the name it knows MCP by, but only where the bridge
/// could say which server it goes to. `<server>-<tool>` cannot be split on its own, and a
/// guess would name the wrong server; the call is judged either way.
#[tokio::test]
async fn an_mcp_call_is_named_by_its_server_where_the_bridge_knows_it() {
    let mut call = pre_tool_use("github-mcp-server-get_file_contents", json!({"path": "a"}));
    assert_eq!(
        translated_call(call.clone(), None).await.0,
        "github-mcp-server-get_file_contents",
        "a server the bridge said nothing about is judged under the raw name"
    );
    call["withhuman_mcp_server"] = json!("github-mcp-server");
    assert_eq!(
        translated_call(call, None).await.0,
        "mcp__github-mcp-server__get_file_contents"
    );
}

/// G: a subagent's calls are judged inside the session it was spawned from, not as a session
/// of their own, so a turn's intent still covers them.
#[tokio::test]
async fn a_subagents_call_belongs_to_the_session_it_runs_under() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "PreToolUse",
        json!({
            "session_id": "agent-1", "parent_agent_id": "session-1",
            "agent_id": "agent-1", "agent_type": "explore",
            "tool_name": "Read", "tool_input": {"file_path": "/repo/a"},
            "tool_use_id": "call_1", "cwd": "/repo",
        }),
    )
    .await;
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PreToolUse(call) = &events[0] else {
        panic!("expected a call, got {:?}", events[0]);
    };
    assert_eq!(call.event.session_id, "session-1");
    assert_eq!(call.event.meta.agent_id.as_deref(), Some("agent-1"));
    assert_eq!(call.event.meta.agent_type.as_deref(), Some("explore"));
}

/// G: the turn the bridge read from the transcript becomes the turn the engine judges against,
/// since no Copilot Hook carries one.
#[tokio::test]
async fn the_turn_the_bridge_read_becomes_the_turn_the_engine_judges() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    let mut call = pre_tool_use("Read", json!({"file_path": "/repo/a"}));
    call["withhuman_turn"] = json!("3");
    send(&app, "PreToolUse", call).await;
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PreToolUse(call) = &events[0] else {
        panic!("expected a call");
    };
    assert_eq!(call.event.meta.prompt_id.as_deref(), Some("3"));
}

/// G: what a call brought in reaches the engine in the shape the rules for that tool read, so
/// text a command or a file brought in is judged as external.
#[tokio::test]
async fn a_result_arrives_in_the_shape_its_tool_is_read_by() {
    let result = |tool: &str| {
        let mut payload = pre_tool_use(tool, json!({"command": "cat secrets"}));
        payload["tool_result"] =
            json!({"result_type": "success", "text_result_for_llm": "brought in"});
        payload
    };
    assert_eq!(
        result_of(result("Bash")).await,
        json!({"stdout": "brought in", "stderr": ""})
    );
    assert_eq!(
        result_of(result("Read")).await,
        json!({"file": {"content": "brought in"}})
    );
    assert_eq!(
        result_of(result("withhuman-fixture-write_file")).await,
        json!({"content": "brought in"})
    );
}

/// G: a failed call reaches the engine with what Copilot said went wrong, and a failure it
/// explained with nothing still arrives as a failure.
#[tokio::test]
async fn a_failed_call_carries_why_it_failed() {
    let failure = |error: Value| async move {
        let generator = Arc::new(Recording::allowing());
        let app = app(generator.clone());
        let mut payload = pre_tool_use("Edit", json!("*** Begin Patch\n*** End Patch\n"));
        payload["error"] = error;
        send(&app, "PostToolUseFailure", payload).await;
        let events = generator.events.lock().unwrap();
        match &events[0] {
            NormalizedEvent::PostToolUseFailure(event) => event.payload.error.clone(),
            other => panic!("expected a failure, got {other:?}"),
        }
    };
    assert_eq!(
        failure(json!("Failed to apply patch: File already exists")).await,
        "Failed to apply patch: File already exists"
    );
    assert_eq!(failure(Value::Null).await, "the call did not finish");
}

/// G: a turn's end closes the batch of calls it opened, so the calls of one turn are not left
/// waiting on a turn that already ended.
#[tokio::test]
async fn the_turns_end_closes_its_batch() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "Stop",
        json!({
            "session_id": "s", "stop_reason": "end_turn",
            "transcript_path": "/state/events.jsonl",
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
/// where the turn's intent line is found. No Copilot Hook carries the answer.
#[tokio::test]
async fn the_answer_the_bridge_read_reaches_the_engine_as_a_message() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    let (status, _) = send(
        &app,
        "MessageDisplay",
        json!({
            "session_id": "s", "message_id": "3-abc", "index": 0,
            "delta": "[의도] 파일을 읽는다", "final": true, "turn_id": "3",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = generator.events.lock().unwrap();
    match &events[0] {
        NormalizedEvent::MessageDisplay(event) => {
            assert_eq!(event.payload.text, "[의도] 파일을 읽는다");
            assert_eq!(event.meta.turn_id.as_deref(), Some("3"));
        }
        other => panic!("expected a message, got {other:?}"),
    }
}

/// G: every event is marked as Copilot's and keeps the Hook as the client sent it, so an event
/// can be read back against the client that raised it.
#[tokio::test]
async fn an_event_is_marked_as_copilots_and_keeps_the_hook() {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    send(
        &app,
        "PreToolUse",
        pre_tool_use("Read", json!({"file_path": "/repo/a"})),
    )
    .await;
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PreToolUse(call) = &events[0] else {
        panic!("expected a call");
    };
    assert_eq!(
        call.event.meta.additional_fields.get("agent_kind"),
        Some(&json!("copilot"))
    );
    assert!(
        call.event
            .additional_fields
            .get("copilot_payload")
            .is_some_and(|payload| payload["tool_name"] == json!("Read")),
        "the Hook as sent should travel with the event"
    );
}

/// G: a Hook this agent does not have, and a Hook that is not its JSON, are turned away under
/// codes the client's self-check knows.
#[tokio::test]
async fn an_unknown_hook_is_turned_away() {
    let app = app(Arc::new(Recording::allowing()));
    let (status, body) = send(&app, "beforeSubmitPrompt", json!({"session_id": "s"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], json!("unknown_event"));
    // A call with no id cannot be judged, since nothing would key its verdict.
    assert_eq!(
        send(
            &app,
            "PreToolUse",
            json!({"session_id": "s", "tool_name": "Read"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

// ---- harness ----

fn pre_tool_use(tool_name: &str, tool_input: Value) -> Value {
    json!({
        "session_id": "s", "cwd": "/repo", "withhuman_turn": "0",
        "tool_use_id": "call_1", "tool_name": tool_name, "tool_input": tool_input
    })
}

/// The tool name and input one Hook became.
async fn translated_call(payload: Value, shell: Option<&str>) -> (String, Value) {
    let generator = Arc::new(Recording::allowing());
    let app = app(generator.clone());
    let request = post("/v1/hooks/copilot/PreToolUse", payload, shell);
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
        .oneshot(post(&format!("/v1/hooks/copilot/{event}"), body, None))
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
    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        self.events.lock().unwrap().push(event);
        Ok(self.response.clone())
    }
}
