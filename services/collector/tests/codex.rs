//! The Codex route: Codex Hooks translated into the Claude Code requests the Collector handles,
//! checked against Hooks captured from Codex CLI 0.154.0 on Windows.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_collector::{
    CollectorConfig, CollectorService, GeneratorError, GeneratorTransport, INTENT_INSTRUCTION,
    INTENT_REMINDER, NormalizedEvent, ReviewPolicy, app_with_transport,
    codex::{Hunk, PatchStep, Translated, parse_patch, resolve, translate, translate_tool},
};
use withhuman_common::origin;
use withhuman_contracts::{
    codex::{CodexHookEvent, CodexHookInput, CodexShell},
    decisions::{CausalStart, Decision, DecisionResponse, EnforcementMode},
    events::EventResponse,
    hooks::{
        PostToolBatchRequest, PostToolUseFailureRequest, PostToolUseRequest, PreToolUseRequest,
        SessionStartRequest, SubagentLifecycleRequest, UserPromptSubmitRequest,
    },
};

const C0: &str = include_str!("../../../crates/contracts/tests/fixtures/codex/c0-windows.json");
const C0_TRANSLATED: &str =
    include_str!("../../../crates/contracts/tests/fixtures/codex/c0-windows.translated.json");

fn event_of(input: &Value) -> CodexHookEvent {
    let name = input["hook_event_name"].as_str().unwrap();
    CodexHookEvent::from_path(name).unwrap_or_else(|| panic!("unknown event {name}"))
}

fn request_json(translated: &Translated) -> Value {
    match translated {
        Translated::SessionStart(request) => serde_json::to_value(request),
        Translated::UserPromptSubmit(request) => serde_json::to_value(request),
        Translated::PreToolUse(request) => serde_json::to_value(request),
        Translated::PostToolUse(request) => serde_json::to_value(request),
        Translated::PostToolUseFailure(request) => serde_json::to_value(request),
        Translated::PostToolBatch(request) => serde_json::to_value(request),
        Translated::SubagentStart(request) | Translated::SubagentStop(request) => {
            serde_json::to_value(request)
        }
        Translated::Nothing => Ok(Value::Null),
    }
    .unwrap()
}

/// G4: every captured Hook translates into the Claude Code request kept in the snapshot.
/// `UPDATE_CODEX_SNAPSHOT=1` rewrites the snapshot.
#[test]
fn c0_hooks_translate_into_the_recorded_claude_requests() {
    let c0: Value = serde_json::from_str(C0).unwrap();
    assert_eq!(c0["platform"], "windows");
    let translated: Vec<Value> = c0["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|fixture| {
            let input = &fixture["input"];
            let event = event_of(input);
            let translation = translate(
                event,
                serde_json::from_value(input.clone()).unwrap(),
                CodexShell::PowerShell,
            )
            .unwrap();
            json!({
                "scenario": fixture["scenario"],
                "codex_event": input["hook_event_name"],
                "claude_event": claude_event(&translation.request),
                "workdir_unknown": translation.workdir_unknown,
                "request": request_json(&translation.request),
            })
        })
        .collect();
    if std::env::var_os("UPDATE_CODEX_SNAPSHOT").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/contracts/tests/fixtures/codex/c0-windows.translated.json"
        );
        let mut text = serde_json::to_string_pretty(&translated).unwrap();
        text.push('\n');
        std::fs::write(path, text).unwrap();
        return;
    }
    let expected: Vec<Value> = serde_json::from_str(C0_TRANSLATED).unwrap();
    assert_eq!(translated.len(), expected.len());
    for (index, (actual, expected)) in translated.iter().zip(&expected).enumerate() {
        assert_eq!(actual, expected, "fixture {index}");
    }
}

fn claude_event(translated: &Translated) -> &'static str {
    match translated {
        Translated::SessionStart(_) => "SessionStart",
        Translated::UserPromptSubmit(_) => "UserPromptSubmit",
        Translated::PreToolUse(_) => "PreToolUse",
        Translated::PostToolUse(_) => "PostToolUse",
        Translated::PostToolUseFailure(_) => "PostToolUseFailure",
        Translated::PostToolBatch(_) => "PostToolBatch",
        Translated::SubagentStart(_) => "SubagentStart",
        Translated::SubagentStop(_) => "SubagentStop",
        Translated::Nothing => "",
    }
}

/// G4: the translated requests have the fields and tool input shapes of Claude Code's own.
#[test]
fn c0_translations_have_the_shape_of_claude_code_requests() {
    let claude: Value = serde_json::from_str(include_str!(
        "../../../crates/contracts/tests/fixtures/hooks/requests.json"
    ))
    .unwrap();
    let fields = |name: &str| -> Vec<String> {
        let mut fields: Vec<String> = claude[name].as_object().unwrap().keys().cloned().collect();
        // Optional fields Claude Code sends that the fixture leaves out.
        fields.extend(
            [
                "hook_event_name",
                "transcript_path",
                "cwd",
                "prompt_id",
                "agent_id",
                "agent_type",
                "tool_input",
            ]
            .map(str::to_owned),
        );
        fields
    };
    let snapshot: Vec<Value> = serde_json::from_str(C0_TRANSLATED).unwrap();
    for entry in &snapshot {
        let request = &entry["request"];
        let fixture = match entry["claude_event"].as_str().unwrap() {
            "SessionStart" => "session_start",
            "UserPromptSubmit" => "user_prompt_submit",
            "PreToolUse" => "pre_tool_use",
            "PostToolUse" => "post_tool_use",
            "PostToolUseFailure" => "post_tool_use_failure",
            "PostToolBatch" => "post_tool_batch",
            "" => continue,
            other => panic!("unexpected {other}"),
        };
        let allowed = fields(fixture);
        for field in request.as_object().unwrap().keys() {
            assert!(
                allowed.contains(field) || field == "tool_calls",
                "{field} in {request}"
            );
        }
        let Some(tool_name) = request["tool_name"].as_str() else {
            continue;
        };
        let mut keys: Vec<&str> = request["tool_input"]
            .as_object()
            .map(|input| input.keys().map(String::as_str).collect())
            .unwrap_or_default();
        keys.sort_unstable();
        let expected: &[&str] = match tool_name {
            "PowerShell" | "Bash" => &["command"],
            "Write" => &["content", "file_path"],
            "MultiEdit" => &["edits", "file_path"],
            "WebSearch" => &["query"],
            "apply_patch" => &["changes", "command"],
            name if name.starts_with("mcp__") => continue,
            other => panic!("untranslated tool {other}"),
        };
        assert_eq!(keys, expected, "{request}");
        if tool_name == "PowerShell" || tool_name == "Bash" {
            if let Some(response) = request.get("tool_response") {
                assert!(response.get("stdout").is_some(), "{request}");
            }
        }
    }
    // Every Claude Code request type parses the translations back.
    for entry in &snapshot {
        let request = entry["request"].clone();
        let parsed = match entry["claude_event"].as_str().unwrap() {
            "SessionStart" => serde_json::from_value::<SessionStartRequest>(request).is_ok(),
            "UserPromptSubmit" => {
                serde_json::from_value::<UserPromptSubmitRequest>(request).is_ok()
            }
            "PreToolUse" => serde_json::from_value::<PreToolUseRequest>(request).is_ok(),
            "PostToolUse" => serde_json::from_value::<PostToolUseRequest>(request).is_ok(),
            "PostToolBatch" => serde_json::from_value::<PostToolBatchRequest>(request).is_ok(),
            _ => true,
        };
        assert!(parsed, "{entry}");
    }
}

#[test]
fn turns_a_patch_into_the_claude_calls_making_its_changes() {
    let cwd = Some("C:\\proj");
    let tool = |patch: &str| {
        translate_tool(
            "apply_patch",
            &json!({ "command": patch }),
            cwd,
            CodexShell::PowerShell,
        )
    };
    // One added file is a Write.
    assert_eq!(
        tool("*** Begin Patch\n*** Add File: a.txt\n+one\n+two\n*** End Patch"),
        (
            "Write".to_owned(),
            json!({"file_path": "C:\\proj\\a.txt", "content": "one\ntwo\n"})
        )
    );
    // One file updated in place is a MultiEdit, one edit per hunk, context kept on both sides.
    assert_eq!(
        tool(
            "*** Begin Patch\n*** Update File: src/a.py\n@@ def f():\n x = 1\n-y = 2\n+y = 3\n@@\n-z\n+w\n*** End of File\n*** End Patch"
        ),
        (
            "MultiEdit".to_owned(),
            json!({"file_path": "C:\\proj\\src\\a.py", "edits": [
                {"old_string": "x = 1\ny = 2", "new_string": "x = 1\ny = 3"},
                {"old_string": "z", "new_string": "w"}
            ]})
        )
    );
    // One deleted file is a removal.
    assert_eq!(
        tool("*** Begin Patch\n*** Delete File: old.txt\n*** End Patch"),
        (
            "Bash".to_owned(),
            json!({"command": "rm -- C:\\proj\\old.txt"})
        )
    );
    // Several files, or a move, keep the patch and list its steps.
    let patch = "*** Begin Patch\n*** Update File: allow-edit.txt\n@@\n-before\n+after\n*** Update File: allow-move.txt\n*** Move to: allow-moved.txt\n@@\n-before\n+after\n*** Delete File: allow-delete.txt\n*** End Patch";
    assert_eq!(
        tool(patch),
        (
            "apply_patch".to_owned(),
            json!({"command": patch, "changes": [
                {"tool_name": "MultiEdit", "tool_input": {"file_path": "C:\\proj\\allow-edit.txt",
                    "edits": [{"old_string": "before", "new_string": "after"}]}},
                {"tool_name": "Bash", "tool_input": {"command": "mv -- C:\\proj\\allow-move.txt C:\\proj\\allow-moved.txt"}},
                {"tool_name": "MultiEdit", "tool_input": {"file_path": "C:\\proj\\allow-moved.txt",
                    "edits": [{"old_string": "before", "new_string": "after"}]}},
                {"tool_name": "Bash", "tool_input": {"command": "rm -- C:\\proj\\allow-delete.txt"}}
            ]})
        )
    );
    // A patch that does not parse is judged as written.
    assert_eq!(
        tool("*** Begin Patch\n*** Frobnicate: .codex/hooks.json\n*** End Patch"),
        (
            "apply_patch".to_owned(),
            json!({"command": "*** Begin Patch\n*** Frobnicate: .codex/hooks.json\n*** End Patch"})
        )
    );
}

#[test]
fn parses_patches_strictly() {
    assert_eq!(
        parse_patch(
            "apply_patch <<'EOF'\n*** Begin Patch\r\n*** Add File: a\r\n+x\r\n*** End Patch\r\nEOF"
        ),
        Some(vec![PatchStep::Add {
            path: "a".to_owned(),
            lines: vec!["x\r".to_owned()]
        }])
    );
    assert_eq!(
        parse_patch("*** Begin Patch\n*** Update File: a\n@@\n keep\n\n-old\n*** End Patch"),
        Some(vec![PatchStep::Update {
            path: "a".to_owned(),
            move_to: None,
            hunks: vec![Hunk {
                old: vec!["keep".to_owned(), String::new(), "old".to_owned()],
                new: vec!["keep".to_owned(), String::new()],
            }],
        }])
    );
    for broken in [
        "*** Add File: a\n+x\n*** End Patch",
        "*** Begin Patch\n*** Add File: a\n+x",
        "*** Begin Patch\n*** Add File: a\nx\n*** End Patch",
        "*** Begin Patch\n+x\n*** End Patch",
        "*** Begin Patch\n*** Delete File: a\n-x\n*** End Patch",
        "*** Begin Patch\n*** End Patch",
    ] {
        assert_eq!(parse_patch(broken), None, "{broken}");
    }
}

#[test]
fn translates_shell_and_other_tools() {
    let shell = |input: Value, shell| translate_tool("exec_command", &input, None, shell);
    assert_eq!(
        shell(json!({"command": "Get-ChildItem"}), CodexShell::PowerShell),
        ("PowerShell".to_owned(), json!({"command": "Get-ChildItem"}))
    );
    assert_eq!(
        shell(
            json!({"command": ["bash", "-lc", "cat a > .codex/hooks.json"]}),
            CodexShell::Posix
        ),
        (
            "Bash".to_owned(),
            json!({"command": "cat a > .codex/hooks.json"})
        )
    );
    assert_eq!(
        shell(
            json!({"command": ["powershell.exe", "-Command", "Set-Content x y"]}),
            CodexShell::PowerShell
        )
        .1,
        json!({"command": "Set-Content x y"})
    );
    assert_eq!(
        shell(
            json!({"cmd": ["git", "commit", "-m", "it's"]}),
            CodexShell::Posix
        )
        .1,
        json!({"command": "git commit -m 'it'\\''s'"})
    );
    let tool =
        |name: &str, input: Value| translate_tool(name, &input, Some("/p"), CodexShell::Posix);
    assert_eq!(
        tool(
            "webrun",
            json!({"search_query": [{"q": "codex hooks"}], "response_length": "short"})
        ),
        ("WebSearch".to_owned(), json!({"query": "codex hooks"}))
    );
    assert_eq!(
        tool("webrun", json!({"open": [{"ref_id": "https://a.test/x"}]})),
        ("WebFetch".to_owned(), json!({"url": "https://a.test/x"}))
    );
    assert_eq!(
        tool(
            "webrun",
            json!({"find": [{"ref_id": "turn0", "pattern": "hooks"}]})
        ),
        (
            "WebFetch".to_owned(),
            json!({"url": "turn0", "prompt": "hooks"})
        )
    );
    assert_eq!(
        tool(
            "update_plan",
            json!({"plan": [{"step": "fix", "status": "pending"}]})
        ),
        (
            "TodoWrite".to_owned(),
            json!({"todos": [{"content": "fix", "status": "pending"}]})
        )
    );
    assert_eq!(
        tool("view_image", json!({"path": "shot.png"})),
        ("Read".to_owned(), json!({"file_path": "/p/shot.png"}))
    );
    assert_eq!(
        tool("mcp__c0__record", json!({"marker": "m"})),
        ("mcp__c0__record".to_owned(), json!({"marker": "m"}))
    );
}

#[test]
fn resolves_paths_against_the_directory_a_call_runs_in() {
    assert_eq!(resolve(Some("C:\\proj"), "nested"), "C:\\proj\\nested");
    assert_eq!(
        resolve(Some("C:\\proj\\nested"), "..\\.codex"),
        "C:\\proj\\.codex"
    );
    assert_eq!(resolve(Some("/p/a"), "./b/../c"), "/p/a/c");
    assert_eq!(resolve(Some("/p"), "/etc/x"), "/etc/x");
    assert_eq!(resolve(Some("/p"), "D:\\x"), "D:\\x");
    assert_eq!(resolve(None, "x"), "x");
}

/// The C0 `workdir` run: the call's directory comes from the bridge, so a relative path in it is
/// judged where it lands. Without it the call is marked.
#[test]
fn sends_a_shell_call_with_the_directory_it_runs_in() {
    let input = |workdir: Option<&str>| -> CodexHookInput {
        let mut input = json!({
            "session_id": "s", "turn_id": "t", "cwd": "C:\\proj", "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_use_id": "call_1",
            "tool_input": {"command": "Set-Content -LiteralPath 'hooks.json' -Value '{}'"}
        });
        if let Some(workdir) = workdir {
            input["withhuman_workdir"] = json!(workdir);
        }
        serde_json::from_value(input).unwrap()
    };
    let translation = translate(
        CodexHookEvent::PreToolUse,
        input(Some(".codex")),
        CodexShell::PowerShell,
    )
    .unwrap();
    let Translated::PreToolUse(request) = translation.request else {
        panic!("expected PreToolUse");
    };
    assert_eq!(request.cwd.as_deref(), Some("C:\\proj\\.codex"));
    assert_eq!(request.tool_name, "PowerShell");
    assert_eq!(request.prompt_id.as_deref(), Some("t"));
    assert!(!translation.workdir_unknown);

    let translation = translate(
        CodexHookEvent::PreToolUse,
        input(None),
        CodexShell::PowerShell,
    )
    .unwrap();
    assert!(translation.workdir_unknown);
}

// ---- The HTTP route ----

#[tokio::test]
async fn denies_a_review_on_codex_even_where_claude_code_asks() {
    let config = CollectorConfig {
        review_policy: ReviewPolicy::Ask,
        ..Default::default()
    };
    let generator = Arc::new(Recording::decision(Decision::Review, "needs a look"));
    let app = app(config.clone(), generator.clone());
    let (status, body) = send(&app, "PreToolUse", pre("Read", "c1"), Some("powershell")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(body["hookSpecificOutput"]["hookEventName"], "PreToolUse");

    // The Claude Code route keeps the configured policy.
    let claude = app_with_transport(CollectorService::new(config, generator));
    let response = claude
        .oneshot(post(
            "/v1/hooks/PreToolUse",
            json!({"session_id":"s2","tool_name":"Read","tool_input":{},"tool_use_id":"c2"}),
            None,
        ))
        .await
        .unwrap();
    let (_, body) = json_body(response).await;
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[tokio::test]
async fn blocks_a_denied_mcp_call_at_the_codex_hook() {
    // AgentGateway enforces MCP calls for Claude Code here; Codex calls never pass it.
    let config = CollectorConfig {
        enforce_mcp_at_hook: false,
        ..Default::default()
    };
    let generator = Arc::new(Recording::decision(Decision::Deny, "blocked"));
    let app = app(config, generator.clone());
    let (_, body) = send(
        &app,
        "PreToolUse",
        pre("mcp__c0__record", "call_deny-mcp"),
        None,
    )
    .await;
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecisionReason"],
        "blocked"
    );
}

#[tokio::test]
async fn keeps_the_codex_hook_with_every_event() {
    let generator = Arc::new(Recording::decision(Decision::Allow, ""));
    let app = app(CollectorConfig::default(), generator.clone());
    let (status, body) = send(
        &app,
        "SessionStart",
        json!({"session_id":"s","cwd":"C:\\proj","hook_event_name":"SessionStart","source":"startup","model":"m"}),
        Some("powershell"),
    )
    .await;
    // Watched paths are a Claude Code feature: Codex gets no output.
    assert_eq!((status, body), (StatusCode::OK, Value::Null));

    let (_, body) = send(
        &app,
        "UserPromptSubmit",
        json!({"session_id":"s","turn_id":"turn-1","cwd":"C:\\proj","prompt":"fix it"}),
        Some("powershell"),
    )
    .await;
    assert_eq!(
        body["hookSpecificOutput"]["additionalContext"],
        INTENT_INSTRUCTION
    );

    // The bridge sends the turn's message, with its intent line, before the call.
    send(
        &app,
        "MessageDisplay",
        json!({"session_id":"s","message_id":"m1","index":0,"delta":"[의도] 파일을 읽는다","final":true}),
        Some("powershell"),
    )
    .await;
    let mut call = pre("Bash", "call_1");
    call["tool_input"] = json!({"command": "Get-Content a.txt"});
    call["withhuman_programs"] = json!([{"path": "C:\\proj\\run.ps1", "content": "x"}]);
    assert_eq!(
        send(&app, "PreToolUse", call, Some("powershell")).await,
        (StatusCode::OK, Value::Null)
    );

    let events = generator.events.lock().unwrap();
    let NormalizedEvent::UserPromptSubmit(prompt) = &events[1] else {
        panic!("expected UserPromptSubmit");
    };
    assert_eq!(prompt.meta.prompt_id.as_deref(), Some("turn-1"));
    assert_eq!(prompt.meta.additional_fields["agent_kind"], "codex");
    assert_eq!(
        prompt.additional_fields["codex_payload"]["turn_id"],
        "turn-1"
    );
    let NormalizedEvent::PreToolUse(call) = &events[3] else {
        panic!("expected PreToolUse");
    };
    assert_eq!(call.event.payload.tool_name, "PowerShell");
    assert_eq!(call.event.meta.additional_fields["agent_kind"], "codex");
    assert_eq!(
        call.event.meta.additional_fields["codex_workdir"],
        "unknown"
    );
    let original = &call.event.additional_fields["codex_payload"];
    assert_eq!(original["tool_name"], "Bash");
    assert!(original.get("withhuman_programs").is_none());
    // The program files ride with the Call as for Claude Code.
    assert!(
        call.event
            .payload
            .additional_fields
            .contains_key("programs")
    );
}

#[tokio::test]
async fn reports_a_failed_call_and_reminds_through_codexs_post_hook() {
    let generator = Arc::new(Recording::decision(Decision::Allow, ""));
    let app = app(CollectorConfig::default(), generator.clone());
    send(
        &app,
        "UserPromptSubmit",
        json!({"session_id":"s","turn_id":"t","cwd":"/p","prompt":"go"}),
        None,
    )
    .await;
    let (_, body) = send(
        &app,
        "PostToolUse",
        json!({"session_id":"s","turn_id":"t","cwd":"/p","tool_name":"Bash",
               "tool_input":{"command":"exit 7"},"tool_response":"","tool_use_id":"c1",
               "withhuman_failure":"exit code 7"}),
        None,
    )
    .await;
    // Codex reads the output of the Hook it ran, PostToolUse.
    assert_eq!(body["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    assert_eq!(
        body["hookSpecificOutput"]["additionalContext"],
        INTENT_REMINDER
    );
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PostToolUseFailure(failure) = &events[1] else {
        panic!("expected PostToolUseFailure");
    };
    assert_eq!(failure.payload.error, "exit code 7");
    assert_eq!(failure.payload.tool_name, "Bash");
}

#[tokio::test]
async fn closes_the_batch_at_stop_and_records_nothing_at_session_end() {
    let generator = Arc::new(Recording::decision(Decision::Allow, ""));
    let app = app(CollectorConfig::default(), generator.clone());
    let stop = json!({"session_id":"s","turn_id":"t","cwd":"/p","stop_hook_active":false,
                      "last_assistant_message":"done"});
    assert_eq!(
        send(&app, "Stop", stop, None).await,
        (StatusCode::OK, Value::Null)
    );
    assert_eq!(
        send(
            &app,
            "SessionEnd",
            json!({"session_id":"s","reason":"other"}),
            None
        )
        .await,
        (StatusCode::OK, Value::Null)
    );
    let events = generator.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], NormalizedEvent::PostToolBatch(_)));
}

#[tokio::test]
async fn takes_messages_and_batches_the_bridge_makes() {
    let generator = Arc::new(Recording::decision(Decision::Allow, ""));
    let app = app(CollectorConfig::default(), generator.clone());
    let (status, body) = send(
        &app,
        "MessageDisplay",
        json!({"session_id":"s","message_id":"m1","index":0,
               "delta":"[의도] 테스트를 고친다\n고치겠습니다.","final":true,"turn_id":"t"}),
        None,
    )
    .await;
    // Codex cannot hide the intent line, so no display content comes back.
    assert_eq!((status, body), (StatusCode::OK, Value::Null));
    send(
        &app,
        "PostToolBatch",
        json!({"session_id":"s","tool_calls":[]}),
        None,
    )
    .await;
    let events = generator.events.lock().unwrap();
    let names: Vec<&str> = events.iter().map(NormalizedEvent::event_name).collect();
    assert_eq!(names, ["Intent", "MessageDisplay", "PostToolBatch"]);
    let NormalizedEvent::Intent(intent) = &events[0] else {
        panic!("expected Intent");
    };
    assert_eq!(intent.payload.intent, "테스트를 고친다");
    assert_eq!(intent.meta.additional_fields["agent_kind"], "codex");
    assert!(!intent.additional_fields.contains_key("codex_payload"));
}

#[tokio::test]
async fn rejects_unknown_events_and_incomplete_hooks() {
    let app = app(
        CollectorConfig::default(),
        Arc::new(Recording::decision(Decision::Allow, "")),
    );
    assert_eq!(
        send(&app, "PreModelRequest", json!({"session_id":"s"}), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            "PreToolUse",
            json!({"session_id":"s","tool_name":"Bash"}),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

/// A web search the bridge found only in the transcript already ran: it is recorded, never
/// blocked, and asks for no intent.
#[tokio::test]
async fn records_a_search_found_in_the_transcript_without_blocking() {
    let generator = Arc::new(Recording::decision(Decision::Deny, "blocked"));
    let app = app(CollectorConfig::default(), generator.clone());
    let (status, body) = send(
        &app,
        "PreToolUse",
        json!({"session_id":"s","turn_id":"t","cwd":"/p","tool_name":"webrun",
               "tool_input":{"search_query":[{"q":"codex hooks"}]},
               "tool_use_id":"transcript-call_w","withhuman_record":true}),
        None,
    )
    .await;
    assert_eq!((status, body), (StatusCode::OK, Value::Null));
    let events = generator.events.lock().unwrap();
    let NormalizedEvent::PreToolUse(call) = &events[0] else {
        panic!("expected PreToolUse");
    };
    assert_eq!(call.mode, EnforcementMode::Record);
    assert_eq!(call.event.payload.tool_name, "WebSearch");
}

// ---- G5a: Claude Code sessions sent through the Codex route ----

/// G5a. Each Claude Code Hook in recorded sessions, made into the Hook Codex would send for it,
/// translates back into the original request, but for the differences listed in `canonical`.
/// The events are real (masked) and stay outside the repository:
/// `WITHHUMAN_G5A_EVENTS=/data/events.jsonl cargo test -p withhuman-collector --test codex -- --ignored`.
#[test]
#[ignore = "needs the recorded events outside the repository"]
fn g5a_claude_sessions_survive_the_codex_round_trip() {
    let path = std::env::var("WITHHUMAN_G5A_EVENTS").expect("WITHHUMAN_G5A_EVENTS");
    let text = std::fs::read_to_string(path).unwrap();
    let mut compared = 0;
    let mut identical = 0;
    let mut skipped = std::collections::BTreeMap::<String, usize>::new();
    let mut allowed = std::collections::BTreeMap::<String, usize>::new();
    let mut differences = Vec::new();
    for line in text.lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let name = row["event_name"].as_str().unwrap();
        let event: Value = serde_json::from_str(row["event_json"].as_str().unwrap()).unwrap();
        let Some((codex_event, original, shell)) = claude_request(name, &event) else {
            *skipped.entry(name.to_owned()).or_default() += 1;
            continue;
        };
        let codex = to_codex(codex_event, &original);
        let back = translate(codex_event, serde_json::from_value(codex).unwrap(), shell).unwrap();
        compared += 1;
        let back = request_json(&back.request);
        if back == original {
            identical += 1;
        } else {
            // Which differences the allowed list absorbed, by event and tool.
            let key = format!("{name}/{}", original["tool_name"].as_str().unwrap_or("-"));
            *allowed.entry(key).or_default() += 1;
        }
        let (expected, actual) = (canonical(&original), canonical(&back));
        if expected != actual {
            differences.push(format!("{name}: {expected}\n  -> {actual}"));
        }
    }
    println!(
        "G5a compared={compared} identical={identical} equal_after_allowed_differences={} \
         differences={} skipped={skipped:?} allowed={allowed:?}",
        compared - differences.len(),
        differences.len()
    );
    assert!(compared > 0);
    assert!(
        differences.is_empty(),
        "{}",
        differences
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The Claude Code Hook request a committed event came from; none for events Codex has no Hook
/// for (messages, intents, batches, tool descriptions, configuration changes).
fn claude_request(name: &str, event: &Value) -> Option<(CodexHookEvent, Value, CodexShell)> {
    let meta = &event["meta"];
    let payload = &event["payload"];
    let mut request = json!({ "session_id": event["session_id"] });
    let mut set = |field: &str, value: &Value| {
        if !value.is_null() {
            request[field] = value.clone();
        }
    };
    set("cwd", &meta["cwd"]);
    let codex_event = match name {
        "SessionStart" => {
            set("hook_event_name", &json!("SessionStart"));
            set("source", &payload["source"]);
            CodexHookEvent::SessionStart
        }
        "UserPromptSubmit" => {
            set("hook_event_name", &json!("UserPromptSubmit"));
            set("prompt", &payload["prompt"]);
            set("prompt_id", &meta["prompt_id"]);
            CodexHookEvent::UserPromptSubmit
        }
        "PreToolUse" | "PostToolUse" | "PostToolUseFailure" => {
            set("hook_event_name", &json!(name));
            set("tool_name", &payload["tool_name"]);
            set("tool_input", &payload["tool_input"]);
            set("tool_use_id", &meta["tool_use_id"]);
            set("prompt_id", &meta["prompt_id"]);
            set("agent_id", &meta["agent_id"]);
            set("agent_type", &meta["agent_type"]);
            set("tool_response", &payload["tool_response"]);
            set("error", &payload["error"]);
            if name == "PreToolUse" {
                CodexHookEvent::PreToolUse
            } else {
                CodexHookEvent::PostToolUse
            }
        }
        "SubagentStart" | "SubagentStop" => {
            set("hook_event_name", &json!(name));
            set("agent_id", &payload["agent_id"]);
            set("agent_type", &payload["agent_type"]);
            set("agent_type", &meta["agent_type"]);
            if name == "SubagentStart" {
                CodexHookEvent::SubagentStart
            } else {
                CodexHookEvent::SubagentStop
            }
        }
        _ => return None,
    };
    if request.get("tool_input").is_none() && request.get("tool_name").is_some() {
        request["tool_input"] = Value::Null;
    }
    let shell = if payload["tool_name"] == "PowerShell" {
        CodexShell::PowerShell
    } else {
        CodexShell::Posix
    };
    // Normalize through the Claude Code types so absent and null fields compare alike.
    let request = match codex_event {
        CodexHookEvent::SessionStart => {
            serde_json::to_value(serde_json::from_value::<SessionStartRequest>(request).ok()?)
        }
        CodexHookEvent::UserPromptSubmit => {
            serde_json::to_value(serde_json::from_value::<UserPromptSubmitRequest>(request).ok()?)
        }
        CodexHookEvent::PreToolUse => {
            serde_json::to_value(serde_json::from_value::<PreToolUseRequest>(request).ok()?)
        }
        CodexHookEvent::PostToolUse if name == "PostToolUseFailure" => {
            serde_json::to_value(serde_json::from_value::<PostToolUseFailureRequest>(request).ok()?)
        }
        CodexHookEvent::PostToolUse => {
            serde_json::to_value(serde_json::from_value::<PostToolUseRequest>(request).ok()?)
        }
        _ => {
            serde_json::to_value(serde_json::from_value::<SubagentLifecycleRequest>(request).ok()?)
        }
    }
    .ok()?;
    Some((codex_event, request, shell))
}

/// The Hook Codex would send for a Claude Code request.
fn to_codex(event: CodexHookEvent, claude: &Value) -> Value {
    let mut codex = json!({ "session_id": claude["session_id"] });
    for field in [
        "cwd",
        "source",
        "prompt",
        "tool_use_id",
        "agent_id",
        "agent_type",
    ] {
        if !claude[field].is_null() {
            codex[field] = claude[field].clone();
        }
    }
    if !claude["prompt_id"].is_null() {
        codex["turn_id"] = claude["prompt_id"].clone();
    }
    // The bridge reports the directory of a shell call; Claude Code's Hook carries it as `cwd`.
    if !claude["cwd"].is_null() {
        codex["withhuman_workdir"] = claude["cwd"].clone();
    }
    if let Some(tool_name) = claude["tool_name"].as_str() {
        let (name, input) = codex_tool(tool_name, &claude["tool_input"]);
        codex["tool_name"] = json!(name);
        codex["tool_input"] = input;
    }
    if let Some(error) = claude.get("error").filter(|error| !error.is_null()) {
        codex["withhuman_failure"] = error.clone();
    } else if matches!(event, CodexHookEvent::PostToolUse) {
        let response = &claude["tool_response"];
        codex["tool_response"] = match claude["tool_name"].as_str() {
            // Codex reports a command's output as text.
            Some("Bash" | "PowerShell") => json!(origin::tool_output(response).unwrap_or_default()),
            _ => response.clone(),
        };
    }
    codex
}

fn codex_tool(name: &str, input: &Value) -> (String, Value) {
    let text = |field: &str| input[field].as_str().unwrap_or_default().to_owned();
    let hunk = |old: &str, new: &str| {
        let mut lines: Vec<String> = Vec::new();
        if !old.is_empty() {
            lines.extend(old.split('\n').map(|line| format!("-{line}")));
        }
        if !new.is_empty() {
            lines.extend(new.split('\n').map(|line| format!("+{line}")));
        }
        format!("@@\n{}", lines.join("\n"))
    };
    match name {
        "Bash" | "PowerShell" => ("Bash".to_owned(), json!({ "command": text("command") })),
        "Write" => {
            let content = text("content");
            let body: Vec<String> = if content.is_empty() {
                Vec::new()
            } else {
                content
                    .strip_suffix('\n')
                    .unwrap_or(&content)
                    .split('\n')
                    .map(|line| format!("+{line}"))
                    .collect()
            };
            let mut patch = format!("*** Begin Patch\n*** Add File: {}\n", text("file_path"));
            for line in body {
                patch.push_str(&line);
                patch.push('\n');
            }
            patch.push_str("*** End Patch");
            ("apply_patch".to_owned(), json!({ "command": patch }))
        }
        "Edit" | "MultiEdit" => {
            let edits: Vec<(String, String)> = if name == "Edit" {
                vec![(text("old_string"), text("new_string"))]
            } else {
                input["edits"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|edit| {
                        (
                            edit["old_string"].as_str().unwrap_or_default().to_owned(),
                            edit["new_string"].as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect()
            };
            let hunks: Vec<String> = edits.iter().map(|(old, new)| hunk(old, new)).collect();
            let patch = format!(
                "*** Begin Patch\n*** Update File: {}\n{}\n*** End Patch",
                text("file_path"),
                hunks.join("\n")
            );
            ("apply_patch".to_owned(), json!({ "command": patch }))
        }
        "WebSearch" => (
            "webrun".to_owned(),
            json!({ "search_query": [{ "q": text("query") }] }),
        ),
        "WebFetch" => (
            "webrun".to_owned(),
            json!({ "open": [{ "ref_id": text("url") }] }),
        ),
        "TodoWrite" => {
            let plan: Vec<Value> = input["todos"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|todo| json!({ "step": todo["content"], "status": todo["status"] }))
                .collect();
            ("update_plan".to_owned(), json!({ "plan": plan }))
        }
        "Task" => (
            "spawn_agent".to_owned(),
            json!({ "message": text("prompt"), "agent_type": input["subagent_type"] }),
        ),
        _ => (name.to_owned(), input.clone()),
    }
}

/// A request with the differences the translation is allowed to make taken out:
/// - Hook-only fields: `hook_event_name`, `transcript_path`.
/// - `Edit` becomes `MultiEdit` with one edit; `replace_all` has no patch counterpart.
/// - A file written without a final newline gets one, as Codex's added files do.
/// - Tool options with no Codex counterpart: Bash `description`/`timeout`/`run_in_background`,
///   `WebFetch.prompt`, `WebSearch` domain filters, `TodoWrite.activeForm`, `Task.description`.
/// - A command's output is compared as the text the engine reads from it.
fn canonical(request: &Value) -> Value {
    let mut request = request.clone();
    let fields = request.as_object_mut().unwrap();
    fields.remove("hook_event_name");
    fields.remove("transcript_path");
    let tool_name = fields
        .get("tool_name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(response) = fields.get_mut("tool_response") {
        if matches!(tool_name.as_deref(), Some("Bash" | "PowerShell")) {
            *response = json!(origin::tool_output(response).unwrap_or_default());
        }
    }
    let Some(tool_name) = tool_name else {
        return request;
    };
    let input = request["tool_input"].clone();
    let text = |field: &str| input[field].as_str().unwrap_or_default().to_owned();
    let (name, input) = match tool_name.as_str() {
        "Bash" | "PowerShell" => (tool_name.clone(), json!({ "command": text("command") })),
        "Edit" => (
            "MultiEdit".to_owned(),
            json!({ "file_path": text("file_path"),
                    "edits": [{ "old_string": text("old_string"), "new_string": text("new_string") }] }),
        ),
        "MultiEdit" => (
            "MultiEdit".to_owned(),
            json!({ "file_path": text("file_path"), "edits": input["edits"].as_array().into_iter().flatten()
                .map(|edit| json!({ "old_string": edit["old_string"], "new_string": edit["new_string"] }))
                .collect::<Vec<_>>() }),
        ),
        "Write" => {
            let mut content = text("content");
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            (
                "Write".to_owned(),
                json!({ "file_path": text("file_path"), "content": content }),
            )
        }
        "WebFetch" => ("WebFetch".to_owned(), json!({ "url": text("url") })),
        "WebSearch" => ("WebSearch".to_owned(), json!({ "query": text("query") })),
        "TodoWrite" => (
            "TodoWrite".to_owned(),
            json!({ "todos": input["todos"].as_array().into_iter().flatten()
                .map(|todo| json!({ "content": todo["content"], "status": todo["status"] }))
                .collect::<Vec<_>>() }),
        ),
        "Task" => {
            let mut task = json!({ "prompt": text("prompt") });
            if let Some(kind) = input["subagent_type"].as_str() {
                task["subagent_type"] = json!(kind);
            }
            ("Task".to_owned(), task)
        }
        _ => (tool_name.clone(), input),
    };
    request["tool_name"] = json!(name);
    request["tool_input"] = input;
    request
}

// ---- Helpers ----

fn app(config: CollectorConfig, generator: Arc<Recording>) -> axum::Router {
    app_with_transport(CollectorService::new(config, generator))
}

fn pre(tool_name: &str, tool_use_id: &str) -> Value {
    json!({
        "session_id": "s", "turn_id": "t", "cwd": "C:\\proj", "hook_event_name": "PreToolUse",
        "model": "gpt-5.4", "permission_mode": "bypassPermissions",
        "tool_name": tool_name, "tool_input": {}, "tool_use_id": tool_use_id
    })
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

async fn send(
    app: &axum::Router,
    event: &str,
    body: Value,
    shell: Option<&str>,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(post(&format!("/v1/hooks/codex/{event}"), body, shell))
        .await
        .unwrap();
    json_body(response).await
}

async fn json_body(response: axum::response::Response) -> (StatusCode, Value) {
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
