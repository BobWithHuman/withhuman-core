//! Every Cursor Hook captured from a real session must match the contract.
//!
//! The captures under `fixtures/cursor/` are whole sessions of Cursor CLI 2026.11.22, recorded
//! by `capture-harness.py` registered on all 21 Hooks. They are the only evidence of what
//! Cursor actually sends, so the contract is checked against them rather than against the
//! documentation: a field that changes shape, or an event that gains one, fails here.
//!
//! The paths and the user in them are masked; nothing else was changed, so what the shapes say
//! is what the client sent. To record more, copy `capture-harness.py` and `capture-hooks.json`
//! into a scratch project's `.cursor/` and run `cursor-agent` there — a session without a
//! terminal (`-p`) fires neither the prompt nor the answer Hooks, so record an interactive one
//! for those.

use std::collections::BTreeSet;

use serde_json::Value;
use withhuman_contracts::cursor::{CursorHookEvent, CursorHookInput, turn_of};

const CAPTURES: [(&str, &str); 6] = [
    (
        "session-1",
        include_str!("fixtures/cursor/capture-session-1.jsonl"),
    ),
    (
        "session-2",
        include_str!("fixtures/cursor/capture-session-2.jsonl"),
    ),
    (
        "session-3-tools",
        include_str!("fixtures/cursor/capture-session-3-tools.jsonl"),
    ),
    (
        "session-4-subagent",
        include_str!("fixtures/cursor/capture-session-4-subagent.jsonl"),
    ),
    (
        "session-5-mcp",
        include_str!("fixtures/cursor/capture-session-5-mcp.jsonl"),
    ),
    (
        "session-6-interactive",
        include_str!("fixtures/cursor/capture-session-6-interactive.jsonl"),
    ),
];

/// Fields Cursor sends that the contract deliberately does not name: the client's own version
/// and user, the workspace it opened, the model's parameters, and timings and token counts the
/// engine does not judge. They travel with the event as evidence. Anything else appearing here
/// is a Cursor change nobody has looked at yet.
const UNMODELLED: [&str; 12] = [
    "cache_read_tokens",
    "cache_write_tokens",
    "cursor_version",
    "duration",
    "duration_ms",
    "input_tokens",
    "loop_count",
    "model_id",
    "model_params",
    "output_tokens",
    "user_email",
    "workspace_roots",
];

struct Captured {
    session: &'static str,
    event: String,
    payload: Value,
}

fn captured() -> Vec<Captured> {
    let mut all = Vec::new();
    for (session, text) in CAPTURES {
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let row: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("{session} holds invalid JSON: {error}"));
            all.push(Captured {
                session,
                event: row["_event"].as_str().expect("_event").to_owned(),
                payload: row["payload"].clone(),
            });
        }
    }
    assert!(all.len() > 100, "the captures should hold whole sessions");
    all
}

#[test]
fn every_captured_hook_is_a_known_event() {
    for row in captured() {
        assert!(
            CursorHookEvent::from_path(&row.event).is_some(),
            "{} sent {}, which the route would turn away — with failClosed that blocks the call",
            row.session,
            row.event
        );
    }
}

#[test]
fn every_captured_payload_matches_the_contract() {
    let mut unknown = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for row in captured() {
        let input: CursorHookInput = serde_json::from_value(row.payload.clone())
            .unwrap_or_else(|error| panic!("{} {}: {error}", row.session, row.event));
        unknown.extend(input.additional_fields.keys().cloned());
        seen.insert(row.event.clone());
    }
    let expected: BTreeSet<String> = UNMODELLED.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        unknown, expected,
        "Cursor's fields changed: look at the difference before widening the contract"
    );
    assert!(seen.len() >= 16, "captured only {} event kinds", seen.len());
}

/// What the Collector reads off each Hook it judges or records. A Cursor release that stops
/// sending one of these breaks the translation, so it is pinned per event.
#[test]
fn the_fields_the_translation_needs_are_there() {
    for row in captured() {
        let input: CursorHookInput = serde_json::from_value(row.payload.clone()).unwrap();
        let what = |name: &str, present: bool| {
            assert!(present, "{} {}: no {name}", row.session, row.event);
        };
        match CursorHookEvent::from_path(&row.event).unwrap() {
            CursorHookEvent::WorkspaceOpen => {}
            CursorHookEvent::PreToolUse | CursorHookEvent::PostToolUse => {
                what("session_id", input.session_id.is_some());
                what("generation_id", input.generation_id.is_some());
                what("tool_name", input.tool_name.is_some());
                what("tool_use_id", input.tool_use_id.is_some());
                what("tool_input", input.tool_input.is_some());
            }
            CursorHookEvent::PostToolUseFailure => {
                what("tool_use_id", input.tool_use_id.is_some());
                what("error_message", input.error_message.is_some());
            }
            CursorHookEvent::BeforeMcpExecution | CursorHookEvent::AfterMcpExecution => {
                what("mcp_server_name", input.mcp_server_name.is_some());
                what("tool_name", input.tool_name.is_some());
                what("tool_use_id", input.tool_use_id.is_some());
            }
            CursorHookEvent::BeforeSubmitPrompt => {
                what("prompt", input.prompt.is_some());
                what("generation_id", input.generation_id.is_some());
            }
            CursorHookEvent::AfterAgentResponse => {
                what("text", input.text.is_some());
                what("generation_id", input.generation_id.is_some());
            }
            CursorHookEvent::AfterFileEdit => {
                what("file_path", input.file_path.is_some());
                what("edits", input.edits.is_some());
            }
            _ => what("session_id", input.session_id.is_some()),
        }
    }
}

/// An MCP call is named `MCP:<tool>` on the tool Hooks and the server appears only on the MCP
/// ones, which is why those are the Hooks the engine judges MCP calls on.
#[test]
fn an_mcp_call_names_its_server_on_the_mcp_hooks_alone() {
    let rows = captured();
    let tool_hook: Vec<_> = rows
        .iter()
        .filter(|row| row.event == "preToolUse")
        .filter_map(|row| row.payload["tool_name"].as_str())
        .filter(|name| name.starts_with("MCP:"))
        .collect();
    assert_eq!(tool_hook, ["MCP:list_alps_sections"]);
    let mcp_hook: Vec<_> = rows
        .iter()
        .filter(|row| row.event == "beforeMCPExecution")
        .map(|row| {
            (
                row.payload["mcp_server_name"].as_str().unwrap(),
                row.payload["tool_name"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        mcp_hook,
        [("plugin-alps-writer-alps-writer", "list_alps_sections")]
    );
    for row in rows.iter().filter(|row| row.event == "preToolUse") {
        assert!(
            row.payload.get("mcp_server_name").is_none(),
            "preToolUse named a server after all; judge MCP there instead"
        );
    }
}

/// A turn is one `generation_id`: the prompt, the calls it led to, the answer and the stop all
/// carry it, and a thought only adds a suffix.
#[test]
fn one_turn_holds_its_prompt_calls_and_answer() {
    let rows: Vec<_> = captured()
        .into_iter()
        .filter(|row| row.session == "session-6-interactive")
        .collect();
    let turn = rows
        .iter()
        .find(|row| row.event == "beforeSubmitPrompt")
        .and_then(|row| row.payload["generation_id"].as_str())
        .expect("the interactive capture should open with a prompt")
        .to_owned();
    for name in ["preToolUse", "postToolUse", "afterAgentResponse", "stop"] {
        let row = rows
            .iter()
            .find(|row| row.event == name)
            .unwrap_or_else(|| panic!("no {name} in the interactive capture"));
        assert_eq!(
            turn_of(row.payload["generation_id"].as_str().unwrap()),
            turn,
            "{name} belongs to another turn"
        );
    }
    let thought = rows
        .iter()
        .filter(|row| row.event == "afterAgentThought")
        .filter_map(|row| row.payload["generation_id"].as_str())
        .find(|id| id.len() > turn.len())
        .expect("a thought should carry the suffixed form");
    assert_eq!(turn_of(thought), turn);
}
