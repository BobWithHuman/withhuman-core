//! Every Copilot Hook captured from a real session must match the contract.
//!
//! The captures under `fixtures/copilot/` are whole sessions of Copilot CLI 1.0.115-7,
//! recorded by `capture-harness.py` registered on every event under **both** of Copilot's
//! spellings, so the two can be compared against each other. They are the only evidence of
//! what Copilot actually sends, so the contract is checked against them rather than against
//! the documentation: a field that changes shape, or an event that gains one, fails here.
//!
//! Sessions 4 and 5 were recorded with a second Hook that answered `deny` on
//! `preMcpToolCall` and on `permissionRequest`. Both are in the list of Hooks Copilot calls
//! authoritative, and in both sessions the call ran anyway — which the captures show as a
//! `PostToolUse` under the very `toolCallId` the denial was given for.
//!
//! The paths and the user in them are masked; nothing else was changed, so what the shapes
//! say is what the client sent. To record more, copy `capture-harness.py` and
//! `capture-hooks.json` into `~/.copilot/hooks/` and run `copilot -p "…" --allow-all-tools`
//! — with `GITHUB_TOKEN` and `GH_TOKEN` out of the environment, which the CLI refuses to
//! start with.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use withhuman_contracts::copilot::{CopilotHookEvent, CopilotHookInput};

const CAPTURES: [(&str, &str); 5] = [
    (
        "session-1-shell",
        include_str!("fixtures/copilot/capture-session-1-shell.jsonl"),
    ),
    (
        "session-2-edit-failure",
        include_str!("fixtures/copilot/capture-session-2-edit-failure.jsonl"),
    ),
    (
        "session-3-mcp-subagent",
        include_str!("fixtures/copilot/capture-session-3-mcp-subagent.jsonl"),
    ),
    (
        "session-4-mcp-gate-premcp",
        include_str!("fixtures/copilot/capture-session-4-mcp-gate-premcp.jsonl"),
    ),
    (
        "session-5-mcp-gate-permission",
        include_str!("fixtures/copilot/capture-session-5-mcp-gate-permission.jsonl"),
    ),
];

/// Fields Copilot sends that the contract does not name. There are none: every field of
/// every captured event is named, so anything appearing here is a Copilot change nobody has
/// looked at yet. What is not named still travels with the event as evidence.
const UNMODELLED: [&str; 0] = [];

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

/// The rows of one event, in the order they were captured.
fn rows_of(event: &str) -> Vec<Captured> {
    captured()
        .into_iter()
        .filter(|row| row.event == event)
        .collect()
}

#[test]
fn every_captured_hook_is_a_known_event() {
    for row in captured() {
        assert!(
            CopilotHookEvent::from_path(&row.event).is_some(),
            "{} sent {}, which the route would turn away",
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
        let input: CopilotHookInput = serde_json::from_value(row.payload.clone())
            .unwrap_or_else(|error| panic!("{} {}: {error}", row.session, row.event));
        unknown.extend(input.additional_fields.keys().cloned());
        seen.insert(row.event.clone());
    }
    let expected: BTreeSet<String> = UNMODELLED.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        unknown, expected,
        "Copilot's fields changed: look at the difference before widening the contract"
    );
    assert!(seen.len() >= 17, "captured only {} event kinds", seen.len());
}

/// What the Collector reads off each Hook it judges or records. A Copilot release that stops
/// sending one of these breaks the translation, so it is pinned per event.
#[test]
fn the_fields_the_translation_needs_are_there() {
    for row in captured() {
        // The camelCase spelling is the one the bridge does not register; only the names it
        // sends to the route have to carry what the translation needs.
        if row.event.starts_with(char::is_lowercase) {
            continue;
        }
        let input: CopilotHookInput = serde_json::from_value(row.payload.clone()).unwrap();
        let what = |name: &str, present: bool| {
            assert!(present, "{} {}: no {name}", row.session, row.event);
        };
        what("session_id", input.session_id.is_some());
        match CopilotHookEvent::from_path(&row.event).unwrap() {
            CopilotHookEvent::PreToolUse | CopilotHookEvent::PostToolUse => {
                what("tool_name", input.tool_name.is_some());
                what("tool_use_id", input.tool_use_id.is_some());
                what("tool_input", input.tool_input.is_some());
            }
            CopilotHookEvent::PostToolUseFailure => {
                what("tool_name", input.tool_name.is_some());
                what("tool_use_id", input.tool_use_id.is_some());
                what("error", input.error.is_some());
            }
            CopilotHookEvent::UserPromptSubmit => what("prompt", input.prompt.is_some()),
            CopilotHookEvent::SessionStart => what("source", input.source.is_some()),
            CopilotHookEvent::SessionEnd => what("reason", input.reason.is_some()),
            CopilotHookEvent::Stop => {
                // The turn's own answer is not here, which is why the bridge reads the
                // transcript this names.
                what("transcript_path", input.transcript_path.is_some());
                what("stop_reason", input.stop_reason.is_some());
            }
            CopilotHookEvent::SubagentStop => {
                what(
                    "last_assistant_message",
                    input.last_assistant_message.is_some(),
                );
                what("parent_agent_id", input.parent_agent_id.is_some());
            }
            CopilotHookEvent::SubagentStart => {
                what("agent_name", input.agent_name.is_some());
                what("agent_id", input.agent_id.is_some());
                what("parent_agent_id", input.parent_agent_id.is_some());
            }
            _ => {}
        }
    }
}

/// The same call arrives twice, and Claude Code's name for it is Copilot's own translated:
/// the bridge registers the Claude Code spelling for exactly this reason, so the engine
/// judges the tool names it already knows.
#[test]
fn claude_codes_name_for_a_call_is_what_the_claude_named_hook_sends() {
    let by_id = |event: &str| -> BTreeMap<String, String> {
        rows_of(event)
            .into_iter()
            .filter_map(|row| {
                let input: CopilotHookInput = serde_json::from_value(row.payload).ok()?;
                Some((input.tool_use_id?, input.tool_name?))
            })
            .collect()
    };
    let copilot = by_id("preToolUse");
    let claude = by_id("PreToolUse");
    assert_eq!(
        copilot.keys().collect::<Vec<_>>(),
        claude.keys().collect::<Vec<_>>(),
        "the two spellings should cover the same calls"
    );

    let mut pairs: BTreeSet<(String, String)> = BTreeSet::new();
    for (id, native) in &copilot {
        pairs.insert((native.clone(), claude[id].clone()));
    }
    let seen: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(native, claude)| (native.as_str(), claude.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            ("apply_patch", "Edit"),
            ("bash", "Bash"),
            ("task", "Agent"),
            ("view", "Read"),
            // An MCP call keeps its `<server>-<tool>` name under both spellings.
            (
                "withhuman-fixture-write_file",
                "withhuman-fixture-write_file"
            ),
        ],
        "Copilot's translation of its tool names changed"
    );
}

/// `apply_patch` arrives as `Edit` whose arguments are the patch itself, as a string. Nothing
/// in the engine can read a `file_path` off that, which is why the translation hands it to
/// Codex's patch parser.
#[test]
fn an_edits_arguments_are_a_patch_not_an_object() {
    let edits: Vec<CopilotHookInput> = rows_of("PreToolUse")
        .into_iter()
        .filter_map(|row| serde_json::from_value(row.payload).ok())
        .filter(|input: &CopilotHookInput| input.tool_name.as_deref() == Some("Edit"))
        .collect();
    assert!(!edits.is_empty(), "no Edit was captured");
    for edit in edits {
        let patch = edit.tool_input.as_ref().and_then(Value::as_str);
        let patch = patch.unwrap_or_else(|| panic!("Edit now sends {:?}", edit.tool_input));
        assert!(patch.starts_with("*** Begin Patch"), "not a patch: {patch}");
    }
}

/// An MCP call's server is nowhere on the Hook that can stop it. The Hooks that do name it
/// run after the call was judged, so what the bridge learns there serves the calls that come
/// after.
#[test]
fn an_mcp_call_names_its_server_only_after_it_was_judged() {
    let gate: Vec<String> = rows_of("PreToolUse")
        .into_iter()
        .filter_map(|row| row.payload["tool_name"].as_str().map(str::to_owned))
        .filter(|name| name.contains("write_file"))
        .collect();
    assert_eq!(gate, ["withhuman-fixture-write_file"; 3]);
    for row in rows_of("PreToolUse") {
        for name in ["server_name", "serverName", "withhuman_mcp_server"] {
            assert!(
                row.payload.get(name).is_none(),
                "PreToolUse named a server after all; split the name there instead"
            );
        }
    }

    let mcp: Vec<(String, String)> = rows_of("preMcpToolCall")
        .into_iter()
        .filter_map(|row| {
            let input: CopilotHookInput = serde_json::from_value(row.payload).ok()?;
            Some((input.server_name?, input.tool_name?))
        })
        .collect();
    assert_eq!(
        mcp,
        [
            ("withhuman-fixture".to_owned(), "write_file".to_owned()),
            ("withhuman-fixture".to_owned(), "write_file".to_owned()),
            ("withhuman-fixture".to_owned(), "write_file".to_owned()),
        ]
    );
    // The permission Hook separates the two with a slash, the one place the name comes apart
    // on its own.
    let suggested: Vec<String> = rows_of("PermissionRequest")
        .into_iter()
        .filter_map(|row| row.payload["toolName"].as_str().map(str::to_owned))
        .filter(|name| name.contains('/'))
        .collect();
    assert_eq!(suggested, ["withhuman-fixture/write_file"; 3]);
}

/// Copilot calls `preMcpToolCall` and `permissionRequest` authoritative, but a command Hook's
/// `deny` on either is discarded. Sessions 4 and 5 were recorded with exactly such a Hook,
/// and the call it refused still completed. This is the measurement that puts every call,
/// MCP included, on `PreToolUse`.
#[test]
fn a_deny_on_copilots_other_gates_does_not_stop_the_call() {
    for session in ["session-4-mcp-gate-premcp", "session-5-mcp-gate-permission"] {
        let of = |event: &str| -> Option<String> {
            captured()
                .into_iter()
                .filter(|row| row.session == session && row.event == event)
                .find_map(|row| {
                    let input: CopilotHookInput = serde_json::from_value(row.payload).ok()?;
                    input.tool_use_id
                })
        };
        let refused = of("preMcpToolCall").expect("the MCP gate should have been asked");
        assert_eq!(
            of("PostToolUse").as_deref(),
            Some(refused.as_str()),
            "{session}: the refused call left no result, so the gate held after all"
        );
    }
}

/// A subagent's events carry an id of their own, and the session they belong to beside it.
#[test]
fn a_subagents_events_name_the_session_they_run_under() {
    let subagent: Vec<CopilotHookInput> = captured()
        .into_iter()
        .filter(|row| !row.event.starts_with(char::is_lowercase))
        .filter_map(|row| serde_json::from_value(row.payload).ok())
        .filter(|input: &CopilotHookInput| {
            input.parent_agent_id.is_some() && input.parent_agent_id != input.session_id
        })
        .collect();
    assert!(!subagent.is_empty(), "no subagent event was captured");
    for input in subagent {
        let parent = input.parent_agent_id.clone().unwrap();
        assert_eq!(input.session(), Some(parent.as_str()));
        assert_ne!(input.session_id, input.parent_agent_id);
    }
}

/// No Hook carries a turn, under either spelling. This is why the bridge reads `turnId` from
/// the transcript: without it every call of a session would look like one turn.
#[test]
fn no_hook_carries_a_turn() {
    for row in captured() {
        for name in ["turn_id", "turnId", "prompt_id", "promptId"] {
            assert!(
                row.payload.get(name).is_none(),
                "{} {} carries {name} after all; read the turn off it instead",
                row.session,
                row.event
            );
        }
    }
}
