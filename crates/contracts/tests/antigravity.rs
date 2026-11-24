//! Every Antigravity Hook captured from a real session must match the contract.
//!
//! The captures under `fixtures/antigravity/` are whole sessions of Antigravity CLI 1.5.16,
//! recorded by `capture-harness.py` installed as the plugin `capture-plugin.json` describes.
//! They are the only evidence of what Antigravity actually sends, so the contract is checked
//! against them rather than against the reference the client ships: a field that changes
//! shape, or an event that gains one, fails here.
//!
//! The paths and the user in them are masked; nothing else was changed, so what the shapes say
//! is what the client sent. To record more, install the capture plugin with
//! `agy plugin install <dir>` and run `agy -p "…" --dangerously-skip-permissions`.

use std::collections::BTreeSet;

use serde_json::Value;
use withhuman_contracts::antigravity::{AntigravityHookEvent, AntigravityHookInput, MCP_TOOL};

const CAPTURES: [(&str, &str); 6] = [
    (
        "session-1-shell",
        include_str!("fixtures/antigravity/capture-session-1-shell.jsonl"),
    ),
    (
        "session-2-edit",
        include_str!("fixtures/antigravity/capture-session-2-edit.jsonl"),
    ),
    (
        "session-3-failure",
        include_str!("fixtures/antigravity/capture-session-3-failure.jsonl"),
    ),
    (
        "session-4-mcp",
        include_str!("fixtures/antigravity/capture-session-4-mcp.jsonl"),
    ),
    (
        "session-5-web-subagent",
        include_str!("fixtures/antigravity/capture-session-5-web-subagent.jsonl"),
    ),
    // The subagent's own session, which arrives with a conversation of its own and no prompt.
    (
        "session-6-subagent-own",
        include_str!("fixtures/antigravity/capture-session-6-subagent-own.jsonl"),
    ),
];

/// Fields Antigravity sends that the contract does not name. There are none: every field of
/// every captured event is named, so anything appearing here is an Antigravity change nobody
/// has looked at yet. What is not named still travels with the event as evidence.
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
    assert!(all.len() > 30, "the captures should hold whole sessions");
    all
}

fn parsed() -> Vec<(Captured, AntigravityHookInput)> {
    captured()
        .into_iter()
        .map(|row| {
            let input = serde_json::from_value(row.payload.clone())
                .unwrap_or_else(|error| panic!("{} {}: {error}", row.session, row.event));
            (row, input)
        })
        .collect()
}

#[test]
fn every_captured_hook_is_a_known_event() {
    for row in captured() {
        assert!(
            AntigravityHookEvent::from_path(&row.event).is_some(),
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
    for (row, input) in parsed() {
        unknown.extend(input.additional_fields.keys().cloned());
        seen.insert(row.event);
    }
    let expected: BTreeSet<String> = UNMODELLED.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        unknown, expected,
        "Antigravity's fields changed: look at the difference before widening the contract"
    );
    assert_eq!(
        seen,
        BTreeSet::from([
            "PostInvocation".to_owned(),
            "PostToolUse".to_owned(),
            "PreInvocation".to_owned(),
            "PreToolUse".to_owned(),
            "SessionStart".to_owned(),
            "Stop".to_owned(),
        ]),
        "Antigravity has six events; the captures should hold all of them"
    );
}

/// What the Collector reads off each Hook it judges or records. An Antigravity release that
/// stops sending one of these breaks the translation, so it is pinned per event.
#[test]
fn the_fields_the_translation_needs_are_there() {
    for (row, input) in parsed() {
        let what = |name: &str, present: bool| {
            assert!(present, "{} {}: no {name}", row.session, row.event);
        };
        // Every event names the conversation it belongs to and the turn's prompt.
        what("conversation_id", input.conversation_id.is_some());
        what("cwd", input.cwd.is_some());
        what("transcript_path", input.transcript_path.is_some());
        what("last_user_input", input.last_user_input.is_some());
        match AntigravityHookEvent::from_path(&row.event).unwrap() {
            AntigravityHookEvent::PreToolUse | AntigravityHookEvent::PostToolUse => {
                let call = input.tool_call.as_ref().expect("tool_call");
                what("tool_call.id", call.id.is_some());
                what("tool_call.name", call.name.is_some());
                what("tool_call.args", call.args.is_some());
                what("step_idx", input.step_idx.is_some());
            }
            AntigravityHookEvent::PreInvocation | AntigravityHookEvent::PostInvocation => {
                what("invocation_num", input.invocation_num.is_some());
            }
            AntigravityHookEvent::Stop => {
                what("termination_reason", input.termination_reason.is_some());
                what("execution_num", input.execution_num.is_some());
            }
            _ => {}
        }
    }
}

/// The prompt is the turn, not the invocation count. `invocation_num` starts again at 0 for
/// each loop, and a loop re-enters **within one prompt** — a turn that waits for a subagent
/// stops and comes back at 0 with the same `last_user_input`. A bridge that minted a turn
/// there would split one turn into two, which is why it mints by the prompt instead.
#[test]
fn an_invocation_of_zero_comes_again_within_one_prompt() {
    let mut split = 0;
    for (session, _) in CAPTURES {
        let rows: Vec<(Captured, AntigravityHookInput)> = parsed()
            .into_iter()
            .filter(|(row, _)| row.session == session)
            .collect();
        let opening: Vec<&AntigravityHookInput> = rows
            .iter()
            .filter(|(_, input)| input.opens_a_loop())
            .map(|(_, input)| input)
            .collect();
        assert!(
            !opening.is_empty(),
            "{session}: a session should open at least one loop"
        );
        // Every event of a session carries one prompt: these captures are one prompt each.
        let prompts: BTreeSet<&str> = rows
            .iter()
            .filter_map(|(_, input)| input.last_user_input.as_deref())
            .collect();
        assert_eq!(
            prompts.len(),
            1,
            "{session}: a one-prompt session should carry one prompt"
        );
        if opening.len() > 1 {
            split += 1;
        }
    }
    assert!(
        split > 0,
        "no capture shows a loop re-entering at 0 within one prompt; \
         the turn could then be the invocation after all"
    );
}

/// A call's result is in no Hook: `PostToolUse` says only whether it failed. This is why the
/// bridge reads the transcript, and `step_idx` is what it reads it by.
#[test]
fn a_calls_result_is_in_no_hook() {
    let results: Vec<(String, Option<String>, Option<i64>)> = parsed()
        .into_iter()
        .filter(|(row, _)| row.event == "PostToolUse")
        .map(|(row, input)| {
            for name in ["toolResponse", "result", "output", "toolResult"] {
                assert!(
                    row.payload.get(name).is_none(),
                    "PostToolUse now carries {name}; read the result there instead"
                );
            }
            (
                input
                    .tool_call
                    .as_ref()
                    .and_then(|call| call.name.clone())
                    .unwrap_or_default(),
                input.error.clone(),
                input.step_idx,
            )
        })
        .collect();
    assert!(!results.is_empty(), "no finished call was captured");
    for (tool, error, step) in &results {
        assert!(step.is_some(), "{tool}: no step_idx to find its result by");
        assert!(
            error.is_some(),
            "{tool}: no error field, not even an empty one"
        );
    }
    // The failing session's read did report an error; the rest came back empty.
    assert!(
        results
            .iter()
            .any(|(_, error, _)| { error.as_deref().is_some_and(|error| !error.is_empty()) }),
        "a failed call should carry why it failed"
    );
}

/// An MCP call names its server and its tool in its own arguments, so the name the engine
/// knows MCP by needs nothing guessed.
#[test]
fn an_mcp_call_names_its_server_and_tool() {
    let calls: Vec<(String, String)> = parsed()
        .into_iter()
        .filter_map(|(_, input)| {
            let call = input.tool_call?;
            let (server, tool) = call.mcp_call()?;
            Some((server.to_owned(), tool.to_owned()))
        })
        .collect();
    assert_eq!(
        calls,
        [
            ("withhuman-fixture".to_owned(), "write_file".to_owned()),
            ("withhuman-fixture".to_owned(), "write_file".to_owned()),
        ],
        "the MCP session's call should be named on both its Hooks"
    );
    // Every MCP call is this one tool; nothing else carries a server name.
    for (_, input) in parsed() {
        let Some(call) = input.tool_call else {
            continue;
        };
        if call.name.as_deref() != Some(MCP_TOOL) {
            assert!(
                call.arg("ServerName").is_none(),
                "{:?} named a server after all",
                call.name
            );
        }
    }
}

/// The tools the captures show, and the arguments each is read by. A release that renames one
/// breaks the translation, so the set is pinned.
#[test]
fn the_tools_a_session_uses_are_named_as_captured() {
    let mut tools: BTreeSet<(String, String)> = BTreeSet::new();
    for (_, input) in parsed() {
        let Some(call) = input.tool_call else {
            continue;
        };
        let name = call.name.clone().unwrap_or_default();
        let mut keys: Vec<String> = call
            .args
            .as_ref()
            .and_then(Value::as_object)
            .map(|args| args.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        tools.insert((name, keys.join(",")));
    }
    let seen: Vec<(&str, &str)> = tools
        .iter()
        .map(|(name, keys)| (name.as_str(), keys.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            ("call_mcp_tool", "Arguments,ServerName,ToolName"),
            ("invoke_subagent", "Prompt,Role,TypeName"),
            ("read_file", "Path"),
            ("run_command", "CommandLine,WaitMsBeforeAsync,toolSummary"),
            ("send_message", "Message,Recipient"),
            ("write_file", "Content,Overwrite,Path"),
        ],
        "Antigravity's tools or their arguments changed"
    );
}
