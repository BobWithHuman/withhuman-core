//! Every OpenClaw Hook captured from a real session must match the contract.
//!
//! The captures under `fixtures/openclaw/` are whole sessions of OpenClaw 2026.11.7, recorded
//! by `capture-harness.js` installed as a plugin of its own and registered on every Hook the
//! host accepts. They are the only evidence of what OpenClaw actually sends, so the contract
//! is checked against them rather than against the documentation — which, for this host,
//! differs: the documentation gives `before_agent_reply` as the model's answer, while the
//! captures show it opening the turn with the inbound text alone.
//!
//! Paths and the user name are masked, and two fields the client does not send — the system
//! prompt and the message history — are kept as their size alone, since each turn carried 50
//! KB of the first and a whole transcript of the second. Nothing else was changed, so what the
//! shapes say is what the client sent.
//!
//! To record more, install `fixtures/openclaw/` as a plugin (`openclaw plugins install`), allow
//! it the conversation
//! (`openclaw config set plugins.entries.withhuman-capture.hooks.allowConversationAccess true`)
//! and run `openclaw chat` with `WH_CAPTURE_OUT` naming the file. Without that config line
//! OpenClaw refuses the turn's Hooks and the capture holds the Calls alone.

use std::collections::BTreeSet;

use serde_json::Value;
use withhuman_contracts::openclaw::{
    OpenClawHookEvent, OpenClawHookInput, dispatch_key, dispatched_by,
};

const CAPTURES: [(&str, &str); 4] = [
    (
        "session-1",
        include_str!("fixtures/openclaw/capture-session-1.jsonl"),
    ),
    (
        "session-2-tools",
        include_str!("fixtures/openclaw/capture-session-2-tools.jsonl"),
    ),
    (
        "session-3-failure",
        include_str!("fixtures/openclaw/capture-session-3-failure.jsonl"),
    ),
    (
        "session-4-nested",
        include_str!("fixtures/openclaw/capture-session-4-nested.jsonl"),
    ),
];

/// Fields OpenClaw sends that the contract deliberately does not name: the model's own
/// identity and parameters, the context window it was given, and the token counts — none of
/// which the engine judges. They travel with the event as evidence. Anything else appearing
/// here is an OpenClaw change nobody has looked at yet.
const UNMODELLED: [&str; 9] = [
    "contextTokenBudget",
    "contextWindowReferenceTokens",
    "contextWindowSource",
    "harnessId",
    "model",
    "provider",
    "resolvedRef",
    "stopHookActive",
    "usage",
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
            let event = row["_event"].as_str().expect("_event").to_owned();
            // The harness's own line, naming the Hooks the host let it register.
            if event == "capture:registered" {
                continue;
            }
            all.push(Captured {
                session,
                event,
                payload: row["payload"].clone(),
            });
        }
    }
    assert!(all.len() > 80, "the captures should hold whole sessions");
    all
}

#[test]
fn every_captured_hook_is_a_known_event() {
    for row in captured() {
        assert!(
            OpenClawHookEvent::from_path(&row.event).is_some(),
            "{} sent {}, which the route would turn away — on an event that decides a Call \
             that blocks it",
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
        let input: OpenClawHookInput = serde_json::from_value(row.payload.clone())
            .unwrap_or_else(|error| panic!("{} {}: {error}", row.session, row.event));
        unknown.extend(input.additional_fields.keys().cloned());
        seen.insert(row.event.clone());
    }
    let expected: BTreeSet<String> = UNMODELLED.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        unknown, expected,
        "OpenClaw's fields changed: look at the difference before widening the contract"
    );
    assert!(seen.len() >= 8, "captured only {} event kinds", seen.len());
}

/// What the Collector reads off each Hook it judges or records. An OpenClaw release that stops
/// sending one of these breaks the translation, so it is pinned per event.
#[test]
fn the_fields_the_translation_needs_are_there() {
    for row in captured() {
        let input: OpenClawHookInput = serde_json::from_value(row.payload.clone()).unwrap();
        let what = |name: &str, present: bool| {
            assert!(present, "{} {}: no {name}", row.session, row.event);
        };
        what("sessionId", input.session_id.is_some());
        what("runId", input.run_id.is_some());
        what("agentId", input.agent_id.is_some());
        match OpenClawHookEvent::from_path(&row.event).unwrap() {
            OpenClawHookEvent::BeforeToolCall => {
                what("toolName", input.tool_name.is_some());
                what("toolCallId", input.tool_call_id.is_some());
                what("params", input.params.is_some());
            }
            OpenClawHookEvent::AfterToolCall => {
                what("toolName", input.tool_name.is_some());
                what("toolCallId", input.tool_call_id.is_some());
                what("result", input.result.is_some());
            }
            OpenClawHookEvent::BeforeAgentRun => {
                what("prompt", input.prompt.is_some());
                what("workspaceDir", input.workspace_dir.is_some());
                what("senderIsOwner", input.sender_is_owner.is_some());
            }
            OpenClawHookEvent::BeforeAgentFinalize => {
                what(
                    "lastAssistantMessage",
                    input.last_assistant_message.is_some(),
                );
            }
            OpenClawHookEvent::AgentEnd => {
                what("success", input.success.is_some());
                what("durationMs", input.duration_ms.is_some());
            }
            _ => {}
        }
    }
}

/// A tool Hook names neither the workspace nor the turn's prompt: what it carries is the Call
/// itself. The client keeps the turn's directory and fills it in, so a Call with a relative
/// path still resolves — this is what makes that the client's job rather than the route's.
#[test]
fn a_tool_hook_does_not_name_the_workspace() {
    for row in captured() {
        if row.event != "before_tool_call" && row.event != "after_tool_call" {
            continue;
        }
        assert!(
            row.payload.get("workspaceDir").is_none(),
            "{} {} named the workspace after all; the client need not fill it in",
            row.session,
            row.event
        );
    }
}

/// A shell call says where it runs and what it did, so neither has to be read back from a
/// transcript as Codex's does.
#[test]
fn a_shell_call_carries_its_directory_and_its_exit_code() {
    let rows = captured();
    let call = rows
        .iter()
        .find(|row| row.event == "before_tool_call" && row.payload["toolName"] == "exec")
        .expect("a captured session should run a shell call");
    assert!(
        call.payload["params"]["workdir"].is_string(),
        "a shell call must name the directory it runs in"
    );
    assert!(call.payload["params"]["command"].is_string());

    let failed = rows
        .iter()
        .filter(|row| row.event == "after_tool_call" && row.payload["toolName"] == "exec")
        .find(|row| row.payload["result"]["details"]["exitCode"].as_i64() != Some(0))
        .expect("session-3-failure should hold a command that exited non-zero");
    assert_eq!(failed.payload["result"]["details"]["exitCode"], 1);
    // The host did not fail the call — the program did. Reading `error` alone would take a
    // failed command for a successful one.
    assert!(failed.payload["error"].is_null());
    assert_eq!(failed.payload["result"]["details"]["status"], "completed");
}

/// A file edit arrives as the change it made, in the form Claude Code's `MultiEdit` takes, and
/// its result holds the patch the engine checks line by line.
#[test]
fn a_file_edit_carries_its_edits_and_its_patch() {
    let rows = captured();
    let call = rows
        .iter()
        .find(|row| row.event == "before_tool_call" && row.payload["toolName"] == "edit")
        .expect("session-2-tools should edit a file");
    let edits = call.payload["params"]["edits"]
        .as_array()
        .expect("an edit names the changes it makes");
    assert!(edits[0]["oldText"].is_string() && edits[0]["newText"].is_string());

    let result = rows
        .iter()
        .find(|row| row.event == "after_tool_call" && row.payload["toolName"] == "edit")
        .expect("the edit should have a result");
    assert!(
        result.payload["result"]["details"]["patch"].is_string(),
        "an edit's result must carry the patch the engine reads the change from"
    );
}

/// OpenClaw runs a Call for another: `dispatch_action` names an action, and the action arrives
/// as a Call of its own naming the one that dispatched it. The inner Call carries the real
/// tool, so it is the one the engine judges.
#[test]
fn a_dispatched_call_arrives_as_a_call_of_its_own() {
    let rows = captured();
    let dispatch = rows
        .iter()
        .find(|row| row.event == "before_tool_call" && row.payload["toolName"] == "dispatch_action")
        .expect("session-4-nested should dispatch an action");
    let caller = dispatch.payload["toolCallId"].as_str().unwrap();
    let dispatched_id = dispatch.payload["params"]["id"]
        .as_str()
        .expect("a dispatch names the action it runs");

    let inner = rows
        .iter()
        .filter(|row| row.event == "before_tool_call")
        .filter_map(|row| {
            let id = row.payload["toolCallId"].as_str()?;
            (dispatched_by(id)? == dispatch_key(caller)).then_some(row)
        })
        .next()
        .expect("the dispatched action should arrive as a Call of its own");
    let tool = inner.payload["toolName"].as_str().unwrap();
    assert!(
        dispatched_id.ends_with(tool),
        "the dispatch named {dispatched_id} but the Call that ran it was {tool}"
    );
    // Nothing of the dispatching call is lost: both carry the turn they belong to.
    assert_eq!(inner.payload["runId"], dispatch.payload["runId"]);
}

/// The turn is `runId`: a prompt and every Call it leads to share it.
#[test]
fn one_turn_holds_its_prompt_and_its_calls() {
    let rows: Vec<_> = captured()
        .into_iter()
        .filter(|row| row.session == "session-2-tools")
        .collect();
    let prompt = rows
        .iter()
        .find(|row| row.event == "before_agent_run")
        .expect("the capture should open with a prompt");
    let turn = prompt.payload["runId"].as_str().unwrap();
    let calls = rows
        .iter()
        .filter(|row| row.event == "before_tool_call")
        .filter(|row| row.payload["runId"] == *turn)
        .count();
    assert!(calls > 0, "the first turn ran no call");
    for row in rows.iter().filter(|row| row.event == "before_tool_call") {
        assert!(
            row.payload["runId"].is_string(),
            "a Call that names no turn cannot be put on the turn's path"
        );
    }
}

/// OpenClaw refuses the turn's Hooks to a plugin that was not allowed the conversation, so a
/// capture made without that permission holds Calls and nothing around them. The captures here
/// were made with it, which is what makes the intent line reachable at all.
#[test]
fn the_captures_were_allowed_the_conversation() {
    let seen: BTreeSet<_> = captured().into_iter().map(|row| row.event).collect();
    for event in ["before_agent_run", "agent_end"] {
        assert!(
            seen.contains(event),
            "no {event}: the capture was made without allowConversationAccess"
        );
        assert!(
            OpenClawHookEvent::from_path(event)
                .unwrap()
                .needs_conversation_access()
        );
    }
}
