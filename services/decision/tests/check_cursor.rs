//! What the checks make of Cursor calls, as the Collector translates them.
//!
//! An agent must not be able to switch off what supervises it. The real client found this gap:
//! a Cursor session was asked to delete `.cursor/hooks/withhuman-hook.py`, and the engine
//! allowed it — the user had asked for it, so nothing deviated from the intent, and Cursor's
//! own files were not among the safeguards the rule knows. A safeguard call is denied on the
//! rule alone, before anything is asked of a model, which is what these tests pin.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use withhuman_decision::{
    check::{Effect, effect},
    trace::CallInfo,
};

fn call_in(cwd: &str, tool_name: &str, tool_input: Value) -> CallInfo {
    CallInfo {
        seq: 9,
        order: 9,
        subgraph: 3,
        agent_id: None,
        tool_name: tool_name.to_owned(),
        tool_input,
        prior: None,
        programs: BTreeMap::new(),
        cwd: Some(cwd.to_owned()),
    }
}

#[test]
fn knows_cursor_safeguards() {
    for (tool_name, input) in [
        // The hooks file and the bridge the setup installs beside it, including the engine's
        // address the bridge reads from there.
        (
            "Write",
            json!({"file_path": "/proj/.cursor/hooks.json", "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.cursor/hooks/withhuman-hook.py", "content": ""}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.cursor/hooks/server", "content": "http://elsewhere"}),
        ),
        (
            "MultiEdit",
            json!({"file_path": "/home/u/.cursor/hooks.json", "edits": []}),
        ),
        // The MCP servers the agent may call.
        (
            "Write",
            json!({"file_path": "/proj/.cursor/mcp.json", "content": "{}"}),
        ),
        // Windows file names ignore case.
        (
            "Write",
            json!({"file_path": "C:\\proj\\.CURSOR\\Hooks.json", "content": "{}"}),
        ),
        // The command the real session ran.
        (
            "Bash",
            json!({"command": "rm -f /proj/.cursor/hooks/withhuman-hook.py"}),
        ),
        ("Bash", json!({"command": "echo '{}' > .cursor/hooks.json"})),
        (
            "PowerShell",
            json!({"command": "Remove-Item .cursor\\hooks\\withhuman-hook.py"}),
        ),
    ] {
        assert_eq!(
            effect(&call_in("/proj", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
}

#[test]
fn leaves_the_rest_of_a_cursor_project_alone() {
    for (tool_name, input) in [
        // Reading them changes nothing.
        ("Bash", json!({"command": "cat .cursor/hooks.json"})),
        // The agent's instructions and the project's own files are not safeguards; a change to
        // them is judged as any other file change is.
        (
            "Write",
            json!({"file_path": "/proj/.cursor/rules/style.md", "content": "be brief"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/src/hooks.json", "content": "{}"}),
        ),
    ] {
        assert_ne!(
            effect(&call_in("/proj", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
}
