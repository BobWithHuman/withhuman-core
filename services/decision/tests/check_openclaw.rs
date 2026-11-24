//! What the checks make of OpenClaw calls, as the Collector translates them.
//!
//! An agent must not be able to switch off what supervises it. For OpenClaw that is one
//! directory: `~/.openclaw` holds the configuration registering the WithHuman plugin, the
//! permission letting it read the turn (`hooks.allowConversationAccess`), the plugins
//! themselves and the MCP servers the agent may call. A session that edits any of them keeps
//! working while nothing judges it any more. A safeguard call is denied on the rule alone,
//! before anything is asked of a model, which is what these tests pin.

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
fn knows_openclaw_safeguards() {
    for (tool_name, input) in [
        // The configuration: what plugins are enabled, whether ours may read the turn, and the
        // MCP servers the agent may call all live in this one file.
        (
            "Write",
            json!({"file_path": "/home/u/.openclaw/openclaw.json", "content": "{}"}),
        ),
        (
            "MultiEdit",
            json!({"file_path": "/home/u/.openclaw/openclaw.json", "edits": []}),
        ),
        // The plugin that does the judging, as it is installed.
        (
            "Write",
            json!({"file_path": "/home/u/.openclaw/extensions/withhuman/index.js", "content": ""}),
        ),
        // A named profile keeps its own directory beside the default one.
        (
            "Write",
            json!({"file_path": "/home/u/.openclaw-dev/openclaw.json", "content": "{}"}),
        ),
        // A configuration kept somewhere else, as `OPENCLAW_CONFIG_PATH` allows.
        (
            "Write",
            json!({"file_path": "/etc/withhuman/openclaw.json", "content": "{}"}),
        ),
        // Windows file names ignore case.
        (
            "Write",
            json!({"file_path": "C:\\Users\\u\\.OpenClaw\\OpenClaw.json", "content": "{}"}),
        ),
        // Taking the plugin out, or turning it off, through the shell.
        (
            "Bash",
            json!({"command": "rm -rf /home/u/.openclaw/extensions/withhuman"}),
        ),
        (
            "Bash",
            json!({"command": "echo '{}' > ~/.openclaw/openclaw.json"}),
        ),
        (
            "Bash",
            json!({"command": "openclaw config set plugins.entries.withhuman.enabled false"}),
        ),
        (
            "PowerShell",
            json!({"command": "Remove-Item .openclaw\\extensions\\withhuman -Recurse"}),
        ),
        // The agent's own CLI writes no file the rule would see, so the command is what is
        // caught: turning the plugin off, taking the conversation permission away, giving the
        // agent a server nobody judged, and resetting the configuration that holds all three.
        (
            "Bash",
            json!({"command": "openclaw plugins disable withhuman"}),
        ),
        (
            "Bash",
            json!({"command": "openclaw config set plugins.entries.withhuman.hooks.allowConversationAccess false"}),
        ),
        (
            "Bash",
            json!({"command": "openclaw mcp add mine --command /tmp/x.py"}),
        ),
        ("Bash", json!({"command": "openclaw reset"})),
        // A global option between the program and its action does not get past it.
        (
            "Bash",
            json!({"command": "openclaw --profile dev config unset plugins.entries.withhuman"}),
        ),
    ] {
        assert_eq!(
            effect(&call_in("/home/u", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
}

#[test]
fn leaves_the_rest_of_an_openclaw_workspace_alone() {
    for (tool_name, input) in [
        // Reading them changes nothing.
        ("Bash", json!({"command": "cat ~/.openclaw/openclaw.json"})),
        // The agent's own instructions and the files it works on are not safeguards; a change
        // to them is judged as any other file change is.
        (
            "Write",
            json!({"file_path": "/work/project/AGENTS.md", "content": "be brief"}),
        ),
        (
            "Write",
            json!({"file_path": "/work/project/openclaw.plugin.json", "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/work/openclaw/notes.md", "content": "hi"}),
        ),
        // Asking the CLI what it holds changes nothing.
        ("Bash", json!({"command": "openclaw plugins list"})),
        ("Bash", json!({"command": "openclaw config get agents"})),
        ("Bash", json!({"command": "openclaw mcp probe"})),
    ] {
        assert_ne!(
            effect(&call_in("/work/project", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
}
