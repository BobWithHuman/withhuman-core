//! What the checks make of Antigravity calls, as the Collector translates them.
//!
//! An agent must not be able to switch off what supervises it. Antigravity reads a project's
//! hooks from one customization root that also holds the agents, skills and rules steering it,
//! and a user's own hooks and plugins from under `.gemini` — so all of those are safeguards. A
//! safeguard call is denied on the rule alone, before anything is asked of a model.

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
fn knows_antigravity_safeguards() {
    for (tool_name, input) in [
        // The project's hooks file and the bridge the setup installs beside it, including the
        // engine's address the bridge reads from there.
        (
            "Write",
            json!({"file_path": "/proj/.agents/hooks.json", "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.agents/hooks/withhuman-hook.py", "content": ""}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.agents/hooks/server", "content": "http://elsewhere"}),
        ),
        // The rest of the customization root steers the agent as much as its hooks do.
        (
            "Write",
            json!({"file_path": "/proj/.agents/rules.json", "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.agents/agents.json", "content": "{}"}),
        ),
        // A user's own hooks, and the plugins a session loads.
        (
            "MultiEdit",
            json!({"file_path": "/home/u/.gemini/config/hooks.json", "edits": []}),
        ),
        (
            "Write",
            json!({"file_path": "/home/u/.gemini/config/plugins/withhuman/hooks.json",
                   "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/home/u/.gemini/antigravity-cli/hooks.json", "content": "{}"}),
        ),
        // Windows file names ignore case.
        (
            "Write",
            json!({"file_path": "C:\\proj\\.AGENTS\\Hooks.json", "content": "{}"}),
        ),
        // Switching the supervision off with a command rather than a file write.
        (
            "Bash",
            json!({"command": "rm -f /proj/.agents/hooks/withhuman-hook.py"}),
        ),
        ("Bash", json!({"command": "echo '{}' > .agents/hooks.json"})),
        (
            "PowerShell",
            json!({"command": "Remove-Item .agents\\hooks\\withhuman-hook.py"}),
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
fn leaves_the_rest_of_a_project_alone() {
    for (tool_name, input) in [
        // Reading them changes nothing.
        ("Bash", json!({"command": "cat .agents/hooks.json"})),
        // A project's own files are judged as any other file change is, including ones whose
        // names hold the word.
        (
            "Write",
            json!({"file_path": "/proj/src/agents/registry.ts", "content": "export {}"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/docs/agents.md", "content": "# agents"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/GEMINI.md", "content": "notes"}),
        ),
    ] {
        assert_ne!(
            effect(&call_in("/proj", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
}
