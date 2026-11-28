//! What the checks make of Hermes Agent calls, as the Collector translates them.
//!
//! An agent must not be able to switch off what supervises it. Hermes loads WithHuman as a
//! plugin of its profile: deleting or rewriting the plugin folder, or taking it out of the
//! profile's `plugins.enabled`, stops every later call from being judged. A safeguard call is
//! denied on the rule alone, before anything is asked of a model, which is what these tests pin.

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
        instructions: BTreeMap::new(),
        cwd: Some(cwd.to_owned()),
    }
}

#[test]
fn knows_hermes_safeguards() {
    for (tool_name, input) in [
        // The plugin the setup installs, its bridge and the engine's address beside it.
        (
            "Write",
            json!({"file_path": "/home/u/.hermes/plugins/withhuman/__init__.py", "content": ""}),
        ),
        (
            "Write",
            json!({"file_path": "/home/u/.hermes/plugins/withhuman/withhuman.json",
                   "content": "{\"server\": \"http://elsewhere\"}"}),
        ),
        // The profile configuration that enables it, where the desktop app keeps it on Windows.
        (
            "Edit",
            json!({"file_path": "C:\\Users\\u\\AppData\\Local\\hermes\\config.yaml",
                   "old_string": "    - withhuman\n", "new_string": ""}),
        ),
        (
            "Write",
            json!({"file_path": "/home/u/.hermes/config.yaml", "content": "plugins: {}"}),
        ),
        // Hermes runs commands in bash, Git Bash on Windows.
        (
            "Bash",
            json!({"command": "rm -rf ~/.hermes/plugins/withhuman"}),
        ),
        (
            "Bash",
            json!({"command": "sed -i '/withhuman/d' /home/u/.hermes/config.yaml"}),
        ),
        // Git Bash on Windows names the desktop app's profile this way.
        (
            "Bash",
            json!({"command": "rm -rf /c/Users/u/AppData/Local/hermes/plugins/withhuman"}),
        ),
        // Hermes' own CLI switches the plugin off without writing a file the rule would see.
        (
            "Bash",
            json!({"command": "hermes plugins disable withhuman && hermes gateway restart"}),
        ),
        (
            "Bash",
            json!({"command": "hermes -p work config set plugins.enabled '[]'"}),
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
fn leaves_the_rest_of_a_hermes_profile_alone() {
    for (tool_name, input) in [
        // Reading them changes nothing.
        (
            "Bash",
            json!({"command": "cat ~/.hermes/plugins/withhuman/plugin.yaml"}),
        ),
        // Hermes' CLI for anything but its plugins and their configuration.
        ("Bash", json!({"command": "hermes plugins list"})),
        (
            "Bash",
            json!({"command": "hermes config set model.default claude-haiku-4-5"}),
        ),
        // Hermes' memories, skills and a project's own config file are not safeguards.
        (
            "Write",
            json!({"file_path": "/home/u/.hermes/memories/notes.md", "content": "x"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/config.yaml", "content": "a: 1"}),
        ),
        // A project of the user's own that only shares the names.
        (
            "Write",
            json!({"file_path": "/proj/services/hermes/config.yaml", "content": "a: 1"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/src/plugins/withhuman_utils.py", "content": ""}),
        ),
    ] {
        assert_ne!(
            effect(&call_in("/proj", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
}
