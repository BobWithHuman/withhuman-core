//! What the checks make of Copilot calls, as the Collector translates them.
//!
//! An agent must not be able to switch off what supervises it. Copilot widens that surface:
//! it loads hooks from a repository's `.github/hooks`, from a user's own `.copilot/hooks`,
//! from `.github/copilot/settings.json` — **and from Claude Code's `.claude/settings.json`**,
//! so a Copilot session can switch off the hooks installed for Claude Code as easily as its
//! own. A safeguard call is denied on the rule alone, before anything is asked of a model,
//! which is what these tests pin.

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
fn knows_copilot_safeguards() {
    for (tool_name, input) in [
        // The repository's hooks file and the bridge the setup installs beside it, including
        // the engine's address the bridge reads from there.
        (
            "Write",
            json!({"file_path": "/proj/.github/hooks/withhuman-copilot.json", "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.github/hooks/withhuman-hook.py", "content": ""}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.github/hooks/server", "content": "http://elsewhere"}),
        ),
        // A user's own hook directory, which every repository's sessions run.
        (
            "MultiEdit",
            json!({"file_path": "/home/u/.copilot/hooks/withhuman-copilot.json", "edits": []}),
        ),
        // The settings that can hold a `hooks` key — Copilot's own, and Claude Code's, which
        // Copilot reads too.
        (
            "Write",
            json!({"file_path": "/proj/.github/copilot/settings.json", "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.claude/settings.json", "content": "{}"}),
        ),
        // The MCP servers the agent may call: the user's, and a workspace's.
        (
            "Write",
            json!({"file_path": "/home/u/.copilot/mcp-config.json", "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.mcp.json", "content": "{}"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.github/mcp.json", "content": "{}"}),
        ),
        // Windows file names ignore case.
        (
            "Write",
            json!({"file_path": "C:\\proj\\.GITHUB\\Hooks\\withhuman-copilot.json",
                   "content": "{}"}),
        ),
        // Switching the supervision off with a command rather than a file write.
        (
            "Bash",
            json!({"command": "rm -f /proj/.github/hooks/withhuman-hook.py"}),
        ),
        (
            "Bash",
            json!({"command": "echo '{}' > .github/hooks/withhuman-copilot.json"}),
        ),
        (
            "PowerShell",
            json!({"command": "Remove-Item .copilot\\hooks\\withhuman-copilot.json"}),
        ),
        // The patch form Copilot sends, once the translation has made calls of it.
        (
            "Bash",
            json!({"command": "rm -- /proj/.github/hooks/withhuman-copilot.json"}),
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
fn leaves_the_rest_of_a_repository_alone() {
    for (tool_name, input) in [
        // Reading them changes nothing.
        (
            "Bash",
            json!({"command": "cat .github/hooks/withhuman-copilot.json"}),
        ),
        // The rest of `.github` is the repository's own: workflows, templates and the
        // instructions the agent reads are judged as any other file change is.
        (
            "Write",
            json!({"file_path": "/proj/.github/workflows/ci.yml", "content": "on: push"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.github/copilot-instructions.md", "content": "be brief"}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/src/hooks/useThing.ts", "content": "export {}"}),
        ),
    ] {
        assert_ne!(
            effect(&call_in("/proj", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
}
