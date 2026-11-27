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
    category::{Group, category},
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

/// What the rules make of OpenClaw's own tool names, pinned as it stands.
///
/// The Collector translates the tools with a Claude Code counterpart, and those are judged by
/// that tool's rules. The rest keep their own name and are placed by the words in it, which for
/// most of OpenClaw's names says nothing — `process` is not `execute`, `canvas` is not a verb at
/// all — so they land in [`Group::Unknown`] and are judged on whether they serve what the user
/// asked, with no rule for the kind of thing they do.
///
/// That is the state this pins, so a release that renames a tool or a change to the classifier
/// shows here. An operator who turns on more of OpenClaw's tools classifies them with
/// `WITHHUMAN_TOOL_CATEGORIES`, the table the decision service reads before judging a tool by
/// its name; nothing here needs changing for that.
///
/// Verified against OpenClaw 2026.11.7: of the names below, a session only ever reached `exec`,
/// `read`, `write`, `edit`, `ls`, `apply_patch`, `web_search`, `dispatch_action` and `process`
/// — the rest are behind plugins or capabilities a default setup does not enable. A model asked
/// for one of those (`plugins`, `openclaw`, `terminal`, `code_execution`, `secrets`) looked for
/// it, did not find it, and reached for the shell instead, where the safeguard rules above
/// already apply.
#[test]
fn openclaw_tool_names_the_rules_can_place() {
    for (name, expected) in [
        // Translated by the Collector, and judged by that tool's own rules.
        ("exec", Group::Execute),
        ("write", Group::Change),
        ("edit", Group::Change),
        ("apply_patch", Group::Change),
        ("read", Group::Read),
        ("web_search", Group::Read),
        ("x_search", Group::Read),
        ("view_image", Group::Read),
        // Placed by their own name, correctly.
        ("message", Group::Send),
        ("github_publish", Group::Send),
        ("conversations_send", Group::Send),
        ("sessions_send", Group::Send),
        ("sessions_create", Group::Change),
        ("image_generate", Group::Change),
        ("memory_search", Group::Read),
        ("skills_read", Group::Read),
        ("agents_list", Group::Read),
        ("show_widget", Group::Read),
    ] {
        assert_eq!(category(name).group, expected, "{name}");
    }
}

/// The names the words in them say nothing about. Each is judged on its purpose alone, which is
/// what `WITHHUMAN_TOOL_CATEGORIES` exists to improve on; the list is here so an operator
/// writing that table has it, and so a change to either side is visible.
#[test]
fn openclaw_tool_names_the_rules_cannot_place() {
    for name in [
        // Runs or operates something, and the name does not say so.
        "process",
        "terminal",
        "code_execution",
        "computer",
        "mobile_ui",
        "screen",
        "gateway",
        "nodes",
        // Changes what the agent is or may do.
        "plugins",
        "openclaw",
        "personal_instructions",
        "skill_workshop",
        "secrets",
        // Hands work to another agent.
        "subagents",
        "sessions_spawn",
        // Searches and reads whose names are not verbs.
        "fd",
        "ripgrep",
        "ls",
        "pdf",
        "transcripts",
        "sessions_history",
        "session_status",
        // Shows something on a screen, or waits.
        "canvas",
        "dashboard",
        "portal",
        "presence",
        "progress_card",
        "suggest_task",
        "dismiss_task",
        "theme",
        "tts",
        "agents_wait",
        "sessions_yield",
        "ask_user",
        "autoreview",
        "decision_evaluate",
        "conversations_turn",
        "github_identity_status",
        "sessions",
    ] {
        assert_eq!(
            category(name).group,
            Group::Unknown,
            "{name} is placed after all; the README says it is not"
        );
    }
}
