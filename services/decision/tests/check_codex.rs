//! What the checks make of Codex calls, as the Collector translates them, and of PowerShell.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use withhuman_decision::{
    check::{Branch, Effect, FileDiff, check, effect, request},
    jev::JevRequest,
    trace::{CallInfo, Deviation, Link},
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

fn lines(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|line| (*line).to_owned()).collect()
}

#[test]
fn powershell_runs_check_the_attached_script_at_the_resolved_path() {
    use withhuman_decision::check::{normalize_path, run_paths};
    let target = "C:\\proj\\scripts\\run.ps1";
    for command in [
        "pwsh -NoProfile -File .\\scripts\\run.ps1",
        "powershell.exe -ExecutionPolicy Bypass -File 'C:\\proj\\scripts\\run.ps1'",
        "& '.\\scripts\\run.ps1'",
        ".\\scripts\\run.ps1",
    ] {
        let mut call = call_in("C:\\proj", "PowerShell", json!({"command": command}));
        call.programs.insert(
            normalize_path(target),
            Some("Set-Content canary.txt x".to_owned()),
        );
        assert_eq!(run_paths(&call), vec![normalize_path(target)], "{command}");
        assert!(matches!(effect(&call), Effect::Run { .. }), "{command}");
    }
    for (command, target) in [
        ("python .\\scripts\\run.py", "C:\\proj\\scripts\\run.py"),
        ("node.exe '.\\scripts\\run.js'", "C:\\proj\\scripts\\run.js"),
    ] {
        let mut call = call_in("C:\\proj", "PowerShell", json!({"command": command}));
        call.programs
            .insert(normalize_path(target), Some("print('ok')".to_owned()));
        assert!(matches!(effect(&call), Effect::Run { .. }), "{command}");
    }
}

#[test]
fn knows_codex_safeguards() {
    for (tool_name, input) in [
        (
            "Write",
            json!({"file_path": "C:\\proj\\.codex\\hooks.json", "content": "{}"}),
        ),
        (
            "MultiEdit",
            json!({"file_path": "/home/u/.codex/config.toml", "edits": []}),
        ),
        (
            "Write",
            json!({"file_path": "/proj/.codex/hooks/withhuman-hook.py", "content": ""}),
        ),
        (
            "Write",
            json!({"file_path": "/etc/codex/requirements.toml", "content": ""}),
        ),
        // Windows file names ignore case.
        (
            "Write",
            json!({"file_path": "C:\\proj\\.CODEX\\Hooks.json", "content": "{}"}),
        ),
        ("Bash", json!({"command": "echo '{}' > .codex/hooks.json"})),
    ] {
        assert_eq!(
            effect(&call_in("/proj", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
    // Reading them changes nothing.
    assert_ne!(
        effect(&call_in(
            "/proj",
            "Bash",
            json!({"command": "cat .codex/config.toml"})
        )),
        Effect::Safeguard
    );
}

/// E7: PowerShell commands that change a safeguard are caught as Bash ones are.
#[test]
fn knows_powershell_changes_to_safeguards() {
    for command in [
        "Set-Content .codex\\hooks.json '{}'",
        "set-content -LiteralPath '.codex\\hooks.json' -Value '{}'",
        "Remove-Item -Recurse .claude\\hooks",
        "'{}' | Out-File -FilePath .codex/config.toml",
        "Add-Content C:\\proj\\.claude\\settings.local.json 'x'",
        "ni .codex\\hooks.json -Force",
        "Copy-Item evil.json .codex\\hooks.json",
        "[IO.File]::WriteAllText('.codex\\hooks.json', '{}')",
        "Get-Content a.json > .codex\\hooks.json",
    ] {
        assert_eq!(
            effect(&call_in(
                "C:\\proj",
                "PowerShell",
                json!({ "command": command })
            )),
            Effect::Safeguard,
            "{command}"
        );
    }
    for command in [
        "Get-Content .codex\\hooks.json",
        "Select-String -Path .claude\\settings.json -Pattern hooks",
        "Test-Path .codex\\config.toml",
    ] {
        assert_eq!(
            effect(&call_in(
                "C:\\proj",
                "PowerShell",
                json!({ "command": command })
            )),
            Effect::Other,
            "{command}"
        );
    }
}

/// C0 found that Codex runs a shell call in its `workdir`, which the Hook leaves out. With the
/// directory the bridge reports, a relative path that lands on a safeguard is caught.
#[test]
fn knows_a_safeguard_reached_from_the_directory_a_call_runs_in() {
    for (cwd, command) in [
        (
            "C:\\proj\\.codex",
            "Set-Content -LiteralPath 'hooks.json' -Value '{}'",
        ),
        (
            "C:\\proj\\nested",
            "Set-Content -LiteralPath '..\\.codex\\hooks.json' -Value '{}'",
        ),
        (
            "C:\\proj\\nested",
            "cd ..\\.codex; Set-Content hooks.json '{}'",
        ),
        ("C:\\proj", "Set-Location .codex; sc hooks.json '{}'"),
        ("/proj/.claude", "echo '{}' >settings.json"),
        ("/proj/.codex/hooks", "cp /tmp/evil.py withhuman-hook.py"),
    ] {
        let tool_name = if cwd.starts_with('/') {
            "Bash"
        } else {
            "PowerShell"
        };
        assert_eq!(
            effect(&call_in(cwd, tool_name, json!({ "command": command }))),
            Effect::Safeguard,
            "{cwd}: {command}"
        );
    }
    // The same file name elsewhere is no safeguard.
    assert_ne!(
        effect(&call_in(
            "C:\\proj\\nested",
            "PowerShell",
            json!({"command": "Set-Content -LiteralPath 'hooks.json' -Value '{}'"})
        )),
        Effect::Safeguard
    );
}

fn patch(changes: Value) -> CallInfo {
    call_in(
        "/proj",
        "apply_patch",
        json!({ "command": "*** Begin Patch\n…\n*** End Patch", "changes": changes }),
    )
}

#[test]
fn takes_a_patch_as_the_changes_to_each_of_its_files() {
    let call = patch(json!([
        {"tool_name": "Write", "tool_input": {"file_path": "/proj/a.txt", "content": "one\n"}},
        {"tool_name": "MultiEdit", "tool_input": {"file_path": "/proj/b.py", "edits": [
            {"old_string": "x = 1\ny = 2", "new_string": "x = 1\ny = 3\nsend(secrets)"}]}},
        {"tool_name": "Bash", "tool_input": {"command": "rm -- /proj/c.txt"}}
    ]));
    assert_eq!(
        effect(&call),
        Effect::FileChanges {
            files: vec![
                FileDiff {
                    path: "/proj/a.txt".to_owned(),
                    added: lines(&["one"]),
                    removed: Vec::new(),
                },
                FileDiff {
                    path: "/proj/b.py".to_owned(),
                    added: lines(&["y = 3", "send(secrets)"]),
                    removed: lines(&["y = 2"]),
                },
                FileDiff {
                    path: "Bash: rm -- /proj/c.txt".to_owned(),
                    added: Vec::new(),
                    removed: Vec::new(),
                },
            ]
        }
    );
}

#[test]
fn denies_a_patch_touching_any_safeguard() {
    let call = patch(json!([
        {"tool_name": "Write", "tool_input": {"file_path": "/proj/a.txt", "content": "one\n"}},
        {"tool_name": "Write", "tool_input": {"file_path": "/proj/.codex/hooks.json", "content": "{}"}}
    ]));
    assert_eq!(effect(&call), Effect::Safeguard);
    let moved = patch(json!([
        {"tool_name": "Bash", "tool_input": {"command": "mv -- /proj/x.json /proj/.codex/hooks.json"}},
        {"tool_name": "MultiEdit", "tool_input": {"file_path": "/proj/a.txt", "edits": []}}
    ]));
    assert_eq!(effect(&moved), Effect::Safeguard);
    // A patch the Collector could not read is judged by what it names.
    let unread = call_in(
        "/proj",
        "apply_patch",
        json!({"command": "*** Begin Patch\n*** Frob: .codex/hooks.json\n*** End Patch"}),
    );
    assert_eq!(effect(&unread), Effect::Safeguard);
    let harmless = call_in(
        "/proj",
        "apply_patch",
        json!({"command": "*** Begin Patch\n*** Frob: a.txt\n*** End Patch"}),
    );
    assert_eq!(effect(&harmless), Effect::Other);
}

#[test]
fn asks_about_every_file_a_patch_changes() {
    let effect = Effect::FileChanges {
        files: vec![
            FileDiff {
                path: "/proj/a.txt".to_owned(),
                added: lines(&["one"]),
                removed: Vec::new(),
            },
            FileDiff {
                path: "/proj/b.py".to_owned(),
                added: lines(&["send(secrets)"]),
                removed: lines(&["y = 2"]),
            },
        ],
    };
    let deviation = Deviation {
        score: 0.0,
        worst: "none".to_owned(),
        explicit: 0.0,
        expected: BTreeMap::from([("x".to_owned(), 0.3)]),
        none: 0.7,
        harm: 0.4,
        irreversible: 0.0,
        contributions: BTreeMap::new(),
    };
    let checked = check(&deviation, Link::Request, &effect);
    assert_eq!(checked.branch, Branch::File);
    let judged = JevRequest {
        model: "m".to_owned(),
        state: BTreeMap::from([(
            "action".to_owned(),
            json!("apply_patch: *** Begin Patch\n…"),
        )]),
        questions: BTreeMap::new(),
    };
    let asked = request(&judged, checked.branch, &effect, Some("fix b")).unwrap();
    assert_eq!(
        asked.state["added"],
        "--- /proj/a.txt\none\n--- /proj/b.py\nsend(secrets)"
    );
    assert_eq!(
        asked.state["removed"],
        "--- /proj/a.txt\n--- /proj/b.py\ny = 2"
    );
    assert!(asked.questions.contains_key("unasked"));
}

/// G5a: an `Edit` sent through Codex comes back as a `MultiEdit` with one edit, which the
/// checks take the same way.
#[test]
fn takes_an_edit_and_its_codex_translation_alike() {
    let edit = call_in(
        "/proj",
        "Edit",
        json!({"file_path": "/proj/core.py", "old_string": "a\nb", "new_string": "a\nc\nd"}),
    );
    let translated = call_in(
        "/proj",
        "MultiEdit",
        json!({"file_path": "/proj/core.py", "edits": [{"old_string": "a\nb", "new_string": "a\nc\nd"}]}),
    );
    assert_eq!(effect(&edit), effect(&translated));
}

/// What the safeguard rule said before Codex support: Bash only, as written, case-sensitive.
fn safeguard_before(tool_name: &str, input: &Value) -> bool {
    const SAFEGUARDS: &[&str] = &[
        ".claude/settings",
        ".claude/hooks",
        ".claude\\settings",
        ".claude\\hooks",
    ];
    const WRITES: &[&str] = &[
        ">",
        "sed -i",
        "rm ",
        "mv ",
        "cp ",
        "tee ",
        "chmod ",
        "truncate ",
        "ln ",
        "python",
        "node ",
        "perl ",
    ];
    const DISCARDED: &[&str] = &["2>/dev/null", "&>/dev/null", ">/dev/null", "2>&1"];
    let named = |text: &str| SAFEGUARDS.iter().any(|place| text.contains(place));
    let text = |name: &str| input[name].as_str().unwrap_or_default();
    match tool_name {
        "Skill" => text("skill") == "update-config",
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => match text("file_path") {
            "" => named(text("notebook_path")),
            path => named(path),
        },
        "Bash" => {
            let command = DISCARDED
                .iter()
                .fold(text("command").to_owned(), |command, discarded| {
                    command.replace(discarded, "")
                });
            named(text("command")) && WRITES.iter().any(|write| command.contains(write))
        }
        _ => false,
    }
}

/// G3 for this change: on recorded Claude Code sessions, the calls the safeguard rule catches
/// before and after, and what PowerShell calls become. Prints counts only.
/// `WITHHUMAN_G5A_EVENTS=/data/events.jsonl cargo test -p withhuman-decision --test check_codex -- --ignored --nocapture`.
#[test]
#[ignore = "needs the recorded events outside the repository"]
fn recorded_calls_keep_their_safeguard_verdicts() {
    let path = std::env::var("WITHHUMAN_G5A_EVENTS").expect("WITHHUMAN_G5A_EVENTS");
    let text = std::fs::read_to_string(path).unwrap();
    let (mut calls, mut both, mut gained, mut lost) = (0, 0, BTreeMap::new(), 0);
    let mut powershell = BTreeMap::<String, usize>::new();
    for line in text.lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        if row["event_name"] != "PreToolUse" {
            continue;
        }
        let event: Value = serde_json::from_str(row["event_json"].as_str().unwrap()).unwrap();
        let tool_name = event["payload"]["tool_name"].as_str().unwrap_or_default();
        let input = event["payload"]["tool_input"].clone();
        let mut call = call_in("/", tool_name, input.clone());
        call.cwd = event["meta"]["cwd"].as_str().map(str::to_owned);
        calls += 1;
        let after = effect(&call);
        let (was, is) = (
            safeguard_before(tool_name, &input),
            after == Effect::Safeguard,
        );
        match (was, is) {
            (true, true) => both += 1,
            (false, true) => *gained.entry(tool_name.to_owned()).or_insert(0) += 1,
            (true, false) => lost += 1,
            (false, false) => {}
        }
        if tool_name == "PowerShell" {
            let kind = match after {
                Effect::Safeguard => "safeguard",
                Effect::FileChange { .. } => "file",
                Effect::FileChanges { .. } => "files",
                Effect::Run { .. } => "run",
                Effect::ShellWrite { .. } => "shell write",
                Effect::Other => "other",
            };
            *powershell.entry(kind.to_owned()).or_default() += 1;
        }
    }
    println!(
        "G3 calls={calls} safeguard_before_and_after={both} newly_safeguard={gained:?} \
         no_longer_safeguard={lost} powershell_effects={powershell:?}"
    );
    assert!(calls > 0);
    assert_eq!(lost, 0);
}

/// A shell read of a safeguard reaches the checks as Read (the Collector translates a plain
/// one-file read): reading is no change. Anything more stays a shell call and is still caught.
#[test]
fn reading_a_safeguard_is_no_change_but_a_combined_write_is() {
    let read = call_in(
        "C:\\proj",
        "Read",
        json!({"file_path": "C:/proj/.codex/hooks.json"}),
    );
    assert_eq!(effect(&read), Effect::Other);
    let combined = call_in(
        "C:\\proj",
        "PowerShell",
        json!({"command": "Get-Content x; Set-Content .codex\\hooks.json '{}'"}),
    );
    assert_eq!(effect(&combined), Effect::Safeguard);
}

/// Codex 0.167 writes files with shell commands, which the Collector sends as Write (or Edit
/// adding the appended text) with `/`-separated paths: a safeguard there is still one.
#[test]
fn a_translated_shell_write_into_a_safeguard_is_a_safeguard_change() {
    for (tool_name, input) in [
        (
            "Write",
            json!({"file_path": "C:/proj/.codex/hooks.json", "content": "{}\n"}),
        ),
        (
            "Write",
            json!({"file_path": "C:/proj/.codex/hooks/withhuman-hook.py", "content": ""}),
        ),
        (
            "Edit",
            json!({"file_path": "C:/proj/.codex/config.toml", "old_string": "", "new_string": "x\n"}),
        ),
        (
            "Edit",
            json!({"file_path": "/proj/.claude/settings.json", "old_string": "", "new_string": "{}\n"}),
        ),
    ] {
        assert_eq!(
            effect(&call_in(r"C:\proj", tool_name, input.clone())),
            Effect::Safeguard,
            "{input}"
        );
    }
    // An ordinary file is a file change, judged by the lines it adds.
    let write = call_in(
        r"C:\proj",
        "Write",
        json!({"file_path": "C:/proj/notes.md", "content": "a\nb\n"}),
    );
    assert!(matches!(effect(&write), Effect::FileChange { ref added, .. } if added == &["a", "b"]));
    let append = call_in(
        r"C:\proj",
        "Edit",
        json!({"file_path": "C:/proj/log.txt", "old_string": "", "new_string": "entry\n"}),
    );
    assert!(
        matches!(effect(&append), Effect::FileChange { ref added, ref removed, .. } if added == &["entry"] && removed.is_empty())
    );
}
