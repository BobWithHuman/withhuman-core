//! The patch translation an agent's adapter reaches for, and the path keys every adapter must
//! agree on.
//!
//! Codex edits files with `apply_patch`, and it is not the only agent that does: OpenClaw sends
//! the same text under a field of its own name, so what was Codex's alone is here instead of
//! copied. The form is `*** Begin Patch` … `*** End Patch`. The engine's
//! rules are written against Claude Code's tools, so the patch is translated into the calls
//! making the same changes — a file added is a `Write`, a file updated is a `MultiEdit` with one
//! edit per hunk, a file deleted or moved is the command doing it — and a patch touching more
//! than one file becomes an `apply_patch` call listing them in `changes`.
//!
//! The path keys live here too: a file one Call read must be the file another Call wrote, which
//! only holds while every adapter keys paths the same way ([`file_key`]).
//!
//! Nothing here is either agent's own; what is Codex's stays in [`crate::codex`], and the names
//! its code and tests use are re-exported there.

use serde_json::{Value, json};

/// `word` quoted for a POSIX shell when it needs it.
pub fn quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,\\".contains(c));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// `path` resolved against `cwd`, with `.` and `..` steps taken out; separators follow `cwd`.
pub fn resolve(cwd: Option<&str>, path: &str) -> String {
    let absolute =
        path.starts_with('/') || path.starts_with('\\') || path.as_bytes().get(1) == Some(&b':');
    let Some(cwd) = cwd.filter(|_| !absolute) else {
        return path.to_owned();
    };
    let separator = if cwd.contains('\\') { '\\' } else { '/' };
    let (root, base) = if cwd.as_bytes().get(1) == Some(&b':') {
        (format!("{}{separator}", &cwd[..2]), &cwd[2..])
    } else if cwd.starts_with(['/', '\\']) {
        (separator.to_string(), cwd)
    } else {
        (String::new(), cwd)
    };
    let mut steps: Vec<&str> = Vec::new();
    for step in base.split(['/', '\\']).chain(path.split(['/', '\\'])) {
        match step {
            "" | "." => {}
            ".." => {
                steps.pop();
            }
            step => steps.push(step),
        }
    }
    format!("{root}{}", steps.join(&separator.to_string()))
}

/// File reads and patch writes must use the same lexically normalized path key, so a file
/// one Call read is the file another Call wrote.
pub fn file_key(cwd: Option<&str>, path: &str) -> String {
    let full = resolve(cwd, path).replace('\\', "/");
    let (prefix, rest) = if full.as_bytes().get(1) == Some(&b':') {
        (format!("{}/", full[..2].to_ascii_uppercase()), &full[2..])
    } else if full.starts_with("//") {
        ("//".to_owned(), full.as_str())
    } else if full.starts_with('/') {
        ("/".to_owned(), full.as_str())
    } else {
        (String::new(), full.as_str())
    };
    let mut steps = Vec::new();
    for step in rest.split('/') {
        match step {
            "" | "." => {}
            ".." => {
                steps.pop();
            }
            part => steps.push(part),
        }
    }
    format!("{prefix}{}", steps.join("/"))
}

/// One step of a patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchStep {
    Add {
        path: String,
        lines: Vec<String>,
    },
    Update {
        path: String,
        move_to: Option<String>,
        hunks: Vec<Hunk>,
    },
    Delete {
        path: String,
    },
}

/// A hunk as the lines it replaces and the lines it leaves, context included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hunk {
    pub old: Vec<String>,
    pub new: Vec<String>,
}

/// The steps of a patch (`*** Begin Patch` … `*** End Patch`); none when it does not
/// parse, so a malformed patch is never taken for less than it is.
pub fn parse_patch(patch: &str) -> Option<Vec<PatchStep>> {
    // Headers are matched without a trailing `\r`; added and removed lines keep theirs.
    let mut lines = patch.split('\n');
    // Codex accepts the patch wrapped in a here-document; only its body counts.
    lines
        .by_ref()
        .find(|line| line.trim() == "*** Begin Patch")?;
    let mut steps: Vec<PatchStep> = Vec::new();
    let mut ended = false;
    for line in lines {
        let header = line.trim_end();
        if header == "*** End Patch" {
            ended = true;
            break;
        }
        if let Some(path) = header.strip_prefix("*** Add File: ") {
            steps.push(PatchStep::Add {
                path: path.trim().to_owned(),
                lines: Vec::new(),
            });
        } else if let Some(path) = header.strip_prefix("*** Update File: ") {
            steps.push(PatchStep::Update {
                path: path.trim().to_owned(),
                move_to: None,
                hunks: Vec::new(),
            });
        } else if let Some(path) = header.strip_prefix("*** Delete File: ") {
            steps.push(PatchStep::Delete {
                path: path.trim().to_owned(),
            });
        } else if let Some(target) = header.strip_prefix("*** Move to: ") {
            match steps.last_mut() {
                Some(PatchStep::Update { move_to, hunks, .. })
                    if move_to.is_none() && hunks.is_empty() =>
                {
                    *move_to = Some(target.trim().to_owned());
                }
                _ => return None,
            }
        } else if header == "*** End of File" {
            if !matches!(steps.last(), Some(PatchStep::Update { .. })) {
                return None;
            }
        } else if header.starts_with("***") {
            return None;
        } else {
            match steps.last_mut()? {
                PatchStep::Add { lines, .. } => lines.push(line.strip_prefix('+')?.to_owned()),
                PatchStep::Update { hunks, .. } => {
                    if line.starts_with("@@") {
                        hunks.push(Hunk::default());
                        continue;
                    }
                    if hunks.is_empty() {
                        hunks.push(Hunk::default());
                    }
                    let hunk = hunks.last_mut()?;
                    let line = if line.trim_end_matches('\r').is_empty() {
                        ""
                    } else {
                        line
                    };
                    match line.chars().next() {
                        Some('+') => hunk.new.push(line[1..].to_owned()),
                        Some('-') => hunk.old.push(line[1..].to_owned()),
                        Some(' ') => {
                            hunk.old.push(line[1..].to_owned());
                            hunk.new.push(line[1..].to_owned());
                        }
                        // An empty context line whose leading space was trimmed.
                        None => {
                            hunk.old.push(String::new());
                            hunk.new.push(String::new());
                        }
                        Some(_) => return None,
                    }
                }
                PatchStep::Delete { .. } => return None,
            }
        }
    }
    (ended && !steps.is_empty()).then_some(steps)
}

/// The patch's text, wherever the call keeps it: Codex names the field `command` or
/// `patch`, OpenClaw `input`, and a call may send the text alone.
fn patch_text(input: &Value) -> Option<&str> {
    match input {
        Value::String(patch) => Some(patch),
        _ => ["command", "input", "patch"]
            .iter()
            .find_map(|field| input.get(*field).and_then(Value::as_str)),
    }
}

/// A patch as the Claude Code calls making the same changes: one when it makes one change,
/// else an `apply_patch` call listing them in `changes`. A patch that does not parse keeps its
/// name and text, judged as written.
pub fn translate(input: &Value, cwd: Option<&str>) -> (String, Value) {
    let Some(patch) = patch_text(input) else {
        return ("apply_patch".to_owned(), input.clone());
    };
    let Some(steps) = parse_patch(patch) else {
        return ("apply_patch".to_owned(), json!({ "command": patch }));
    };
    let mut changes: Vec<(String, Value)> = Vec::new();
    for step in steps {
        match step {
            PatchStep::Add { path, lines } => {
                let content = if lines.is_empty() {
                    String::new()
                } else {
                    format!("{}\n", lines.join("\n"))
                };
                changes.push((
                    "Write".to_owned(),
                    json!({ "file_path": file_key(cwd, &path), "content": content }),
                ));
            }
            PatchStep::Update {
                path,
                move_to,
                hunks,
            } => {
                let mut target = file_key(cwd, &path);
                if let Some(move_to) = move_to {
                    let destination = file_key(cwd, &move_to);
                    changes.push((
                        "Bash".to_owned(),
                        json!({ "command": format!("mv -- {} {}", quote(&target), quote(&destination)) }),
                    ));
                    target = destination;
                    if hunks.is_empty() {
                        continue;
                    }
                }
                let edits: Vec<Value> = hunks
                    .into_iter()
                    .map(|hunk| {
                        json!({ "old_string": hunk.old.join("\n"), "new_string": hunk.new.join("\n") })
                    })
                    .collect();
                changes.push((
                    "MultiEdit".to_owned(),
                    json!({ "file_path": target, "edits": edits }),
                ));
            }
            PatchStep::Delete { path } => changes.push((
                "Bash".to_owned(),
                json!({ "command": format!("rm -- {}", quote(&file_key(cwd, &path))) }),
            )),
        }
    }
    if let [(tool_name, tool_input)] = changes.as_slice() {
        return (tool_name.clone(), tool_input.clone());
    }
    let changes: Vec<Value> = changes
        .into_iter()
        .map(|(tool_name, tool_input)| json!({ "tool_name": tool_name, "tool_input": tool_input }))
        .collect();
    (
        "apply_patch".to_owned(),
        json!({ "command": patch, "changes": changes }),
    )
}
