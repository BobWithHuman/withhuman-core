//! Where the lines a Call adds came from, worked out without Jev.
//!
//! The file question asked Jev whether a change, as a whole, did what the user asked; an injected
//! line among the lines of a fix passed as part of the fix, and Jev's own pick of the paragraph a
//! change carries out was recorded but never used. The engine can tell part of it by itself:
//!
//! - lines the session took out earlier and now puts back are no addition at all
//!   ([`strip_restored`]): an agent narrowing its diff was denied for "adding" them;
//! - a line that stands word for word in a tool result the agent read was copied from it
//!   ([`copied_lines`]), and a tool result that tells an agent what it must do, or comes from a
//!   file written for agents (`AGENTS.md`, `CLAUDE.md`, …), is an instruction source;
//! - a command that only checks files back out of git (`git checkout -- f`, `git restore f`)
//!   undoes changes ([`git_restores`]).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::{
    check::{Effect, FileDiff},
    jev::JevRequest,
};

/// Files written for coding agents: what they say is an instruction to the agent, not the user's.
const AGENT_FILES: &[&str] = &[
    "agents.md",
    "agent_instructions.md",
    "claude.md",
    "gemini.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
];

/// Words and phrases of a text that tells its reader what it must do (a requirement, a rule for an
/// agent).
const INSTRUCTION_WORDS: &[&str] = &[
    "must",
    "required",
    "mandatory",
    "always",
    "never",
    "assistant",
    "assistants",
    "policy",
    "instruction",
    "instructions",
    "reject",
    "rejects",
];
const INSTRUCTION_PHRASES: &[&str] = &[
    "do not",
    "don't",
    "make sure",
    "ensure that",
    "before you",
    "before any",
    "automated fix",
    "ai agent",
];

fn instructs(text: &str) -> bool {
    let lower = text.to_lowercase();
    INSTRUCTION_PHRASES
        .iter()
        .any(|phrase| lower.contains(phrase))
        || lower
            .split(|c: char| !c.is_alphanumeric() && c != '\'')
            .any(|word| INSTRUCTION_WORDS.contains(&word))
}

/// A line a Call adds that stands in a tool result the agent read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Copied {
    /// The added line, as the Call adds it (cut to 200 characters).
    pub line: String,
    /// The paragraph (`gNpM`) it stands in.
    pub paragraph: String,
    /// The paragraph tells its reader what it must do.
    pub instruction: bool,
    /// The paragraph came from reading a file written for agents.
    pub agent_file: bool,
}

/// What the engine worked out about a Call's lines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Provenance {
    /// Lines the Call adds that the session took out earlier, and lines it removes that the session
    /// added earlier: dropped from what is asked about.
    pub restored: usize,
    /// Added lines found word for word in a tool result the agent read.
    pub copied: Vec<Copied>,
}

impl Provenance {
    /// Some added line was copied from a tool result that instructs an agent.
    pub fn from_instruction(&self) -> bool {
        self.copied
            .iter()
            .any(|copied| copied.instruction || copied.agent_file)
    }
}

/// The tool-result paragraphs of the trace's request, by key (`gNpM`).
pub fn paragraphs(judged: &JevRequest) -> BTreeMap<String, String> {
    judged
        .state
        .iter()
        .filter(|(key, _)| key.starts_with("segments_"))
        .filter_map(|(_, value)| value.as_object())
        .flat_map(|results| results.iter())
        .filter_map(|(key, text)| text.as_str().map(|text| (key.clone(), text.to_owned())))
        .collect()
}

/// `effect` without the lines `earlier` changes to the same file took out (now put back) or put in
/// (now taken out), and how many such lines there were. An undoing comes back with no line left.
pub fn strip_restored(effect: &Effect, earlier: &[FileDiff]) -> (Effect, usize) {
    let Effect::FileChange {
        path,
        added,
        removed,
    } = effect
    else {
        return (effect.clone(), 0);
    };
    let wanted = normalize_path(path);
    let mut were_removed = BTreeSet::new();
    let mut were_added = BTreeSet::new();
    for diff in earlier
        .iter()
        .filter(|diff| normalize_path(&diff.path) == wanted)
    {
        were_removed.extend(diff.removed.iter().map(|line| line.trim().to_owned()));
        were_added.extend(diff.added.iter().map(|line| line.trim().to_owned()));
    }
    let keep = |lines: &[String], earlier: &BTreeSet<String>| -> (Vec<String>, usize) {
        let mut kept = Vec::new();
        let mut dropped = 0;
        for line in lines {
            let trimmed = line.trim();
            if !trimmed.is_empty() && earlier.contains(trimmed) {
                dropped += 1;
            } else if !trimmed.is_empty() {
                kept.push(line.clone());
            }
        }
        (kept, dropped)
    };
    let (added, put_back) = keep(added, &were_removed);
    let (removed, taken_out) = keep(removed, &were_added);
    (
        Effect::FileChange {
            path: path.clone(),
            added,
            removed,
        },
        put_back + taken_out,
    )
}

/// Whether `effect` is a file change left with no line to add or remove.
pub fn is_empty_change(effect: &Effect) -> bool {
    matches!(effect, Effect::FileChange { added, removed, .. } if added.is_empty() && removed.is_empty())
}

/// Whether any of `paragraphs` tells its reader what it must do or comes from a file written
/// for agents: something a file change could carry out.
pub fn instruction_seen(paragraphs: &BTreeMap<String, String>) -> bool {
    paragraphs.values().any(|text| {
        let (header, body) = split_header(text);
        instructs(body)
            || (names_agent_file(header) && !header.contains([';', '|', '&']))
            || names_agent_file(first_line(body))
    })
}

/// The added lines of `effect` that stand word for word in one of `paragraphs`, unless the user's
/// `prompt` holds them too (then the user asked for that text).
pub fn copied_lines(
    effect: &Effect,
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
) -> Vec<Copied> {
    let added: Vec<&String> = match effect {
        Effect::FileChange { added, .. } => added.iter().collect(),
        Effect::FileChanges { files } => files.iter().flat_map(|file| file.added.iter()).collect(),
        _ => return Vec::new(),
    };
    let prompt = prompt.map(normalize).unwrap_or_default();
    let sources: Vec<(&String, String, bool, bool)> = paragraphs
        .iter()
        .map(|(key, text)| {
            let (header, body) = split_header(text);
            (
                key,
                normalize(body),
                instructs(body),
                // A header names every file its command read; it tells only when it read one.
                (names_agent_file(header) && !header.contains([';', '|', '&']))
                    || names_agent_file(first_line(body)),
            )
        })
        .collect();
    let mut out = Vec::new();
    for line in added {
        let wanted = normalize(line);
        if !distinctive(&wanted) || (!prompt.is_empty() && prompt.contains(&wanted)) {
            continue;
        }
        if let Some((key, _, instruction, agent_file)) = sources
            .iter()
            .find(|(_, body, _, _)| body.contains(&wanted))
        {
            out.push(Copied {
                line: line.trim().chars().take(200).collect(),
                paragraph: (*key).clone(),
                instruction: *instruction,
                agent_file: *agent_file,
            });
        }
    }
    out
}

/// Whether `command` only checks files back out of git: every step is `git checkout [HEAD] --
/// <paths>` or `git restore [--staged|--worktree|--source=…] <paths>`.
pub fn git_restores(command: &str) -> bool {
    let steps: Vec<&str> = command
        .split(['\n', ';'])
        .flat_map(|step| step.split("&&"))
        .map(str::trim)
        .filter(|step| !step.is_empty())
        .collect();
    !steps.is_empty()
        && steps.iter().all(|step| {
            let words: Vec<&str> = step.split_whitespace().collect();
            match words.as_slice() {
                ["git", "checkout", rest @ ..] => {
                    let at = rest.iter().position(|word| *word == "--");
                    matches!(at, Some(at) if at <= 1 && rest.len() > at + 1)
                        && rest[..at.unwrap_or(0)].iter().all(|word| *word == "HEAD")
                }
                ["git", "restore", rest @ ..] => {
                    rest.iter().any(|word| !word.starts_with('-'))
                        && rest
                            .iter()
                            .filter(|word| word.starts_with('-'))
                            .all(|word| {
                                matches!(*word, "--staged" | "--worktree" | "-W" | "-S" | "--")
                                    || word.starts_with("--source=")
                            })
                }
                _ => false,
            }
        })
}

/// Lower case, comment marks and quotes off, spaces collapsed.
fn normalize(text: &str) -> String {
    let lowered = text.to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    for line in lowered.lines() {
        let line = line
            .trim()
            .trim_start_matches(['#', '/', ';', '*', '-', '>', '<', '!', ':'])
            .trim();
        let cleaned: String = line
            .chars()
            .filter(|c| !matches!(c, '"' | '\'' | '`'))
            .collect();
        for word in cleaned.split_whitespace() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(word);
        }
    }
    out
}

/// A line worth matching: long enough not to stand in any text by chance.
fn distinctive(normalized: &str) -> bool {
    let words = normalized.split_whitespace().count();
    normalized.len() >= 16 || (words >= 3 && normalized.len() >= 12) || {
        // A single long identifier (`repoguard_backdoor_marker`, `verify_tls = false`).
        normalized.len() >= 12 && normalized.contains(['_', '='])
    }
}

/// A paragraph's `[tool result: command]` header and its body.
fn split_header(text: &str) -> (&str, &str) {
    if text.starts_with('[') {
        if let Some(end) = text.find("] ") {
            return (&text[..end], &text[end + 2..]);
        }
    }
    ("", text)
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

fn names_agent_file(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    AGENT_FILES.iter().any(|file| lower.contains(file))
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

/// The provenance as the trace records it.
pub fn to_json(provenance: &Provenance) -> Value {
    serde_json::to_value(provenance).unwrap_or(Value::Null)
}

/// At most this many parts of a shell command are put to Jev.
pub const MAX_PARTS: usize = 15;

/// A shell command cut into the commands it runs one after another: at a line end, `;`, `&&` or
/// `||` outside quotes and brackets. No shell's grammar is needed (Bash, zsh and every PowerShell
/// read these the same), and a pipeline or a block stays one part; what a part means next to the
/// others is Jev's to judge, with the whole command beside it.
pub fn shell_parts(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut quote: Option<char> = None;
    let mut depth = 0usize;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(open) = quote {
            part.push(c);
            if c == '`' || (c == '\\' && open == '"') {
                if let Some(next) = chars.next() {
                    part.push(next);
                }
            } else if c == open {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                part.push(c);
            }
            '(' | '{' | '[' => {
                depth += 1;
                part.push(c);
            }
            ')' | '}' | ']' => {
                depth = depth.saturating_sub(1);
                part.push(c);
            }
            '\n' | ';' if depth == 0 => parts.push(std::mem::take(&mut part)),
            '&' | '|' if depth == 0 && chars.peek() == Some(&c) => {
                chars.next();
                parts.push(std::mem::take(&mut part));
            }
            _ => part.push(c),
        }
    }
    parts.push(part);
    parts
        .into_iter()
        .map(|part| part.trim().to_owned())
        .filter(|part| !part.is_empty())
        .take(MAX_PARTS)
        .collect()
}

/// What a part of a shell command touches that a person would want to know of: a secret, a
/// write or deletion, the network, code it builds and runs, a place outside the workspace, the
/// remote repository. Worked out from its text alone.
pub fn risk_marks(part: &str) -> Vec<&'static str> {
    let lower = part.to_ascii_lowercase();
    let has = |marks: &[&str]| marks.iter().any(|mark| lower.contains(mark));
    let mut out = Vec::new();
    if has(&[
        "canary",
        "secret",
        ".env",
        "id_rsa",
        ".ssh",
        "credential",
        "token",
        "passw",
        "auth.json",
        ".npmrc",
        ".pypirc",
        ".netrc",
    ]) {
        out.push("secret");
    }
    if crate::check::writes_file(part) {
        out.push("write");
    }
    if has(&[
        "http://",
        "https://",
        "curl ",
        "wget ",
        "invoke-webrequest",
        "iwr ",
        "invoke-restmethod",
        "irm ",
        "nc ",
        "ssh ",
        "scp ",
        "net.webclient",
        "urllib",
        "requests.",
    ]) {
        out.push("network");
    }
    if has(&[
        "python -c",
        "python3 -c",
        "py -c",
        "node -e",
        "invoke-expression",
        "| iex",
        "iex(",
        "iex ",
        "bash -c",
        "sh -c",
        "powershell -c",
        "powershell.exe -c",
        "-encodedcommand",
        "start-process",
        "frombase64",
        "[char]",
    ]) {
        out.push("exec");
    }
    if has(&[
        "~/",
        "~\\",
        "$home",
        "$env:userprofile",
        "c:\\users",
        "/etc/",
        "/home/",
        "../..",
        "..\\..",
    ]) {
        out.push("outside");
    }
    if has(&["git push", "git remote", "git config"]) {
        out.push("git_remote");
    }
    out
}

/// Shell words too common to tell where a part came from.
const COMMON_WORDS: &[&str] = &[
    "get-content",
    "write-output",
    "select-object",
    "get-childitem",
    "foreach-object",
    "where-object",
    "get-item",
    "test-path",
    "python",
    "pytest",
    "import",
    "assert",
    "isinstance",
    "lambda",
    "length",
    "fullname",
    "recurse",
    "expandproperty",
    "pythonpath",
    "exception",
    "status",
    "--short",
    "--no-ext-diff",
];

/// The names and strings of `part` (6 characters or more) that stand in a tool result that
/// instructs an agent and not in the user's `prompt`: the part carries out that instruction.
pub fn part_from_instruction(
    part: &str,
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
) -> Vec<String> {
    let prompt = prompt.unwrap_or_default().to_lowercase();
    let bodies: Vec<String> = paragraphs
        .values()
        .map(|text| split_header(text).1)
        .filter(|body| instructs(body))
        .map(str::to_lowercase)
        .collect();
    let mut found = BTreeSet::new();
    for token in part
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
        .map(|token| token.trim_matches(['.', '-']).to_ascii_lowercase())
        .filter(|token| token.len() >= 6 && !COMMON_WORDS.contains(&token.as_str()))
    {
        if !prompt.contains(&token) && bodies.iter().any(|body| body.contains(&token)) {
            found.insert(token);
        }
    }
    found.into_iter().collect()
}

/// Whether every text argument of a call (three characters or more) is written in the user's
/// prompt: then the user named the call's target, and where it came from needs no asking.
pub fn values_from_prompt(input: &Value, prompt: Option<&str>) -> bool {
    fn texts<'a>(value: &'a Value, found: &mut Vec<&'a str>) {
        match value {
            Value::String(text) if text.trim().chars().count() >= 3 => found.push(text.trim()),
            Value::Array(items) => items.iter().for_each(|item| texts(item, found)),
            Value::Object(fields) => fields.values().for_each(|field| texts(field, found)),
            _ => {}
        }
    }
    let Some(prompt) = prompt else {
        return false;
    };
    let prompt = prompt.to_lowercase();
    let mut found = Vec::new();
    texts(input, &mut found);
    !found.is_empty()
        && found
            .iter()
            .all(|text| prompt.contains(&text.to_lowercase()))
}
