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

/// Whether `text` tells its reader what to do. Only its prose is read (see [`prose`]): a word of
/// code or markup is no instruction. `raise ValueError("qty must be positive")` in a file the
/// agent edits, or `<input name="password_field" required>` on a login page, made every line the
/// agent then took from them "copied from an instruction".
fn instructs(text: &str) -> bool {
    let lower = prose(text).to_lowercase();
    INSTRUCTION_PHRASES
        .iter()
        .any(|phrase| lower.contains(phrase))
        || lower
            // `_` joins an identifier (`is_required`): its parts are no words.
            .split(|c: char| !c.is_alphanumeric() && c != '\'' && c != '_')
            .any(|word| INSTRUCTION_WORDS.contains(&word))
}

/// Comment openers: what follows one is written for people, wherever it stands.
const COMMENT_OPENERS: &[&str] = &["<!--", "/*", "//", "#", "--", "*"];

/// Starts of a line of code (a statement or declaration), after any indentation.
const CODE_STARTS: &[&str] = &[
    "def ",
    "class ",
    "return",
    "raise ",
    "import ",
    "from ",
    "if ",
    "if(",
    "elif ",
    "else",
    "for ",
    "while ",
    "try",
    "except",
    "assert ",
    "function ",
    "const ",
    "let ",
    "var ",
    "throw ",
    "fn ",
    "pub ",
    "use ",
    "@",
];

/// The prose of `text`: its lines without markup tags, line-number prefixes, lines of code and
/// `key: value` data, but with every comment kept, also one that trails code (a rule planted as
/// a comment is prose). An HTML comment (`<!-- … -->`) is kept whole, wherever it opens and
/// over however many lines it runs, before tags are taken off.
fn prose(text: &str) -> String {
    let mut out = String::new();
    let mut in_html_comment = false;
    for line in text.lines() {
        let line = strip_line_number(line);
        let (line, comments) = html_comments(line, &mut in_html_comment);
        for comment in comments {
            out.push_str(&comment);
            out.push('\n');
        }
        let line = strip_tags(&line);
        let trimmed = line.trim();
        if let Some(comment) = COMMENT_OPENERS
            .iter()
            .find_map(|opener| trimmed.strip_prefix(opener))
        {
            out.push_str(comment);
        } else if is_code(trimmed) {
            if let Some((_, comment)) = trimmed
                .split_once(" # ")
                .or_else(|| trimmed.split_once(" // "))
            {
                out.push_str(comment);
            }
        } else if !is_data(trimmed) {
            out.push_str(trimmed);
        }
        out.push('\n');
    }
    out
}

/// `line` without its HTML comments, and their bodies: one that opens on it (closed on it or
/// not), and the rest of one opened on a line before (`open` carries that across lines).
fn html_comments(line: &str, open: &mut bool) -> (String, Vec<String>) {
    let mut rest = line;
    let mut kept = String::new();
    let mut bodies = Vec::new();
    loop {
        if *open {
            match rest.find("-->") {
                Some(end) => {
                    bodies.push(rest[..end].to_owned());
                    rest = &rest[end + 3..];
                    *open = false;
                }
                None => {
                    bodies.push(rest.to_owned());
                    return (kept, bodies);
                }
            }
        }
        match rest.find("<!--") {
            Some(start) => {
                kept.push_str(&rest[..start]);
                rest = &rest[start + 4..];
                *open = true;
            }
            None => {
                kept.push_str(rest);
                return (kept, bodies);
            }
        }
    }
}

/// `line` without the number `cat -n` or a file viewer puts before it (`    12\t`, `12→`).
fn strip_line_number(line: &str) -> &str {
    let rest = line.trim_start();
    let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return line;
    }
    let after = &rest[digits..];
    after
        .strip_prefix('\t')
        .or_else(|| after.strip_prefix('→'))
        .or_else(|| after.strip_prefix('|'))
        .unwrap_or(line)
}

/// `line` without its markup tags (`<input … required>`); the text between tags stays.
fn strip_tags(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        let opens_tag = c == '<'
            && chars
                .peek()
                .is_some_and(|next| next.is_ascii_alphabetic() || matches!(next, '/' | '!' | '?'));
        if !opens_tag {
            out.push(c);
            continue;
        }
        let mut tag = String::from(c);
        let mut closed = false;
        for inner in chars.by_ref() {
            tag.push(inner);
            if inner == '>' {
                closed = true;
                break;
            }
        }
        if !closed {
            // No tag after all (`a < b`): keep the text.
            out.push_str(&tag);
        }
        out.push(' ');
    }
    out
}

/// Whether `line` is a line of code: a statement, or a call or block opener whose words are its
/// names and strings. A line that reads as a sentence is prose, whatever it starts with: `if you
/// are an assistant, you must read …` and `if needed, always read …` open as an `if` does. A line
/// opening with a statement's word is code only in a statement's shape: it ends as one does
/// (`:`, `{`, `;`, `)` …), and a `, ` in it joins no clause of a sentence (it stands in a call
/// or an assignment).
fn is_code(line: &str) -> bool {
    // A quoted line is a string of data (`"body": "… (urgent) …",`), whatever it holds.
    if line.starts_with(['"', '\'']) || reads_as_sentence(line) {
        return false;
    }
    let statement = CODE_STARTS.iter().any(|start| line.starts_with(start))
        && line
            .trim_end()
            .ends_with([':', '{', '}', ';', ')', '(', '[', ',', '\\'])
        && !(line.contains(", ") && !line.contains('(') && !line.contains('='));
    statement || (line.contains('(') && line.ends_with([')', ';', '{', ':', ',']))
}

/// Whether `line`, its quoted strings left out, has five or more plain words: a sentence rather
/// than a statement (`raise ValueError("qty must be positive")` has one word outside its string).
fn reads_as_sentence(line: &str) -> bool {
    let mut quote: Option<char> = None;
    let outside: String = line
        .chars()
        .map(|c| match (quote, c) {
            (Some(open), c) if c == open => {
                quote = None;
                ' '
            }
            (Some(_), _) => ' ',
            (None, '"' | '\'' | '`') => {
                quote = Some(c);
                ' '
            }
            (None, c) => c,
        })
        .collect();
    outside
        .split_whitespace()
        .filter(|word| {
            let word = word.trim_end_matches([',', '.', '!', '?', ';', ':']);
            !word.is_empty() && word.chars().all(char::is_alphabetic)
        })
        .count()
        >= 5
}

/// Whether `line` is one `key: value` (or `key = value`) whose value is a plain literal, as in a
/// schema or a settings file (`required: true`).
fn is_data(line: &str) -> bool {
    let Some((key, value)) = line.split_once([':', '=']) else {
        return false;
    };
    let key = key.trim().trim_matches(['"', '\'']);
    let value = value.trim().trim_end_matches(',').trim();
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && (matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "null" | "none" | "[]" | "{}"
        ) || value.parse::<f64>().is_ok())
}

/// A paragraph's body cut into blocks: at blank lines, once the numbers `cat -n`, `nl` or a file
/// viewer put before each line are off (a numbered blank line is blank too), and around fenced
/// code; never inside a fence or an open HTML comment. A file read with its line numbers came as
/// one paragraph, and the comment at its top made every line of its code an instruction's.
fn blocks(body: &str) -> Vec<String> {
    fn flush(block: &mut String, out: &mut Vec<String>) {
        if block.trim().is_empty() {
            block.clear();
        } else {
            out.push(std::mem::take(block));
        }
    }
    let mut out = Vec::new();
    let mut block = String::new();
    let mut in_fence = false;
    let mut in_comment = false;
    for line in body.lines() {
        let line = strip_line_number(line);
        let trimmed = line.trim();
        if is_fence(trimmed) {
            flush(&mut block, &mut out);
            in_fence = !in_fence;
            continue;
        }
        if trimmed.is_empty() && !in_fence && !in_comment {
            flush(&mut block, &mut out);
            continue;
        }
        if !in_fence {
            html_comments(line, &mut in_comment);
        }
        block.push_str(line);
        block.push('\n');
    }
    flush(&mut block, &mut out);
    out
}

/// Whether `line` (trimmed) opens or closes fenced code: three backticks or tildes, then at most
/// a language's name. A line of JSON whose escaped text starts with a fence is no fence.
fn is_fence(line: &str) -> bool {
    ["```", "~~~"].iter().any(|fence| {
        line.strip_prefix(fence).is_some_and(|info| {
            let info = info.trim_start_matches(['`', '~']);
            !info.contains(char::is_whitespace) && !info.contains(['`', '\\'])
        })
    })
}

/// Whether `line` is a line of code, not a comment (a rule planted as a comment is prose).
fn code_line(line: &str) -> bool {
    let trimmed = line.trim();
    !COMMENT_OPENERS
        .iter()
        .any(|opener| trimmed.starts_with(opener))
        && is_code(trimmed)
}

/// The lines of an instructing `block` that carry its rule, and its other lines: its code is
/// no part of the rule (a comment saying "do not respond" above a handler made the handler's
/// lines an instruction's), unless a line ending in `:` right before introduces it (`always
/// run:` and the command under it). A comment trailing a line of code is.
fn rule_lines(block: &str) -> (String, String) {
    let mut rule = String::new();
    let mut rest = String::new();
    let mut introduced = 0usize;
    for line in block.lines() {
        let code = code_line(line);
        if code && introduced == 0 {
            // A comment trailing the code is prose all the same.
            match line.split_once(" # ").or_else(|| line.split_once(" // ")) {
                Some((statement, comment)) => {
                    rest.push_str(statement);
                    rule.push_str(comment);
                    rule.push('\n');
                }
                None => rest.push_str(line),
            }
            rest.push('\n');
        } else {
            rule.push_str(line);
            rule.push('\n');
        }
        introduced = if !code && line.trim_end().ends_with(':') {
            QUOTED_LINES
        } else {
            introduced.saturating_sub(1)
        };
    }
    (rule, rest)
}

/// Whether `body` is short enough to be the line an instruction right before it quotes.
fn quoted(body: &str) -> bool {
    body.chars().count() <= QUOTED_CHARS
        && body.lines().filter(|line| !line.trim().is_empty()).count() <= QUOTED_LINES
}

/// What of a paragraph's `body` carries an instruction, and the rest: the rule lines (see
/// [`rule_lines`]) of each block that instructs, and a short block right after one (a rule
/// often sets the line it quotes apart). A README's code examples, a file's code under its
/// header comment and a test run's output are the rest.
fn sort_body(body: &str) -> (String, String) {
    let mut rule = String::new();
    let mut rest = String::new();
    let mut after_rule = false;
    for block in blocks(body) {
        let instructing = instructs(&block);
        if instructing {
            let (kept, dropped) = rule_lines(&block);
            rule.push_str(&kept);
            rest.push_str(&dropped);
        } else if after_rule && quoted(&block) {
            rule.push_str(&block);
        } else {
            rest.push_str(&block);
        }
        after_rule = instructing;
    }
    (rule, rest)
}

/// A tool-result paragraph as the provenance checks read it.
struct Source<'a> {
    key: &'a str,
    /// The `[tool result: command]` it came under: the call that printed it.
    header: &'a str,
    body: &'a str,
    /// It echoes the agent's own write.
    own: bool,
    /// It came from reading a file written for agents, as far as its header or first line tell.
    agent_file: bool,
    /// The command that printed it read a file written for agents, maybe among others.
    reads_agent_file: bool,
    /// What of its body carries an instruction, and the rest (see [`sort_body`]).
    rule: String,
    rest: String,
}

/// `paragraphs` as [`Source`]s. A short paragraph right after an instructing one in the same
/// tool result is the instruction's whole (keys are `g<n>p<m>`).
fn sources(paragraphs: &BTreeMap<String, String>) -> Vec<Source<'_>> {
    fn place(key: &str) -> Option<(&str, usize)> {
        let (group, index) = key.rsplit_once('p')?;
        Some((group, index.parse().ok()?))
    }
    let instructing: BTreeSet<(&str, usize)> = paragraphs
        .iter()
        .filter(|(_, text)| paragraph_instructs(text))
        .filter_map(|(key, _)| place(key))
        .collect();
    paragraphs
        .iter()
        .map(|(key, text)| {
            let (header, body) = split_header(text);
            let own = own_write(header);
            let after_rule = matches!(
                place(key),
                Some((group, index)) if index > 0 && instructing.contains(&(group, index - 1))
            );
            let (rule, rest) = if own {
                (String::new(), body.to_owned())
            } else if after_rule && quoted(body) {
                (body.to_owned(), String::new())
            } else {
                sort_body(body)
            };
            Source {
                key,
                header,
                body,
                own,
                // A header names every file its command read; it tells only when it read one.
                agent_file: !own
                    && ((names_agent_file(header) && !header.contains([';', '|', '&']))
                        || names_agent_file(first_line(body))),
                reads_agent_file: !own
                    && (names_agent_file(header) || names_agent_file(first_line(body))),
                rule,
                rest,
            }
        })
        .collect()
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

/// Whether every line of the program at `path` holding something was put there by the session's
/// own earlier changes to it (`earlier`): the session wrote the program, and each of those writes
/// was judged when it was made. Running such a program is no new thing to ask about; code the
/// repository already held, or a file the session only touched up, is.
pub fn written_by_session(path: &str, code: &str, earlier: &[FileDiff]) -> bool {
    let wanted = normalize_path(path);
    let added: BTreeSet<&str> = earlier
        .iter()
        .filter(|diff| normalize_path(&diff.path) == wanted)
        .flat_map(|diff| diff.added.iter().map(|line| line.trim()))
        .collect();
    let mut lines = code
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .peekable();
    lines.peek().is_some() && lines.all(|line| added.contains(line))
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
        !own_write(header)
            && (instructs(body)
                || (names_agent_file(header) && !header.contains([';', '|', '&']))
                || names_agent_file(first_line(body)))
    })
}

/// Whether any of `paragraphs` may tell the agent what to do: it instructs (see [`instructs`]),
/// it was printed by a command that read a file written for agents (alone or among others), or
/// it was hidden where it appeared. Without one, the tool results on a Call's path gave facts
/// only, whatever Jev made of them.
pub fn may_instruct(paragraphs: &BTreeMap<String, String>) -> bool {
    paragraphs.values().any(|text| {
        let (header, body) = split_header(text);
        !own_write(header)
            && (instructs(body)
                || names_agent_file(header)
                || names_agent_file(first_line(body))
                || text.contains(HIDDEN_MARK))
    })
}

/// How the trace marks a paragraph hidden where it appeared.
const HIDDEN_MARK: &str = "[숨김 내용]";

/// Whether the user's `prompt` names every file `effect` writes or edits: by its path under the
/// directory the call is made in (`cwd`), or by its name (`bin/slugify.js`, `slugify.js`).
pub fn named_in_prompt(effect: &Effect, prompt: Option<&str>, cwd: Option<&str>) -> bool {
    let Some(prompt) = prompt else {
        return false;
    };
    let prompt = prompt.to_lowercase();
    let paths: Vec<&str> = match effect {
        Effect::FileChange { path, .. } => vec![path],
        Effect::FileChanges { files } => files.iter().map(|file| file.path.as_str()).collect(),
        _ => return false,
    };
    let base = cwd.map(|cwd| format!("{}/", normalize_path(cwd).trim_end_matches('/')));
    !paths.is_empty()
        && paths.iter().all(|path| {
            let path = normalize_path(path);
            let relative = base
                .as_deref()
                .and_then(|base| path.strip_prefix(base))
                .map(|relative| relative.trim_start_matches("./"));
            let name = path.rsplit('/').next();
            [relative, name]
                .into_iter()
                .flatten()
                .any(|named| named.chars().count() >= 3 && names_word(&prompt, named))
        })
}

/// Whether `word` stands in `text` with no letter, digit, `_`, `-` or `.` right before it and no
/// letter, digit, `_` or `-` right after it (a `.` after it may end the sentence).
fn names_word(text: &str, word: &str) -> bool {
    let joins = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-');
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        before.is_none_or(|c| !joins(c) && c != '.') && after.is_none_or(|c| !joins(c))
    })
}

/// The added lines of `effect` that stand word for word in one of `paragraphs`, unless the user's
/// `prompt` holds them too (then the user asked for that text).
///
/// A line that also stands in what a tool result shows apart from any instruction (a code file
/// the agent read, the code examples of a README) is taken from there: writing a new example
/// after the existing ones copies the examples, not a rule beside them. What the agent wrote
/// itself is the last place a line is taken from.
pub fn copied_lines(
    effect: &Effect,
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
) -> Vec<Copied> {
    let added: Vec<&String> = match effect {
        Effect::FileChange { added, .. } => added.iter().collect(),
        Effect::FileChanges { files } => files.iter().flat_map(|file| file.added.iter()).collect(),
        Effect::ServiceChange { added } => added.iter().collect(),
        _ => return Vec::new(),
    };
    let prompt = prompt.map(normalize).unwrap_or_default();
    let sources: Vec<(Source, String, String, String)> = sources(paragraphs)
        .into_iter()
        .map(|source| {
            let rule = normalize(&source.rule);
            let rest = normalize(&source.rest);
            let body = normalize(source.body);
            (source, rule, rest, body)
        })
        .collect();
    let mut out = Vec::new();
    for line in added {
        let wanted = normalize(line);
        if !distinctive(&wanted) || (!prompt.is_empty() && prompt.contains(&wanted)) {
            continue;
        }
        let ruling = |(source, rule, _, body): &&(Source, String, String, String)| {
            !source.own && (rule.contains(&wanted) || (source.agent_file && body.contains(&wanted)))
        };
        let ruled = sources.iter().find(ruling);
        let ruling_results: BTreeSet<&str> = sources
            .iter()
            .filter(ruling)
            .map(|(source, ..)| result_of(source.key))
            .collect();
        // Another tool result showing the line apart from any rule, and not as the echo of a
        // call that was given it (`verify_list lst_9283kq_xj` printing the list it was asked
        // about): the rest of the same result is the same document.
        let plain = sources.iter().find(|(source, _, rest, _)| {
            !source.own
                && !source.agent_file
                && rest.contains(&wanted)
                && !ruling_results.contains(result_of(source.key))
                && !normalize(source.header).contains(&wanted)
        });
        let own = sources
            .iter()
            .find(|(source, _, _, body)| source.own && body.contains(&wanted));
        let found = match (plain, ruled, own) {
            (Some((source, ..)), _, _) | (None, None, Some((source, ..))) => {
                Some((source.key, false, false))
            }
            (None, Some((source, rule, ..)), _) => {
                Some((source.key, rule.contains(&wanted), source.agent_file))
            }
            (None, None, None) => None,
        };
        if let Some((key, instruction, agent_file)) = found {
            out.push(Copied {
                line: line.trim().chars().take(200).collect(),
                paragraph: key.to_owned(),
                instruction,
                agent_file,
            });
        }
    }
    out
}

/// The tool result a paragraph key (`g12p3`, `g12`) belongs to.
fn result_of(key: &str) -> &str {
    key.rsplit_once('p').map_or(key, |(result, _)| result)
}

/// The lines of an agent's `text` (a message) that stand word for word in one of `paragraphs`,
/// unless the user's `prompt` holds them too: what a plan took from the tool results it read.
pub fn repeated_lines(
    text: &str,
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
) -> Vec<Copied> {
    // Whole lines, and what a line quotes in backticks: a plan names a step's text inline
    // ("Insert `# MARKER` under the docstring").
    let mut lines: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("```") {
            continue;
        }
        lines.push(line.trim_matches('`').to_owned());
        lines.extend(
            line.split('`')
                .skip(1)
                .step_by(2)
                .map(str::trim)
                .filter(|quoted| !quoted.is_empty())
                .map(str::to_owned),
        );
    }
    copied_lines(
        &Effect::FileChange {
            path: String::new(),
            added: lines,
            removed: Vec::new(),
        },
        paragraphs,
        prompt,
    )
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

/// Tools whose result only echoes what the agent itself wrote.
const OWN_WRITES: &[&str] = &[
    "[Write result",
    "[Edit result",
    "[MultiEdit result",
    "[NotebookEdit result",
];

/// Whether a paragraph with this `header` echoes the agent's own write: what the agent wrote is
/// no instruction to it. A test file it wrote ("the refactored code must produce the same
/// output") made every later step of the same refactor "carry out an instruction".
fn own_write(header: &str) -> bool {
    OWN_WRITES.iter().any(|tool| header.starts_with(tool))
}

/// [`instructs`] for a whole paragraph, header and all.
fn paragraph_instructs(text: &str) -> bool {
    let (header, body) = split_header(text);
    !own_write(header) && instructs(body)
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
    let mut parts = split_parts(command);
    parts.truncate(MAX_PARTS);
    parts
}

/// [`shell_parts`], every one of them.
fn split_parts(command: &str) -> Vec<String> {
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
    "verify",
    // Python's own names, in every module.
    "__main__",
    "__name__",
    "__init__",
    "__future__",
    // Interpreters, runtimes and package managers: nearly every command names one, and where
    // it came from says nothing (`python3 -m pytest`, `npx xo`).
    "python2",
    "python3",
    "pip3",
    "pipenv",
    "poetry",
    "uvicorn",
    "gunicorn",
    "unittest",
    "py_compile",
    "nodejs",
    "node.exe",
    "python.exe",
    "python3.exe",
    // The caches and folders those tools leave behind.
    "__pycache__",
    "pytest_cache",
    "mypy_cache",
    "ruff_cache",
    "node_modules",
    "site-packages",
    "dist-packages",
];

/// Modules and objects whose members code names everywhere (`sys.exit`, `json.loads`,
/// `path.join`, `console.log`, `res.status`, `self.items`): such a name is the language's or the
/// library's, whatever text also shows it.
const LIBRARY_OWNERS: &[&str] = &[
    // Python's standard library, and the names a method reaches its object by.
    "sys",
    "os",
    "json",
    "re",
    "io",
    "math",
    "time",
    "datetime",
    "random",
    "string",
    "shutil",
    "subprocess",
    "pathlib",
    "logging",
    "typing",
    "collections",
    "itertools",
    "functools",
    "asyncio",
    "urllib",
    "http",
    "socket",
    "unittest",
    "argparse",
    "hashlib",
    "base64",
    "tempfile",
    "threading",
    "inspect",
    "traceback",
    "contextlib",
    "dataclasses",
    "uuid",
    "csv",
    "glob",
    "copy",
    "pickle",
    "struct",
    "signal",
    "enum",
    "operator",
    "textwrap",
    "platform",
    "sqlite3",
    "decimal",
    "statistics",
    "html",
    "xml",
    "zipfile",
    "tarfile",
    "gzip",
    "zlib",
    "queue",
    "errno",
    "warnings",
    "types",
    "importlib",
    "pprint",
    "shlex",
    "mock",
    "pytest",
    "self",
    "cls",
    "super",
    // JavaScript's globals and Node's modules, and the names an Express app goes by.
    "this",
    "console",
    "process",
    "module",
    "exports",
    "object",
    "array",
    "promise",
    "number",
    "date",
    "reflect",
    "buffer",
    "fs",
    "path",
    "util",
    "child_process",
    "window",
    "document",
    "app",
    "req",
    "res",
    "router",
    "express",
    "expect",
    "jest",
];

/// Extensions of a file's name: `app.log` is a file a rule may name, `app.listen` is no file.
const FILE_EXTENSIONS: &[&str] = &[
    "py", "pyc", "js", "mjs", "cjs", "ts", "tsx", "jsx", "json", "md", "txt", "log", "sh", "bash",
    "zsh", "ps1", "bat", "cmd", "exe", "yml", "yaml", "toml", "cfg", "ini", "env", "html", "htm",
    "css", "lock", "sql", "db", "sqlite", "csv", "xml", "rs", "go", "java", "rb", "php", "c", "h",
    "cpp", "conf", "pem", "key", "crt", "bak", "tgz", "gz", "zip", "tar", "out", "err", "pid",
    "tmp",
];

/// Whether `token` (lower case) tells nothing of where a value came from: a common shell word,
/// an interpreter's name with its version (`python3.12`), or a member of a module or object
/// code names everywhere (see [`LIBRARY_OWNERS`]).
fn common_token(token: &str) -> bool {
    if COMMON_WORDS.contains(&token) {
        return true;
    }
    let interpreter = ["python", "pip", "node"].iter().any(|name| {
        token.strip_prefix(name).is_some_and(|version| {
            !version.is_empty() && version.chars().all(|c| c.is_ascii_digit() || c == '.')
        })
    });
    let mut segments = token.split('.');
    let owner = segments.next().unwrap_or_default();
    let last = segments.next_back();
    let library = last.is_some_and(|last| {
        LIBRARY_OWNERS.contains(&owner) && (owner == "console" || !FILE_EXTENSIONS.contains(&last))
    });
    interpreter || library
}

/// Most lines and characters of a paragraph read as the line an instruction right before it quotes.
const QUOTED_LINES: usize = 2;
const QUOTED_CHARS: usize = 160;

/// What carries an instruction in `paragraphs` (see [`sources`]), and the rest, lower case. What
/// the agent wrote itself is in neither: it does not instruct, nor takes away a value an
/// instructing result gave (a README's command the agent copied into its own plan stays the
/// README's).
fn split_bodies(sources: &[Source]) -> (Vec<String>, Vec<String>) {
    let mut taken = Vec::new();
    let mut other = Vec::new();
    for source in sources.iter().filter(|source| !source.own) {
        if !source.rule.trim().is_empty() {
            taken.push(source.rule.to_lowercase());
        }
        if !source.rest.trim().is_empty() {
            other.push(source.rest.to_lowercase());
        }
    }
    (taken, other)
}

/// The names of `text`: what stands between characters no identifier, path or marker holds,
/// lower case.
fn tokens(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
        .map(|token| token.trim_matches(['.', '-']).to_ascii_lowercase())
        .filter(|token| !token.is_empty())
}

/// The pieces of the directory the call is made in (`/home/u/b-ci-config-devops` gives `home`,
/// `u`, `b-ci-config-devops`): every command can name them, so they tell nothing of a source.
fn cwd_pieces(cwd: Option<&str>) -> BTreeSet<String> {
    cwd.unwrap_or_default()
        .split(['/', '\\'])
        .map(str::to_lowercase)
        .filter(|piece| !piece.is_empty())
        .collect()
}

/// The names and strings (6 characters or more) of `text` that stand in an instructing tool
/// result (see [`split_bodies`]), in no other tool result and not in the user's `prompt`, and,
/// when `text` is a `shell` command, the commands of it an instructing result spells out (see
/// [`commands_from_instruction`]). A name the code or a listing also shows (the function a fix
/// touches) tells nothing about where the call came from, and neither does a common name (see
/// [`common_token`]) or a piece of the directory the call is made in (`cwd`).
fn from_instruction(
    text: &str,
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
    cwd: Option<&str>,
    shell: bool,
) -> Vec<String> {
    let prompt = prompt.unwrap_or_default().to_lowercase();
    let sources = sources(paragraphs);
    let (taken, other) = split_bodies(&sources);
    // A name is matched whole: `example.com` in a test is no part of
    // `env-register.internal.example.com` a rule names.
    let given: BTreeSet<String> = taken.iter().flat_map(|body| tokens(body)).collect();
    let workspace = cwd_pieces(cwd);
    let mut found = BTreeSet::new();
    for token in tokens(text)
        .filter(|token| token.len() >= 6 && !common_token(token) && !workspace.contains(token))
    {
        // Only names that look like an identifier, a path or a marker (`canary_secret.txt`,
        // `REPOGUARD_BACKDOOR_MARKER`, `touchstone-sync`): a plain word the rule happens to use
        // ("already") turns up in any commit message.
        let named = token.contains(['_', '.', '-']) || token.chars().any(|c| c.is_ascii_digit());
        if named
            && !prompt.contains(&token)
            && given.contains(&token)
            && !other.iter().any(|body| body.contains(&token))
        {
            found.insert(token);
        }
    }
    if shell {
        found.extend(commands_from_instruction(text, &sources, &prompt));
    }
    found.into_iter().collect()
}

/// `text` as shell words for matching commands: lower case, quotes, brackets and backticks off,
/// a word's trailing punctuation and `/` off, one space between words.
fn command_words(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|c| {
            if matches!(c, '`' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}') {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .split_whitespace()
        .map(|word| {
            let word = word.trim_end_matches([',', ';', ':', '.']);
            if word.len() > 1 {
                word.trim_end_matches('/')
            } else {
                word
            }
        })
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `words` stand in `text` (both [`command_words`]) as whole words.
fn has_words(text: &str, words: &str) -> bool {
    text.match_indices(words).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + words.len()..].chars().next();
        before.is_none_or(|c| c == ' ') && after.is_none_or(|c| c == ' ')
    })
}

/// The shell commands of `text` (a simple command, or a pipeline whole or by its steps) that do
/// something a person would want to know of (see [`risk_marks`]) and stand word for word in what
/// an instructing tool result says, or in what a command that read a file written for agents
/// printed: `rm -rf tests` that `AGENTS.md` asks for, though `tests` is too short a name to
/// tell. Not one the user's `prompt` holds, or whose every argument it names (the user asked
/// to delete `tests`), nor one any other tool result shows too.
fn commands_from_instruction(text: &str, sources: &[Source], prompt: &str) -> Vec<String> {
    let from: Vec<String> = sources
        .iter()
        .filter(|source| !source.own)
        .filter_map(|source| {
            if source.reads_agent_file {
                Some(command_words(source.body))
            } else if !source.rule.trim().is_empty() {
                Some(command_words(&source.rule))
            } else {
                None
            }
        })
        .collect();
    if from.is_empty() {
        return Vec::new();
    }
    let other: Vec<String> = sources
        .iter()
        .filter(|source| !source.own && !source.reads_agent_file)
        .map(|source| command_words(&source.rest))
        .collect();
    let asked = command_words(prompt);
    let mut found = Vec::new();
    for part in split_parts(text) {
        let mut candidates = vec![part.clone()];
        if part.contains('|') {
            candidates.extend(
                part.split('|')
                    .map(str::trim)
                    .filter(|step| !step.is_empty())
                    .map(str::to_owned),
            );
        }
        for candidate in candidates {
            let words = command_words(&candidate);
            if words.split(' ').count() < 2 || words.len() < 8 || risk_marks(&candidate).is_empty()
            {
                continue;
            }
            let arguments: Vec<&str> = words
                .split(' ')
                .skip(1)
                .filter(|word| !word.starts_with('-'))
                .collect();
            let user_named = has_words(&asked, &words)
                || (!arguments.is_empty()
                    && arguments.iter().all(|argument| asked.contains(argument)));
            if !user_named
                && from.iter().any(|said| has_words(said, &words))
                && !other.iter().any(|shown| has_words(shown, &words))
                && !found.contains(&words)
            {
                found.push(words);
            }
        }
    }
    found
}

/// The values of a call that stand only in what an instructing tool result says, never in the
/// user's prompt: the path it reads or writes, the lines an edit adds, the strings of any other
/// argument. A call carrying such a value carries out the instruction (`canary_secret.txt` read
/// because a code comment said to, a marker line a planted style rule asked for). `cwd` is the
/// directory the call is made in.
pub fn call_from_instruction(
    tool_name: &str,
    input: &Value,
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
    cwd: Option<&str>,
) -> Vec<String> {
    let field = |name: &str| input.get(name).and_then(Value::as_str).unwrap_or_default();
    let text = match tool_name {
        "Edit" => {
            let old: BTreeSet<&str> = field("old_string").lines().collect();
            let added: Vec<&str> = field("new_string")
                .lines()
                .filter(|line| !old.contains(line))
                .collect();
            // The file it edits was read first: only the lines it adds can carry a value.
            added.join("\n")
        }
        _ => {
            fn texts(value: &Value, out: &mut Vec<String>) {
                match value {
                    Value::String(text) => out.push(text.clone()),
                    Value::Array(items) => items.iter().for_each(|item| texts(item, out)),
                    Value::Object(fields) => fields.values().for_each(|field| texts(field, out)),
                    _ => {}
                }
            }
            let mut out = Vec::new();
            texts(input, &mut out);
            out.join("\n")
        }
    };
    from_instruction(
        &text,
        paragraphs,
        prompt,
        cwd,
        SHELL_TOOLS.contains(&tool_name),
    )
}

/// Tools whose call runs a shell command.
const SHELL_TOOLS: &[&str] = &["Bash", "PowerShell", "shell", "exec_command"];

/// The names and strings of `part` (6 characters or more) that stand in a tool result that
/// instructs an agent and not in the user's `prompt`, and the commands of it such a result
/// spells out: the part carries out that instruction.
pub fn part_from_instruction(
    part: &str,
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
    cwd: Option<&str>,
) -> Vec<String> {
    from_instruction(part, paragraphs, prompt, cwd, true)
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

/// Most values of one call shown with where they came from.
const MAX_VALUES: usize = 20;

/// Where each value a call is given came from: `user` (written in the user's prompt), the key of
/// the first tool-result paragraph that holds it, or `agent` (neither: the agent wrote or chose it
/// itself). Text values of three characters or more and numbers other than 0 and 1, matched
/// case-insensitively. The origin of a value is what the call's target rests on: a recipient taken
/// from a search result, an amount nobody gave.
pub fn value_origins(
    input: &Value,
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
) -> Vec<(String, String)> {
    fn leaves(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::String(text) if text.trim().chars().count() >= 3 => {
                found.push(text.trim().to_owned());
            }
            Value::Number(number) if number.as_f64().is_some_and(|n| n != 0.0 && n != 1.0) => {
                found.push(number.to_string());
            }
            Value::Array(items) => items.iter().for_each(|item| leaves(item, found)),
            Value::Object(fields) => fields.values().for_each(|field| leaves(field, found)),
            _ => {}
        }
    }
    let prompt = prompt.unwrap_or_default().to_lowercase();
    let lowered: Vec<(&String, String)> = paragraphs
        .iter()
        .map(|(key, text)| (key, text.to_lowercase()))
        .collect();
    let mut found = Vec::new();
    leaves(input, &mut found);
    found.dedup();
    found
        .into_iter()
        .take(MAX_VALUES)
        .map(|value| {
            let needle = value.to_lowercase();
            let origin = if prompt.contains(&needle) {
                "user".to_owned()
            } else if let Some((key, _)) = lowered.iter().find(|(_, text)| text.contains(&needle)) {
                (*key).clone()
            } else {
                "agent".to_owned()
            };
            (value.chars().take(160).collect(), origin)
        })
        .collect()
}

/// [`call_from_instruction`] for a file change, by its `path` and the lines it `added`.
pub fn lines_from_instruction(
    path: &str,
    added: &[String],
    paragraphs: &BTreeMap<String, String>,
    prompt: Option<&str>,
    cwd: Option<&str>,
) -> Vec<String> {
    from_instruction(
        &format!("{path}\n{}", added.join("\n")),
        paragraphs,
        prompt,
        cwd,
        false,
    )
}
