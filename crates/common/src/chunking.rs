//! Splits agent-visible text into paragraphs that the graph stores by content hash.
//!
//! Text is cut at line breaks first. A short paragraph absorbs the paragraphs that follow it,
//! and a paragraph longer than [`MAX_CHARS`] is cut at whitespace and labelled
//! `long_paragraph`. Lengths are counted in `char`s, never bytes, so multi-byte text is never
//! cut mid-character.
//!
//! Values that must stay whole — URLs, socket and broker addresses, DSNs, memory, MMIO and I2C
//! addresses, MAC addresses, wallet addresses, UNC paths, ARNs, hashes, base64 — contain no
//! whitespace, so they are never cut: a cut only lands on whitespace, and when a window has
//! none the paragraph runs on to the next whitespace instead. The few such values that do
//! contain whitespace or line breaks are matched explicitly below.

use std::{fmt::Write as _, ops::Range, sync::LazyLock};

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::{hidden::hidden_spans, origin::Origin};

/// Longest paragraph, in chars, before it is cut and labelled `long_paragraph`.
pub const MAX_CHARS: usize = 600;
/// A paragraph shorter than this, in chars, absorbs the paragraph that follows it.
pub const SHORT_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Prompts and assistant messages: a long paragraph is cut at sentence ends first.
    Prose,
    /// Tool output such as code, logs and JSON, where `.` rarely ends a sentence: a long
    /// paragraph is cut at any whitespace.
    ToolOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub index: usize,
    pub text: String,
    pub hash: String,
    /// The paragraph came from a line or block longer than [`MAX_CHARS`].
    pub long_paragraph: bool,
    /// The paragraph holds content hidden from a human reader.
    pub hidden: bool,
    /// The [`crate::hidden`] rules that found it, sorted and without duplicates.
    pub hidden_rules: Vec<&'static str>,
}

/// Splits external content, applying every hidden-content rule.
pub fn chunk_text(text: &str, profile: Profile) -> Vec<Chunk> {
    chunk_text_from(text, profile, Origin::External)
}

/// Splits content from `origin`; hidden-content rules for rendered content apply only to
/// [`Origin::External`] text.
pub fn chunk_text_from(text: &str, profile: Profile, origin: Origin) -> Vec<Chunk> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    // Each paragraph keeps the byte range it came from, so hidden content found anywhere in the
    // text (even spanning paragraphs) marks exactly the paragraphs it touches.
    let mut paragraphs: Vec<(String, bool, Range<usize>)> = Vec::new();
    for unit in units(&text) {
        let long = chars(&unit.text) > MAX_CHARS;
        let pieces = match unit.kind {
            _ if !long => vec![unit.text.clone()],
            UnitKind::Atomic => vec![unit.text.clone()],
            UnitKind::Fence => split_lines(&unit.text, profile),
            UnitKind::Line => split_line(&unit.text, profile),
        };
        let mut cursor = 0;
        for piece in pieces {
            let range = match unit.text[cursor..].find(&piece) {
                Some(offset) => {
                    let start = cursor + offset;
                    cursor = start + piece.len();
                    unit.range.start + start..unit.range.start + cursor
                }
                None => unit.range.clone(),
            };
            if let Some((last, last_long, last_range)) = paragraphs.last_mut() {
                let last_chars = chars(last);
                if !*last_long
                    && !long
                    && last_chars < SHORT_CHARS
                    && last_chars + 1 + chars(&piece) <= MAX_CHARS
                {
                    last.push('\n');
                    last.push_str(&piece);
                    last_range.end = range.end;
                    continue;
                }
            }
            paragraphs.push((piece, long, range));
        }
    }

    let hidden: Vec<_> = hidden_spans(&text)
        .into_iter()
        .filter(|span| span.scope.applies_to(origin))
        .collect();
    paragraphs
        .into_iter()
        .enumerate()
        .map(|(index, (text, long_paragraph, range))| {
            let mut hidden_rules: Vec<&'static str> = hidden
                .iter()
                .filter(|span| span.range.start < range.end && range.start < span.range.end)
                .map(|span| span.rule)
                .collect();
            hidden_rules.sort_unstable();
            hidden_rules.dedup();
            Chunk {
                index,
                hash: sha256(&text),
                text,
                long_paragraph,
                hidden: !hidden_rules.is_empty(),
                hidden_rules,
            }
        })
        .collect()
}

pub fn sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}

enum UnitKind {
    Line,
    /// A fenced code block: kept together, and cut between its lines only when too long.
    Fence,
    /// A PEM block or a run of wrapped base64 lines: never cut.
    Atomic,
}

struct Unit {
    text: String,
    kind: UnitKind,
    /// Byte range of `text` in the chunked text.
    range: Range<usize>,
}

/// Splits text into lines, keeping fenced code, PEM blocks and wrapped base64 together.
fn units(text: &str) -> Vec<Unit> {
    let lines = text.split('\n').collect::<Vec<_>>();
    let starts = lines
        .iter()
        .scan(0, |offset, line| {
            let start = *offset;
            *offset += line.len() + 1;
            Some(start)
        })
        .collect::<Vec<_>>();
    let mut units = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        if line.is_empty() {
            index += 1;
            continue;
        }
        let (end, kind) = if let Some(fence) = fence_marker(line) {
            let end = (index + 1..lines.len())
                .find(|&next| is_closing_fence(lines[next].trim(), fence))
                .unwrap_or(lines.len() - 1);
            (end, UnitKind::Fence)
        } else if line.starts_with("-----BEGIN ") {
            let end = (index + 1..lines.len())
                .find(|&next| lines[next].trim().starts_with("-----END "))
                .unwrap_or(lines.len() - 1);
            (end, UnitKind::Atomic)
        } else if let Some(end) = wrapped_base64_end(&lines, index) {
            (end, UnitKind::Atomic)
        } else {
            (index, UnitKind::Line)
        };
        let block = &text[starts[index]..starts[end] + lines[end].len()];
        let leading = block.len() - block.trim_start().len();
        let unit = block.trim();
        let range = starts[index] + leading..starts[index] + leading + unit.len();
        let text = match kind {
            UnitKind::Line => line.to_owned(),
            _ => unit.to_owned(),
        };
        units.push(Unit { text, kind, range });
        index = end + 1;
    }
    units
}

fn fence_marker(line: &str) -> Option<&'static str> {
    ["```", "~~~"]
        .into_iter()
        .find(|marker| line.starts_with(marker))
}

fn is_closing_fence(line: &str, marker: &str) -> bool {
    let fence = marker.chars().next().unwrap_or('`');
    line.starts_with(marker) && line.trim_start_matches(fence).is_empty()
}

/// Returns the last line of a run of base64 lines wrapped at one width, as in MIME or PEM bodies.
/// The first line must mix upper and lower case so that a list of hex hashes is not mistaken
/// for one encoded value.
fn wrapped_base64_end(lines: &[&str], start: usize) -> Option<usize> {
    let first = lines[start].trim();
    if first.len() < 40
        || !is_base64(first)
        || !first.bytes().any(|byte| byte.is_ascii_uppercase())
        || !first.bytes().any(|byte| byte.is_ascii_lowercase())
    {
        return None;
    }
    let mut end = start;
    while let Some(next) = lines.get(end + 1).map(|line| line.trim()) {
        if next.is_empty() || !is_base64(next) || next.len() > first.len() {
            break;
        }
        end += 1;
        if next.len() < first.len() {
            break;
        }
    }
    (end > start).then_some(end)
}

fn is_base64(line: &str) -> bool {
    line.trim_end_matches('=')
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

/// Cuts a long fenced block between lines, packing lines up to [`MAX_CHARS`].
fn split_lines(block: &str, profile: Profile) -> Vec<String> {
    let mut pieces = Vec::new();
    let mut current = String::new();
    for line in block.lines() {
        if chars(line) > MAX_CHARS {
            if !current.is_empty() {
                pieces.push(std::mem::take(&mut current));
            }
            pieces.extend(split_line(line.trim(), profile));
        } else if !current.is_empty() && chars(&current) + 1 + chars(line) > MAX_CHARS {
            pieces.push(std::mem::replace(&mut current, line.to_owned()));
        } else {
            if !current.is_empty() {
                current.push('\n');
            }
            current.push_str(line);
        }
    }
    if !current.trim().is_empty() {
        pieces.push(current);
    }
    pieces
}

/// Cuts a long line at whitespace, preferring sentence ends for prose, into pieces of at most
/// [`MAX_CHARS`]. A piece runs past the limit only when its window holds no allowed cut.
fn split_line(line: &str, profile: Profile) -> Vec<String> {
    let protected = protected_spans(line);
    let cuts = cut_points(line, profile)
        .into_iter()
        .filter(|(position, _)| {
            !protected
                .iter()
                .any(|span| span.start < *position && *position < span.end)
        })
        .collect::<Vec<_>>();

    let mut pieces = Vec::new();
    let mut start = 0;
    loop {
        let rest = &line[start..];
        let Some((offset, _)) = rest.char_indices().nth(MAX_CHARS) else {
            pieces.push(rest.trim().to_owned());
            break;
        };
        let limit = start + offset;
        let half = start
            + rest
                .char_indices()
                .nth(MAX_CHARS / 2)
                .map_or(0, |(offset, _)| offset);
        let window = cuts
            .iter()
            .filter(|(position, _)| start < *position && *position <= limit);
        let cut = [2, 1]
            .into_iter()
            .find_map(|level| {
                window
                    .clone()
                    .rfind(|(position, cut_level)| *cut_level == level && *position >= half)
            })
            .or_else(|| window.clone().next_back())
            .or_else(|| cuts.iter().find(|(position, _)| *position > limit));
        let Some(&(position, _)) = cut else {
            pieces.push(rest.trim().to_owned());
            break;
        };
        pieces.push(line[start..position].trim().to_owned());
        start = position + (line[position..].len() - line[position..].trim_start().len());
    }
    pieces.retain(|piece| !piece.is_empty());
    pieces
}

/// Byte offsets of whitespace runs, ranked 2 after a sentence end in prose and 1 otherwise.
fn cut_points(line: &str, profile: Profile) -> Vec<(usize, u8)> {
    let mut points = Vec::new();
    let mut previous: Option<char> = None;
    for (position, character) in line.char_indices() {
        let after_word = previous.filter(|previous| !previous.is_whitespace());
        if let (true, Some(previous)) = (character.is_whitespace(), after_word) {
            let sentence_end = matches!(previous, '.' | '!' | '?' | '。' | '！' | '？');
            let level = if profile == Profile::Prose && sentence_end {
                2
            } else {
                1
            };
            points.push((position, level));
        }
        previous = Some(character);
    }
    points
}

/// Values that contain whitespace yet must not be cut.
fn protected_spans(line: &str) -> Vec<Range<usize>> {
    static PROTECTED: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
            // Markdown links and images: [label with spaces](target)
            r"!?\[[^\]\n]*\]\([^)\n]*\)",
            // Inline code spans
            r"`[^`\n]+`",
            // libpq keyword/value DSN: host=db port=5432 dbname=app user='me'
            r"\b(?:host|hostaddr|port|dbname|user|password|passfile|sslmode|sslrootcert|connect_timeout|application_name|options|target_session_attrs)=(?:'[^']*'|\S+)(?:\s+[a-z_]+=(?:'[^']*'|\S+))+",
            // ADO.NET and ODBC connection strings: Server=db; Initial Catalog=app; User Id=me;
            r"(?i)\b(?:server|data source|driver|dsn|provider|host|address|addr)\s*=\s*(?:\{[^}\n]*\}|[^;\n]*)(?:;\s*[a-z][a-z ]*?\s*=\s*(?:\{[^}\n]*\}|[^;\n]*))+;?",
            // Broker and host lists: kafka-1:9092, kafka-2:9092
            r"[\w.-]+:\d{1,5}(?:\s*,\s*[\w.-]+:\d{1,5})+",
            // Windows drive and UNC paths whose folders contain spaces
            r#"(?:\b[A-Za-z]:|\\\\[\w.$-]+)\\(?:[^\\\n"<>|*?]+\\)*[^\\\s"<>|*?]*"#,
            // Timestamps with a space between date and time: 2026-10-23 12:00:00 +09:00
            r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?",
            // Spaced hex byte dumps: de ad be ef 00 11 22 33
            r"\b[0-9a-fA-F]{2}(?:[ :][0-9a-fA-F]{2}){7,}\b",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("protected pattern is valid"))
        .collect()
    });

    PROTECTED
        .iter()
        .flat_map(|pattern| pattern.find_iter(line).map(|found| found.range()))
        .collect()
}

fn chars(value: &str) -> usize {
    value.chars().count()
}
