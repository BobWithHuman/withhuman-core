//! What a shell command spells out of encoded or split pieces, for the file question: a marker
//! written as `[char]35+…`, decoded from base64 or joined from literals reads as plain text to
//! no one but the shell, so the question shows Jev the text as well.

/// Text a shell command builds out of encoded or split pieces (C2): base64 literals, character
/// codes and string literals joined with `+`. A command that writes a marker it spells as
/// `[char]35+…` or decodes from base64 shows Jev the marker.
pub fn decoded(command: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut push = |text: String| {
        let text = text.trim().to_owned();
        if !text.is_empty() && !found.contains(&text) {
            found.push(text);
        }
    };
    let literals = quoted_literals(command);
    for literal in &literals {
        if let Some(text) = base64_text(&literal.text) {
            push(text);
        }
    }
    // `-EncodedCommand <base64>` takes its argument unquoted.
    let words: Vec<&str> = command.split_whitespace().collect();
    for pair in words.windows(2) {
        let flag = pair[0].to_ascii_lowercase();
        if matches!(flag.as_str(), "-encodedcommand" | "-enc" | "-e" | "-ec") {
            if let Some(text) = base64_text(pair[1].trim_matches(|c| c == '\'' || c == '"')) {
                push(text);
            }
        }
    }
    for text in char_codes(command) {
        push(text);
    }
    // 'a' + 'b' + …: neighbouring literals joined by `+` only.
    let mut joined = String::new();
    let mut parts = 0;
    for pair in literals.windows(2) {
        let between = &command[pair[0].end..pair[1].start];
        if between.trim() == "+" {
            if parts == 0 {
                joined.push_str(&pair[0].text);
                parts = 1;
            }
            joined.push_str(&pair[1].text);
            parts += 1;
        } else if parts > 0 {
            push(std::mem::take(&mut joined));
            parts = 0;
        }
    }
    if parts > 0 {
        push(joined);
    }
    found
}

struct Literal {
    text: String,
    start: usize,
    end: usize,
}

/// The single- and double-quoted strings of a command, with where each starts and ends.
fn quoted_literals(command: &str) -> Vec<Literal> {
    let mut literals = Vec::new();
    let mut open: Option<(char, usize)> = None;
    let mut text = String::new();
    for (at, c) in command.char_indices() {
        match open {
            Some((quote, start)) if c == quote => {
                literals.push(Literal {
                    text: std::mem::take(&mut text),
                    start,
                    end: at + c.len_utf8(),
                });
                open = None;
            }
            Some(_) => text.push(c),
            None if c == '\'' || c == '"' => open = Some((c, at)),
            None => {}
        }
    }
    literals
}

fn base64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// `text` decoded from base64 when it is base64 of printable text (UTF-8, or UTF-16 as
/// PowerShell's `-EncodedCommand` takes it).
fn base64_text(text: &str) -> Option<String> {
    let text = text.trim().trim_end_matches('=');
    if text.len() < 8 || text.contains(' ') {
        return None;
    }
    // A plain word is valid base64 too; ask for a mix that words rarely have.
    let has_digit_or_case = text.bytes().any(|c| c.is_ascii_digit())
        || (text.bytes().any(|c| c.is_ascii_uppercase())
            && text.bytes().any(|c| c.is_ascii_lowercase()));
    if !has_digit_or_case {
        return None;
    }
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        buffer = (buffer << 6) | base64_value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    let utf16 = bytes.len() >= 4 && bytes.iter().skip(1).step_by(2).all(|byte| *byte == 0);
    let decoded = if utf16 {
        let units: Vec<u16> = bytes
            .chunks(2)
            .map(|pair| u16::from(pair[0]) | (u16::from(*pair.get(1).unwrap_or(&0)) << 8))
            .collect();
        String::from_utf16(&units).ok()?
    } else {
        String::from_utf8(bytes).ok()?
    };
    let printable = decoded
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .count();
    (decoded.chars().count() >= 3 && printable * 10 >= decoded.chars().count() * 9)
        .then_some(decoded)
}

/// Text spelled with character codes: `[char]35+[char]32`, `[char[]](35,32,82)`, `chr(35)`.
fn char_codes(command: &str) -> Vec<String> {
    let lower = command.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut found = Vec::new();
    let mut current = String::new();
    let mut last_end = 0;
    let number_at = |mut at: usize| -> Option<(u32, usize)> {
        while at < bytes.len() && (bytes[at] == b' ' || bytes[at] == b'(') {
            at += 1;
        }
        let start = at;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
        }
        (at > start)
            .then(|| lower[start..at].parse().ok().map(|value| (value, at)))
            .flatten()
    };
    let mut index = 0;
    while index < bytes.len() {
        let rest = &lower[index..];
        let (marker, list) = if rest.starts_with("[char[]]") {
            ("[char[]]", true)
        } else if rest.starts_with("[char]") {
            ("[char]", false)
        } else if rest.starts_with("chr(") {
            ("chr", false)
        } else {
            index += 1;
            continue;
        };
        let after = index + marker.len();
        if list {
            // `(35,32,82)` or `@(35,32,82)`.
            let mut at = after;
            while at < bytes.len() && matches!(bytes[at], b' ' | b'(' | b'@') {
                at += 1;
            }
            let mut text = String::new();
            while let Some((value, end)) = number_at(at) {
                text.extend(char::from_u32(value));
                at = end;
                while at < bytes.len() && matches!(bytes[at], b' ' | b',') {
                    at += 1;
                }
            }
            if text.chars().count() >= 3 {
                found.push(text);
            }
            index = at.max(after);
            continue;
        }
        if let Some((value, end)) = number_at(after) {
            let joined = lower[last_end..index]
                .trim()
                .trim_matches(|c| c == '+' || c == ',');
            if !current.is_empty() && !joined.trim().is_empty() && last_end != 0 {
                if current.chars().count() >= 3 {
                    found.push(std::mem::take(&mut current));
                }
                current.clear();
            }
            current.extend(char::from_u32(value));
            last_end = end;
            index = end;
        } else {
            index = after;
        }
    }
    if current.chars().count() >= 3 {
        found.push(current);
    }
    found
}
