//! Token Indexing: regex detectors for values that can locate an external destination or reveal
//! sensitive data. The Generator stores every token with the node that mentions it, so a later
//! tool call that sends the same value can be traced back to where the value came from.
//!
//! Locators (URLs, socket addresses, DSNs, ARNs, ...) keep their text as the key. Credentials,
//! PII, financial and device identifiers are keyed by the SHA-256 of their normalized value and
//! only a masked form is kept, so the index never holds the secret itself while equal values
//! still share a key.
//!
//! Formats with a checksum (card numbers, IBAN, IMEI, VIN, Bitcoin and Tron addresses) are
//! validated. Formats that look like ordinary numbers or hex (memory, MMIO and I2C addresses,
//! account numbers, IMSI, passport numbers, unhyphenated ID numbers) need a context keyword next
//! to them.

use std::{borrow::Cow, collections::BTreeSet, net::IpAddr, ops::Range, sync::LazyLock};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::chunking::sha256;

macro_rules! regex {
    ($pattern:expr) => {{
        static PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
        &*PATTERN
    }};
}

/// Characters inspected on each side of a candidate when a context keyword is required.
const CONTEXT_BEFORE: usize = 48;
const CONTEXT_AFTER: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// Where data can be sent or read: network, storage, hardware and cloud locators.
    Address,
    /// Authentication material: JWTs, API keys, private keys.
    Credential,
    /// Personal identifiers: resident registration, passport and driver's license numbers.
    Pii,
    /// Payment and banking identifiers: card numbers, account numbers, IBANs.
    Financial,
    /// Device and hardware identifiers: IMEI, IMSI, VIN.
    Device,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Credential => "credential",
            Self::Pii => "pii",
            Self::Financial => "financial",
            Self::Device => "device",
        }
    }

    /// Whether tokens of this category are stored hashed and masked.
    pub fn is_sensitive(self) -> bool {
        !matches!(self, Self::Address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token {
    pub kind: &'static str,
    pub category: Category,
    /// Lookup key: the normalized value, or `sha256:<hex>` of it for sensitive categories.
    pub key: String,
    /// Display value: the value itself, or a masked form for sensitive categories.
    pub decoded: String,
}

/// Every token found in `text`, deduplicated and in a stable order.
pub fn extract_tokens(text: &str) -> Vec<Token> {
    scan(text).tokens.into_iter().collect()
}

/// `text` with every sensitive value (credential, PII, financial, device identifier, DSN
/// password) replaced by its masked form, so stored events never hold the secret. Redacting
/// already redacted text changes nothing.
pub fn redact(text: &str) -> Cow<'_, str> {
    let mut redactions = scan(text).redactions;
    if redactions.is_empty() {
        return Cow::Borrowed(text);
    }
    // Earliest first and, at the same start, the widest; overlapped spans are dropped.
    redactions.sort_by(|a, b| a.0.start.cmp(&b.0.start).then(b.0.end.cmp(&a.0.end)));
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0;
    for (span, replacement) in redactions {
        if span.start < cursor {
            continue;
        }
        redacted.push_str(&text[cursor..span.start]);
        redacted.push_str(&replacement);
        cursor = span.end;
    }
    redacted.push_str(&text[cursor..]);
    Cow::Owned(redacted)
}

/// The masked value of a structured field whose name marks it as secret (`api_key`,
/// `GITHUB_TOKEN`, `password`, `Authorization`, ...), whatever the value looks like.
pub fn redact_field(name: &str, value: &str) -> Option<String> {
    let secret_name = regex!(
        r"(?i)(?:^|[_.-])(?:api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|secret(?:[_-]?(?:access[_-]?)?key)?|client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|token|password|passwd|pwd|authorization|private[_-]?key)$"
    );
    (secret_name.is_match(name) && !is_placeholder(value)).then(|| mask_ends(value))
}

/// Masks sensitive values in every string of a JSON value and every string field named as a
/// secret; reports whether anything changed. Object keys are left as they are.
pub fn redact_json(value: &mut Value) -> bool {
    match value {
        Value::String(text) => match redact(text) {
            Cow::Owned(redacted) => {
                *text = redacted;
                true
            }
            Cow::Borrowed(_) => false,
        },
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |changed, item| redact_json(item) | changed),
        Value::Object(fields) => fields.iter_mut().fold(false, |changed, (name, item)| {
            if let Value::String(text) = item {
                if let Some(masked) = redact_field(name, text) {
                    *text = masked;
                    return true;
                }
            }
            redact_json(item) | changed
        }),
        _ => false,
    }
}

/// Values that are references or masks rather than secrets.
fn is_placeholder(value: &str) -> bool {
    value.len() < 4
        || value.chars().all(|c| c == '*')
        || value.contains('…')
        || value.starts_with("${")
        || value.starts_with('<')
}

fn scan(text: &str) -> Tokens {
    let mut found = Tokens::default();
    locators(text, &mut found);
    socket_addresses(text, &mut found);
    endpoints(text, &mut found);
    hardware_addresses(text, &mut found);
    mac_addresses(text, &mut found);
    wallet_addresses(text, &mut found);
    unc_paths(text, &mut found);
    arns(text, &mut found);
    credentials(text, &mut found);
    personal_ids(text, &mut found);
    financial_ids(text, &mut found);
    device_ids(text, &mut found);
    found
}

#[derive(Default)]
struct Tokens {
    tokens: BTreeSet<Token>,
    /// Byte spans of sensitive values in the scanned text and their masked replacement.
    redactions: Vec<(Range<usize>, String)>,
}

impl Tokens {
    fn address(&mut self, kind: &'static str, value: &str) {
        self.tokens.insert(Token {
            kind,
            category: Category::Address,
            key: value.to_owned(),
            decoded: value.to_owned(),
        });
    }

    fn sensitive(
        &mut self,
        kind: &'static str,
        category: Category,
        normalized: &str,
        masked: String,
        span: Range<usize>,
    ) {
        self.redactions.push((span, masked.clone()));
        self.tokens.insert(Token {
            kind,
            category,
            key: format!("sha256:{}", sha256(normalized)),
            decoded: masked,
        });
    }

    fn contains(&self, kind: &str, key: &str) -> bool {
        self.tokens
            .iter()
            .any(|token| token.kind == kind && token.key == key)
    }
}

fn trim_punctuation(value: &str) -> &str {
    value.trim_end_matches([',', '.', ')', ']', '}', ';'])
}

fn locators(text: &str, found: &mut Tokens) {
    let url = regex!(r#"https?://[^\s\"'<>\\]+"#);
    let email = regex!(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}");
    let ip = regex!(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b");
    let path = regex!(r#"(?:^|[\s\"'=])((?:/|\./|\.\./)[A-Za-z0-9._~/-]+)"#);

    for value in url.find_iter(text) {
        found.address("url", trim_punctuation(value.as_str()));
    }
    for value in email.find_iter(text) {
        found.address("email", trim_punctuation(value.as_str()));
    }
    for value in ip.find_iter(text) {
        if value.as_str().parse::<IpAddr>().is_ok() {
            found.address("ip", trim_punctuation(value.as_str()));
        }
    }
    for captures in path.captures_iter(text) {
        if let Some(value) = captures.get(1) {
            found.address("path", trim_punctuation(value.as_str()));
        }
    }
}

/// File extensions that make `name.ext:42` a source location rather than `host:port`.
const FILE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cs", "css", "go", "h", "hpp", "html", "java", "js", "json", "jsx", "kt",
    "lock", "log", "md", "php", "py", "rb", "rs", "scala", "sh", "sql", "swift", "toml", "ts",
    "tsx", "txt", "vue", "xml", "yaml", "yml", "zig",
];

fn socket_addresses(text: &str, found: &mut Tokens) {
    let socket = regex!(
        r"(?:\[([0-9A-Fa-f:.]+)\]|((?:[0-9]{1,3}\.){3}[0-9]{1,3})|(localhost)|((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}))):([0-9]{1,5})\b"
    );
    for captures in socket.captures_iter(text) {
        let whole = captures.get(0).expect("match");
        // `/lib/x.so:1` and `scheme://host:port` belong to paths and URLs.
        if previous_char(text, whole.start())
            .is_some_and(|c| c.is_alphanumeric() || "/\\.:".contains(c))
        {
            continue;
        }
        let port_ok = captures[6]
            .parse::<u32>()
            .is_ok_and(|port| (1..=65_535).contains(&port));
        let host_ok = if let Some(ipv6) = captures.get(1) {
            ipv6.as_str().parse::<std::net::Ipv6Addr>().is_ok()
        } else if let Some(ipv4) = captures.get(2) {
            ipv4.as_str().parse::<std::net::Ipv4Addr>().is_ok()
        } else if captures.get(3).is_some() {
            true
        } else {
            let tld = captures[5].to_ascii_lowercase();
            !FILE_EXTENSIONS.contains(&tld.as_str())
        };
        if port_ok && host_ok {
            found.address("socket_address", &whole.as_str().to_ascii_lowercase());
        }
    }
}

fn endpoints(text: &str, found: &mut Tokens) {
    let broker = regex!(
        r#"(?i)\b(?:amqps?|mqtts?|kafka|nats|stomp|pulsar(?:\+ssl)?|sqs|activemq)://[^\s"'<>\\]+"#
    );
    let bootstrap = regex!(
        r#"(?i)\bbootstrap[._-]?servers?\\?["']?\s*[=:]\s*\\?["']?([A-Za-z0-9._:,\[\]-]*:[0-9]+[A-Za-z0-9._:,\[\]-]*)"#
    );
    let uri_dsn = regex!(
        r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|sqlserver|mssql|oracle|cockroachdb|clickhouse|cassandra|couchdb|neo4j(?:\+s)?|bolt)://[^\s"'<>\\]+"#
    );
    let jdbc = regex!(r#"(?i)\bjdbc:[a-z0-9]+:[^\s"'<>\\]+"#);
    let ado = regex!(
        r#"(?i)\b(?:server|data source)\s*=\s*[^;"'\n\\]+;[^"'\n\\]*?(?:database|initial catalog)\s*=\s*[^;"'\n\\]+"#
    );

    for value in broker.find_iter(text) {
        found.address("broker_endpoint", trim_punctuation(value.as_str()));
    }
    for captures in bootstrap.captures_iter(text) {
        found.address("broker_endpoint", trim_punctuation(&captures[1]));
    }
    for value in uri_dsn
        .find_iter(text)
        .chain(jdbc.find_iter(text))
        .chain(ado.find_iter(text))
    {
        // The `mysql://...` inside `jdbc:mysql://...` is the same DSN.
        if previous_char(text, value.start()) == Some(':') {
            continue;
        }
        let dsn = trim_punctuation(value.as_str());
        let mut masked = String::with_capacity(dsn.len());
        let mut cursor = 0;
        for password in dsn_passwords(dsn) {
            found.redactions.push((
                value.start() + password.start..value.start() + password.end,
                "***".to_owned(),
            ));
            masked.push_str(&dsn[cursor..password.start]);
            masked.push_str("***");
            cursor = password.end;
        }
        masked.push_str(&dsn[cursor..]);
        found.address("db_dsn", &masked);
    }
}

/// Byte spans of the passwords in a DSN, in order.
fn dsn_passwords(dsn: &str) -> Vec<Range<usize>> {
    let userinfo = regex!(r"://[^/:@\s]*:([^@/\s]+)@");
    let parameter = regex!(r"(?i)\b(?:password|pwd)\s*=\s*([^;&\s]+)");
    let mut spans: Vec<Range<usize>> = userinfo
        .captures_iter(dsn)
        .chain(parameter.captures_iter(dsn))
        .filter_map(|captures| captures.get(1))
        .filter(|password| password.as_str() != "***")
        .map(|password| password.range())
        .collect();
    spans.sort_by_key(|span| span.start);
    spans.dedup_by(|later, earlier| later.start < earlier.end);
    spans
}

fn hardware_addresses(text: &str, found: &mut Tokens) {
    const MMIO: &[&str] = &[
        "mmio*",
        "iomem",
        "ioremap*",
        "devmem*",
        "register*",
        "reg",
        "regs",
    ];
    const I2C: &[&str] = &["i2c*", "smbus*", "twi", "slave"];
    const MEMORY: &[&str] = &[
        "addr*",
        "address*",
        "pointer*",
        "ptr",
        "rip",
        "rsp",
        "rbp",
        "eip",
        "esp",
        "pc",
        "sp",
        "lr",
        "fault*",
        "segfault*",
        "segv",
        "sigsegv",
        "virt*",
        "phys*",
        "va",
        "pa",
        "vaddr",
        "paddr",
        "stack*",
        "heap*",
        "mmap*",
        "page*",
        "주소*",
        "메모리*",
    ];
    let i2c = regex!(r"\b0[xX][0-7][0-9a-fA-F]\b");
    let hex = regex!(r"\b0[xX][0-9a-fA-F]{4,16}\b");

    for value in i2c.find_iter(text) {
        if has_context(text, value.start(), value.end(), I2C) {
            found.address("i2c_address", &value.as_str().to_ascii_lowercase());
        }
    }
    for value in hex.find_iter(text) {
        let digits = value.len() - 2;
        let normalized = value.as_str().to_ascii_lowercase();
        if has_context(text, value.start(), value.end(), MMIO) {
            found.address("mmio_address", &normalized);
        } else if digits >= 8 && has_context(text, value.start(), value.end(), MEMORY) {
            found.address("memory_address", &normalized);
        }
    }
}

fn mac_addresses(text: &str, found: &mut Tokens) {
    let colon = regex!(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b");
    let dash = regex!(r"\b[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}\b");
    let dotted = regex!(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b");

    for value in colon
        .find_iter(text)
        .chain(dash.find_iter(text))
        .chain(dotted.find_iter(text))
    {
        // Part of a longer colon-separated run such as an IPv6 address.
        if previous_char(text, value.start()).is_some_and(|c| c == ':' || c == '-' || c == '.')
            || next_char(text, value.end()).is_some_and(|c| c == ':' || c == '-')
        {
            continue;
        }
        let digits: String = value
            .as_str()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if digits.chars().all(|c| c == '0') {
            continue;
        }
        let normalized = digits
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).expect("hex digits"))
            .collect::<Vec<_>>()
            .join(":");
        found.address("mac_address", &normalized);
    }
}

fn wallet_addresses(text: &str, found: &mut Tokens) {
    let bitcoin = regex!(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b");
    let tron = regex!(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b");
    let bech32 = regex!(r"\b(?:bc|tb)1[ac-hj-np-z02-9]{11,71}\b");
    let ethereum = regex!(r"\b0x[0-9a-fA-F]{40}\b");

    for value in bitcoin.find_iter(text) {
        if base58check_version(value.as_str()).is_some_and(|version| matches!(version, 0x00 | 0x05))
        {
            found.address("wallet_address", value.as_str());
        }
    }
    for value in tron.find_iter(text) {
        if base58check_version(value.as_str()) == Some(0x41) {
            found.address("wallet_address", value.as_str());
        }
    }
    for value in bech32.find_iter(text) {
        if bech32_valid(value.as_str()) {
            found.address("wallet_address", value.as_str());
        }
    }
    for value in ethereum.find_iter(text) {
        found.address("wallet_address", &value.as_str().to_ascii_lowercase());
    }
}

fn unc_paths(text: &str, found: &mut Tokens) {
    // In JSON every backslash is escaped, so a UNC path may start with four backslashes.
    let unc = regex!(r"(?:\\\\){1,2}([A-Za-z0-9._-]+)((?:\\{1,2}[A-Za-z0-9._$-]+)+)");
    let url = regex!(r#"(?i)\b(?:smb|cifs)://[^\s"'<>\\]+|\bfile://[A-Za-z0-9.-]+/[^\s"'<>\\]*"#);

    for captures in unc.captures_iter(text) {
        let whole = captures.get(0).expect("match");
        // `C:\\Users` in JSON, or a longer run of backslashes.
        if previous_char(text, whole.start())
            .is_some_and(|c| c.is_alphanumeric() || c == ':' || c == '\\')
        {
            continue;
        }
        let segments = captures[2]
            .split('\\')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>()
            .join("\\");
        found.address("unc_path", &format!("\\\\{}\\{segments}", &captures[1]));
    }
    for value in url.find_iter(text) {
        found.address("unc_path", trim_punctuation(value.as_str()));
    }
}

fn arns(text: &str, found: &mut Tokens) {
    let arn = regex!(
        r#"\barn:aws(?:-cn|-us-gov|-iso(?:-[a-z])?)?:[a-z0-9-]+:[a-z0-9-]*:(?:[0-9]{12})?:[^\s"'<>,\\]+"#
    );
    for value in arn.find_iter(text) {
        found.address("cloud_arn", trim_punctuation(value.as_str()));
    }
}

fn credentials(text: &str, found: &mut Tokens) {
    let jwt = regex!(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*");
    let prefixed = regex!(
        r"\b(?:(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255}|glpat-[A-Za-z0-9_-]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"
    );
    let assigned = regex!(
        r#"(?i)(?:\b|_)(?:api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|secret[_-]?(?:access[_-]?)?key|client[_-]?secret|auth[_-]?token|access[_-]?token|secret|token)\\?["']?\s*[:=]\s*\\?["']?([A-Za-z0-9_\-./+=]{16,256})"#
    );
    let password = regex!(
        r#"(?i)(?:\b|_)(?:password|passwd|pwd)\\?["']?\s*[:=]\s*\\?["']?([^\s"'\\,;&]{1,128})"#
    );

    for value in jwt.find_iter(text) {
        if let Some(alg) = jwt_algorithm(value.as_str()) {
            found.sensitive(
                "jwt",
                Category::Credential,
                value.as_str(),
                format!("jwt(alg={alg}) {}", mask_ends(value.as_str())),
                value.range(),
            );
        }
    }
    for value in prefixed.find_iter(text) {
        found.sensitive(
            "api_key",
            Category::Credential,
            value.as_str(),
            mask_ends(value.as_str()),
            value.range(),
        );
    }
    for captures in assigned.captures_iter(text) {
        let matched = captures.get(1).expect("value group");
        let value = matched.as_str();
        let has_letter = value.chars().any(|c| c.is_ascii_alphabetic());
        let has_digit = value.chars().any(|c| c.is_ascii_digit());
        let key = format!("sha256:{}", sha256(value));
        if has_letter && has_digit && !found.contains("jwt", &key) {
            found.sensitive(
                "api_key",
                Category::Credential,
                value,
                mask_ends(value),
                matched.range(),
            );
        }
    }
    for captures in password.captures_iter(text) {
        let matched = captures.get(1).expect("value group");
        let value = matched.as_str();
        // `pwd: /repo` is a working directory, not a password.
        if !is_placeholder(value) && !value.starts_with(['/', '~', '.']) {
            found.sensitive(
                "password",
                Category::Credential,
                value,
                mask_ends(value),
                matched.range(),
            );
        }
    }
    private_keys(text, found);
}

fn private_keys(text: &str, found: &mut Tokens) {
    let begin = regex!(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----");
    let body_char = |c: char| c.is_ascii_alphanumeric() || "+/=\\ \r\n\t:-,".contains(c);

    for header in begin.find_iter(text) {
        let rest = &text[header.end()..];
        let end = rest.find("-----END ").filter(|&end| {
            rest[end..]
                .find("PRIVATE KEY-----")
                .is_some_and(|tail| tail < 48)
        });
        let (body, block_end) = match end {
            Some(end) => {
                let marker = rest[end..].find("PRIVATE KEY-----").expect("checked above");
                (&rest[..end], end + marker + "PRIVATE KEY-----".len())
            }
            None => {
                let body_end = rest.find(|c: char| !body_char(c)).unwrap_or(rest.len());
                (&rest[..body_end], body_end)
            }
        };
        // Escaped newlines in JSON and real whitespace do not change the key.
        let normalized: String = body
            .replace("\\n", "")
            .replace("\\r", "")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let label = header
            .as_str()
            .trim_start_matches("-----BEGIN ")
            .trim_end_matches("-----");
        found.sensitive(
            "private_key",
            Category::Credential,
            &format!("{}{normalized}", header.as_str()),
            format!("[{label} ({} chars)]", normalized.len()),
            header.start()..header.end() + block_end,
        );
    }
}

fn personal_ids(text: &str, found: &mut Tokens) {
    const RRN: &[&str] = &["주민*", "rrn", "resident*", "jumin*"];
    const PASSPORT: &[&str] = &["passport*", "여권*"];
    const LICENSE: &[&str] = &["운전*", "면허*", "license*", "licence*", "driver*"];
    let rrn = regex!(r"\b([0-9]{2})([0-9]{2})([0-9]{2})(-?)([1-8])([0-9]{6})\b");
    let passport = regex!(r"\b(?:[MSRODG][0-9]{3}[A-Z][0-9]{4}|[MSRODG][0-9]{8})\b");
    let license = regex!(r"\b(1[1-9]|2[0-8])(-?)([0-9]{2})(-?)([0-9]{6})(-?)([0-9]{2})\b");

    for captures in rrn.captures_iter(text) {
        let whole = captures.get(0).expect("match");
        let valid_date = captures[2]
            .parse::<u8>()
            .is_ok_and(|month| (1..=12).contains(&month))
            && captures[3]
                .parse::<u8>()
                .is_ok_and(|day| (1..=31).contains(&day));
        let hyphenated = !captures[4].is_empty();
        if valid_date && (hyphenated || has_context(text, whole.start(), whole.end(), RRN)) {
            let digits = digits_only(whole.as_str());
            let masked = format!("{}-{}******", &digits[..6], &digits[6..7]);
            found.sensitive("kr_rrn", Category::Pii, &digits, masked, whole.range());
        }
    }
    for value in passport.find_iter(text) {
        if has_context(text, value.start(), value.end(), PASSPORT) {
            let masked = format!("{}*******", &value.as_str()[..2]);
            found.sensitive(
                "passport",
                Category::Pii,
                value.as_str(),
                masked,
                value.range(),
            );
        }
    }
    for captures in license.captures_iter(text) {
        let whole = captures.get(0).expect("match");
        let hyphenated =
            !captures[2].is_empty() && !captures[4].is_empty() && !captures[6].is_empty();
        let separators_consistent = hyphenated
            || (captures[2].is_empty() && captures[4].is_empty() && captures[6].is_empty());
        if separators_consistent
            && (hyphenated || has_context(text, whole.start(), whole.end(), LICENSE))
        {
            let digits = digits_only(whole.as_str());
            let masked = format!("{}-{}-******-**", &digits[..2], &digits[2..4]);
            found.sensitive(
                "driver_license",
                Category::Pii,
                &digits,
                masked,
                whole.range(),
            );
        }
    }
}

fn financial_ids(text: &str, found: &mut Tokens) {
    const ACCOUNT: &[&str] = &[
        "계좌*", "account*", "acct*", "입금*", "송금*", "bank*", "은행*",
    ];
    // Printed groupings only, so neighbouring numbers never join into one candidate.
    let card = regex!(
        r"\b(?:[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4}(?:[ -][0-9]{3})?|[0-9]{4}[ -][0-9]{6}[ -][0-9]{4,5}|[0-9]{13,19})\b"
    );
    let account = regex!(r"\b[0-9]{2,6}-[0-9]{2,6}-[0-9]{2,8}(?:-[0-9]{1,3})?\b|\b[0-9]{10,14}\b");
    let iban = regex!(r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b");
    let date = regex!(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$");

    let mut cards = BTreeSet::new();
    for value in card.find_iter(text) {
        let digits = digits_only(value.as_str());
        if card_brand_length_ok(&digits) && luhn_valid(&digits) {
            let masked = format!("{}******{}", &digits[..6], &digits[digits.len() - 4..]);
            found.sensitive(
                "card_pan",
                Category::Financial,
                &digits,
                masked,
                value.range(),
            );
            cards.insert(digits);
        }
    }
    for value in account.find_iter(text) {
        let digits = digits_only(value.as_str());
        if digits.len() < 10 || date.is_match(value.as_str()) || cards.contains(&digits) {
            continue;
        }
        if has_context(text, value.start(), value.end(), ACCOUNT) {
            let masked = format!("{}****{}", &digits[..3], &digits[digits.len() - 2..]);
            found.sensitive(
                "bank_account",
                Category::Financial,
                &digits,
                masked,
                value.range(),
            );
        }
    }
    for value in iban.find_iter(text) {
        let normalized: String = value
            .as_str()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if (15..=34).contains(&normalized.len()) && iban_valid(&normalized) {
            let masked = format!(
                "{}****{}",
                &normalized[..4],
                &normalized[normalized.len() - 4..]
            );
            found.sensitive(
                "iban",
                Category::Financial,
                &normalized,
                masked,
                value.range(),
            );
        }
    }
}

fn device_ids(text: &str, found: &mut Tokens) {
    const IMEI: &[&str] = &["imei*"];
    const IMSI: &[&str] = &["imsi*"];
    const VIN: &[&str] = &["vin", "차대*", "vehicle*", "chassis*"];
    let imei = regex!(r"\b[0-9]{15}\b|\b[0-9]{2}-[0-9]{6}-[0-9]{6}-[0-9]\b");
    let imsi = regex!(r"\b[2-7][0-9]{14}\b");
    let vin = regex!(r"\b[A-HJ-NPR-Z0-9]{17}\b");

    for value in imei.find_iter(text) {
        let digits = digits_only(value.as_str());
        let hyphenated = value.as_str().contains('-');
        if luhn_valid(&digits)
            && (hyphenated || has_context(text, value.start(), value.end(), IMEI))
        {
            let masked = format!("{}*******{}", &digits[..8], &digits[14..]);
            found.sensitive("imei", Category::Device, &digits, masked, value.range());
        }
    }
    for value in imsi.find_iter(text) {
        if has_context(text, value.start(), value.end(), IMSI) {
            let masked = format!("{}*******{}", &value.as_str()[..5], &value.as_str()[12..]);
            found.sensitive(
                "imsi",
                Category::Device,
                value.as_str(),
                masked,
                value.range(),
            );
        }
    }
    for value in vin.find_iter(text) {
        let vin = value.as_str();
        let mixed =
            vin.chars().any(|c| c.is_ascii_digit()) && vin.chars().any(|c| c.is_ascii_uppercase());
        if mixed
            && (vin_check_digit_valid(vin) || has_context(text, value.start(), value.end(), VIN))
        {
            found.sensitive(
                "vin",
                Category::Device,
                vin,
                format!("{}********", &vin[..9]),
                value.range(),
            );
        }
    }
}

fn previous_char(text: &str, index: usize) -> Option<char> {
    text[..index].chars().next_back()
}

fn next_char(text: &str, index: usize) -> Option<char> {
    text[index..].chars().next()
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Whether a keyword appears among the words just before or after `start..end` on the same
/// line. A keyword ending in `*` matches any word it starts.
fn has_context(text: &str, start: usize, end: usize, keywords: &[&str]) -> bool {
    let before = &text[floor_boundary(text, start.saturating_sub(CONTEXT_BEFORE))..start];
    let after = &text[end..floor_boundary(text, (end + CONTEXT_AFTER).min(text.len()))];
    let before = before.rsplit('\n').next().unwrap_or_default();
    let after = after.split('\n').next().unwrap_or_default();
    format!("{before} {after}")
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .any(|word| {
            keywords
                .iter()
                .any(|keyword| match keyword.strip_suffix('*') {
                    Some(prefix) => word.starts_with(prefix),
                    None => word == *keyword,
                })
        })
}

fn digits_only(value: &str) -> String {
    value.chars().filter(char::is_ascii_digit).collect()
}

fn mask_ends(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

fn luhn_valid(digits: &str) -> bool {
    let sum: u32 = digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(index, byte)| {
            let digit = u32::from(byte - b'0');
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                digit
            }
        })
        .sum();
    !digits.is_empty() && sum % 10 == 0
}

/// Whether the number has the issuer prefix and a length a card network issues.
fn card_brand_length_ok(digits: &str) -> bool {
    let length = digits.len();
    let prefix = |count: usize| digits[..count].parse::<u32>().unwrap_or(0);
    match digits.as_bytes()[0] {
        b'4' => matches!(length, 13 | 16 | 19),
        b'3' => match prefix(2) {
            34 | 37 => length == 15,
            35 => (16..=19).contains(&length),
            36 | 38 | 39 | 30 => (14..=19).contains(&length),
            _ => false,
        },
        b'5' => (51..=55).contains(&prefix(2)) && length == 16,
        b'2' => (2221..=2720).contains(&prefix(4)) && length == 16,
        b'6' => {
            (prefix(4) == 6011 || prefix(2) == 65 || prefix(2) == 62) && (16..=19).contains(&length)
        }
        _ => false,
    }
}

fn iban_valid(iban: &str) -> bool {
    let rearranged = iban[4..].chars().chain(iban[..4].chars());
    let mut remainder = 0_u32;
    for c in rearranged {
        let value = match c.to_digit(36) {
            Some(value) => value,
            None => return false,
        };
        for digit in value.to_string().chars() {
            remainder = (remainder * 10 + digit.to_digit(10).expect("decimal digit")) % 97;
        }
    }
    remainder == 1
}

fn vin_check_digit_valid(vin: &str) -> bool {
    const WEIGHTS: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let value = |c: char| match c {
        '0'..='9' => c.to_digit(10),
        'A' | 'J' => Some(1),
        'B' | 'K' | 'S' => Some(2),
        'C' | 'L' | 'T' => Some(3),
        'D' | 'M' | 'U' => Some(4),
        'E' | 'N' | 'V' => Some(5),
        'F' | 'W' => Some(6),
        'G' | 'P' | 'X' => Some(7),
        'H' | 'Y' => Some(8),
        'R' | 'Z' => Some(9),
        _ => None,
    };
    let mut sum = 0;
    for (c, weight) in vin.chars().zip(WEIGHTS) {
        match value(c) {
            Some(value) => sum += value * weight,
            None => return false,
        }
    }
    let check = match sum % 11 {
        10 => 'X',
        digit => char::from_digit(digit, 10).expect("single digit"),
    };
    vin.chars().nth(8) == Some(check)
}

fn jwt_algorithm(jwt: &str) -> Option<String> {
    let header = jwt.split('.').next()?;
    let decoded = URL_SAFE_NO_PAD.decode(header).ok()?;
    let algorithm = regex!(r#""alg"\s*:\s*"([A-Za-z0-9+_-]{1,16})""#);
    let header = String::from_utf8(decoded).ok()?;
    algorithm
        .captures(&header)
        .map(|captures| captures[1].to_owned())
}

/// The version byte of a valid Base58Check string.
fn base58check_version(value: &str) -> Option<u8> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes: Vec<u8> = Vec::new();
    for c in value.bytes() {
        let mut carry = u32::try_from(ALPHABET.iter().position(|&a| a == c)?).ok()?;
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading = value.bytes().take_while(|&c| c == b'1').count();
    let mut decoded = vec![0; leading];
    decoded.extend(bytes);
    if decoded.len() != 25 {
        return None;
    }
    let (payload, checksum) = decoded.split_at(21);
    let digest = Sha256::digest(Sha256::digest(payload));
    (digest[..4] == *checksum).then_some(payload[0])
}

fn bech32_valid(value: &str) -> bool {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let Some((hrp, data)) = value.rsplit_once('1') else {
        return false;
    };
    let mut values: Vec<u32> = hrp.bytes().map(|c| u32::from(c >> 5)).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|c| u32::from(c & 31)));
    for c in data.bytes() {
        match CHARSET.iter().position(|&a| a == c) {
            Some(position) => values.push(position as u32),
            None => return false,
        }
    }
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ value;
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    // Bech32 (SegWit v0) or Bech32m (v1+).
    checksum == 1 || checksum == 0x2bc8_30a3
}
