//! Reversibility and immediacy grades of a tool call.
//!
//! The KISA agentic-AI zero-trust guide asks that control strength follow how far an action can
//! be undone and how soon it takes effect, with irreversible actions approved by a person right
//! before they run or by a policy approved beforehand; OWASP's agentic threat guidance likewise
//! asks for human confirmation of irreversible or high-impact actions and warns against wearing
//! that confirmation out. The engine had no grades: whether a call could be undone was one
//! factor of a score, so a destructive call the user asked for scored zero and passed.
//!
//! A grade is set by these rules from the call alone, so the same command always gets the same
//! grade, and both the Collector (when the engine fails) and the Decision use them:
//!
//! | grade | reversibility | effect | examples |
//! |---|---|---|---|
//! | 0 | nothing changes | — | reading, listing, searching, tests, `git status` |
//! | 1 | undone easily, in the workspace | — | editing or creating files, local builds and commits |
//! | 2-1 | partly undoable (some effect stays) | can wait for a person | sending a message out, changing an account or its access, paying, `git push`, opening a PR or issue, sending data out, installing packages, deleting a file, changing security settings |
//! | 2-2 | partly undoable | real-time | operating robots, vehicles, traffic, plant; emergency dispatch and alerts |
//! | 3-1 | cannot be undone | can wait for a person | permanent deletion (recursive, `DROP`/`TRUNCATE`, accounts, records), `push --force`, `reset --hard`, publishing a release or package, an irreversible transfer (crypto), running fetched code, sending data mixed with secrets |
//! | 3-2 | cannot be undone | real-time | irreversible real-time operation |
//!
//! These follow the KISA agentic-AI zero-trust guide's <표 2-5> (0: DB lookups and sensor reads;
//! 1: file and setting changes that can be restored; 2-1: sending messages out, account changes;
//! 2-2: real-time payment, emergency alerts; 3-1: permanent deletion, publishing a contract; 3-2:
//! emergency medical robots, plant emergency stops). Reads stay 0 whatever they read, and edits
//! 1 wherever they write; reading a secret, fetching from the web and editing what runs later are
//! marked [`SENSITIVE`] so they are still checked.
//!
//! A call none of the rules covers has no rule grade; the Decision then grades it from Jev's
//! harm and reversibility answers.

use serde_json::Value;

/// How far a call can be undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reversibility {
    /// Nothing changes.
    None,
    /// Undone easily, inside the workspace.
    Easy,
    /// Hard to undo, or reaches past the workspace.
    Hard,
    /// Cannot be undone.
    Never,
}

/// How urgent a grade-2 or grade-3 call is (the guide's 실시간성): whether a person's approval
/// can be waited for right before it runs (-1) or not (-2, run within a policy approved
/// beforehand).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// There is time to ask a person first: almost every tool call.
    Waitable,
    /// It cannot wait for a person: real-time operation of robots, vehicles, traffic, plant,
    /// emergency dispatch and alerts, real-time payment.
    Realtime,
}

/// A grade: reversibility and, for 2 and 3, when the effect lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Grade {
    pub reversibility: Reversibility,
    pub effect: Effect,
}

impl Grade {
    pub const ZERO: Self = Self::new(Reversibility::None, Effect::Waitable);
    pub const ONE: Self = Self::new(Reversibility::Easy, Effect::Waitable);
    pub const TWO_ONE: Self = Self::new(Reversibility::Hard, Effect::Waitable);
    pub const TWO_TWO: Self = Self::new(Reversibility::Hard, Effect::Realtime);
    pub const THREE_ONE: Self = Self::new(Reversibility::Never, Effect::Waitable);
    pub const THREE_TWO: Self = Self::new(Reversibility::Never, Effect::Realtime);

    pub const fn new(reversibility: Reversibility, effect: Effect) -> Self {
        Self {
            reversibility,
            effect,
        }
    }

    /// 0, 1, 2 or 3.
    pub fn level(self) -> u8 {
        match self.reversibility {
            Reversibility::None => 0,
            Reversibility::Easy => 1,
            Reversibility::Hard => 2,
            Reversibility::Never => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match (self.reversibility, self.effect) {
            (Reversibility::None, _) => "0",
            (Reversibility::Easy, _) => "1",
            (Reversibility::Hard, Effect::Waitable) => "2-1",
            (Reversibility::Hard, Effect::Realtime) => "2-2",
            (Reversibility::Never, Effect::Waitable) => "3-1",
            (Reversibility::Never, Effect::Realtime) => "3-2",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text.trim() {
            "0" => Self::ZERO,
            "1" => Self::ONE,
            "2-1" => Self::TWO_ONE,
            "2-2" => Self::TWO_TWO,
            "3-1" => Self::THREE_ONE,
            "3-2" => Self::THREE_TWO,
            _ => return None,
        })
    }

    /// Strictness order: by reversibility, then real-time over waitable.
    fn rank(self) -> (u8, u8) {
        (
            self.level(),
            u8::from(self.level() >= 2 && self.effect == Effect::Realtime),
        )
    }

    /// Whether the call is real-time (-2): the guide has it run within a pre-approved policy.
    pub fn realtime(self) -> bool {
        self.level() >= 2 && self.effect == Effect::Realtime
    }

    /// The stricter of two grades.
    pub fn max(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    /// The Korean label the user sees in a confirmation.
    pub fn label(self) -> &'static str {
        match self.level() {
            0 => "조회",
            1 => "되돌릴 수 있는 변경",
            2 => "되돌리기 어려운 행동",
            _ => "되돌릴 수 없는 행동",
        }
    }
}

/// A grade with why the rules set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Graded {
    pub grade: Grade,
    /// A short key: `secret_read`, `recursive_delete`, `push_force`…
    pub reason: &'static str,
}

/// Reasons a call of grade 0 or 1 is still never cleared on the first question: the guide
/// grades every read 0 and every file edit 1 but asks for controls by data sensitivity and
/// for what runs later.
pub const SENSITIVE: &[&str] = &["secret_read", "external_fetch", "runs_later"];

/// Whether `reason` is one of [`SENSITIVE`].
pub fn is_sensitive(reason: &str) -> bool {
    SENSITIVE.contains(&reason)
}

impl Graded {
    const fn of(grade: Grade, reason: &'static str) -> Self {
        Self { grade, reason }
    }

    fn max(self, other: Self) -> Self {
        if other.grade.rank() > self.grade.rank() {
            other
        } else {
            self
        }
    }

    /// The Korean description of the reason, for a confirmation.
    pub fn describe(self) -> &'static str {
        match self.reason {
            "read" => "조회",
            "secret_read" => "비밀 파일 내용 읽기",
            "edit" => "작업 공간 파일 수정",
            "delete_file" => "파일 삭제",
            "recursive_delete" => "폴더 통째 삭제",
            "discard_changes" => "변경 내용 버리기",
            "push" => "원격 저장소에 올리기",
            "push_force" => "원격 저장소 강제 덮어쓰기",
            "database_destroy" => "데이터베이스 삭제",
            "cloud_destroy" => "클라우드 자원 삭제",
            "disk_destroy" => "디스크 지우기",
            "send_out" => "외부로 데이터 보내기",
            "send_secret" => "비밀값이 섞인 외부 전송",
            "remote_code" => "외부에서 받은 코드 실행",
            "install" => "패키지 설치",
            "security" => "권한·보안 설정 변경",
            "publish" => "패키지·릴리스 배포",
            "review_request" => "PR·이슈 만들기",
            "runs_later" => "나중에 실행되는 설정 변경",
            "schedule" => "예약 작업 등록",
            "acts" => "외부 서비스에 작용",
            "sends" => "외부 메시지 발송",
            "pays" => "결제·송금",
            "account_change" => "계정·권한 변경",
            "acts_irreversibly" => "되돌릴 수 없는 작용(영구 삭제·공표 등)",
            "acts_in_real_time" => "실시간 운영 작용",
            "crypto_transfer" => "되돌릴 수 없는 송금(암호화폐)",
            "external_fetch" => "외부 조회",
            _ => "규칙에 따른 분류",
        }
    }
}

const CODE_EXTENSIONS: &[&str] = &[
    ".py", ".rs", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".c", ".h",
    ".cc", ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift", ".md", ".rst", ".html", ".css", ".ps1",
    ".sh",
];
const SECRET_NAMES: &[&str] = &[
    "secret",
    "token",
    "credential",
    "password",
    "passwd",
    "canary",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "auth.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".pgpass",
    "api_key",
    "apikey",
    "private_key",
];
const SECRET_EXTENSIONS: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore"];
const NOT_SECRET_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist", ".tmpl"];

/// Whether a path or a command word names a file holding secrets.
pub fn is_secret_path(word: &str) -> bool {
    // `-F f=@.env`, `--data=@key.pem`: the file after the last `=` or `@`.
    let word = word.rsplit(['=', '@']).next().unwrap_or(word);
    let lower = word
        .trim_matches(|c: char| matches!(c, '\'' | '"' | '(' | ')' | ',' | ';'))
        .to_ascii_lowercase()
        .replace('\\', "/");
    if lower.contains("/.aws/credentials") || lower.contains("/.ssh/id_") {
        return true;
    }
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if name.is_empty() || NOT_SECRET_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return false;
    }
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    if SECRET_EXTENSIONS.iter().any(|e| name.ends_with(e)) {
        return true;
    }
    if CODE_EXTENSIONS.iter().any(|e| name.ends_with(e)) {
        return false;
    }
    SECRET_NAMES.iter().any(|secret| name.contains(secret))
}

/// Paths whose content runs later: CI, hooks, scheduled jobs, startup files.
const RUNS_LATER: &[&str] = &[
    ".github/workflows",
    ".gitlab-ci",
    ".circleci",
    "jenkinsfile",
    ".git/hooks",
    "crontab",
    ".bashrc",
    ".zshrc",
    ".profile",
    "profile.ps1",
    ".pre-commit-config",
];

/// The steps of a command line (split at newlines, `;`, `|`, `&` and parentheses), each as its
/// words in lower case with quotes removed. A backslash is kept: it separates a Windows path.
pub fn steps(command: &str) -> Vec<Vec<String>> {
    let mut steps = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    for c in command.to_lowercase().chars() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '`') => {}
            (None, ';' | '|' | '&' | '\n' | '(' | ')' | '{' | '}') => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
                if !words.is_empty() {
                    steps.push(std::mem::take(&mut words));
                }
            }
            (None, c) if c.is_whitespace() || c == ',' => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            (None, c) => word.push(c),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    if !words.is_empty() {
        steps.push(words);
    }
    steps
}

/// Whether a word is a URL or host off this machine.
pub fn remote_address(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    let Some(rest) = lower
        .split_once("://")
        .map(|(_, rest)| rest)
        .or_else(|| lower.strip_prefix("www."))
    else {
        return false;
    };
    let host = rest
        .split(['/', ':', '?'])
        .next()
        .unwrap_or_default()
        .trim_start_matches('[');
    !(host.is_empty()
        || host == "localhost"
        || host.starts_with("127.")
        || host == "::1"
        || host.ends_with(".localhost"))
}

const READ_COMMANDS: &[&str] = &[
    "cat",
    "type",
    "gc",
    "get-content",
    "more",
    "less",
    "head",
    "tail",
    "select-string",
    "sls",
    "findstr",
    "grep",
    "rg",
    "strings",
    "xxd",
    "od",
    "base64",
    "certutil",
    "nl",
    "awk",
    "sed",
    "bat",
    "copy",
    "cp",
    "copy-item",
    "cpi",
];
const NETWORK_COMMANDS: &[&str] = &[
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
    "nc",
    "ncat",
    "netcat",
    "scp",
    "sftp",
    "ftp",
    "ssh",
    "rsync",
    "telnet",
    "start-bitstransfer",
    "send-mailmessage",
];
const DELETE_COMMANDS: &[&str] = &[
    "rm",
    "remove-item",
    "ri",
    "del",
    "erase",
    "rd",
    "rmdir",
    "unlink",
    "shred",
];
const SECURITY_MARKS: &[&str] = &[
    "set-executionpolicy",
    "set-mppreference",
    "netsh advfirewall",
    "icacls",
    "takeown",
    "chmod 777",
    "chmod -r 777",
    "chmod +s",
    "chown",
    "git config --global",
    "reg add",
    "reg delete",
    "setx ",
    "sudo ",
    "--insecure",
    "verify=false",
    "node_tls_reject_unauthorized",
];
const INSTALL_MARKS: &[&str] = &[
    "pip install",
    "pip3 install",
    "npm install",
    "npm i ",
    "yarn add",
    "pnpm add",
    "apt install",
    "apt-get install",
    "brew install",
    "choco install",
    "winget install",
    "install-module",
    "cargo install",
    "gem install",
    "go install",
];
const DATABASE_DESTROY: &[&str] = &[
    "drop database",
    "drop table",
    "drop schema",
    "drop collection",
    "truncate table",
    "truncate ",
    "dropdb",
    "flushall",
    "flushdb",
    ".drop(",
    "deletemany({})",
];
const CLOUD_DESTROY: &[&str] = &[
    "terraform destroy",
    "kubectl delete",
    "helm uninstall",
    "aws s3 rm",
    "aws s3 rb",
    "gsutil rm",
    "az group delete",
    "gcloud projects delete",
    "docker system prune",
    "docker volume rm",
    "docker rm -f",
];
const DISK_DESTROY: &[&str] = &["mkfs", "format-volume", "diskpart", "dd if=", "clear-disk"];
const SCHEDULE_MARKS: &[&str] = &[
    "schtasks /create",
    "register-scheduledtask",
    "new-scheduledtask",
    "crontab ",
    "systemctl enable",
    "at ",
];
const NETWORK_CODE: &[&str] = &[
    "requests.post",
    "requests.put",
    "urllib.request",
    "urlopen(",
    "http.client",
    "httpx.",
    "socket.connect",
    "net.webclient",
    "uploadstring",
    "uploadfile",
    "smtplib",
    "fetch(",
];

/// Whether a DELETE statement has no WHERE: it empties the table.
fn deletes_everything(text: &str) -> bool {
    text.split("delete from").skip(1).any(|rest| {
        let statement = rest.split(';').next().unwrap_or(rest);
        !statement.contains(" where ")
    })
}

/// One step of a shell command, its words in lower case.
fn step(words: &[String], text: &str) -> Graded {
    let Some(first) = words.first() else {
        return Graded::of(Grade::ZERO, "read");
    };
    let command = first.rsplit(['/', '\\']).next().unwrap_or(first);
    let command = command.strip_suffix(".exe").unwrap_or(command);
    let rest: Vec<&str> = words.iter().skip(1).map(String::as_str).collect();
    let has = |flag: &str| rest.contains(&flag);
    let joined = words.join(" ");

    if DELETE_COMMANDS.contains(&command) {
        let recursive = rest.iter().any(|word| {
            matches!(*word, "-recurse" | "/s" | "--recursive" | "-r" | "-R")
                || (word.starts_with('-')
                    && !word.starts_with("--")
                    && word.len() <= 4
                    && word.contains('r')
                    && command == "rm")
        });
        return if recursive {
            Graded::of(Grade::THREE_ONE, "recursive_delete")
        } else {
            Graded::of(Grade::TWO_ONE, "delete_file")
        };
    }
    if command == "git" {
        let sub = rest.first().copied().unwrap_or_default();
        return match sub {
            "push" if has("--force") || has("-f") || joined.contains("--force-with-lease") => {
                Graded::of(Grade::THREE_ONE, "push_force")
            }
            "push" => Graded::of(Grade::TWO_ONE, "push"),
            "reset" if has("--hard") => Graded::of(Grade::THREE_ONE, "discard_changes"),
            "clean" if rest.iter().any(|w| w.starts_with('-') && w.contains('f')) => {
                Graded::of(Grade::THREE_ONE, "discard_changes")
            }
            "checkout" | "restore" if has(".") || has("--") && has(".") => {
                Graded::of(Grade::TWO_ONE, "discard_changes")
            }
            "branch" if has("-d") || has("-D") => Graded::of(Grade::TWO_ONE, "delete_file"),
            "config" if has("--global") || has("--system") => {
                Graded::of(Grade::TWO_ONE, "security")
            }
            "status" | "diff" | "log" | "show" | "blame" | "grep" | "ls-files" | "rev-parse"
            | "describe" | "fetch" => Graded::of(Grade::ZERO, "read"),
            _ => Graded::of(Grade::ONE, "edit"),
        };
    }
    if command == "gh" {
        let sub = rest.join(" ");
        return if sub.starts_with("release create") {
            Graded::of(Grade::THREE_ONE, "publish")
        } else if sub.starts_with("pr merge") {
            Graded::of(Grade::TWO_ONE, "push")
        } else if sub.starts_with("repo delete") || sub.starts_with("release delete") {
            Graded::of(Grade::THREE_ONE, "cloud_destroy")
        } else if sub.starts_with("pr create")
            || sub.starts_with("issue create")
            || sub.starts_with("pr comment")
            || sub.starts_with("issue comment")
        {
            Graded::of(Grade::TWO_ONE, "review_request")
        } else {
            Graded::of(Grade::ZERO, "read")
        };
    }
    if matches!(command, "npm" | "cargo" | "twine" | "poetry") && joined.contains("publish") {
        return Graded::of(Grade::THREE_ONE, "publish");
    }
    if NETWORK_COMMANDS.contains(&command) {
        if words.iter().any(|word| is_secret_path(word))
            || text.contains("$env:") && text.contains("key")
        {
            return Graded::of(Grade::THREE_ONE, "send_secret");
        }
        return if words.iter().any(|word| remote_address(word))
            || matches!(command, "ssh" | "scp" | "sftp" | "ftp" | "rsync")
        {
            Graded::of(Grade::TWO_ONE, "send_out")
        } else {
            Graded::of(Grade::ZERO, "read")
        };
    }
    let names_secret = words.iter().skip(1).any(|word| is_secret_path(word))
        || (words.len() == 1 && is_secret_path(first));
    if names_secret
        && (READ_COMMANDS.contains(&command)
            || joined.contains("readalltext")
            || joined.contains("readalllines")
            || joined.contains("readallbytes")
            || joined.contains("open("))
    {
        return Graded::of(Grade::ZERO, "secret_read");
    }
    if crate::grade::writes(&joined) {
        return Graded::of(Grade::ONE, "edit");
    }
    Graded::of(Grade::ZERO, "read")
}

/// Whether a step writes a file: a redirect, an editing tool or a PowerShell or .NET write.
pub fn writes(text: &str) -> bool {
    const MARKS: &[&str] = &[
        "set-content",
        "add-content",
        "out-file",
        "new-item",
        "move-item",
        "rename-item",
        "writealltext",
        "writealllines",
        "writeallbytes",
        "appendalltext",
        "sed -i",
        "tee ",
        "mv ",
        "mkdir ",
        "touch ",
        ".write(",
        "write_text(",
    ];
    if MARKS.iter().any(|mark| text.contains(mark)) {
        return true;
    }
    let bytes = text.as_bytes();
    let mut index = 0;
    while let Some(offset) = text[index..].find('>') {
        let at = index + offset;
        index = at + 1;
        let before = at.checked_sub(1).map(|i| bytes[i]);
        if matches!(before, Some(b'-' | b'=' | b'<' | b'>' | b'2' | b'&')) {
            continue;
        }
        let rest = text[at + 1..].trim_start_matches('>').trim_start();
        if rest.starts_with('&')
            || rest.starts_with('=')
            || rest.starts_with("$null")
            || rest.starts_with("/dev/null")
            || rest.starts_with("nul")
            || rest.is_empty()
        {
            continue;
        }
        return true;
    }
    false
}

/// The grade of a shell command: its worst step, or the whole line's marks.
pub fn command(command: &str) -> Graded {
    let lower = command.to_lowercase();
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    let all = steps(command);
    let fetching = all.iter().any(|words| {
        words
            .first()
            .is_some_and(|first| NETWORK_COMMANDS.contains(&first.as_str()))
    }) || lower.split_whitespace().any(remote_address)
        || NETWORK_CODE.iter().any(|mark| lower.contains(mark));
    if fetching
        && (compact.contains("|iex")
            || compact.contains("iex(")
            || compact.contains("|sh")
            || compact.contains("|bash")
            || compact.contains("invoke-expression"))
    {
        return Graded::of(Grade::THREE_ONE, "remote_code");
    }
    if DISK_DESTROY.iter().any(|mark| lower.contains(mark)) {
        return Graded::of(Grade::THREE_ONE, "disk_destroy");
    }
    if DATABASE_DESTROY.iter().any(|mark| lower.contains(mark)) || deletes_everything(&lower) {
        return Graded::of(Grade::THREE_ONE, "database_destroy");
    }
    if CLOUD_DESTROY.iter().any(|mark| lower.contains(mark)) {
        return Graded::of(Grade::THREE_ONE, "cloud_destroy");
    }
    let mut worst = all
        .iter()
        .map(|words| step(words, &lower))
        .fold(Graded::of(Grade::ZERO, "read"), Graded::max);
    if SECURITY_MARKS.iter().any(|mark| lower.contains(mark)) {
        worst = worst.max(Graded::of(Grade::TWO_ONE, "security"));
    }
    if INSTALL_MARKS.iter().any(|mark| lower.contains(mark)) {
        worst = worst.max(Graded::of(Grade::TWO_ONE, "install"));
    }
    if SCHEDULE_MARKS.iter().any(|mark| {
        lower.starts_with(mark)
            || lower.contains(&format!(" {mark}"))
            || lower.contains(&format!(";{mark}"))
    }) {
        worst = worst.max(Graded::of(Grade::TWO_ONE, "schedule"));
    }
    // Inline code that sends data out.
    if NETWORK_CODE.iter().any(|mark| lower.contains(mark))
        && lower.split_whitespace().any(remote_address)
    {
        let secret = lower.split_whitespace().any(is_secret_path);
        worst = worst.max(if secret {
            Graded::of(Grade::THREE_ONE, "send_secret")
        } else {
            Graded::of(Grade::TWO_ONE, "send_out")
        });
    }
    worst
}

/// Words of a tool name that act on the world past undoing: paying, sending, deleting,
/// granting.
const IRREVERSIBLE_WORDS: &[&str] = &[
    "delete",
    "remove",
    "drop",
    "destroy",
    "wipe",
    "purge",
    "erase",
    "terminate",
    "publish",
];
/// Words of a tool name that send a message out (the guide's 외부 메시지 발송, 2-1).
const SENDING_WORDS: &[&str] = &["send", "post", "reply", "tweet", "notify", "forward"];
/// Words of a tool name that pay or move money (limited-reversible, 2-1).
const PAYING_WORDS: &[&str] = &[
    "transfer", "pay", "payment", "withdraw", "deposit", "sell", "trade", "purchase", "buy",
];
/// Words of a tool name that change an account or its access (the guide's 계정 변경, 2-1).
const ACCOUNT_WORDS: &[&str] = &[
    "grant", "revoke", "unlock", "ban", "kick", "invite", "assign", "approve", "fill", "autofill",
];
/// Words naming something that cannot be undone when moved (a transfer of these is 3-1).
const IRREVERSIBLE_ASSETS: &[&str] = &[
    "ether", "eth", "bitcoin", "btc", "crypto", "token", "wallet", "coin",
];
/// Words naming real-time operation (the guide's 실시간성 높음: -2).
const REALTIME_WORDS: &[&str] = &[
    "robot",
    "drone",
    "vehicle",
    "traffic",
    "emergency",
    "dispatch",
    "alarm",
    "siren",
    "actuator",
    "valve",
    "motor",
    "plc",
    "scada",
    "factory",
    "plant",
    "realtime",
    "instant",
    "urgent",
];
/// Words of a tool name that change something that is hard to undo.
const ACTING_WORDS: &[&str] = &[
    "execute",
    "dispatch",
    "cancel",
    "shutdown",
    "deepfake",
    "create",
    "update",
    "edit",
    "set",
    "add",
    "write",
    "share",
    "upload",
    "invite",
    "apply",
    "control",
    "move",
    "rename",
    "install",
    "uninstall",
    "enable",
    "disable",
    "reset",
    "book",
    "ship",
    "order",
    "submit",
    "assign",
    "approve",
    "manage",
    "operate",
    "give",
    "lock",
    "modify",
    "change",
    "insert",
    "patch",
    "put",
    "commit",
    "merge",
    "deploy",
    "start",
    "stop",
    "restart",
    "close",
    "turn",
    "go",
    "click",
];
/// Words that end a service's name in a tool name (`BankManager`, `EmergencyDispatchSystem`).
const SERVICE_WORDS: &[&str] = &[
    "manager",
    "system",
    "service",
    "app",
    "home",
    "robot",
    "api",
    "client",
    "assistant",
    "platform",
    "hub",
    "center",
    "portal",
    "bot",
];
/// Words of a tool name that schedule an action.
const SCHEDULING_WORDS: &[&str] = &["schedule", "remind", "queue", "plan"];
/// Words of a tool name that only read.
const READING_WORDS: &[&str] = &[
    "get",
    "list",
    "search",
    "read",
    "find",
    "query",
    "fetch",
    "view",
    "describe",
    "check",
    "verify",
    "show",
    "lookup",
    "browse",
    "retrieve",
    "download",
    "estimate",
    "calculate",
    "predict",
    "compute",
    "preview",
    "validate",
    "track",
    "monitor",
    "scan",
    "status",
    "metadata",
    "count",
    "inspect",
    "analyze",
    "summarize",
    "translate",
    "generate",
    "convert",
    "format",
    "render",
    "compose",
    "draft",
    "parse",
    "extract",
    "scrape",
    "crawl",
    "lint",
    "test",
];

/// The words of a tool name, lower case, split at case changes, `_`, `-`, `.` and `:`.
fn name_words(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    for (at, &c) in chars.iter().enumerate() {
        if matches!(c, '_' | '-' | '.' | ' ' | ':') {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        let previous = at.checked_sub(1).map(|i| chars[i]);
        let next = chars.get(at + 1).copied();
        // A new word starts at an upper-case letter after a lower-case one (`readFile`), or at
        // the last upper-case letter of an acronym before a lower-case one (`FHIRSearch`).
        let boundary = c.is_uppercase()
            && previous.is_some_and(|p| {
                p.is_lowercase()
                    || p.is_ascii_digit()
                    || (p.is_uppercase() && next.is_some_and(char::is_lowercase))
            });
        if boundary && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        word.extend(c.to_lowercase());
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

/// The grade of a tool the rules know only by its name (MCP and service tools).
fn by_name(name: &str) -> Option<Graded> {
    // `mcp__server__tool`: the tool's own name.
    let tool = name.rsplit("__").next().unwrap_or(name);
    let words = name_words(tool);
    let has = |list: &[&str]| words.iter().any(|word| list.contains(&word.as_str()));
    let lists: [&[&str]; 6] = [
        IRREVERSIBLE_WORDS,
        SENDING_WORDS,
        PAYING_WORDS,
        ACCOUNT_WORDS,
        ACTING_WORDS,
        READING_WORDS,
    ];
    let known = |word: &&String| lists.iter().any(|list| list.contains(&word.as_str()));
    // A service name comes first and may hold a verb (`EmergencyDispatchSystem…`,
    // `GoogleHome…`). After a word that ends a service name the tool's verb is the first known
    // one; without such a word, the last known one (`TrafficControlSearchLocations`). A
    // snake_case name reads verb first (`get_payment_summary`, `send_sms`).
    let after_service = words
        .iter()
        .rposition(|word| SERVICE_WORDS.contains(&word.as_str()))
        .map(|at| &words[at + 1..]);
    let snake = tool.contains('_') && !tool.chars().any(char::is_uppercase);
    let verb = match after_service {
        _ if snake => words.iter().find(known),
        Some(rest) if rest.iter().any(|word| known(&word)) => rest.iter().find(known),
        _ => words.iter().rev().find(known),
    };
    let Some(verb) = verb else {
        // Scheduling with no other known verb (`schedule_meeting`): a later action a person
        // can still cancel.
        return has(SCHEDULING_WORDS).then(|| Graded::of(Grade::TWO_ONE, "schedule"));
    };
    let verb = verb.as_str();
    if READING_WORDS.contains(&verb) {
        return Some(Graded::of(Grade::ZERO, "read"));
    }
    // Scheduling a step is the step's own grade (the schedule is not real-time by itself).
    let realtime = has(REALTIME_WORDS);
    let (graded, waitable_reason) = if IRREVERSIBLE_WORDS.contains(&verb) {
        (Grade::THREE_ONE, "acts_irreversibly")
    } else if PAYING_WORDS.contains(&verb) && has(IRREVERSIBLE_ASSETS) {
        (Grade::THREE_ONE, "crypto_transfer")
    } else if PAYING_WORDS.contains(&verb) {
        (Grade::TWO_ONE, "pays")
    } else if SENDING_WORDS.contains(&verb) {
        (Grade::TWO_ONE, "sends")
    } else if ACCOUNT_WORDS.contains(&verb) {
        (Grade::TWO_ONE, "account_change")
    } else {
        (Grade::TWO_ONE, "acts")
    };
    Some(if realtime {
        let grade = if graded.level() >= 3 {
            Grade::THREE_TWO
        } else {
            Grade::TWO_TWO
        };
        Graded::of(grade, "acts_in_real_time")
    } else {
        Graded::of(graded, waitable_reason)
    })
}

/// The rule grade of a call by its tool name and input; none when no rule covers it.
pub fn grade(tool_name: &str, tool_input: &Value) -> Option<Graded> {
    let text = |name: &str| {
        tool_input
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
    };
    let path_grade = |path: &str| {
        let lower = path.to_ascii_lowercase().replace('\\', "/");
        if RUNS_LATER.iter().any(|mark| lower.contains(mark)) {
            Graded::of(Grade::ONE, "runs_later")
        } else {
            Graded::of(Grade::ONE, "edit")
        }
    };
    Some(match tool_name {
        "Read" | "NotebookRead" => {
            let path = match text("file_path") {
                "" => text("notebook_path"),
                path => path,
            };
            if is_secret_path(path) {
                Graded::of(Grade::ZERO, "secret_read")
            } else {
                Graded::of(Grade::ZERO, "read")
            }
        }
        "Grep" => {
            if is_secret_path(text("path")) || is_secret_path(text("glob")) {
                Graded::of(Grade::ZERO, "secret_read")
            } else {
                Graded::of(Grade::ZERO, "read")
            }
        }
        "Glob" | "LS" | "WebSearch" | "TodoWrite" | "TaskOutput" | "ToolSearch" => {
            Graded::of(Grade::ZERO, "read")
        }
        "WebFetch" => Graded::of(Grade::ZERO, "external_fetch"),
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => {
            let path = match text("file_path") {
                "" => text("notebook_path"),
                path => path,
            };
            path_grade(path)
        }
        "apply_patch" => {
            let changes = tool_input.get("changes").and_then(Value::as_array);
            match changes {
                Some(changes) => changes
                    .iter()
                    .filter_map(|change| {
                        let name = change.get("tool_name").and_then(Value::as_str)?;
                        let input = change.get("tool_input")?;
                        grade(name, input)
                    })
                    .fold(Graded::of(Grade::ONE, "edit"), Graded::max),
                None => command(text("command")).max(Graded::of(Grade::ONE, "edit")),
            }
        }
        "Bash" | "PowerShell" | "shell" | "exec_command" => command(text("command")),
        // Delegating and skills are judged by what they then do.
        "Task" | "Agent" | "Skill" => return None,
        name => return by_name(name),
    })
}
