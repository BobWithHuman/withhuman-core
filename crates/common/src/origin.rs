//! Where agent-visible content came from. Content from outside the workspace (web pages, MCP
//! tools, network commands, downloaded or vendored files) is viewed rendered by a person, so
//! source-level hidden-content rules apply to it; workspace sources are read in an editor.

use std::{
    path::{Component, Path, PathBuf},
    sync::LazyLock,
};

use regex::Regex;
use serde_json::Value;

macro_rules! regex {
    ($pattern:expr) => {{
        static PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
        &*PATTERN
    }};
}

/// Where scanned content came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Workspace files, local command output, prompts and agent messages: read as source.
    Local,
    /// Web pages, MCP tool results, network command output, and files that were downloaded,
    /// vendored or lie outside the workspace: viewed rendered.
    External,
}

/// What is known about the session when judging a tool result.
#[derive(Debug, Clone, Copy, Default)]
pub struct OriginContext<'a> {
    /// The session working directory.
    pub cwd: Option<&'a str>,
    /// Commands, besides the built-in list, whose output comes from the network.
    pub network_commands: &'a [String],
    /// Paths the session wrote downloaded content to (see [`downloaded_paths`]).
    pub downloaded_paths: &'a [String],
}

/// Directories holding third-party code the user neither wrote nor reads.
const VENDORED_DIRECTORIES: &[&str] = &[
    "node_modules",
    "bower_components",
    "vendor",
    "third_party",
    "third-party",
    ".venv",
    "venv",
    "site-packages",
    "dist-packages",
    "Pods",
];

/// Commands that print or save content fetched from the network.
const NETWORK_COMMANDS: &[&str] = &[
    "curl",
    "wget",
    "http",
    "https",
    "xh",
    "lynx",
    "links",
    "w3m",
    "aria2c",
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr",
    "irm",
];

/// Commands that print a file given as an argument.
const FILE_VIEWERS: &[&str] = &[
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "bat",
    "type",
    "get-content",
    "gc",
];

/// The origin of a tool result, from the tool, its input, what it printed and the session.
pub fn tool_origin(
    tool_name: &str,
    tool_input: Option<&Value>,
    output: Option<&str>,
    context: &OriginContext<'_>,
) -> Origin {
    let field = |name: &str| {
        tool_input
            .and_then(|input| input.get(name))
            .and_then(Value::as_str)
    };
    let external = match tool_name {
        "WebFetch" | "WebSearch" => true,
        name if name.starts_with("mcp__") => true,
        "Bash" | "PowerShell" => field("command").is_some_and(|command| {
            command_is_external(command, output.unwrap_or_default(), context)
        }),
        _ => ["file_path", "notebook_path", "path"]
            .into_iter()
            .find_map(field)
            .is_some_and(|path| path_is_external(path, context)),
    };
    if external {
        Origin::External
    } else {
        Origin::Local
    }
}

fn command_is_external(command: &str, output: &str, context: &OriginContext<'_>) -> bool {
    let segments = segments(command);
    let fetches = segments.iter().any(|words| {
        words.iter().enumerate().any(|(index, word)| {
            let program = program_name(word);
            NETWORK_COMMANDS.contains(&program.as_str())
                || context
                    .network_commands
                    .iter()
                    .any(|command| command.eq_ignore_ascii_case(&program))
                || (program == "gh"
                    && words.get(index + 1).is_some_and(|sub| {
                        matches!(sub.as_str(), "api" | "issue" | "pr" | "release" | "gist")
                            || (sub == "repo" && words.get(index + 2).is_some_and(|v| v == "view"))
                    }))
        })
    });
    if fetches {
        return true;
    }
    let arguments: Vec<&str> = segments
        .iter()
        .flat_map(|words| words.iter().skip(1).map(String::as_str))
        .filter(|word| !word.starts_with('-'))
        .collect();
    if arguments.iter().any(|path| path_is_external(path, context)) {
        return true;
    }
    // A local command printing a rendered document it did not read from the workspace most
    // likely fetched it, as `python fetch.py` would.
    let views_workspace_file = segments.first().is_some_and(|words| {
        words
            .first()
            .is_some_and(|word| FILE_VIEWERS.contains(&program_name(word).as_str()))
            && words.len() > 1
    });
    !views_workspace_file && looks_rendered(output)
}

/// The text a tool result shows the agent. Claude Code tools answer with different shapes:
/// Bash `{stdout, stderr}`, Read `{file: {content}}`, WebFetch `{result}`, Grep `{content}`,
/// MCP content blocks `[{type: "text", text}]`, or a plain string.
pub fn tool_output(response: &Value) -> Option<String> {
    match response {
        Value::String(text) => Some(text.clone()),
        Value::Array(blocks) => block_texts(blocks),
        Value::Object(_) => {
            if response.get("stdout").is_some() {
                let parts: Vec<&str> = ["stdout", "stderr"]
                    .into_iter()
                    .filter_map(|field| non_empty(response.get(field)))
                    .collect();
                return (!parts.is_empty()).then(|| parts.join("\n"));
            }
            non_empty(response.pointer("/file/content"))
                .or_else(|| non_empty(response.get("content")))
                .or_else(|| non_empty(response.get("result")))
                .or_else(|| non_empty(response.get("text")))
                .map(str::to_owned)
                .or_else(|| {
                    response
                        .get("content")
                        .and_then(Value::as_array)
                        .and_then(|blocks| block_texts(blocks))
                })
                .or_else(|| {
                    response
                        .get("results")
                        .and_then(Value::as_array)
                        .and_then(|results| search_results(results))
                })
        }
        _ => None,
    }
}

/// WebSearch results: the summaries the search wrote and the title and address of each hit, a
/// paragraph each.
fn search_results(results: &[Value]) -> Option<String> {
    let mut parts = Vec::new();
    for result in results {
        if let Some(summary) = non_empty(Some(result)) {
            parts.push(summary.to_owned());
        }
        let hits = result.get("content").and_then(Value::as_array);
        for hit in hits.into_iter().flatten() {
            let fields: Vec<&str> = ["title", "url"]
                .into_iter()
                .filter_map(|field| non_empty(hit.get(field)))
                .collect();
            if !fields.is_empty() {
                parts.push(fields.join("\n"));
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join("\n\n"))
}

fn non_empty(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// The joined text of MCP content blocks.
fn block_texts(blocks: &[Value]) -> Option<String> {
    let texts: Vec<&str> = blocks
        .iter()
        .filter_map(|block| non_empty(block.get("text")))
        .collect();
    (!texts.is_empty()).then(|| texts.join("\n"))
}

/// Whether text is a web document or an HTTP response rather than source.
pub fn looks_rendered(output: &str) -> bool {
    let head = &output[..floor_boundary(output, output.len().min(4096))];
    regex!(r"(?is)^\s*(?:<!doctype\s+html\b|<html\b)").is_match(head)
        || regex!(r"(?is)<html\b[^>]*>.*?<head\b").is_match(head)
        || regex!(r"(?i)\AHTTP/\d(?:\.\d)?\s+\d{3}\b").is_match(head.trim_start())
}

fn path_is_external(path: &str, context: &OriginContext<'_>) -> bool {
    let path = Path::new(path);
    if path
        .components()
        .any(|component| matches!(component, Component::Normal(name) if VENDORED_DIRECTORIES.iter().any(|dir| name == *dir)))
    {
        return true;
    }
    let Some(cwd) = context.cwd else {
        return false;
    };
    let absolute = resolve(Path::new(cwd), path);
    // Only absolute paths can be judged outside the workspace; a relative one is in it.
    (path.is_absolute() && !absolute.starts_with(cwd))
        || context
            .downloaded_paths
            .iter()
            .any(|downloaded| absolute.starts_with(resolve(Path::new(cwd), Path::new(downloaded))))
}

/// Where a command saves downloaded content: clone directories and output files, resolved
/// against `cwd` and any `cd` earlier in the command.
pub fn downloaded_paths(command: &str, cwd: Option<&str>) -> Vec<String> {
    let mut directory = cwd.map(PathBuf::from);
    let mut paths = Vec::new();
    for words in segments(command) {
        let Some(program) = words.first().map(|word| program_name(word)) else {
            continue;
        };
        let arguments = &words[1..];
        if program == "cd" {
            if let Some(target) = arguments.first() {
                directory = Some(match &directory {
                    Some(directory) => resolve(directory, Path::new(target)),
                    None => PathBuf::from(target),
                });
            }
            continue;
        }
        let destinations = match program.as_str() {
            "git" if arguments.first().is_some_and(|word| word == "clone") => {
                clone_destination(&arguments[1..], GIT_CLONE_VALUE_OPTIONS)
            }
            "gh" if arguments.len() > 2 && arguments[0] == "repo" && arguments[1] == "clone" => {
                clone_destination(&arguments[2..], &[])
            }
            "curl" => curl_destinations(arguments),
            "wget" => wget_destinations(arguments),
            "invoke-webrequest" | "iwr" => {
                option_value(arguments, &["-OutFile"]).into_iter().collect()
            }
            _ => Vec::new(),
        };
        let redirected = NETWORK_COMMANDS
            .contains(&program.as_str())
            .then(|| redirect_target(&words))
            .flatten();
        for destination in destinations.into_iter().chain(redirected) {
            let path = match &directory {
                Some(directory) => resolve(directory, Path::new(&destination)),
                None => PathBuf::from(&destination),
            };
            paths.push(path.to_string_lossy().into_owned());
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

const GIT_CLONE_VALUE_OPTIONS: &[&str] = &[
    "-b",
    "--branch",
    "-o",
    "--origin",
    "-c",
    "--config",
    "--depth",
    "--reference",
    "--template",
    "--separate-git-dir",
    "-j",
    "--jobs",
    "--filter",
    "-u",
    "--upload-pack",
    "--shallow-since",
    "--shallow-exclude",
];

/// The directory a clone creates: the explicit one, or the repository name.
fn clone_destination(arguments: &[String], value_options: &[&str]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut skip = false;
    for argument in arguments {
        if skip {
            skip = false;
        } else if value_options.contains(&argument.as_str()) {
            skip = true;
        } else if !argument.starts_with('-') {
            positional.push(argument.as_str());
        }
    }
    match positional.as_slice() {
        [_, directory, ..] => vec![(*directory).to_owned()],
        [repository] => repository_name(repository).into_iter().collect(),
        [] => Vec::new(),
    }
}

fn repository_name(repository: &str) -> Option<String> {
    let last = repository.trim_end_matches('/').rsplit(['/', ':']).next()?;
    let name = last.trim_end_matches(".git");
    (!name.is_empty()).then(|| name.to_owned())
}

fn curl_destinations(arguments: &[String]) -> Vec<String> {
    let mut destinations: Vec<String> = Vec::new();
    let directory = option_value(arguments, &["--output-dir"]);
    for (index, argument) in arguments.iter().enumerate() {
        let explicit = match argument.as_str() {
            "-o" | "--output" => arguments.get(index + 1).cloned(),
            short if short.starts_with("-o") && short.len() > 2 && !short.starts_with("--") => {
                Some(short[2..].to_owned())
            }
            long => long.strip_prefix("--output=").map(str::to_owned),
        };
        destinations.extend(explicit);
    }
    let remote_name = arguments.iter().any(|argument| {
        argument == "-O" || argument == "--remote-name" || argument == "--remote-name-all"
    });
    if remote_name {
        destinations.extend(
            arguments
                .iter()
                .filter_map(|argument| url_file_name(argument)),
        );
    }
    destinations
        .into_iter()
        .filter(|destination| destination != "-")
        .map(|destination| match &directory {
            Some(directory) => format!("{directory}/{destination}"),
            None => destination,
        })
        .collect()
}

fn wget_destinations(arguments: &[String]) -> Vec<String> {
    if let Some(document) = option_value(arguments, &["-O", "--output-document"]) {
        return if document == "-" {
            Vec::new()
        } else {
            vec![document]
        };
    }
    let directory = option_value(arguments, &["-P", "--directory-prefix"]);
    arguments
        .iter()
        .filter(|argument| argument.contains("://"))
        .map(|argument| url_file_name(argument).unwrap_or_else(|| "index.html".to_owned()))
        .map(|name| match &directory {
            Some(directory) => format!("{directory}/{name}"),
            None => name,
        })
        .collect()
}

/// The value of the first of `names` given as `name value`, `name=value` or `-Xvalue`.
fn option_value(arguments: &[String], names: &[&str]) -> Option<String> {
    arguments.iter().enumerate().find_map(|(index, argument)| {
        names.iter().find_map(|name| {
            if argument.eq_ignore_ascii_case(name) {
                arguments.get(index + 1).cloned()
            } else if let Some(value) = argument.strip_prefix(&format!("{name}=")) {
                Some(value.to_owned())
            } else if name.len() == 2 && !name.starts_with("--") && argument.len() > 2 {
                argument.strip_prefix(name).map(str::to_owned)
            } else {
                None
            }
        })
    })
}

fn url_file_name(argument: &str) -> Option<String> {
    let path = argument.split("://").nth(1)?.split(['?', '#']).next()?;
    let name = path.split_once('/')?.1.rsplit('/').next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

fn redirect_target(words: &[String]) -> Option<String> {
    words
        .iter()
        .enumerate()
        .find_map(|(index, word)| match word.as_str() {
            ">" | ">>" | "1>" => words.get(index + 1).cloned(),
            redirect if redirect.starts_with('>') && redirect.len() > 1 => {
                Some(redirect.trim_start_matches('>').to_owned())
            }
            _ => None,
        })
}

/// The commands of a shell line split at `&&`, `||`, `;` and `|`, as words with quotes removed
/// and leading `VAR=value` assignments dropped.
fn segments(command: &str) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut characters = command.chars().peekable();
    let mut in_word = false;
    let finish_word = |words: &mut Vec<String>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            words.push(std::mem::take(word));
            *in_word = false;
        }
    };
    while let Some(character) = characters.next() {
        match (quote, character) {
            (Some(open), close) if close == open => quote = None,
            (Some(_), other) => word.push(other),
            (None, '\'' | '"') => {
                quote = Some(character);
                in_word = true;
            }
            (None, '&' | '|' | ';' | '\n') => {
                finish_word(&mut words, &mut word, &mut in_word);
                if characters.peek() == Some(&character) {
                    characters.next();
                }
                segments.push(std::mem::take(&mut words));
            }
            (None, whitespace) if whitespace.is_whitespace() => {
                finish_word(&mut words, &mut word, &mut in_word);
            }
            (None, other) => {
                word.push(other);
                in_word = true;
            }
        }
    }
    finish_word(&mut words, &mut word, &mut in_word);
    segments.push(words);
    segments
        .into_iter()
        .map(|words| {
            words
                .into_iter()
                .skip_while(|word| regex!(r"^[A-Za-z_][A-Za-z0-9_]*=").is_match(word))
                .collect::<Vec<_>>()
        })
        .filter(|words| !words.is_empty())
        .collect()
}

/// A command word's program name, lower-cased and without its directory.
fn program_name(word: &str) -> String {
    word.rsplit(['/', '\\'])
        .next()
        .unwrap_or(word)
        .trim_end_matches(".exe")
        .to_ascii_lowercase()
}

/// `path` joined to `base` with `.` and `..` folded, without touching the file system.
fn resolve(base: &Path, path: &Path) -> PathBuf {
    let mut resolved = PathBuf::new();
    for component in base.join(path).components() {
        match component {
            Component::ParentDir => {
                resolved.pop();
            }
            Component::CurDir => {}
            other => resolved.push(other),
        }
    }
    resolved
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}
