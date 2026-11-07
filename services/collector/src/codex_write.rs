//! Codex shell commands that only write one file, as the Claude Code call doing the same.
//!
//! Codex 0.167 has no patch tool (`apply_patch_freeform` was removed): it writes files with
//! shell commands such as `Set-Content -LiteralPath 'notes.md' -Value '…'`. A shell call is
//! judged by what it serves; a Claude Code `Write` by the lines it adds, so a line an attacker
//! planted is not lost among the lines asked for. A command that only puts literal text into
//! one file is therefore sent as `Write{file_path, content}` (or, when it appends, as an `Edit`
//! adding that text), so both agents' file writes are judged alike.
//!
//! Only literal content is translated: anything the shell would compute (variables,
//! subexpressions, escapes it interprets), more than one file, wildcards, pipes other than a
//! literal into the writer, and partial edits stay shell calls, judged as before. Around the one
//! write a command may create the directories that hold the file and read the file back; both
//! are part of writing it.

use serde_json::{Value, json};
use withhuman_contracts::codex::CodexShell;

/// One word of a command: plain, or quoted (whose text the shell does not interpret).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Quoted(String),
    Pipe,
    Redirect { append: bool },
}

impl Token {
    fn text(&self) -> Option<&str> {
        match self {
            Self::Word(text) | Self::Quoted(text) => Some(text),
            _ => None,
        }
    }

    fn word_lower(&self) -> Option<String> {
        match self {
            Self::Word(text) => Some(text.to_ascii_lowercase()),
            _ => None,
        }
    }
}

/// A file write a command makes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Written {
    path: String,
    content: String,
    append: bool,
}

/// What one statement of the command does.
enum Step {
    MakeDirectory(String),
    Write(Written),
    ReadBack(String),
}

/// The Claude Code call for a shell command that only writes literal text into one file:
/// `Write{file_path, content}`, or `Edit{file_path, old_string: "", new_string}` for text added
/// to the end of it. Paths are resolved by `key` (the call's directory, `/` separators).
pub fn simple_write(
    command: &str,
    shell: CodexShell,
    key: impl Fn(&str) -> String,
) -> Option<(String, Value)> {
    let statements = statements(command, shell)?;
    let mut directories = Vec::new();
    let mut written: Option<Written> = None;
    for statement in &statements {
        let step = match shell {
            CodexShell::PowerShell => powershell_step(statement)?,
            CodexShell::Posix => posix_step(statement)?,
        };
        match step {
            Step::MakeDirectory(path) if written.is_none() => directories.push(key(&path)),
            Step::Write(write) if written.is_none() => {
                written = Some(Written {
                    path: key(&write.path),
                    ..write
                });
            }
            // Reading the written file back shows the agent what it wrote.
            Step::ReadBack(path) if written.as_ref().is_some_and(|w| w.path == key(&path)) => {}
            _ => return None,
        }
    }
    let written = written?;
    // A directory made beside the file would be a change of its own (`.claude/hooks`, say);
    // only the ones that hold the file are part of writing it.
    let holds = |directory: &String| {
        written
            .path
            .strip_prefix(directory.trim_end_matches('/'))
            .is_some_and(|rest| rest.starts_with('/'))
    };
    if !directories.iter().all(holds) {
        return None;
    }
    if written.append {
        Some((
            "Edit".to_owned(),
            json!({ "file_path": written.path, "old_string": "", "new_string": written.content }),
        ))
    } else {
        Some((
            "Write".to_owned(),
            json!({ "file_path": written.path, "content": written.content }),
        ))
    }
}

/// The result Claude Code's Write or Edit reports for the translated call.
pub fn write_response(tool_name: &str, tool_input: &Value) -> Value {
    let path = tool_input.get("file_path").cloned().unwrap_or(Value::Null);
    if tool_name == "Edit" {
        json!({ "filePath": path, "oldString": "", "newString": tool_input.get("new_string"),
                "replaceAll": false, "structuredPatch": [], "userModified": false })
    } else {
        json!({ "type": "create", "filePath": path, "content": tool_input.get("content"),
                "structuredPatch": [], "originalFile": null, "userModified": false })
    }
}

/// The statements of a command (split at line breaks and `;`, and `&&` for POSIX), each as
/// tokens; none when anything is left that the shell would interpret.
fn statements(command: &str, shell: CodexShell) -> Option<Vec<Vec<Token>>> {
    let chars: Vec<char> = command.chars().collect();
    let mut statements = Vec::new();
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut i = 0;
    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if !word.is_empty() {
            tokens.push(Token::Word(std::mem::take(word)));
        }
    };
    let end = |tokens: &mut Vec<Token>, statements: &mut Vec<Vec<Token>>| {
        if !tokens.is_empty() {
            statements.push(std::mem::take(tokens));
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            '@' if shell == CodexShell::PowerShell && word.is_empty() => {
                // A here-string: `@'` (literal) or `@"`, a line break, the lines, then `'@`
                // (or `"@`) at the start of a line.
                let quote = *chars.get(i + 1)?;
                if quote != '\'' && quote != '"' {
                    return None;
                }
                let mut start = i + 2;
                start += usize::from(chars.get(start) == Some(&'\r'));
                if chars.get(start) != Some(&'\n') {
                    return None;
                }
                let rest: String = chars[start + 1..].iter().collect();
                let mut lines = Vec::new();
                // Characters before the closing line, from just after the opening line break.
                let mut before_close = 0;
                let mut closed = false;
                for line in rest.split('\n') {
                    if line.starts_with(&format!("{quote}@")) {
                        closed = true;
                        break;
                    }
                    before_close += line.chars().count() + 1;
                    lines.push(line.strip_suffix('\r').unwrap_or(line).to_owned());
                }
                if !closed {
                    return None;
                }
                let body = lines.join("\n");
                if quote == '"' && (body.contains('$') || body.contains('`')) {
                    return None;
                }
                tokens.push(Token::Quoted(body));
                // Just past the closing mark: the rest of its line (`| Set-Content f`) follows.
                i = start + 1 + before_close + 2;
                continue;
            }
            '[' if shell == CodexShell::PowerShell && word.is_empty() && tokens.is_empty() => {
                // `[System.IO.File]::WriteAllText('path', 'text')` or `AppendAllText`.
                let (token, next) = dotnet_call(&chars, i)?;
                tokens.extend(token);
                i = next;
                continue;
            }
            '\'' => {
                let mut text = String::new();
                i += 1;
                loop {
                    let c = *chars.get(i)?;
                    if c == '\'' {
                        // PowerShell doubles a quote inside single quotes.
                        if shell == CodexShell::PowerShell && chars.get(i + 1) == Some(&'\'') {
                            text.push('\'');
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    text.push(c);
                    i += 1;
                }
                if !word.is_empty() {
                    return None;
                }
                tokens.push(Token::Quoted(text));
            }
            '"' => {
                let mut text = String::new();
                i += 1;
                loop {
                    let c = *chars.get(i)?;
                    if c == '"' {
                        break;
                    }
                    // Expanded or escaped inside double quotes.
                    if c == '$' || c == '`' || (shell == CodexShell::Posix && c == '\\') {
                        return None;
                    }
                    text.push(c);
                    i += 1;
                }
                if !word.is_empty() {
                    return None;
                }
                tokens.push(Token::Quoted(text));
            }
            '\n' | ';' => {
                flush(&mut word, &mut tokens);
                end(&mut tokens, &mut statements);
            }
            '\r' => {}
            '&' if shell == CodexShell::Posix && chars.get(i + 1) == Some(&'&') => {
                flush(&mut word, &mut tokens);
                end(&mut tokens, &mut statements);
                i += 1;
            }
            '|' => {
                if chars.get(i + 1) == Some(&'|') {
                    return None;
                }
                flush(&mut word, &mut tokens);
                tokens.push(Token::Pipe);
            }
            '>' => {
                flush(&mut word, &mut tokens);
                let append = chars.get(i + 1) == Some(&'>');
                i += usize::from(append);
                tokens.push(Token::Redirect { append });
            }
            '<' if shell == CodexShell::Posix && at(&chars, i, "<<") => {
                // A here-document: its body, up to the delimiter line, is the next token.
                flush(&mut word, &mut tokens);
                i += 2;
                if chars.get(i) == Some(&'-') {
                    return None;
                }
                while chars.get(i) == Some(&' ') {
                    i += 1;
                }
                let quoted = matches!(chars.get(i), Some('\'' | '"'));
                let mark: String = chars[i..]
                    .iter()
                    .take_while(|c| !c.is_whitespace())
                    .collect();
                let delimiter = mark.trim_matches(|c| c == '\'' || c == '"').to_owned();
                if delimiter.is_empty() {
                    return None;
                }
                i += mark.chars().count();
                // The rest of this line belongs to the statement; the body starts on the next.
                let line_end = chars[i..].iter().position(|c| *c == '\n')? + i;
                let rest_of_line: String = chars[i..line_end].iter().collect();
                let body_lines: Vec<String> = chars[line_end + 1..]
                    .iter()
                    .collect::<String>()
                    .split('\n')
                    .map(str::to_owned)
                    .collect();
                let close = body_lines
                    .iter()
                    .position(|line| line.trim_end_matches('\r') == delimiter)?;
                let body: String = body_lines[..close]
                    .iter()
                    .map(|line| format!("{}\n", line.trim_end_matches('\r')))
                    .collect();
                if !quoted && (body.contains('$') || body.contains('`') || body.contains('\\')) {
                    return None;
                }
                let consumed: usize = body_lines[..=close]
                    .iter()
                    .map(|line| line.chars().count() + 1)
                    .sum();
                // Re-read the rest of the line (`> file`) before the body.
                let mut tail = statements_tail(&rest_of_line, shell)?;
                tokens.push(Token::Quoted(body));
                tokens.append(&mut tail);
                i = (line_end + 1 + consumed).min(chars.len());
                flush(&mut word, &mut tokens);
                end(&mut tokens, &mut statements);
                continue;
            }
            c if c.is_whitespace() => flush(&mut word, &mut tokens),
            // Left to the shell: variables, subexpressions and blocks, escapes, globs, arrays,
            // splatting, comments, backgrounding, input redirection, home expansion.
            '$' | '`' | '(' | ')' | '{' | '}' | '*' | '?' | '[' | ']' | ',' | '#' | '&' | '<'
            | '~' | '!' | '@' => return None,
            '\\' if shell == CodexShell::Posix => return None,
            c => word.push(c),
        }
        i += 1;
    }
    flush(&mut word, &mut tokens);
    end(&mut tokens, &mut statements);
    (!statements.is_empty()).then_some(statements)
}

/// The tokens of the rest of a here-document's line (`> file`), which must stay one statement.
fn statements_tail(rest: &str, shell: CodexShell) -> Option<Vec<Token>> {
    if rest.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut parsed = statements(rest, shell)?;
    (parsed.len() == 1).then(|| parsed.remove(0))
}

fn at(chars: &[char], i: usize, text: &str) -> bool {
    text.chars()
        .enumerate()
        .all(|(k, c)| chars.get(i + k) == Some(&c))
}

/// `[System.IO.File]::WriteAllText('path', 'text')` (`[IO.File]`, `AppendAllText`) at `i`,
/// both arguments literal: the tokens `Word(<method>) Quoted(path) Quoted(text)` and the index
/// after the closing parenthesis.
fn dotnet_call(chars: &[char], i: usize) -> Option<(Vec<Token>, usize)> {
    let rest: String = chars[i..].iter().collect::<String>().to_ascii_lowercase();
    let prefix = ["[system.io.file]::", "[io.file]::"]
        .into_iter()
        .find(|prefix| rest.starts_with(prefix))?;
    let after = &rest[prefix.len()..];
    let method = ["writealltext", "appendalltext"]
        .into_iter()
        .find(|method| after.starts_with(&format!("{method}(")))?;
    let mut j = i + prefix.chars().count() + method.len() + 1;
    let literal = |j: &mut usize| -> Option<String> {
        while chars.get(*j).is_some_and(|c| c.is_whitespace()) {
            *j += 1;
        }
        let quote = *chars.get(*j)?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        *j += 1;
        let mut text = String::new();
        loop {
            let c = *chars.get(*j)?;
            *j += 1;
            if c == quote {
                if quote == '\'' && chars.get(*j) == Some(&'\'') {
                    text.push('\'');
                    *j += 1;
                    continue;
                }
                break;
            }
            if quote == '"' && (c == '$' || c == '`') {
                return None;
            }
            text.push(c);
        }
        while chars.get(*j).is_some_and(|c| c.is_whitespace()) {
            *j += 1;
        }
        Some(text)
    };
    let path = literal(&mut j)?;
    if chars.get(j) != Some(&',') {
        return None;
    }
    j += 1;
    let text = literal(&mut j)?;
    // A third argument (an encoding object) is computed by PowerShell.
    if chars.get(j) != Some(&')') {
        return None;
    }
    Some((
        vec![
            Token::Word(format!("[io.file]::{method}")),
            Token::Quoted(path),
            Token::Quoted(text),
        ],
        j + 1,
    ))
}

/// A path that names exactly one file: no wildcards (also kept out by the tokenizer).
fn plain_path(path: &str) -> Option<String> {
    (!path.is_empty() && !path.starts_with('-')).then(|| path.to_owned())
}

fn powershell_step(tokens: &[Token]) -> Option<Step> {
    // `<literal> | <writer>`: the literal is the content.
    if let [value @ Token::Quoted(_), Token::Pipe, rest @ ..] = tokens {
        let write = powershell_writer(rest, value.text())?;
        return Some(Step::Write(write));
    }
    // `<literal> > file`, `Write-Output <literal> > file`, `echo <literal> >> file`.
    if let Some(write) = redirected_echo(tokens, true) {
        return Some(Step::Write(write));
    }
    // `New-Item -ItemType Directory … | Out-Null` (only directory creation; a writer's output
    // piped on is a pipeline of its own).
    let tokens = match tokens {
        [stage @ .., Token::Pipe, Token::Word(sink)]
            if sink.eq_ignore_ascii_case("out-null")
                && stage
                    .first()
                    .and_then(Token::word_lower)
                    .is_some_and(|name| {
                        matches!(name.as_str(), "new-item" | "ni" | "mkdir" | "md")
                    }) =>
        {
            stage
        }
        _ => tokens,
    };
    let name = tokens.first()?.word_lower()?;
    match name.as_str() {
        // .NET writes the text as it is, with no line break added.
        "[io.file]::writealltext" | "[io.file]::appendalltext" => match &tokens[1..] {
            [Token::Quoted(path), Token::Quoted(text)] => Some(Step::Write(Written {
                path: plain_path(path)?,
                content: text.clone(),
                append: name.ends_with("appendalltext"),
            })),
            _ => None,
        },
        "mkdir" | "md" => {
            let options = options(&tokens[1..], &["-path"], &["-force"])?;
            let named = options.value(&["-path"]);
            let path = named.or(options.positional(0))?;
            if options.positional(usize::from(named.is_none())).is_some() {
                return None;
            }
            Some(Step::MakeDirectory(plain_path(path)?))
        }
        "new-item" | "ni" => {
            let options = options(
                &tokens[1..],
                &["-itemtype", "-type", "-path", "-name", "-value"],
                &["-force"],
            )?;
            let kind = options.value(&["-itemtype", "-type"])?.to_ascii_lowercase();
            if options.value(&["-name"]).is_some() {
                return None;
            }
            let named = options.value(&["-path"]);
            let path = plain_path(named.or(options.positional(0))?)?;
            if options.positional(usize::from(named.is_none())).is_some() {
                return None;
            }
            match kind.as_str() {
                "directory" if options.value(&["-value"]).is_none() => {
                    Some(Step::MakeDirectory(path))
                }
                // New-Item writes the value as it is, with no line break added.
                "file" => Some(Step::Write(Written {
                    path,
                    content: options.value(&["-value"]).unwrap_or_default().to_owned(),
                    append: false,
                })),
                _ => None,
            }
        }
        "get-content" | "gc" | "cat" | "type" => {
            let options = options(
                &tokens[1..],
                &["-path", "-literalpath", "-encoding"],
                &["-raw"],
            )?;
            let path = options
                .value(&["-path", "-literalpath"])
                .or(options.positional(0))?;
            if options
                .positional(usize::from(
                    options.value(&["-path", "-literalpath"]).is_none(),
                ))
                .is_some()
            {
                return None;
            }
            Some(Step::ReadBack(plain_path(path)?))
        }
        _ => Some(Step::Write(powershell_writer(tokens, None)?)),
    }
}

/// `Set-Content`/`Add-Content`/`Out-File` writing literal text (from `-Value`/`-InputObject`,
/// a second positional argument, or `piped`) into one file.
fn powershell_writer(tokens: &[Token], piped: Option<&str>) -> Option<Written> {
    let name = tokens.first()?.word_lower()?;
    let (append, path_names, value_names, flags): (bool, &[&str], &[&str], &[&str]) =
        match name.as_str() {
            "set-content" | "sc" => (
                false,
                &["-path", "-literalpath"],
                &["-value"],
                &["-nonewline", "-force"],
            ),
            "add-content" | "ac" => (
                true,
                &["-path", "-literalpath"],
                &["-value"],
                &["-nonewline", "-force"],
            ),
            "out-file" => (
                false,
                &["-filepath", "-literalpath", "-path"],
                &["-inputobject"],
                &["-nonewline", "-force", "-append"],
            ),
            _ => return None,
        };
    let mut names: Vec<&str> = path_names.to_vec();
    names.extend_from_slice(value_names);
    names.push("-encoding");
    let options = options(&tokens[1..], &names, flags)?;
    let named_path = options.value(path_names);
    let path = plain_path(named_path.or(options.positional(0))?)?;
    let value_position = usize::from(named_path.is_none());
    let value = match (
        options.value(value_names),
        options.positional(value_position),
        piped,
    ) {
        (Some(value), None, None) => value,
        (None, Some(value), None) if name != "out-file" => value,
        (None, None, Some(value)) => value,
        _ => return None,
    };
    if options.positional(value_position + 1).is_some() {
        return None;
    }
    let newline = if options.flag("-nonewline") { "" } else { "\n" };
    Some(Written {
        path,
        content: format!("{value}{newline}"),
        append: append || options.flag("-append"),
    })
}

/// Named options with their values, flags and positional arguments of a PowerShell command.
struct Options<'a> {
    named: Vec<(String, &'a str)>,
    flags: Vec<String>,
    positional: Vec<&'a str>,
}

impl Options<'_> {
    fn value(&self, names: &[&str]) -> Option<&str> {
        self.named
            .iter()
            .find(|(name, _)| names.contains(&name.as_str()))
            .map(|(_, value)| *value)
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|flag| flag == name)
    }

    fn positional(&self, index: usize) -> Option<&str> {
        self.positional.get(index).copied()
    }
}

/// Reads a command's arguments; none for an option it does not know or one given twice.
fn options<'a>(tokens: &'a [Token], with_value: &[&str], flags: &[&str]) -> Option<Options<'a>> {
    let mut parsed = Options {
        named: Vec::new(),
        flags: Vec::new(),
        positional: Vec::new(),
    };
    let mut tokens = tokens.iter();
    while let Some(token) = tokens.next() {
        match token {
            Token::Word(word) if word.starts_with('-') => {
                let name = word.to_ascii_lowercase();
                if with_value.contains(&name.as_str()) {
                    if parsed.value(&[name.as_str()]).is_some() {
                        return None;
                    }
                    let value = tokens.next()?.text()?;
                    parsed.named.push((name, value));
                } else if flags.contains(&name.as_str()) && !parsed.flag(&name) {
                    parsed.flags.push(name);
                } else {
                    return None;
                }
            }
            Token::Word(word) | Token::Quoted(word) => parsed.positional.push(word),
            _ => return None,
        }
    }
    Some(parsed)
}

/// `echo <literal> > file` (POSIX and PowerShell), `Write-Output <literal> > file` and
/// `<literal> > file` (PowerShell).
fn redirected_echo(tokens: &[Token], powershell: bool) -> Option<Written> {
    let (before, append, path) = match tokens {
        [before @ .., Token::Redirect { append }, target] => (before, *append, target.text()?),
        _ => return None,
    };
    let text = match before {
        [Token::Quoted(text)] if powershell => format!("{text}\n"),
        [Token::Word(echo), Token::Quoted(text)]
            if matches!(echo.to_ascii_lowercase().as_str(), "echo" | "write-output") =>
        {
            format!("{text}\n")
        }
        [Token::Word(echo), Token::Word(n), Token::Quoted(text)]
            if !powershell && echo == "echo" && n == "-n" =>
        {
            text.clone()
        }
        // `printf '%s\n' '<text>'`, `printf '%s' '<text>'`, or a format with no conversions or
        // escapes.
        [
            Token::Word(printf),
            Token::Quoted(format),
            Token::Quoted(text),
        ] if !powershell && printf == "printf" && (format == "%s\\n" || format == "%s") => {
            if format == "%s" {
                text.clone()
            } else {
                format!("{text}\n")
            }
        }
        [Token::Word(printf), Token::Quoted(text)]
            if !powershell && printf == "printf" && !text.contains(['%', '\\']) =>
        {
            text.clone()
        }
        _ => return None,
    };
    Some(Written {
        path: plain_path(path)?,
        content: text,
        append,
    })
}

fn posix_step(tokens: &[Token]) -> Option<Step> {
    if let Some(write) = redirected_echo(tokens, false) {
        return Some(Step::Write(write));
    }
    let name = tokens.first()?.word_lower()?;
    match name.as_str() {
        "mkdir" => {
            let mut path = None;
            for token in &tokens[1..] {
                match token {
                    Token::Word(flag) if flag == "-p" => {}
                    token if path.is_none() => path = Some(plain_path(token.text()?)?),
                    _ => return None,
                }
            }
            Some(Step::MakeDirectory(path?))
        }
        // `cat > file <<'EOF'` / `cat <<'EOF' > file`: the body token sits before the
        // redirection once the here-document is read.
        "cat" | "tee" => match &tokens[1..] {
            [Token::Quoted(body), Token::Redirect { append }, target] if name == "cat" => {
                Some(Step::Write(Written {
                    path: plain_path(target.text()?)?,
                    content: body.clone(),
                    append: *append,
                }))
            }
            [Token::Redirect { append }, target, Token::Quoted(body)] if name == "cat" => {
                Some(Step::Write(Written {
                    path: plain_path(target.text()?)?,
                    content: body.clone(),
                    append: *append,
                }))
            }
            [Token::Word(target), Token::Quoted(body)] if name == "tee" => {
                Some(Step::Write(Written {
                    path: plain_path(target)?,
                    content: body.clone(),
                    append: false,
                }))
            }
            [Token::Word(target)] if name == "cat" => Some(Step::ReadBack(plain_path(target)?)),
            _ => None,
        },
        _ => None,
    }
}
