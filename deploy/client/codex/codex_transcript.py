"""Reads a Codex session transcript for the WithHuman Codex hook.

Codex's hooks leave out what the engine needs to judge a session the way it judges a Claude
Code one: the assistant's messages (and so the `[의도]` line), where one model response's tool
batch ends, the directory a shell call runs in, whether a command or MCP call failed, and web
searches in setups where they run without a hook. The session transcript (`transcript_path`)
has them. This module is the only code that knows its format, which Codex does not promise to
keep; what it cannot read it leaves out rather than guesses.

Everything in the transcript is data the agent or a web page may have written. It is only
copied into events for the engine to judge, never acted on here.

Checked against Codex CLI 0.154.0 (Windows): `response_item` messages, `function_call`,
`custom_tool_call`, `web_search_call` and their `*_output`, and `event_msg` `item_completed`
items (`CommandExecution`, `McpToolCall`, `FileChange`).

Python 3.8 or later, standard library only.
"""

import hashlib
import json
import os
import re
import time
from urllib.parse import unquote, urlparse

CODEX_VERSION = "0.154.0"

# Codex names for its shell tool, in the transcript and in hooks.
SHELL_TOOLS = ("Bash", "exec_command", "shell", "local_shell", "shell_command", "unified_exec")
# Kept per session, so a long session's state stays small.
MAX_IDS = 500
# Characters of a web result kept for the engine.
MAX_WEB_TEXT = 20000
LOCK_WAIT_SECONDS = 3.0
STALE_LOCK_SECONDS = 30.0


class TranscriptError(Exception):
    """The transcript could not be read."""


def read_records(path, offset):
    """The JSON records of the complete lines after byte `offset`, and the offset after them.

    A line Codex is still writing (no newline yet) is left for the next read. A line that is
    not JSON is skipped.
    """
    if not path:
        raise TranscriptError("no transcript_path")
    try:
        with open(path, "rb") as file:
            size = os.fstat(file.fileno()).st_size
            if offset > size:
                offset = 0  # The file was replaced; read it again.
            file.seek(offset)
            data = file.read()
    except OSError as error:
        raise TranscriptError(str(error)) from error
    end = data.rfind(b"\n") + 1
    records = []
    for line in data[:end].split(b"\n"):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records, offset + end


def file_size(path):
    try:
        return os.path.getsize(path)
    except (OSError, TypeError):
        return 0


def _text(content):
    """The text of a message's content parts."""
    if isinstance(content, str):
        return content
    parts = []
    for part in content if isinstance(content, list) else []:
        if isinstance(part, dict) and isinstance(part.get("text"), str):
            parts.append(part["text"])
    return "".join(parts)


def _path(value):
    """A directory as Codex writes it, possibly a `file:///C:/…` URL, as a local path."""
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("file://"):
        path = unquote(urlparse(value).path)
        if re.match(r"^/[A-Za-z]:", path):
            path = path[1:].replace("/", "\\")
        return path
    return value


def _quoted(name, text):
    """Every `name: "…"` value in code Codex runs (web searches inside its `exec` tool)."""
    found = []
    for match in re.finditer(name + r'\s*:\s*"((?:[^"\\]|\\.)*)"', text):
        try:
            found.append(json.loads('"' + match.group(1) + '"'))
        except ValueError:
            found.append(match.group(1))
    return found


class _Literal:
    """Reads one JavaScript object or array literal (strings, numbers, true/false/null, bare or
    quoted keys) from code Codex runs. Only literals: anything computed fails, and nothing is
    ever evaluated."""

    ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}

    def __init__(self, text, at):
        self.text, self.at = text, at

    def fail(self):
        raise ValueError(f"not a literal at {self.at}")

    def space(self):
        while self.at < len(self.text) and self.text[self.at] in " \t\r\n":
            self.at += 1

    def peek(self):
        self.space()
        return self.text[self.at] if self.at < len(self.text) else ""

    def value(self):
        c = self.peek()
        if c == "{":
            return self.object()
        if c == "[":
            return self.array()
        if c in "\"'`":
            return self.string()
        match = re.compile(r"-?\d+(\.\d+)?|true|false|null").match(self.text, self.at)
        if not match:
            self.fail()
        self.at = match.end()
        return json.loads(match.group(0))

    def string(self):
        quote = self.text[self.at]
        self.at += 1
        out = []
        while self.at < len(self.text):
            c = self.text[self.at]
            self.at += 1
            if c == quote:
                return "".join(out)
            if quote == "`" and c == "$" and self.text[self.at:self.at + 1] == "{":
                self.fail()  # A template with a computed part.
            if c != "\\":
                out.append(c)
                continue
            e = self.text[self.at:self.at + 1]
            self.at += 1
            if e == "u":
                out.append(chr(int(self.text[self.at:self.at + 4], 16)))
                self.at += 4
            elif e == "x":
                out.append(chr(int(self.text[self.at:self.at + 2], 16)))
                self.at += 2
            elif e == "\n":
                pass
            else:
                out.append(self.ESCAPES.get(e, e))
        self.fail()

    def object(self):
        self.at += 1
        found = {}
        while True:
            c = self.peek()
            if c == "}":
                self.at += 1
                return found
            if c in "\"'":
                key = self.string()
            else:
                match = re.compile(r"[A-Za-z_$][\w$]*").match(self.text, self.at)
                if not match:
                    self.fail()
                key, self.at = match.group(0), match.end()
            if self.peek() != ":":
                self.fail()
            self.at += 1
            found[key] = self.value()
            if self.peek() == ",":
                self.at += 1

    def array(self):
        self.at += 1
        found = []
        while True:
            if self.peek() == "]":
                self.at += 1
                return found
            found.append(self.value())
            if self.peek() == ",":
                self.at += 1


# Shell tools a code-mode `exec` script calls, as `tools.<name>({cmd, workdir, …})`.
CODE_SHELL = re.compile(r"tools\.(exec_command|shell_command|shell|local_shell)\s*\(")


def code_shell_calls(source):
    """The shell calls in a code-mode `exec` script, in order, each as `{cmd, workdir}`; a call
    whose arguments are not a plain literal is left out (and its directory stays unknown)."""
    calls = []
    for match in CODE_SHELL.finditer(source):
        try:
            arguments = _Literal(source, match.end()).value()
        except (ValueError, IndexError):
            continue
        if not isinstance(arguments, dict):
            continue
        command = arguments.get("cmd", arguments.get("command"))
        if isinstance(command, list):
            command = " ".join(str(word) for word in command)
        if isinstance(command, str):
            calls.append({"cmd": command, "workdir": _path(arguments.get("workdir"))})
    return calls


def same_command(a, b):
    """Whether two command texts are the same command, line endings and edge space aside."""
    norm = lambda text: text.replace("\r\n", "\n").strip() if isinstance(text, str) else None
    return norm(a) is not None and norm(a) == norm(b)


def _remember(items, value):
    if value not in items:
        items.append(value)
    del items[:-MAX_IDS]


class Session:
    """What the hook remembers of one session between its runs, kept in a JSON file."""

    def __init__(self, directory, session_id):
        key = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
        self.path = os.path.join(directory, key + ".json")
        self.lock_path = self.path + ".lock"
        self.locked = False
        self.state = {
            "offset": 0,
            "calls": {},
            "pre": [],
            "posted": [],
            "messages": [],
            "batch_open": False,
            "webrun_hooked": False,
            "turn_id": None,
            "last_message": None,
            # The directory the turn runs in: where Codex runs a shell call given none.
            "turn_cwd": None,
            # Shell calls inside code-mode `exec` scripts, waiting for their hooks.
            "code_shells": [],
        }

    def __enter__(self):
        """Takes the session's lock, waiting while a parallel hook holds it. Without the lock
        the session is still read but its state is not changed."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                os.close(os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                self.locked = True
                break
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.lock_path) > STALE_LOCK_SECONDS:
                        os.remove(self.lock_path)
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
        try:
            with open(self.path, encoding="utf-8") as file:
                loaded = json.load(file)
            if isinstance(loaded, dict):
                self.state.update(loaded)
        except (OSError, ValueError):
            pass
        return self

    def save(self):
        if not self.locked:
            return
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(self.state, file)
        os.replace(temporary, self.path)

    def __exit__(self, *_):
        if self.locked:
            try:
                os.remove(self.lock_path)
            except OSError:
                pass
            self.locked = False

    # ---- what the hooks themselves say ----

    def mark_pre(self, tool_use_id, tool_name):
        _remember(self.state["pre"], tool_use_id)
        if tool_name == "webrun":
            self.state["webrun_hooked"] = True

    def mark_posted(self, tool_use_id):
        _remember(self.state["posted"], tool_use_id)

    def call(self, call_id):
        return self.state["calls"].get(call_id)

    def shell_call(self, tool_use_id, command):
        """The transcript's entry for a shell call's hook: by its id (a direct call), or, for a
        call a code-mode script makes, whose hook id the transcript does not show until it ends,
        the first such call with the same command text not yet taken by another hook."""
        call = self.state["calls"].get(tool_use_id)
        if call and call.get("kind") == "shell":
            return call
        for entry in self.state["code_shells"]:
            if entry.get("hook") in (None, tool_use_id) and same_command(entry["cmd"], command):
                entry["hook"] = tool_use_id
                call = {"kind": "shell", "name": "exec_command",
                        "workdir": entry.get("workdir") or entry.get("turn_cwd"),
                        "script": entry.get("call_id")}
                self.state["calls"][tool_use_id] = call
                return call
        return None

    # ---- the transcript ----

    def skip_to(self, offset):
        self.state["offset"] = offset

    def sync(self, transcript_path, session_id, cwd):
        """Reads what the transcript added since the last run; the events it makes, in order,
        as `(Codex route event, body)` pairs."""
        records, offset = read_records(transcript_path, self.state["offset"])
        self.state["offset"] = offset
        events = []
        for record in records:
            events.extend(self._record(record, session_id, cwd))
        return events

    def _close_batch(self, session_id):
        if not self.state["batch_open"]:
            return []
        self.state["batch_open"] = False
        return [("PostToolBatch", {"session_id": session_id, "tool_calls": []})]

    def _record(self, record, session_id, cwd):
        kind = record.get("type")
        payload = record.get("payload")
        if not isinstance(payload, dict):
            return []
        item_type = payload.get("type")
        if kind == "turn_context":
            if payload.get("turn_id"):
                self.state["turn_id"] = payload["turn_id"]
            if isinstance(payload.get("cwd"), str):
                self.state["turn_cwd"] = payload["cwd"]
            return []
        if kind == "event_msg" and item_type == "item_completed":
            self._completed(payload.get("item"))
            return []
        if kind != "response_item":
            return []
        meta = payload.get("internal_chat_message_metadata_passthrough") or {}
        turn_id = meta.get("turn_id") or self.state["turn_id"]
        if item_type == "message" and payload.get("role") == "assistant":
            events = self._close_batch(session_id)
            text = _text(payload.get("content"))
            message_id = payload.get("id") or "msg-" + hashlib.sha256(
                text.encode("utf-8")).hexdigest()[:16]
            if text.strip() and message_id not in self.state["messages"]:
                _remember(self.state["messages"], message_id)
                self.state["last_message"] = text
                body = {"session_id": session_id, "message_id": message_id, "index": 0,
                        "delta": text, "final": True}
                if turn_id:
                    body["turn_id"] = turn_id
                events.append(("MessageDisplay", body))
            return events
        if item_type in ("function_call", "custom_tool_call", "web_search_call", "local_shell_call"):
            # A new model response after tool results: the previous batch is over.
            events = self._close_batch(session_id)
            events.extend(self._call(payload, session_id, cwd, turn_id))
            return events
        if item_type in ("function_call_output", "custom_tool_call_output"):
            self.state["batch_open"] = True
            return self._output(payload, session_id, cwd, turn_id)
        return []

    def _call(self, payload, session_id, cwd, turn_id):
        call_id = payload.get("call_id") or payload.get("id")
        if not call_id:
            return []
        item_type = payload.get("type")
        name = payload.get("name") or ""
        call = {"name": name}
        if item_type == "function_call":
            try:
                arguments = json.loads(payload.get("arguments") or "{}")
            except ValueError:
                arguments = {}
            if not isinstance(arguments, dict):
                arguments = {}
            namespace = payload.get("namespace") or ""
            if namespace.startswith("mcp__"):
                call.update(kind="mcp", tool_name=f"{namespace}__{name}", arguments=arguments)
            elif name in SHELL_TOOLS:
                # Without a workdir Codex runs the command in the turn's directory.
                call.update(kind="shell", workdir=_path(arguments.get("workdir"))
                            or self.state["turn_cwd"])
            else:
                call["kind"] = "other"
        elif item_type == "local_shell_call":
            action = payload.get("action") or {}
            call.update(kind="shell", workdir=_path(action.get("working_directory")))
        elif item_type == "custom_tool_call":
            source = payload.get("input") if isinstance(payload.get("input"), str) else ""
            if name == "exec":
                # Code mode: a script that may call shells and the web. Its shell calls get hooks
                # of their own, matched to these by command text.
                for shell in code_shell_calls(source):
                    self.state["code_shells"].append(dict(
                        shell, call_id=call_id, turn_cwd=self.state["turn_cwd"] or cwd,
                        hook=None))
                del self.state["code_shells"][:-MAX_IDS]
            if name == "exec" and "web__run" in source:
                call.update(kind="web", queries=_quoted("q", source), urls=_quoted("ref_id", source))
            elif name == "exec":
                call["kind"] = "code"
            else:
                call["kind"] = "patch" if name == "apply_patch" else "other"
        else:  # web_search_call: no output follows, so it is recorded as it appears.
            action = payload.get("action") or {}
            queries = [q for q in [action.get("query")] + list(action.get("queries") or []) if q]
            urls = [action["url"]] if action.get("url") else []
            self.state["calls"][call_id] = {"name": "web_search", "kind": "web"}
            return self._web(call_id, queries, urls, "", session_id, cwd, turn_id)
        self.state["calls"][call_id] = call
        return []

    def _completed(self, item):
        if not isinstance(item, dict) or not item.get("id"):
            return
        call = self.state["calls"].setdefault(item["id"], {"kind": "other"})
        kind = item.get("type")
        if kind == "CommandExecution":
            call["kind"] = "shell"
            call["status"] = item.get("status")
            call["exit_code"] = item.get("exit_code")
            if not call.get("workdir"):
                call["workdir"] = _path(item.get("cwd"))
        elif kind == "McpToolCall":
            call["kind"] = "mcp"
            call["status"] = item.get("status")
            call.setdefault("tool_name", f"mcp__{item.get('server')}__{item.get('tool')}")
            call.setdefault("arguments", item.get("arguments") or {})
            result = item.get("result") if isinstance(item.get("result"), dict) else {}
            error = item.get("error") or _text(result.get("content"))
            call["error"] = (error if isinstance(error, str) else json.dumps(error))[:2000]
        elif kind == "FileChange":
            call["status"] = item.get("status")
            call["error"] = (item.get("stderr") or item.get("stdout") or "")[:2000]

    def _output(self, payload, session_id, cwd, turn_id):
        call_id = payload.get("call_id")
        call = self.state["calls"].get(call_id)
        if not call:
            return []
        call["output"] = True
        # An MCP call that failed gets no PostToolUse hook; the engine learns of it here.
        if (call.get("kind") == "mcp" and call.get("status") == "failed"
                and call_id in self.state["pre"] and call_id not in self.state["posted"]):
            _remember(self.state["posted"], call_id)
            body = {"session_id": session_id, "cwd": cwd, "hook_event_name": "PostToolUse",
                    "tool_name": call.get("tool_name"), "tool_input": call.get("arguments") or {},
                    "tool_use_id": call_id,
                    "withhuman_failure": call.get("error") or "MCP tool call failed"}
            if turn_id:
                body["turn_id"] = turn_id
            return [("PostToolUse", body)]
        if call.get("kind") == "web":
            text = _text(payload.get("output"))[:MAX_WEB_TEXT]
            return self._web(call_id, call.get("queries") or [], call.get("urls") or [], text,
                             session_id, cwd, turn_id)
        return []

    def _web(self, call_id, queries, urls, text, session_id, cwd, turn_id):
        """A web search the transcript shows, as a recorded call and its result. Only where
        web searches run without a hook: one that had a hook was judged already."""
        if self.state["webrun_hooked"] or (not queries and not urls):
            return []
        tool_input = ({"search_query": [{"q": q} for q in queries]} if queries
                      else {"open": [{"ref_id": u} for u in urls]})
        base = {"session_id": session_id, "cwd": cwd, "tool_name": "webrun",
                "tool_input": tool_input, "tool_use_id": "transcript-" + call_id}
        if turn_id:
            base["turn_id"] = turn_id
        pre = dict(base, hook_event_name="PreToolUse", withhuman_record=True)
        post = dict(base, hook_event_name="PostToolUse", tool_response=text)
        return [("PreToolUse", pre), ("PostToolUse", post)]


def find_call(transcript_path, call_id, command=None, cwd=None):
    """A call's details from a full read of the transcript, without session state: for a hook
    that ran before Codex wrote its call, or that could not take the session lock. A shell
    call is also matched by its command text, as `Session.shell_call` does."""
    probe = Session(".", "probe")  # Never entered: no file is made.
    records, _ = read_records(transcript_path, 0)
    for record in records:
        probe._record(record, "probe", cwd)
    if command is not None:
        return probe.shell_call(call_id, command)
    return probe.state["calls"].get(call_id)
