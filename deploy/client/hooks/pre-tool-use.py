#!/usr/bin/env python3
"""WithHuman command hook for Claude Code.

Forwards a hook event to the WithHuman Collector, as an HTTP hook would. The setup runs it for
the events that carry content (SessionStart, UserPromptSubmit, PreToolUse, PostToolUse,
PostToolUseFailure), so it can keep a session the security team excepted on this device:

usage: pre-tool-use.py --withhuman-hook <WithHuman server>
       pre-tool-use.py <Collector PreToolUse URL>          (an earlier setup's form)

At a session's start it fetches the exceptions that can cover this device and keeps them a day
(~/.config/withhuman/exceptions.json). When one covers the session's folder (CLAUDE_PROJECT_DIR),
it sends only that the session started and under which exception, and nothing else of it. When
the list cannot be fetched, the cache is dropped and everything is sent.

For PreToolUse it attaches the local program files a Bash command may run, read just before
the call, so the engine can judge the code a script run executes even when the agent never read
the script.

Only files a command could run are attached: an existing regular file named in the command
with a script extension, or an executable one that starts with `#!`. Other files the command
names, such as data or secrets, are never read. The Collector's answer is printed as is, so
Claude Code gets the same allow, deny or ask as from the HTTP hook. When the Collector cannot
be reached the hook exits 1, a non-blocking error, as an unreachable HTTP hook is.

It sends the device's client ID (WITHHUMAN_CLIENT_ID) and the user's WithHuman key
(WITHHUMAN_KEY, as `Authorization: Bearer`). When Claude Code was started without them in its
environment, from an IDE or app for instance, it reads them from ~/.config/withhuman/client-id
and ~/.config/withhuman/key, which the setup wrote: the engine stops a revoked key's calls here.

Python 3.8 or later, standard library only.
"""

import hashlib
import json
import os
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCRIPT_EXTENSIONS = (".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1")
# The Collector keeps at most this many files, each cut to this many bytes.
MAX_PROGRAMS = 8
MAX_BYTES = 64 * 1024
# Larger files are attached without a hash.
MAX_HASHED_BYTES = 16 * 1024 * 1024
TIMEOUT_SECONDS = float(os.environ.get("WITHHUMAN_HOOK_TIMEOUT", "30"))
CONFIG = os.path.join(os.path.expanduser("~"), ".config", "withhuman")
# The security team's exceptions, fetched at each session's start and trusted for a day.
EXCEPTIONS_CACHE = os.path.join(CONFIG, "exceptions.json")
EXCEPTIONS_MAX_AGE = 24 * 3600
EXCEPTIONS_TIMEOUT = 3


def words(command, powershell=False):
    """The words of a shell command; a command shlex cannot split is split at whitespace."""
    try:
        lexer = shlex.shlex(command.replace('\\', '/') if powershell else command,
                            posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command.split()


def directories(tokens, cwd):
    """The directories the command's words may be relative to: its own, then each `cd`."""
    found = [cwd]
    for before, word in zip(tokens, tokens[1:]):
        if before in ("cd", "pushd") and not word.startswith("-"):
            found.append(os.path.normpath(os.path.join(found[-1], os.path.expanduser(word))))
    return found


def is_program(path):
    if not os.path.isfile(path):
        return False
    if path.lower().endswith(SCRIPT_EXTENSIONS):
        return True
    if not os.access(path, os.X_OK):
        return False
    with open(path, "rb") as file:
        return file.read(2) == b"#!"


def program(path):
    """The attachment for the file at `path`, or None for a binary file."""
    size = os.path.getsize(path)
    digest = hashlib.sha256() if size <= MAX_HASHED_BYTES else None
    head = b""
    with open(path, "rb") as file:
        while True:
            chunk = file.read(1 << 16)
            if not chunk:
                break
            if len(head) < MAX_BYTES:
                head += chunk[: MAX_BYTES - len(head)]
            if digest is None:
                if len(head) >= MAX_BYTES:
                    break
            else:
                digest.update(chunk)
    if b"\0" in head[:8192]:
        return None
    attached = {
        "path": path,
        "content": head.decode("utf-8", errors="replace"),
        "size": size,
    }
    if digest is not None:
        attached["sha256"] = digest.hexdigest()
    if size > MAX_BYTES:
        attached["truncated"] = True
    return attached


def programs(event):
    """The program files the event's Bash command may run, at most MAX_PROGRAMS."""
    if event.get("tool_name") not in ("Bash", "PowerShell"):
        return []
    command = (event.get("tool_input") or {}).get("command")
    cwd = event.get("cwd") or os.getcwd()
    if not isinstance(command, str) or not os.path.isabs(cwd):
        return []
    tokens = words(command, powershell=event.get("tool_name") == "PowerShell" or os.name == "nt")
    bases = directories(tokens, cwd)
    found = []
    seen = set()
    for word in tokens:
        if word.startswith("-") or "=" in word.split("/")[0] or not word.strip():
            continue
        for base in reversed(bases):
            path = os.path.normpath(os.path.join(base, os.path.expanduser(word)))
            if path in seen:
                break
            try:
                if not is_program(path):
                    continue
                attached = program(path)
            except OSError:
                continue
            seen.add(path)
            if attached is not None:
                found.append(attached)
            break
        if len(found) >= MAX_PROGRAMS:
            break
    return found


def setting(name, file):
    """The environment variable `name`, else the setup's file of that name."""
    value = os.environ.get(name, "").strip()
    if value:
        return value
    try:
        path = os.path.join(CONFIG, file)
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def under(folder, path):
    """`path` is `folder` or below it, on POSIX or Windows."""
    if not folder or not path:
        return False
    if os.name == "nt" or "\\" in folder:
        folder, path = folder.replace("\\", "/").lower(), path.replace("\\", "/").lower()
    folder = folder.rstrip("/")
    return path == folder or path.startswith(folder + "/")


def fetch_exceptions(server, client_id, key):
    """Refreshes the cached exceptions at a session's start. When they cannot be fetched the
    cache is dropped, so the session is sent whole: a missing list never keeps anything out."""
    try:
        query = urllib.parse.urlencode({"client_id": client_id or ""})
        request = urllib.request.Request(f"{server}/v1/clients/exceptions?{query}",
                                         headers=auth_headers(client_id, key))
        with urllib.request.urlopen(request, timeout=EXCEPTIONS_TIMEOUT) as response:
            found = json.loads(response.read())
        if not isinstance(found, list):
            raise ValueError("not a list")
        os.makedirs(CONFIG, exist_ok=True)
        cached = {"fetched_at": time.time(), "client_id": client_id,
                  "exceptions": [{"id": e.get("id"), "folder": e.get("folder")} for e in found
                                 if isinstance(e, dict) and isinstance(e.get("id"), int)]}
        partial = EXCEPTIONS_CACHE + ".part"
        with open(partial, "w", encoding="utf-8") as handle:
            json.dump(cached, handle)
        os.replace(partial, EXCEPTIONS_CACHE)
    except Exception:  # noqa: BLE001
        try:
            os.remove(EXCEPTIONS_CACHE)
        except OSError:
            pass


def exception_for(folder, client_id):
    """The cached exception covering `folder`, or None. A cache that is missing, unreadable,
    stale or for another device covers nothing."""
    try:
        with open(EXCEPTIONS_CACHE, encoding="utf-8") as handle:
            cached = json.load(handle)
        if time.time() - float(cached["fetched_at"]) > EXCEPTIONS_MAX_AGE:
            return None
        if cached.get("client_id") != client_id:
            return None
        for exception in cached["exceptions"]:
            if exception.get("folder") is None or under(exception["folder"], folder):
                return exception["id"]
    except Exception:  # noqa: BLE001
        return None
    return None


def auth_headers(client_id, key):
    headers = {"Content-Type": "application/json"}
    if client_id:
        headers["x-withhuman-client"] = client_id
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def main():
    # `--withhuman-hook <server>` (any event, posted to <server>/v1/hooks/<event>), or the
    # earlier `<Collector PreToolUse URL>`.
    arguments = sys.argv[1:]
    marked = arguments[:1] == ["--withhuman-hook"]
    if marked:
        arguments = arguments[1:]
    if len(arguments) != 1:
        print("usage: pre-tool-use.py --withhuman-hook <WithHuman server>", file=sys.stderr)
        return 1
    raw = sys.stdin.buffer.read()
    try:
        event = json.loads(raw)
    except ValueError:
        event = None  # Not JSON: forwarded as is, for the Collector to reject.
    name = (event or {}).get("hook_event_name") if isinstance(event, dict) else None
    if marked:
        server = arguments[0].rstrip("/")
        url = f"{server}/v1/hooks/{name or 'PreToolUse'}"
    else:
        url = arguments[0]
        server = url.split("/v1/hooks/")[0]
    client_id = setting("WITHHUMAN_CLIENT_ID", "client-id")
    key = setting("WITHHUMAN_KEY", "key")

    if isinstance(event, dict):
        # A session the security team excepted keeps its start, without content, and nothing
        # else. The project folder is where the session started.
        folder = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd")
        if name == "SessionStart":
            fetch_exceptions(server, client_id, key)
        exception = exception_for(folder, client_id) if marked else None
        if exception is not None:
            if name != "SessionStart":
                return 0
            event = {key_: event[key_] for key_ in ("session_id", "hook_event_name", "source",
                                                    "cwd") if key_ in event}
            event["withhuman_exception"] = exception
            raw = json.dumps(event).encode("utf-8")
        elif name in (None, "PreToolUse"):
            # Reading the programs must never keep the event from being judged.
            try:
                attached = programs(event)
            except Exception as error:  # noqa: BLE001
                print(f"WithHuman: programs not attached: {error}", file=sys.stderr)
                attached = []
            if attached:
                event["withhuman_programs"] = attached
                raw = json.dumps(event).encode("utf-8")

    request = urllib.request.Request(url, data=raw, headers=auth_headers(client_id, key),
                                     method="POST")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        print(f"WithHuman Collector answered {error.code}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError) as error:
        print(f"WithHuman Collector unreachable: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
