#!/usr/bin/env python3
"""WithHuman hook for Codex CLI.

usage: withhuman-hook.py <WithHuman server> <Codex hook event>
       withhuman-hook.py --check <WithHuman server>

Codex runs this for each hook event with the event's JSON on stdin. It forwards the event to
the Collector's Codex route (`/v1/hooks/codex/<event>`), which translates it into the Claude
Code hook the engine already judges, and prints the answer in the form Codex reads.

Before the event it sends what only the client can see, read from the session transcript
(`codex_transcript.py`): the assistant's new messages, so the engine has the turn's `[의도]`
line before it judges a call; the end of a tool batch; and failed MCP calls and unhooked web
searches. It adds the directory a shell call runs in and whether a finished call failed, and,
as the Claude Code hook does, the local program files a shell command may run.

Codex runs a call when its hook fails, times out, exits 1 or answers `ask`. So in enforce mode
every failure here (Collector unreachable or slow, a non-200 answer, an answer or input that
does not parse, any exception) ends a PreToolUse with a deny, and exits 2 if even that cannot
be written. Other events have nothing to block and only report the failure on stderr.
WITHHUMAN_MODE=observe lets everything through.

A shell call whose directory the transcript does not show uniquely is denied. Required events
stay in a durable outbox until the Collector acknowledges their stable delivery IDs.

Environment: WITHHUMAN_CLIENT_ID (else ~/.config/withhuman/client-id), WITHHUMAN_REPO,
WITHHUMAN_MODE (enforce | observe), WITHHUMAN_HOOK_TIMEOUT (seconds for the whole run).

Python 3.8 or later, standard library only; Windows and macOS.
"""

import importlib.util
import copy
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# Imported in `run`, inside the handler that turns any failure into a deny: an import error
# here would exit 1, which Codex takes as a failed hook and runs the call.
codex_transcript = None


def load_transcript_module():
    global codex_transcript
    import codex_transcript as module  # beside this file

    codex_transcript = module

# The whole run, kept below the hook timeouts configure.py writes (15 s and 5 s), so a slow
# engine ends in this hook's deny rather than in Codex's timeout, which lets the call run.
DEADLINE_SECONDS = {"PreToolUse": 12.0}
DEFAULT_DEADLINE_SECONDS = 4.0
# How long a shell call's entry may take to appear in the transcript.
TRANSCRIPT_WAIT_SECONDS = 0.5
STATE_DIRECTORY = os.path.join(HERE, "withhuman-state")
# What a command touching the agent's safeguards names: Codex's and Claude Code's settings and
# hooks, and this hook's files.
SAFEGUARD_MARKS = re.compile(
    r"\.codex|\.claude|hooks\.json|config\.toml|requirements\.toml|settings[\w.-]*\.json"
    r"|withhuman-hook|codex_transcript|withhuman-state|pre-tool-use\.py",
    re.IGNORECASE)
BLOCKED = "WithHuman could not check this call, so it was blocked"


class BridgeError(Exception):
    """Something kept the event from being judged."""


def deny(reason):
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }).encode("utf-8")


def client_id():
    value = os.environ.get("WITHHUMAN_CLIENT_ID", "").strip()
    if value:
        return value
    try:
        path = os.path.join(os.path.expanduser("~"), ".config", "withhuman", "client-id")
        with open(path, encoding="utf-8") as file:
            return file.read().strip() or None
    except OSError:
        return None


def headers():
    found = {
        "Content-Type": "application/json",
        "x-withhuman-shell": "powershell" if os.name == "nt" else "posix",
    }
    if client_id():
        found["x-withhuman-client"] = client_id()
    if os.environ.get("WITHHUMAN_REPO"):
        found["x-withhuman-repo"] = os.environ["WITHHUMAN_REPO"]
    return found


class Collector:
    def __init__(self, server, deadline):
        self.server = server.rstrip("/")
        self.deadline = deadline

    def post(self, event, body, delivery_id=None):
        """The Collector's answer to `body` on the Codex route: its parsed JSON, or None when
        empty. Raises BridgeError for anything but a 200 in time."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0.05:
            raise BridgeError("no time left")
        request = urllib.request.Request(
            f"{self.server}/v1/hooks/codex/{event}",
            data=json.dumps(body).encode("utf-8"),
            headers={**headers(), **({"x-withhuman-event": delivery_id} if delivery_id else {})},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=remaining) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            raise BridgeError(f"Collector answered {error.code}") from error
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise BridgeError(f"Collector unreachable: {error}") from error
        if status != 200:
            raise BridgeError(f"Collector answered {status}")
        if not raw.strip():
            return None
        try:
            answer = json.loads(raw)
        except ValueError as error:
            raise BridgeError("Collector answer is not JSON") from error
        if not isinstance(answer, dict):
            raise BridgeError("Collector answer is not an object")
        return answer


def codex_output(event, answer):
    """The engine's answer as Codex reads it. Codex cannot ask the user, so anything but an
    allow blocks a call."""
    output = (answer or {}).get("hookSpecificOutput")
    if event == "PreToolUse":
        if output is None:
            if answer is not None:
                raise BridgeError("Collector answer has no decision")
            return None
        if not isinstance(output, dict):
            raise BridgeError("Collector answer has no decision")
        decision = output.get("permissionDecision")
        if decision == "allow":
            return None
        reason = output.get("permissionDecisionReason")
        return deny(reason if isinstance(reason, str) and reason else BLOCKED)
    if isinstance(output, dict) and isinstance(output.get("additionalContext"), str):
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": output["additionalContext"],
            }
        }).encode("utf-8")
    return None


def load_programs():
    """`programs()` of the Claude Code PreToolUse hook beside this one, reused as it is."""
    path = os.path.join(HERE, "pre-tool-use.py")
    if not os.path.isfile(path):
        path = os.path.join(HERE, "..", "hooks", "pre-tool-use.py")
    spec = importlib.util.spec_from_file_location("withhuman_pre_tool_use", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.programs


def attach_programs(event, workdir):
    """The program files a shell command may run, found from where it runs."""
    try:
        tool_input = event.get("tool_input") or {}
        shown = dict(event, cwd=workdir or event.get("cwd"),
                     tool_input={"command": tool_input.get("command", tool_input.get("cmd"))},
                     tool_name="PowerShell" if os.name == "nt" else "Bash")
        return load_programs()(shown)
    except Exception as error:  # noqa: BLE001  (attaching must never keep a call from judgment)
        raise BridgeError("program attachment failed") from error


def names_safeguard(command):
    """Whether a command names anything of the agent's safeguards (Codex's or Claude Code's
    settings and hooks, this hook), however it is spelled or where it runs."""
    return isinstance(command, str) and SAFEGUARD_MARKS.search(command) is not None


def prepare(event_name, event, session, transcript_ok):
    """Adds transcript metadata; refuses a shell call with an unknown or ambiguous directory."""
    tool_use_id = event.get("tool_use_id")
    tool_name = event.get("tool_name")
    if event_name not in ("PreToolUse", "PostToolUse") or not tool_use_id:
        return
    path = event.get("transcript_path")
    shell = tool_name in codex_transcript.SHELL_TOOLS
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    command = tool_input.get("command", tool_input.get("cmd"))
    if shell:
        call = session.shell_call(tool_use_id, command) if session else None
    else:
        call = session.call(tool_use_id) if session else None
    deadline = time.monotonic() + TRANSCRIPT_WAIT_SECONDS
    while shell and not call and time.monotonic() < deadline:
        # Codex may still be writing the call, or another run holds the session: read the
        # whole transcript again, without the session state.
        time.sleep(0.05)
        try:
            call = codex_transcript.find_call(path, tool_use_id, command, event.get("cwd"))
        except codex_transcript.TranscriptError:
            break
    if shell:
        if call and call.get("workdir"):
            event["withhuman_workdir"] = call["workdir"]
        elif call:
            # The model gave no directory: Codex runs the command in the session's.
            event["withhuman_workdir"] = event.get("cwd")
        elif event_name == "PreToolUse":
            why = "transcript unreadable" if not transcript_ok else "call not in transcript"
            raise BridgeError(f"directory of the shell call unknown ({why})")
    if event_name == "PreToolUse" and shell:
        programs = attach_programs(event, event.get("withhuman_workdir"))
        if programs:
            event["withhuman_programs"] = programs
    if event_name == "PostToolUse" and call:
        failed = call.get("status") == "failed" or call.get("exit_code") not in (None, 0)
        if failed:
            code = call.get("exit_code")
            event["withhuman_failure"] = (
                f"exit code {code}" if code not in (None, 0) else (call.get("error") or "failed"))


def drain(session, collector):
    """Commit the candidate cursor only after every event has an engine receipt.

    Retrying the exact durable ID retrieves a cached success after a lost reply. A pending
    server receipt returns 409 and requires a new session; it is never applied twice.
    """
    transaction = session.state.get("outbox")
    if not transaction:
        return None
    while transaction["index"] < len(transaction["events"]):
        entry = transaction["events"][transaction["index"]]
        try:
            answer = collector.post(entry["event"], entry["body"], entry["id"])
            # Validate a tool decision before acknowledging it, including replayed responses.
            codex_output(entry["event"], answer)
        except BridgeError as error:
            if "Collector answered" in str(error) or "answer is not" in str(error):
                session.state["resync_required"] = True
            session.save()
            raise
        transaction["answer"] = answer
        transaction["index"] += 1
        session.save()
    answer = transaction.get("answer")
    session.state = transaction["next_state"]
    session.state["outbox"] = None
    session.save()
    return answer


def deliver(session, collector, events, next_state):
    if not events:
        session.state = next_state
        session.save()
        return None
    session.state["outbox"] = {"index": 0, "events": [
        {"event": name, "body": body, "id": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
        for name, body in events], "next_state": next_state}
    session.save()
    return drain(session, collector)


def run(argv, stdin):
    """(stdout bytes or None, exit code) for one hook run; raises on failure."""
    server, event_name = argv[1], argv[2]
    load_transcript_module()
    deadline = time.monotonic() + float(
        os.environ.get("WITHHUMAN_HOOK_TIMEOUT")
        or DEADLINE_SECONDS.get(event_name, DEFAULT_DEADLINE_SECONDS))
    collector = Collector(server, deadline)
    try:
        event = json.loads(stdin)
    except ValueError as error:
        raise BridgeError("hook input is not JSON") from error
    if not isinstance(event, dict) or not isinstance(event.get("session_id"), str):
        raise BridgeError("hook input has no session_id")
    session_id = event["session_id"]
    path = event.get("transcript_path")
    # A subagent's transcript is its own; its messages are not the main agent's turn.
    main_agent = not event.get("agent_id")
    before = []
    transcript_ok = True
    scope = session_id + ("/agent/" + event["agent_id"] if event.get("agent_id") else "")
    with codex_transcript.Session(STATE_DIRECTORY, scope) as session:
        if not session.locked:
            raise BridgeError("session lock unavailable")
        if session.state.get("resync_required"):
            raise BridgeError("session resync required; start a new Codex session")
        drain(session, collector)
        confirmed = copy.deepcopy(session.state)
        if event_name == "SessionStart" and not session.state["offset"]:
            # Earlier history (a resumed session) was judged when it happened.
            session.skip_to(codex_transcript.file_size(path))
        elif main_agent:
            # Without the lock another run of this hook is reading the same lines; its events
            # are sent there.
            try:
                before = session.sync(path, session_id, event.get("cwd"))
            except codex_transcript.TranscriptError as error:
                session.state = confirmed
                raise BridgeError("transcript could not be read") from error
        if event_name == "UserPromptSubmit":
            # A new prompt must arrive before its assistant intent is synced on the next hook.
            # Drop stale-turn synthesized messages, retaining old tool results for their calls.
            before = [(name, body) for name, body in before
                      if name != "MessageDisplay" or body.get("turn_id") == event.get("turn_id")]
            session.state["turn_id"] = event.get("turn_id")
            session.state["last_message"] = None
            session.state["batch_open"] = False
        if event_name == "Stop" and main_agent:
            before.extend(session._close_batch(session_id))
            last = event.get("last_assistant_message")
            if isinstance(last, str) and last.strip() and last != session.state["last_message"]:
                # The final message, when Codex has not written it to the transcript yet.
                session.state["last_message"] = last
                before.append(("MessageDisplay", {
                    "session_id": session_id, "message_id": f"stop-{event.get('turn_id')}",
                    "index": 0, "delta": last, "final": True}))
        candidate = copy.deepcopy(session.state)
        session.state = confirmed
        deliver(session, collector, before, candidate)
        confirmed = copy.deepcopy(session.state)
        if event_name == "PreToolUse" and event.get("tool_use_id"):
            session.mark_pre(event["tool_use_id"], event.get("tool_name"))
        if event_name == "PostToolUse" and event.get("tool_use_id"):
            session.mark_posted(event["tool_use_id"])
        prepare(event_name, event, session, transcript_ok)
        if event_name == "Stop":
            # An empty batch would close unrelated unfinished calls on repeated Stop.
            event = None
        candidate = copy.deepcopy(session.state)
        session.state = confirmed
        answer = deliver(session, collector, [(event_name, event)] if event else [], candidate)
    return codex_output(event_name, answer), 0


def check(server):
    """Checks the hook can run here and that the engine has the Codex route.

    An empty event is sent to the route the hook uses: the Collector rejects it as invalid
    (400) without recording anything. That answer proves the gateway passes the route on and
    the engine knows Codex; `/healthz` would prove neither, and some gateways do not route it.
    """
    load_transcript_module()
    load_programs()
    os.makedirs(STATE_DIRECTORY, exist_ok=True)
    request = urllib.request.Request(
        f"{server.rstrip('/')}/v1/hooks/codex/PreToolUse", data=b"{}",
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    try:
        answer = json.loads(body or b"{}")
    except ValueError:
        answer = {}
    if status == 400 and isinstance(answer, dict) and answer.get("error") in (
            "invalid_json", "invalid_codex_hook"):
        print(f"WithHuman Codex hook OK: Python {sys.version.split()[0]}, "
              f"engine {server} reachable with Codex support")
        return 0
    if status == 404:
        raise BridgeError(f"{server} has no Codex route: update the engine to a version "
                          "with Codex support")
    raise BridgeError(f"{server} answered {status} to the Codex route")


def audit(event_name, payload, output, error=None):
    """Local evidence also exists when the Collector is stopped and cannot store a DENY."""
    try:
        event = json.loads(payload)
        result = json.loads(output) if output else {}
        decision = result.get("hookSpecificOutput", {}).get("permissionDecision")
        row = {"time": time.time(), "session_id": event.get("session_id"),
               "event": event_name, "tool_use_id": event.get("tool_use_id"),
               "decision": decision or ("allow" if event_name == "PreToolUse" else None),
               "source": "bridge_error" if error else "collector",
               "error": str(error)[:300] if error else None}
        os.makedirs(STATE_DIRECTORY, exist_ok=True)
        with open(os.path.join(STATE_DIRECTORY, "audit.jsonl"), "ab") as file:
            file.write((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8"))
    except Exception:
        pass  # Logging cannot change the decision already made.


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        try:
            return check(sys.argv[2])
        except Exception as error:  # noqa: BLE001
            print(f"WithHuman Codex hook check failed: {error}", file=sys.stderr)
            return 1
    event_name = sys.argv[2] if len(sys.argv) == 3 else None
    blocking = event_name == "PreToolUse" and os.environ.get("WITHHUMAN_MODE", "enforce") != "observe"
    payload = sys.stdin.buffer.read()
    failure = None
    try:
        if event_name is None:
            raise BridgeError("usage: withhuman-hook.py <server> <event>")
        output, code = run(sys.argv, payload)
    except BaseException as error:  # noqa: BLE001  (every failure must end in a decision)
        print(f"WithHuman: {error}", file=sys.stderr)
        failure = error
        if not blocking:
            audit(event_name, payload, None, error)
            return 0
        output, code = deny(BLOCKED), 0
    audit(event_name, payload, output, failure)
    try:
        if output:
            sys.stdout.buffer.write(output)
            sys.stdout.buffer.flush()
    except BaseException:  # noqa: BLE001
        # A deny that cannot be written still blocks: Codex blocks on exit 2.
        return 2 if blocking else 0
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001
        sys.exit(2)
