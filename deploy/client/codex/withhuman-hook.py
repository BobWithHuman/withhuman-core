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
does not parse, an unknown shell directory, any exception) ends a PreToolUse with a deny, and
exits 2 if even that cannot be written. Other events have nothing to block and only report the
failure on stderr. WITHHUMAN_MODE=observe lets everything through.

Environment: WITHHUMAN_CLIENT_ID (else ~/.config/withhuman/client-id), WITHHUMAN_REPO,
WITHHUMAN_MODE (enforce | observe), WITHHUMAN_HOOK_TIMEOUT (seconds for the whole run).

Python 3.8 or later, standard library only; Windows and macOS.
"""

import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.request

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

    def post(self, event, body):
        """The Collector's answer to `body` on the Codex route: its parsed JSON, or None when
        empty. Raises BridgeError for anything but a 200 in time."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0.05:
            raise BridgeError("no time left")
        request = urllib.request.Request(
            f"{self.server}/v1/hooks/codex/{event}",
            data=json.dumps(body).encode("utf-8"),
            headers=headers(),
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
        shown = dict(event, cwd=workdir or event.get("cwd"), tool_name="Bash")
        return load_programs()(shown)
    except Exception as error:  # noqa: BLE001  (attaching must never keep a call from judgment)
        print(f"WithHuman: programs not attached: {error}", file=sys.stderr)
        return []


def prepare(event_name, event, session, transcript_ok):
    """Adds what the transcript tells about this event's call; raises BridgeError when a shell
    call's directory cannot be known."""
    tool_use_id = event.get("tool_use_id")
    tool_name = event.get("tool_name")
    if event_name not in ("PreToolUse", "PostToolUse") or not tool_use_id:
        return
    call = session.call(tool_use_id) if session else None
    path = event.get("transcript_path")
    deadline = time.monotonic() + TRANSCRIPT_WAIT_SECONDS
    shell = tool_name in codex_transcript.SHELL_TOOLS
    while shell and not call and time.monotonic() < deadline:
        # Codex may still be writing the call: read again, without the session state.
        time.sleep(0.05)
        try:
            call = codex_transcript.find_call(path, tool_use_id)
        except codex_transcript.TranscriptError:
            break
    if shell:
        if call and call.get("workdir"):
            event["withhuman_workdir"] = call["workdir"]
        elif call:
            # The model gave no directory: Codex runs the command in the session's.
            event["withhuman_workdir"] = event.get("cwd")
        elif event_name == "PreToolUse":
            # Without it a relative path would be judged against the project folder, which may
            # not be where the command writes.
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
    with codex_transcript.Session(STATE_DIRECTORY, session_id) as session:
        if event_name == "SessionStart":
            # Earlier history (a resumed session) was judged when it happened.
            session.skip_to(codex_transcript.file_size(path))
        elif main_agent and session.locked:
            # Without the lock another run of this hook is reading the same lines; its events
            # are sent there.
            try:
                before = session.sync(path, session_id, event.get("cwd"))
            except codex_transcript.TranscriptError as error:
                transcript_ok = False
                print(f"WithHuman: transcript not read: {error}", file=sys.stderr)
        if event_name == "Stop" and main_agent:
            last = event.get("last_assistant_message")
            if isinstance(last, str) and last.strip() and last != session.state["last_message"]:
                # The final message, when Codex has not written it to the transcript yet.
                session.state["last_message"] = last
                before.append(("MessageDisplay", {
                    "session_id": session_id, "message_id": f"stop-{event.get('turn_id')}",
                    "index": 0, "delta": last, "final": True}))
        if event_name == "PreToolUse" and event.get("tool_use_id"):
            session.mark_pre(event["tool_use_id"], event.get("tool_name"))
        if event_name == "PostToolUse" and event.get("tool_use_id"):
            session.mark_posted(event["tool_use_id"])
        session.save()
        # Sent in order while the lock is held, so a parallel hook's events do not interleave.
        for synthetic_event, body in before:
            try:
                collector.post(synthetic_event, body)
            except BridgeError as error:
                print(f"WithHuman: {synthetic_event} from transcript not sent: {error}",
                      file=sys.stderr)
        prepare(event_name, event, session, transcript_ok)
    answer = collector.post(event_name, event)
    return codex_output(event_name, answer), 0


def check(server):
    """Checks the hook can run here and reach the engine."""
    load_transcript_module()
    load_programs()
    os.makedirs(STATE_DIRECTORY, exist_ok=True)
    with urllib.request.urlopen(f"{server.rstrip('/')}/healthz", timeout=5) as response:
        if response.status != 200:
            raise BridgeError(f"engine answered {response.status}")
    print(f"WithHuman Codex hook OK: Python {sys.version.split()[0]}, engine {server} reachable")
    return 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        try:
            return check(sys.argv[2])
        except Exception as error:  # noqa: BLE001
            print(f"WithHuman Codex hook check failed: {error}", file=sys.stderr)
            return 1
    event_name = sys.argv[2] if len(sys.argv) == 3 else None
    blocking = event_name == "PreToolUse" and os.environ.get("WITHHUMAN_MODE", "enforce") != "observe"
    try:
        if event_name is None:
            raise BridgeError("usage: withhuman-hook.py <server> <event>")
        output, code = run(sys.argv, sys.stdin.buffer.read())
    except BaseException as error:  # noqa: BLE001  (every failure must end in a decision)
        print(f"WithHuman: {error}", file=sys.stderr)
        if not blocking:
            return 0
        output, code = deny(f"{BLOCKED} ({error})"), 0
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
