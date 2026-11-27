#!/usr/bin/env python3
"""WithHuman bridge for Codex CLI.

usage: withhuman-hook.py <WithHuman server> <Codex hook event>
       withhuman-hook.py --check <WithHuman server>

Codex runs this for each hook event with the event's JSON on stdin. Everything a bridge shares
with the other agents' is in `withhuman_bridge.py` beside it, which forwards the event to the
Collector's agent route (`/v1/hooks/codex/<event>`), where it becomes the Claude Code hook the
engine already judges, and prints the answer in the form Codex reads.

What is Codex's own, and what this file is:

- Codex has no hook for the assistant's messages, the end of a tool batch, a failed MCP call or
  a web search it ran without a hook, so they are read from the session transcript
  (`codex_transcript.py`) and sent in their Claude Code form, before the event itself: the
  engine has the turn's `[의도]` line before it judges a call.
- A shell hook does not say which directory the command runs in, and a finished call carries no
  exit code, so both are read from the transcript as well. A shell call whose directory the
  transcript does not show uniquely is denied.
- As the Claude Code hook does, it attaches the local program files a shell command may run.

Environment: WITHHUMAN_CLIENT_ID (else ~/.config/withhuman/client-id), WITHHUMAN_KEY (else
~/.config/withhuman/key), WITHHUMAN_REPO, WITHHUMAN_MODE (enforce | observe),
WITHHUMAN_HOOK_TIMEOUT (seconds for the whole run).

Python 3.8 or later, standard library only; Windows and macOS.
"""

import copy
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# The shared bridge and the Claude Code hook sit beside this file once installed, and one
# directory up in the repository.
sys.path[:0] = [HERE, os.path.join(HERE, os.pardir, "hooks")]

try:
    import withhuman_bridge as bridge
except BaseException as error:  # noqa: BLE001
    # Nothing here can judge a call without the shared bridge, and an import error would exit 1,
    # which Codex takes as a failed hook and runs the call. So the deny is written by hand.
    print(f"WithHuman: {error}", file=sys.stderr)
    if (len(sys.argv) == 3 and sys.argv[2] == "PreToolUse"
            and os.environ.get("WITHHUMAN_MODE", "enforce") != "observe"):
        sys.stdout.buffer.write(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "WithHuman could not check this call, so it was blocked",
        }}).encode("utf-8"))
    sys.exit(0)

# Imported in `run`, inside the handler that turns any failure into a deny: an import error
# here would exit 1, which Codex takes as a failed hook and runs the call.
codex_transcript = None


def load_transcript_module():
    global codex_transcript
    import codex_transcript as module  # beside this file

    codex_transcript = module


# How long a shell call's entry may take to appear in the transcript.
TRANSCRIPT_WAIT_SECONDS = 0.5
STATE_DIRECTORY = os.path.join(HERE, "withhuman-state")


def attach_programs(event, workdir):
    """The program files a shell command may run, found from where it runs."""
    try:
        tool_input = event.get("tool_input") or {}
        shown = dict(event, cwd=workdir or event.get("cwd"),
                     tool_input={"command": tool_input.get("command", tool_input.get("cmd"))},
                     tool_name="PowerShell" if os.name == "nt" else "Bash")
        return bridge.load_programs()(shown)
    except Exception as error:  # noqa: BLE001  (attaching must never keep a call from judgment)
        raise bridge.BridgeError("program attachment failed") from error


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
            raise bridge.BridgeError(f"directory of the shell call unknown ({why})")
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


class CodexBridge(bridge.Bridge):
    kind = "codex"
    name = "Codex"
    # PreToolUse waits for a judgment (intent wait and decision budget), so it gets more time.
    # Both stay below the hook timeouts configure.py writes (15 s and 5 s), so a slow engine
    # ends in this hook's deny rather than in Codex's timeout, which lets the call run.
    deadlines = {"PreToolUse": 12.0}
    default_deadline = 4.0
    state_directory = STATE_DIRECTORY

    def extra_headers(self):
        return {"x-withhuman-shell": "powershell" if os.name == "nt" else "posix"}

    def self_test(self):
        load_transcript_module()
        bridge.load_programs()

    def run(self, collector, event_name, payload):
        load_transcript_module()
        try:
            event = json.loads(payload)
        except ValueError as error:
            raise bridge.BridgeError("hook input is not JSON") from error
        if not isinstance(event, dict) or not isinstance(event.get("session_id"), str):
            raise bridge.BridgeError("hook input has no session_id")
        session_id = event["session_id"]
        path = event.get("transcript_path")
        # A subagent's transcript is its own; its messages are not the main agent's turn.
        main_agent = not event.get("agent_id")
        before = []
        transcript_ok = True
        scope = session_id + ("/agent/" + event["agent_id"] if event.get("agent_id") else "")
        with codex_transcript.Session(STATE_DIRECTORY, scope) as session:
            if not session.locked:
                raise bridge.BridgeError("session lock unavailable")
            if session.state.get("resync_required"):
                raise bridge.BridgeError("session resync required; start a new Codex session")
            self.drain(session, collector)
            confirmed = copy.deepcopy(session.state)
            if event_name == "SessionStart" and not session.state["offset"]:
                # Earlier history (a resumed session) was judged when it happened.
                session.skip_to(codex_transcript.file_size(path))
            elif main_agent:
                # Without the lock another run of this hook is reading the same lines; its
                # events are sent there.
                try:
                    before = session.sync(path, session_id, event.get("cwd"))
                except codex_transcript.TranscriptError as error:
                    session.state = confirmed
                    raise bridge.BridgeError("transcript could not be read") from error
            if event_name == "UserPromptSubmit":
                # A new prompt must arrive before its assistant intent is synced on the next
                # hook. Drop stale-turn synthesized messages, retaining old tool results for
                # their calls.
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
            self.deliver(session, collector, before, candidate)
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
            return self.deliver(session, collector,
                                [(event_name, event)] if event else [], candidate)


if __name__ == "__main__":
    sys.exit(bridge.run_bridge(CodexBridge()))
