#!/usr/bin/env python3
"""WithHuman bridge for GitHub Copilot CLI.

usage: withhuman-hook.py <Copilot hook event>          (the engine's address sits beside it)
       withhuman-hook.py <WithHuman server> <event>
       withhuman-hook.py --check [<WithHuman server>]

Copilot runs this for each hook event with the event's JSON on stdin. Everything a bridge
shares with the other agents' is in `withhuman_bridge.py` beside it, which forwards the event
to the Collector's agent route (`/v1/hooks/copilot/<event>`), where it becomes the Claude Code
hook the engine already judges, and prints the answer in the form Copilot reads.

What is Copilot's own, and what this file is:

- Copilot sends each event twice, under its own name and under Claude Code's. The installer
  registers Claude Code's, which carry Claude Code's field names and tool names, so there is
  hardly a translation left to make.
- **`PreToolUse` is the only hook Copilot lets stop a call**, and a hook that merely times out
  lets the call run. So this bridge answers on a deadline of its own, well inside the hook
  timeout the installer writes, and every failure ends in a deny rather than in silence.
- No hook carries the model's answer, and the answer is where the turn's `[의도]` line is. It
  is read from the session transcript (`copilot_transcript.py`) and sent in its Claude Code
  form before the event itself, so the engine has the intent before it judges the call.
- No hook carries a turn either. One is minted when a prompt arrives and covers every event
  until the next prompt.
- An MCP call's tool name is `<server>-<tool>`, which cannot be taken apart without knowing
  the server. The server is read from Copilot's MCP configuration, and learned from Copilot's
  own MCP hook for a server configured elsewhere.
- As the Claude Code hook does, it attaches the local program files a shell command may run.

Environment: WITHHUMAN_CLIENT_ID (else ~/.config/withhuman/client-id), WITHHUMAN_KEY (else
~/.config/withhuman/key), WITHHUMAN_REPO, WITHHUMAN_MODE (enforce | observe),
WITHHUMAN_HOOK_TIMEOUT (seconds for the whole run), WITHHUMAN_SERVER (the engine's address),
COPILOT_HOME (Copilot's own directory).

Python 3.8 or later, standard library only; Windows and macOS.
"""

import copy
import json
import os
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
# The shared bridge and the Claude Code hook sit beside this file once installed, and one
# directory up in the repository.
sys.path[:0] = [HERE, os.path.join(HERE, os.pardir, "hooks")]

try:
    import withhuman_bridge as bridge
except BaseException as error:  # noqa: BLE001
    # Nothing here can judge a call without the shared bridge, and an import error would exit
    # 1. Copilot denies a call whose hook exits non-zero, so the deny is already made; writing
    # it by hand says why.
    print(f"WithHuman: {error}", file=sys.stderr)
    if (sys.argv[-1] == "PreToolUse"
            and os.environ.get("WITHHUMAN_MODE", "enforce") != "observe"):
        sys.stdout.buffer.write(json.dumps({
            "permissionDecision": "deny",
            "permissionDecisionReason":
                "WithHuman could not check this call, so it was blocked",
        }).encode("utf-8"))
    sys.exit(0)

# Imported in `run`, inside the handler that turns any failure into a deny: an import error
# here would exit 1 before the deny could say why.
copilot_transcript = None

STATE_DIRECTORY = os.path.join(HERE, "withhuman-state")
#: Events that carry the turn the engine judges a call against.
TURN_EVENTS = ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop")


def load_transcript_module():
    global copilot_transcript
    import copilot_transcript as module  # beside this file

    copilot_transcript = module


def attach_programs(event):
    """The program files a shell command may run, found from where it runs."""
    try:
        tool_input = event.get("tool_input") or {}
        shown = dict(event, tool_input={"command": tool_input.get("command")},
                     tool_name="PowerShell" if os.name == "nt" else "Bash")
        return bridge.load_programs()(shown)
    except Exception as error:  # noqa: BLE001  (attaching must never keep a call from judgment)
        raise bridge.BridgeError("program attachment failed") from error


class CopilotBridge(bridge.Bridge):
    kind = "copilot"
    name = "Copilot"
    # PreToolUse waits for a judgment (intent wait and decision budget), so it gets more time.
    # Both stay below the hook timeouts configure.py writes (15 s and 5 s): Copilot runs a call
    # whose hook timed out, so the answer must be this bridge's own deny, in time.
    deadlines = {"PreToolUse": 12.0}
    default_deadline = 4.0
    state_directory = STATE_DIRECTORY

    def extra_headers(self):
        return {"x-withhuman-shell": "powershell" if os.name == "nt" else "posix"}

    def self_test(self):
        load_transcript_module()
        bridge.load_programs()

    # ---- what Copilot reads ----

    def deny(self, reason):
        """Copilot reads a decision at the top level of the answer, not under Claude Code's
        `hookSpecificOutput`."""
        return json.dumps({
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }).encode("utf-8")

    def context(self, event, text):
        """Copilot takes `additionalContext` at the top level only; under Claude Code's nesting
        it is dropped without a word, and the turn would never state an intent."""
        return json.dumps({"additionalContext": text}, ensure_ascii=False).encode("utf-8")

    def decision_of(self, answer):
        """This bridge's own output carries the decision at the top level; reading Claude
        Code's place would log every deny as an allow."""
        return (answer or {}).get("permissionDecision")

    # ---- one hook ----

    def run(self, collector, event_name, payload):
        load_transcript_module()
        try:
            event = json.loads(payload)
        except ValueError as error:
            raise bridge.BridgeError("hook input is not JSON") from error
        if not isinstance(event, dict):
            raise bridge.BridgeError("hook input is not an object")
        session_id = event.get("session_id") or event.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise bridge.BridgeError("hook input has no session_id")
        # A subagent's events carry its own id as the session and the real one beside it. Both
        # belong to one session: the same state file, and the same transcript.
        parent = event.get("parent_agent_id") or event.get("parentAgentId")
        scope = parent if isinstance(parent, str) and parent else session_id
        path = copilot_transcript.transcript_path(scope)

        with copilot_transcript.Session(STATE_DIRECTORY, scope) as session:
            if not session.locked:
                # Parallel calls each run a hook of their own, at the same time.
                raise bridge.BridgeError("session lock unavailable")
            if session.state.get("resync_required"):
                raise bridge.BridgeError(
                    "session resync required; start a new Copilot session")
            self.drain(session, collector)
            confirmed = copy.deepcopy(session.state)

            # Copilot's own MCP hook is the one place a server names itself. It cannot stop a
            # call, and it runs after the call was judged, so nothing is sent: what it says
            # serves the calls that come after.
            if event_name in ("preMcpToolCall", "PreMcpToolCall"):
                session.learn_server(event.get("serverName") or event.get("server_name"))
                session.save()
                return None

            before = []
            if event_name == "SessionStart":
                # Earlier history (a resumed session) was judged when it happened.
                session.skip_to(bridge.file_size(path))
            else:
                try:
                    before = session.sync(path, scope)
                except bridge.TranscriptError as error:
                    session.state = confirmed
                    raise bridge.BridgeError("transcript could not be read") from error
            if event_name == "UserPromptSubmit":
                # The prompt opens a turn of this bridge's making; answers synced above belong
                # to the turn that just ended.
                session.state["turn"] = uuid.uuid4().hex
            candidate = copy.deepcopy(session.state)
            session.state = confirmed
            self.deliver(session, collector, before, candidate)
            confirmed = copy.deepcopy(session.state)

            self.prepare(event_name, event, session)
            candidate = copy.deepcopy(session.state)
            session.state = confirmed
            return self.deliver(session, collector, [(event_name, event)], candidate)

    def prepare(self, event_name, event, session):
        """Adds what only the client can see: the turn, the server an MCP call goes to, and the
        program files a shell command would run."""
        if event_name in TURN_EVENTS and session.state["turn"]:
            event["withhuman_turn"] = session.state["turn"]
        tool_name = event.get("tool_name")
        if event_name not in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
            return
        servers = copilot_transcript.configured_servers(event.get("cwd"))
        servers.update(session.state["servers"])
        server = copilot_transcript.server_of(tool_name, servers)
        if server:
            event["withhuman_mcp_server"] = server
        if event_name == "PreToolUse" and tool_name in ("Bash", "PowerShell"):
            programs = attach_programs(event)
            if programs:
                event["withhuman_programs"] = programs


if __name__ == "__main__":
    sys.exit(bridge.run_bridge(CopilotBridge()))
