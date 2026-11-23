#!/usr/bin/env python3
"""WithHuman bridge for Cursor CLI.

usage: withhuman-hook.py <WithHuman server> <Cursor hook event>
       withhuman-hook.py --check <WithHuman server>

Cursor runs this for each hook event with the event's JSON on stdin. Everything a bridge shares
with the other agents' is in `withhuman_bridge.py` beside it, which forwards the event to the
Collector's agent route (`/v1/hooks/cursor/<event>`), where it becomes the Claude Code hook the
engine already judges, and prints the answer in the form Cursor reads.

What is Cursor's own, and what this file is:

- Cursor answers in a shape of its own: `permission` with `user_message` and `agent_message` to
  block a call, `additional_context` to add text only the model reads. `output` below maps the
  engine's answer onto it.
- `preToolUse` covers every tool, but it names an MCP call `MCP:<tool>` without saying which
  server. So MCP calls are judged on `beforeMCPExecution`, which carries the server, and the
  `MCP:`-named `preToolUse` is passed over. The server name is remembered for the result, which
  carries neither.
- A file read's text arrives on `beforeReadFile` and is missing from the result, so it is
  remembered for the result too. Without it the engine would judge a read of nothing.
- A subagent runs under a session of its own; the session it belongs to is in its transcript
  path, which is where the parent is read from.
- As the Claude Code hook does, it attaches the local program files a shell command may run.

Environment: WITHHUMAN_CLIENT_ID (else ~/.config/withhuman/client-id), WITHHUMAN_KEY (else
~/.config/withhuman/key), WITHHUMAN_REPO, WITHHUMAN_MODE (enforce | observe),
WITHHUMAN_HOOK_TIMEOUT (seconds for the whole run).

Python 3.8 or later, standard library only; Windows and macOS.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# The shared bridge and the Claude Code hook sit beside this file once installed, and one
# directory up in the repository.
sys.path[:0] = [HERE, os.path.join(HERE, os.pardir, "hooks")]

try:
    import withhuman_bridge as bridge
except BaseException as error:  # noqa: BLE001
    # Nothing here can judge a call without the shared bridge, and an import error would exit 1,
    # which Cursor takes as a failed hook. So the deny is written by hand.
    print(f"WithHuman: {error}", file=sys.stderr)
    if (len(sys.argv) == 3 and sys.argv[2] in ("preToolUse", "beforeMCPExecution")
            and os.environ.get("WITHHUMAN_MODE", "enforce") != "observe"):
        sys.stdout.buffer.write(json.dumps({
            "permission": "deny",
            "user_message": "WithHuman could not check this call, so it was blocked",
            "agent_message": "WithHuman could not check this call, so it was blocked",
        }).encode("utf-8"))
    sys.exit(0)

STATE_DIRECTORY = os.path.join(HERE, "withhuman-state")
# Events the engine judges or records. The rest are registered for what they tell this bridge
# (`beforeReadFile`) or not registered at all.
SENT = ("sessionStart", "sessionEnd", "beforeSubmitPrompt", "preToolUse", "beforeMCPExecution",
        "postToolUse", "postToolUseFailure", "afterAgentResponse", "stop")
# Cursor's name for an MCP call on the tool hooks, which does not say which server.
MCP_PREFIX = "MCP:"
# What Cursor calls its shell tool.
SHELL_TOOL = "Shell"
# A subagent's transcript sits in the folder of the session it was spawned from.
SUBAGENTS = "subagents"


class Session(bridge.State):
    """What this bridge remembers of one Cursor session between its runs.

    Only what Cursor sends on one hook and leaves out of another: the server an MCP call went
    to, and the text a file read brought in. Both are kept against the call's own id and taken
    out again when its result arrives.
    """

    DEFAULTS = {"mcp_servers": {}, "read_contents": {}}
    #: Calls remembered at once, so a long session's state stays small.
    MAX_CALLS = 200

    def remember(self, field, tool_use_id, value):
        if not tool_use_id or value is None:
            return
        kept = self.state[field]
        kept[tool_use_id] = value
        for stale in list(kept)[: max(0, len(kept) - self.MAX_CALLS)]:
            del kept[stale]
        self.save()

    def take(self, field, tool_use_id):
        value = self.state[field].pop(tool_use_id, None)
        if value is not None:
            self.save()
        return value


def parent_session(transcript_path):
    """The session a subagent belongs to, read from its transcript path
    (`…/agent-transcripts/<parent>/subagents/<child>.jsonl`); none when this is not one."""
    if not isinstance(transcript_path, str):
        return None
    parts = transcript_path.replace("\\", "/").split("/")
    if len(parts) < 3 or parts[-2] != SUBAGENTS:
        return None
    return parts[-3] or None


def attach_programs(event):
    """The program files a shell command may run, found from where it runs."""
    try:
        tool_input = event.get("tool_input") or {}
        shown = dict(event, tool_input={"command": tool_input.get("command")},
                     tool_name="PowerShell" if os.name == "nt" else "Bash")
        return bridge.load_programs()(shown)
    except Exception as error:  # noqa: BLE001  (attaching must never keep a call from judgment)
        raise bridge.BridgeError("program attachment failed") from error


class CursorBridge(bridge.Bridge):
    kind = "cursor"
    name = "Cursor"
    # A judged call waits for the engine (intent wait and decision budget), so it gets more
    # time. Both stay below the hook timeouts configure.py writes, so a slow engine ends in
    # this hook's deny rather than in Cursor's timeout.
    deadlines = {"preToolUse": 12.0, "beforeMCPExecution": 12.0}
    default_deadline = 4.0
    blocking_events = ("preToolUse", "beforeMCPExecution")
    probe_event = "preToolUse"
    state_directory = STATE_DIRECTORY

    def extra_headers(self):
        return {"x-withhuman-shell": "powershell" if os.name == "nt" else "posix"}

    # ---- the shape Cursor reads ----

    def deny(self, reason):
        """Blocking a call. `user_message` is what the person sees, `agent_message` what the
        model is told — the engine's reason is written for the model, and seeing it explains
        the block to the person too."""
        return json.dumps({
            "permission": "deny",
            "user_message": reason,
            "agent_message": reason,
        }, ensure_ascii=False).encode("utf-8")

    #: An allowed call has to say so. A hook registered with `failClosed` that answers with
    #: nothing is a failed hook to Cursor, and it blocks the call — so silence, which is how
    #: Claude Code and Codex read an allow, would block everything here.
    ALLOW = json.dumps({"permission": "allow"}).encode("utf-8")

    def decision_of(self, answer):
        return (answer or {}).get("permission")

    def output(self, event, answer):
        """The engine's answer as Cursor reads it. Cursor's `ask` is not carried through to a
        real approval, so anything but an allow blocks."""
        output = (answer or {}).get("hookSpecificOutput")
        if event in self.blocking_events:
            if output is None:
                if answer is not None:
                    raise bridge.BridgeError("Collector answer has no decision")
                # An empty answer is the engine's allow.
                return self.ALLOW
            if not isinstance(output, dict):
                raise bridge.BridgeError("Collector answer has no decision")
            if output.get("permissionDecision") == "allow":
                return self.ALLOW
            reason = output.get("permissionDecisionReason")
            return self.deny(reason if isinstance(reason, str) and reason else bridge.BLOCKED)
        # Text only the model reads: the request for the turn's intent, and the instruction that
        # every prompt carries.
        if isinstance(output, dict) and isinstance(output.get("additionalContext"), str):
            return json.dumps({"additional_context": output["additionalContext"]},
                              ensure_ascii=False).encode("utf-8")
        return None

    # ---- the agent's own part ----

    def self_test(self):
        bridge.load_programs()

    def run(self, collector, event_name, payload):
        try:
            event = json.loads(payload)
        except ValueError as error:
            raise bridge.BridgeError("hook input is not JSON") from error
        if not isinstance(event, dict):
            raise bridge.BridgeError("hook input is not an object")
        session_id = event.get("session_id") or event.get("conversation_id")
        if not isinstance(session_id, str):
            # `workspaceOpen` carries no session, and nothing else the engine wants.
            if event_name == "workspaceOpen":
                return None
            raise bridge.BridgeError("hook input has no session_id")

        parent = parent_session(event.get("transcript_path"))
        if parent and parent != session_id:
            event["withhuman_parent_session"] = parent

        tool_use_id = event.get("tool_use_id")
        tool_name = event.get("tool_name")
        # The state only carries what one hook knows and another needs. Losing it costs the
        # engine that detail, never the judgment, so a parallel run holding the lock is no
        # reason to turn a call back.
        with Session(STATE_DIRECTORY, session_id) as session:
            if event_name == "beforeReadFile":
                session.remember("read_contents", tool_use_id, event.get("content"))
                return None
            if event_name == "beforeMCPExecution":
                session.remember("mcp_servers", tool_use_id, event.get("mcp_server_name"))
            if event_name in ("postToolUse", "postToolUseFailure"):
                if tool_name == "Read":
                    content = session.take("read_contents", tool_use_id)
                    if content is not None:
                        event["withhuman_read_content"] = content
                if isinstance(tool_name, str) and tool_name.startswith(MCP_PREFIX):
                    server = session.take("mcp_servers", tool_use_id)
                    if server is not None:
                        event["withhuman_mcp_server"] = server

        if event_name not in SENT:
            return None
        # An MCP call is judged on `beforeMCPExecution`, the one hook that says which server it
        # goes to; judging it here as well would judge the same call twice.
        if event_name == "preToolUse" and isinstance(tool_name, str) \
                and tool_name.startswith(MCP_PREFIX):
            return None
        if event_name == "preToolUse" and tool_name == SHELL_TOOL:
            programs = attach_programs(event)
            if programs:
                event["withhuman_programs"] = programs
        return collector.post(event_name, event)


if __name__ == "__main__":
    sys.exit(bridge.run_bridge(CursorBridge()))
