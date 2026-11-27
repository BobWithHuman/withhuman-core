#!/usr/bin/env python3
"""WithHuman bridge for OpenClaw.

usage: withhuman-hook.py <OpenClaw hook event>
       withhuman-hook.py --check [<WithHuman server>]

OpenClaw has two hook systems and only one of them can hold a call back. Its automation hooks
carry no tool event and cannot abort what they observe; its **plugin** hooks can. So the client
is a plugin (`index.js` beside this file), and that plugin runs this bridge for each hook with
the event's JSON on stdin. Everything a bridge shares with the other agents' is in
`withhuman_bridge.py`, which forwards the event to the Collector's agent route
(`/v1/hooks/openclaw/<event>`), where it becomes the Claude Code hook the engine already judges.

What is OpenClaw's own, and what this file is:

- The answer is written for `index.js` rather than for OpenClaw: `{"action": "block"|"ask",
  "reason": …}`, or nothing at all for an allow. The plugin turns that into the plugin API's
  own `{block: true, blockReason}` or `{requireApproval: …}`, since only code inside the
  Gateway can answer a plugin hook.
- **The tool hooks name no directory.** Only the turn's hooks carry `workspaceDir`, so it is
  remembered from the turn and filled in on the calls of that turn. Without it a relative path
  in a call resolves against nothing.
- **OpenClaw announces no session.** `session_start` did not fire in any recorded session,
  resumed or not, so the first event of a session this bridge has not seen opens one itself
  (`withhuman_synthesized`).
- As the Claude Code hook does, it attaches the local program files a shell command may run.
- Its state and audit log live in OpenClaw's state directory rather than beside this file: what
  the Gateway loads may be a built copy of the plugin, and state beside the file would be lost
  with that copy.

What the engine asks for and OpenClaw has no carrier for: the standing instruction that every
prompt carries (`additionalContext`). A plugin hook answers a turn with a gate, not with text,
so the instruction is dropped here. The engine still asks a turn for its intent — it turns the
turn's first call back with the request as the reason, which reaches the model as the plugin's
`blockReason` — so an intent line is still arrived at, one round trip later.

Environment: WITHHUMAN_SERVER (else the `server` file beside this hook), WITHHUMAN_CLIENT_ID
(else ~/.config/withhuman/client-id), WITHHUMAN_KEY (else ~/.config/withhuman/key),
WITHHUMAN_REPO, WITHHUMAN_MODE (enforce | observe), WITHHUMAN_HOOK_TIMEOUT (seconds for the
whole run).

Python 3.8 or later, standard library only; Linux, Windows and macOS.
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
    # Nothing here can judge a call without the shared bridge. The plugin reads an empty answer
    # as an allow, so the block is written by hand.
    print(f"WithHuman: {error}", file=sys.stderr)
    if (len(sys.argv) >= 2 and sys.argv[-1] == "before_tool_call"
            and os.environ.get("WITHHUMAN_MODE", "enforce") != "observe"):
        sys.stdout.buffer.write(json.dumps({
            "action": "block",
            "reason": "WithHuman could not check this call, so it was blocked",
        }).encode("utf-8"))
    sys.exit(0)

def state_directory():
    """Where this bridge keeps the session state, the audit log and the outbox.

    Not beside this file: OpenClaw builds a package of a plugin when it installs one, and what
    the Gateway loads may be a copy of it rather than the folder the installer wrote. State
    beside the file would then follow that copy and be lost with it. OpenClaw's own state
    directory does not move, and the engine blocks an agent's changes to it as it does to the
    rest of its configuration.
    """
    configured = os.environ.get("WITHHUMAN_STATE_DIR", "").strip()
    if configured:
        return configured
    root = os.environ.get("OPENCLAW_STATE_DIR", "").strip()
    return os.path.join(root or os.path.join(os.path.expanduser("~"), ".openclaw"),
                        "withhuman-state")


STATE_DIRECTORY = state_directory()
# Events the engine judges or records. The plugin registers these and no others.
SENT = ("session_start", "session_end", "before_agent_run", "before_tool_call",
        "after_tool_call", "before_message_write", "before_agent_finalize", "agent_end")
# The hooks that carry the directory the agent works in; the tool hooks do not.
TURN_EVENTS = ("session_start", "before_agent_run", "before_agent_finalize", "agent_end")
# OpenClaw's own name for its shell tool, and for a tool that runs another tool.
SHELL_TOOL = "exec"
DISPATCH_TOOL = "dispatch_action"


class Session(bridge.State):
    """What this bridge remembers of one OpenClaw session between its runs.

    Only what one hook knows and another needs: the directory the turn works in, which the tool
    hooks leave out, and whether this session has been opened with the engine.
    """

    DEFAULTS = {"workspace_dir": None, "started": False}


def dispatched(tool_call_id):
    """Whether this call is one another call dispatched, and so the duplicate of a call the
    engine judged at the dispatch. `dispatch_action` carries the real tool and its arguments,
    and blocking it keeps the action from running at all."""
    return isinstance(tool_call_id, str) and tool_call_id.startswith("tool_call:")


def attach_programs(event):
    """The program files a shell command may run, found from where it runs."""
    try:
        params = event.get("params") or {}
        shown = dict(event, cwd=params.get("workdir") or event.get("workspaceDir"),
                     tool_input={"command": params.get("command")},
                     tool_name="PowerShell" if os.name == "nt" else "Bash")
        return bridge.load_programs()(shown)
    except Exception as error:  # noqa: BLE001  (attaching must never keep a call from judgment)
        raise bridge.BridgeError("program attachment failed") from error


class OpenClawBridge(bridge.Bridge):
    kind = "openclaw"
    name = "OpenClaw"
    # A judged call waits for the engine (intent wait and decision budget), so it gets more
    # time. Both stay below the timeouts the plugin gives this process, so a slow engine ends in
    # this hook's own answer rather than in the plugin's.
    deadlines = {"before_tool_call": 12.0}
    default_deadline = 4.0
    blocking_events = ("before_tool_call",)
    probe_event = "before_tool_call"
    state_directory = STATE_DIRECTORY

    def extra_headers(self):
        return {"x-withhuman-shell": "powershell" if os.name == "nt" else "posix"}

    # ---- the shape `index.js` reads ----

    def deny(self, reason):
        """Blocking a call. The plugin turns this into the plugin API's `{block: true,
        blockReason}`, which is what OpenClaw shows the model."""
        return json.dumps({"action": "block", "reason": reason},
                          ensure_ascii=False).encode("utf-8")

    def ask(self, reason):
        """Putting a call to the user. OpenClaw pauses the call until they answer and blocks it
        on a deny or a timeout, so a REVIEW can be asked rather than denied."""
        return json.dumps({"action": "ask", "reason": reason},
                          ensure_ascii=False).encode("utf-8")

    def decision_of(self, answer):
        """The decision this bridge's own output carries, for the local audit log. Recording a
        block as an allow would make the only local evidence say the opposite of what
        happened."""
        return {"block": "deny", "ask": "ask"}.get((answer or {}).get("action"))


    def ids_of(self, event):
        """OpenClaw names the session and the call its own way, and a row naming neither could
        not be matched to what the engine recorded."""
        return (event.get("sessionId") or event.get("sessionKey"), event.get("toolCallId"))

    def context(self, text):
        """Text the engine wants the model to read. The plugin keeps it and puts it in front of
        the system context of the turns that follow (`before_prompt_build`), since a plugin hook
        answers a turn with a gate rather than with text."""
        return json.dumps({"action": "context", "text": text},
                          ensure_ascii=False).encode("utf-8")

    def output(self, event, answer):
        """The engine's answer as the plugin reads it.

        A REVIEW is asked of the user rather than denied; everything else that is not an allow
        blocks. An allow is nothing at all, which is how the plugin lets a call through.

        The standing instruction that asks each turn for its `[의도]` line arrives as the
        prompt's `additionalContext`. Nothing can put it into the turn it came with — the
        prompt was built before this Hook ran — so it is handed to the plugin, which keeps it
        for the turns after. The first turn of a Gateway is left without it, and the engine
        asks that turn for its intent by turning its first call back instead.
        """
        output = (answer or {}).get("hookSpecificOutput")
        if event == "before_agent_run":
            text = (output or {}).get("additionalContext") if isinstance(output, dict) else None
            # No instruction means the engine stopped asking for one (intent capture off), and
            # the plugin is told so rather than left repeating the last one it saw.
            return self.context(text if isinstance(text, str) and text.strip() else "")
        if event not in self.blocking_events:
            return None
        if output is None:
            if answer is not None:
                raise bridge.BridgeError("Collector answer has no decision")
            # An empty answer is the engine's allow.
            return None
        if not isinstance(output, dict):
            raise bridge.BridgeError("Collector answer has no decision")
        decision = output.get("permissionDecision")
        if decision == "allow":
            return None
        reason = output.get("permissionDecisionReason")
        reason = reason if isinstance(reason, str) and reason else bridge.BLOCKED
        return self.ask(reason) if decision == "ask" else self.deny(reason)

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
        session_id = event.get("sessionId") or event.get("sessionKey")
        if not isinstance(session_id, str):
            raise bridge.BridgeError("hook input has no sessionId")

        # A call the dispatch already carried: judging it again would record and judge the same
        # work twice, and the engine turns it away as nothing of its own.
        tool_call_id = event.get("toolCallId")
        if event_name in ("before_tool_call", "after_tool_call") and dispatched(tool_call_id):
            return None
        if event_name not in SENT:
            return None

        opening = None
        # The state carries what one hook knows and another needs. Losing it costs the engine
        # that detail, never the judgment, so a parallel run holding the lock is no reason to
        # turn a call back.
        with Session(STATE_DIRECTORY, session_id) as session:
            workspace = event.get("workspaceDir")
            if event_name in TURN_EVENTS and isinstance(workspace, str) and workspace:
                if session.state["workspace_dir"] != workspace:
                    session.state["workspace_dir"] = workspace
                    session.save()
            elif not workspace and session.state["workspace_dir"]:
                # A tool hook: the turn's directory, so a relative path in the call resolves.
                event["workspaceDir"] = session.state["workspace_dir"]
            if not session.state["started"] and event_name != "session_start":
                opening = {
                    "sessionId": session_id,
                    "sessionKey": event.get("sessionKey"),
                    "runId": event.get("runId"),
                    "agentId": event.get("agentId"),
                    "workspaceDir": event.get("workspaceDir"),
                    "modelId": event.get("modelId"),
                    "withhuman_synthesized": True,
                }
            if not session.state["started"]:
                session.state["started"] = True
                session.save()

        if opening is not None:
            # OpenClaw announces no session, so the first event of one opens it. Its answer is
            # nothing the engine blocks on; a failure here loses the session's own record, not
            # the judgment of the call behind it.
            try:
                collector.post("session_start", opening)
            except Exception as error:  # noqa: BLE001
                print(f"WithHuman: session could not be opened ({error})", file=sys.stderr)

        if event_name == "before_tool_call" and event.get("toolName") in (SHELL_TOOL,
                                                                          DISPATCH_TOOL):
            programs = attach_programs(event)
            if programs:
                event["withhuman_programs"] = programs
        return collector.post(event_name, event)


if __name__ == "__main__":
    sys.exit(bridge.run_bridge(OpenClawBridge()))
