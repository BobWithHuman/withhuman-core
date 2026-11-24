#!/usr/bin/env python3
"""WithHuman bridge for Hermes Agent.

usage: withhuman-hook.py <WithHuman server> <Hermes hook>
       withhuman-hook.py --check <WithHuman server>

The WithHuman plugin (`__init__.py` beside this file) runs this for each Hermes hook it forwards,
with the hook's keyword arguments as JSON on stdin and what only the plugin can know already added
(the session's directory, the engine's session, the subagent, the directory a command runs in).
Everything a bridge shares with the other agents' is in `withhuman_bridge.py`: this forwards the
hook to the Collector's agent route (`/v1/hooks/hermes/<hook>`), where it becomes the Claude Code
hook the engine already judges, and prints the answer in Claude Code's form, which the plugin
reads. In enforce mode every failure of a `pre_tool_call` ends in a deny.

What is Hermes' own here: as the Claude Code hook does, it attaches the local program files a
`terminal` command may run, read from the directory the command runs in.

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
    # Nothing here can judge a call without the shared bridge: the deny is written by hand.
    print(f"WithHuman: {error}", file=sys.stderr)
    if (len(sys.argv) == 3 and sys.argv[2] == "pre_tool_call"
            and os.environ.get("WITHHUMAN_MODE", "enforce") != "observe"):
        sys.stdout.buffer.write(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "WithHuman could not check this call, so it was blocked",
        }}).encode("utf-8"))
    sys.exit(0)

STATE_DIRECTORY = os.path.join(HERE, "withhuman-state")


def attach_programs(event):
    """The program files a `terminal` command may run, found from where it runs."""
    args = event.get("args") if isinstance(event.get("args"), dict) else {}
    command = args.get("command")
    if not isinstance(command, str):
        return
    workdir = args.get("workdir") or event.get("withhuman_workdir") or event.get("cwd")
    shown = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": workdir}
    found = bridge.load_programs()(shown)
    if found:
        event["withhuman_programs"] = found


class HermesBridge(bridge.Bridge):
    kind = "hermes"
    name = "Hermes"
    # pre_tool_call waits for a judgment (intent wait and decision budget). The plugin gives the
    # whole run a few seconds more, and Hermes gives the plugin's callback 30, so a slow engine
    # ends in this bridge's deny rather than in a timeout.
    deadlines = {"pre_tool_call": 12.0, "pre_llm_call": 6.0}
    default_deadline = 4.0
    blocking_events = ("pre_tool_call",)
    probe_event = "pre_tool_call"
    state_directory = STATE_DIRECTORY

    def self_test(self):
        bridge.load_programs()

    def run(self, collector, event_name, payload):
        try:
            event = json.loads(payload)
        except ValueError as error:
            raise bridge.BridgeError("hook input is not JSON") from error
        if not isinstance(event, dict):
            raise bridge.BridgeError("hook input is not an object")
        if event_name == "pre_tool_call" and event.get("tool_name") == "terminal":
            attach_programs(event)
        return collector.post(event_name, event)


if __name__ == "__main__":
    sys.exit(bridge.run_bridge(HermesBridge()))
