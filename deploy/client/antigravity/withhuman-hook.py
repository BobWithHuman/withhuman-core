#!/usr/bin/env python3
"""WithHuman bridge for Antigravity CLI.

usage: withhuman-hook.py <Antigravity hook event>      (the engine's address sits beside it)
       withhuman-hook.py <WithHuman server> <event>
       withhuman-hook.py --check [<WithHuman server>]

Antigravity runs this for each hook event with the event's JSON on stdin. Everything a bridge
shares with the other agents' is in `withhuman_bridge.py` beside it, which forwards the event
to the Collector's agent route (`/v1/hooks/antigravity/<event>`), where it becomes the Claude
Code hook the engine already judges, and prints the answer in the form Antigravity reads.

What is Antigravity's own, and what this file is:

- **Every way this hook can fail blocks the call**: a `deny`, a non-zero exit, running past
  the timeout, or an answer that does not parse. Antigravity is the only agent WithHuman
  supports that needs no trick to fail closed — so this bridge's job is to answer in the shape
  Antigravity reads, and to answer in time for the user rather than for safety.
- **The answer is parsed strictly** (protojson): a field the event's result message does not
  name is an error, and an error blocks the call. So nothing is printed but the fields of that
  event's own result, and an allow prints nothing at all.
- **The intent instruction is injected**, not appended: Antigravity takes `injectSteps` on the
  invocation that opens a turn, and the system message it makes persists in the conversation.
- **No hook carries a turn**, so one is minted on the invocation that opens a turn
  (`invocationNum` 0), and every event until the next one carries it.
- **No hook carries what a call brought in**: `PostToolUse` says only whether it failed. The
  result is read from the session transcript (`antigravity_transcript.py`) by the step number
  the hook carries, along with the model's answers.

Environment: WITHHUMAN_CLIENT_ID (else ~/.config/withhuman/client-id), WITHHUMAN_KEY (else
~/.config/withhuman/key), WITHHUMAN_REPO, WITHHUMAN_MODE (enforce | observe),
WITHHUMAN_HOOK_TIMEOUT (seconds for the whole run), WITHHUMAN_SERVER (the engine's address).
Antigravity adds PLUGIN_ROOT and PLUGIN_DATA for a hook that ships with a plugin.

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
    # Nothing here can judge a call without the shared bridge. Antigravity blocks a call whose
    # hook exits non-zero, so the block is already made; this says why.
    print(f"WithHuman: {error}", file=sys.stderr)
    sys.exit(1)

# Imported in `run`, inside the handler that turns any failure into a decision: an import
# error here would be reported without saying what it was.
antigravity_transcript = None

#: Events that carry the turn the engine judges a call against.
TURN_EVENTS = ("PreInvocation", "PreToolUse", "PostToolUse", "Stop")


def load_transcript_module():
    global antigravity_transcript
    import antigravity_transcript as module  # beside this file

    antigravity_transcript = module


#: Where the session state and the audit log go: the plugin's own data directory when
#: Antigravity gave the hook one, else beside this hook.
STATE_DIRECTORY = (os.environ.get("PLUGIN_DATA", "").strip()
                   or os.path.join(HERE, "withhuman-state"))


def attach_programs(event, command):
    """The program files a shell command may run, found from where it runs."""
    try:
        shown = dict(event, tool_input={"command": command},
                     tool_name="PowerShell" if os.name == "nt" else "Bash")
        return bridge.load_programs()(shown)
    except Exception as error:  # noqa: BLE001  (attaching must never keep a call from judgment)
        raise bridge.BridgeError("program attachment failed") from error


class AntigravityBridge(bridge.Bridge):
    kind = "antigravity"
    name = "Antigravity"
    # PreToolUse waits for a judgment (intent wait and decision budget), so it gets more time.
    # Both stay well inside the hook timeout configure.py writes, which Antigravity enforces by
    # killing the hook — and a killed hook blocks the call, so the cost of being late is the
    # user's call being blocked rather than running unjudged.
    deadlines = {"PreToolUse": 12.0}
    default_deadline = 4.0
    state_directory = STATE_DIRECTORY

    def extra_headers(self):
        return {"x-withhuman-shell": "powershell" if os.name == "nt" else "posix"}

    def self_test(self):
        load_transcript_module()
        bridge.load_programs()

    # ---- what Antigravity reads ----

    def deny(self, reason):
        """Antigravity's `PreToolUse` result holds a decision and a reason, and nothing else:
        a field it does not name is an error, and an error blocks the call anyway. An allow
        prints nothing at all — the shared bridge's answer for one — which Antigravity reads as
        an allow."""
        return json.dumps({"decision": "deny", "reason": reason}, ensure_ascii=False).encode(
            "utf-8")

    def context(self, event, text):
        """The engine's instruction as a step Antigravity injects into the conversation. It
        takes these on the invocation that opens a turn, which is where this bridge sends the
        turn's prompt."""
        return json.dumps({"injectSteps": [{"systemMessage": {"systemMessage": text}}]},
                          ensure_ascii=False).encode("utf-8")

    def decision_of(self, answer):
        """This bridge's own output carries the decision at the top level."""
        return (answer or {}).get("decision")

    def ids_of(self, event):
        """Antigravity names the session `conversationId` and the call `toolCall.id`, the id
        the engine records the call under. Read under Claude Code's names, every row of the
        local audit log named neither."""
        call = event.get("toolCall")
        return (event.get("conversationId"),
                call.get("id") if isinstance(call, dict) else None)

    # ---- one hook ----

    def run(self, collector, event_name, payload):
        load_transcript_module()
        try:
            event = json.loads(payload)
        except ValueError as error:
            raise bridge.BridgeError("hook input is not JSON") from error
        if not isinstance(event, dict):
            raise bridge.BridgeError("hook input is not an object")
        session_id = event.get("conversationId")
        if not isinstance(session_id, str) or not session_id:
            raise bridge.BridgeError("hook input has no conversationId")
        path = event.get("transcriptPath")

        with antigravity_transcript.Session(STATE_DIRECTORY, session_id) as session:
            if not session.locked:
                raise bridge.BridgeError("session lock unavailable")
            if session.state.get("resync_required"):
                raise bridge.BridgeError(
                    "session resync required; start a new Antigravity session")
            self.drain(session, collector)
            confirmed = copy.deepcopy(session.state)

            before = []
            if event_name == "SessionStart":
                # Earlier history (a resumed conversation) was judged when it happened.
                session.skip_to(bridge.file_size(path))
            else:
                try:
                    before = session.sync(path, session_id)
                except bridge.TranscriptError as error:
                    session.state = confirmed
                    raise bridge.BridgeError("transcript could not be read") from error
            prompt = event.get("lastUserInput")
            opened = False
            if (event_name == "PreInvocation" and event.get("invocationNum") == 0
                    and prompt != session.state["prompt"]):
                # The prompt is the turn, not the invocation: a turn that waits for a subagent
                # re-enters the loop at invocation 0 with the same prompt, and minting a turn
                # there would split one turn into two. Answers synced above belong to the turn
                # that just ended.
                session.state["turn"] = uuid.uuid4().hex
                session.state["prompt"] = prompt
                opened = True
            candidate = copy.deepcopy(session.state)
            session.state = confirmed
            self.deliver(session, collector, before, candidate)
            confirmed = copy.deepcopy(session.state)

            self.prepare(event_name, event, session, opened)
            candidate = copy.deepcopy(session.state)
            session.state = confirmed
            return self.deliver(session, collector, [(event_name, event)], candidate)

    def prepare(self, event_name, event, session, opened):
        """Adds what only the client can see: the turn and whether this event opened it, what a
        finished call brought in, and the program files a shell command would run."""
        if event_name in TURN_EVENTS and session.state["turn"]:
            event["withhuman_turn"] = session.state["turn"]
        if opened:
            event["withhuman_new_turn"] = True
        parent = session.parent_of(event.get("transcriptPath"))
        if parent and parent != event.get("conversationId"):
            event["withhuman_parent_session"] = parent
        call = event.get("toolCall") if isinstance(event.get("toolCall"), dict) else {}
        arguments = call.get("args") if isinstance(call.get("args"), dict) else {}
        if event_name == "PostToolUse":
            result = session.result_of(event.get("stepIdx"))
            if result:
                event["withhuman_result"] = result
        if event_name == "PreToolUse" and call.get("name") == "run_command":
            programs = attach_programs(event, arguments.get("CommandLine"))
            if programs:
                event["withhuman_programs"] = programs


if __name__ == "__main__":
    sys.exit(bridge.run_bridge(AntigravityBridge()))
