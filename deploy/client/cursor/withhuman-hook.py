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
- No hook carries the model's answer before the turn ends, and the answer is where the turn's
  `[의도]` line is. `afterAgentResponse` comes once, at the end — and Cursor's editor puts only
  the turn's last answer in it, so even then the line can be missing. The session transcript
  has it: the CLI writes each answer there as it is given, the editor at the end of the turn.
  So before a call is judged, and before the turn's answer is sent, the turn's first intent
  line is read from the transcript and sent as an answer of its own, and the engine has the
  intent before it judges the call.
- As the Claude Code hook does, it attaches the local program files a shell command may run.

Environment: WITHHUMAN_CLIENT_ID (else ~/.config/withhuman/client-id), WITHHUMAN_KEY (else
~/.config/withhuman/key), WITHHUMAN_REPO, WITHHUMAN_MODE (enforce | observe),
WITHHUMAN_HOOK_TIMEOUT (seconds for the whole run), CURSOR_CONFIG_DIR (Cursor's own directory,
where transcripts are looked for when a hook does not name one).

Python 3.8 or later, standard library only; Windows and macOS.
"""

import glob
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
# What opens the line the engine asks the model to state the turn's intent in
# (`withhuman_common::intent::MARKER`).
INTENT_MARKER = "[의도]"
# Events before which the turn's intent is read from the transcript: the two a call is judged
# on, and the turn's answer, which in Cursor's editor carries only the last of its passes.
INTENT_EVENTS = ("preToolUse", "beforeMCPExecution", "afterAgentResponse")
# How much of the transcript's end is read first when looking for the turn's start; it grows
# until the turn's prompt is in it.
TRANSCRIPT_TAIL = 64 * 1024
# Payload fields an intent sent on its own carries over from the hook it was read on.
INTENT_FIELDS = ("session_id", "conversation_id", "generation_id", "cursor_version", "model",
                 "workspace_roots", "transcript_path")
# What wraps the person's own prompt in a transcript's user record. Cursor also writes user
# records of its own inside a turn ("Your previous response was interrupted. Continue …"), which
# are not a new turn: the hooks around them carry the same `generation_id`.
USER_QUERY = "<user_query>"
# How often in one turn a call is turned back because its intent, though stated, has not been
# written to the transcript yet. Past this the call goes to the engine as before.
MAX_INTENT_RETRIES = 2
# Why a call is turned back while its intent is on its way. It reaches the model, which wrote
# the line moments ago in the answer the transcript has not taken yet: the retry finds it.
INTENT_PENDING = (
    "이번 프롬프트의 [의도] 줄이 WithHuman 에 아직 전달되지 않았습니다. 응답 첫 줄에 "
    "[의도] ... 형식으로 사용자가 최종적으로 원하는 것을 사용자 입장에서 쓴 다음, 같은 도구 "
    "호출을 다시 할 것.")


class Session(bridge.State):
    """What this bridge remembers of one Cursor session between its runs.

    What Cursor sends on one hook and leaves out of another: the server an MCP call went to,
    and the text a file read brought in. Both are kept against the call's own id and taken out
    again when its result arrives. And the intent already sent for the current turn, so it is
    sent once rather than before every call.
    """

    DEFAULTS = {"mcp_servers": {}, "read_contents": {}, "intent_sent": None,
                # The turn whose call the engine turned back before its intent was known, and
                # how often this bridge has since turned one back while the intent was on its way.
                "gated_turn": None, "intent_retries": 0}
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


def turn_of(generation_id):
    """The turn a `generation_id` names: a thought event adds `-<n>-<suffix>` to the bare id
    (`withhuman_contracts::cursor::turn_of`)."""
    if len(generation_id) > 36 and generation_id[36] == "-":
        return generation_id[:36]
    return generation_id


def cursor_home():
    """Cursor's own directory, as its installer finds it."""
    configured = os.environ.get("CURSOR_CONFIG_DIR", "").strip()
    return configured or os.path.join(os.path.expanduser("~"), ".cursor")


def transcript_of(session_id, given):
    """The session's transcript. Cursor names it on most hooks, but leaves it out until the
    file exists — which, for a turn's first call, can be after the model has already written
    the answer that leads to it. Then it is looked for where Cursor keeps transcripts,
    `<home>/projects/<project>/agent-transcripts/<session>/<session>.jsonl`."""
    if isinstance(given, str) and given:
        return given
    name = glob.escape(session_id)
    found = glob.glob(os.path.join(glob.escape(cursor_home()), "projects", "*",
                                   "agent-transcripts", name, name + ".jsonl"))
    return max(found, key=os.path.getmtime) if found else None


def intent_of(text):
    """The intent a text's first line states, as the engine reads it
    (`withhuman_common::intent::split_intent`); None when it states none."""
    line = text.split("\n", 1)[0].rstrip("\r").strip()
    if line.startswith("**"):
        line = line[2:]
    if not line.startswith(INTENT_MARKER):
        return None
    intent = line[len(INTENT_MARKER):].lstrip("*").lstrip().lstrip(":：")
    if intent.endswith("**"):
        intent = intent[:-2]
    return intent.strip() or None


def texts(record):
    """The text parts of a transcript record."""
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    parts = content if isinstance(content, list) else []
    return [part["text"] for part in parts
            if isinstance(part, dict) and part.get("type") == "text"
            and isinstance(part.get("text"), str)]


def opens_turn(record):
    """Whether a record is the person's prompt, which opens a turn."""
    return record.get("role") == "user" and any(USER_QUERY in text for text in texts(record))


def turn_records(path):
    """The transcript's records since the turn's prompt: the current turn. Read from the end,
    so a long session costs only its last turn. A transcript whose prompts carry no
    `<user_query>` is taken to open a turn at every user record."""
    size = os.path.getsize(path)
    tail = TRANSCRIPT_TAIL
    while True:
        start = max(0, size - tail)
        with open(path, "rb") as file:
            file.seek(start)
            data = file.read(size - start)
        lines = data.split(b"\n")
        if start > 0:
            lines = lines[1:]  # Begins inside a record.
        records = []
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue  # A record still being written, or one this reader does not know.
            if isinstance(record, dict):
                records.append(record)
        prompts = [index for index, record in enumerate(records) if opens_turn(record)]
        if prompts:
            return records[prompts[-1] + 1:]
        if start == 0:
            users = [index for index, record in enumerate(records)
                     if record.get("role") == "user"]
            return records[users[-1] + 1:] if users else records
        tail *= 4


def read_turn(path):
    """What the transcript holds of the current turn: the first intent the model stated in it
    (or None), and whether any answer of the turn is written there yet. Only the model's own
    text is read: what a tool returned is never taken for an intent."""
    answered = False
    for record in turn_records(path):
        if record.get("role") != "assistant":
            continue
        answered = True
        for text in texts(record):
            intent = intent_of(text)
            if intent:
                return intent, True
    return None, answered


def stated_intent(path):
    """The first intent the model stated in the current turn's answers, or None."""
    return read_turn(path)[0]


def denies(answer):
    """Whether the engine's answer to a call turns it back."""
    output = (answer or {}).get("hookSpecificOutput")
    return isinstance(output, dict) and output.get("permissionDecision") not in (None, "allow")


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
        turn = self.send_intent(collector, session_id, event) \
            if event_name in INTENT_EVENTS else None
        judged = event_name in self.blocking_events and turn is not None and not turn["known"]
        if judged and self.intent_pending(session_id, turn):
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                           "permissionDecision": "deny",
                                           "permissionDecisionReason": INTENT_PENDING}}
        answer = collector.post(event_name, event)
        if judged and denies(answer):
            self.remember_gate(session_id, turn["id"])
        return answer

    def send_intent(self, collector, session_id, event):
        """Sends the turn's intent, read from the transcript, ahead of the event it was read on,
        as an answer of its own that holds the intent line alone: the engine takes it as the
        turn's intent and keeps no message for it. Once per turn and intent.

        What it found of the turn, `{"id", "known", "answered"}`: whether the engine has the
        turn's intent from this bridge, and whether the transcript holds any answer of the turn
        yet. None for an event this does not apply to.

        Best effort. Without it the call is judged as before — the engine asks the model for its
        intent — so a transcript that cannot be read, or an engine that does not take the
        intent, never turns a call back here. A subagent's answers are left alone: the engine
        asks a subagent for no intent, and its line must not stand for its parent's turn."""
        generation = event.get("generation_id")
        if event.get("withhuman_parent_session") or not isinstance(generation, str) \
                or not generation:
            return None
        turn = {"id": turn_of(generation), "known": False, "answered": False}
        try:
            path = transcript_of(session_id, event.get("transcript_path"))
            intent, turn["answered"] = read_turn(path) if path else (None, False)
        except (OSError, ValueError):
            intent = None
        with Session(STATE_DIRECTORY, session_id) as session:
            sent = session.state.get("intent_sent")
            # Sent earlier in this turn: the transcript may no longer show it where this reader
            # looks, but the engine has it.
            turn["known"] = isinstance(sent, list) and sent[:1] == [turn["id"]]
            if not intent or sent == [turn["id"], intent]:
                return turn
            body = {field: event[field] for field in INTENT_FIELDS if field in event}
            body.update(hook_event_name="afterAgentResponse",
                        text=f"{INTENT_MARKER} {intent}",
                        withhuman_intent_source="transcript")
            try:
                collector.post("afterAgentResponse", body)
            except bridge.BridgeError:
                return turn
            session.state["intent_sent"] = [turn["id"], intent]
            session.save()
            turn["known"] = True
            return turn

    def intent_pending(self, session_id, turn):
        """Whether to turn a call back, here, until the turn's intent reaches the engine.

        The engine asks for the intent once a turn: it turns the first call back and judges the
        rest without one when none came. Cursor's CLI writes an answer to the transcript only
        once the calls it asked for have run, so the call made right after the model states its
        intent — the retry the engine asked for — finds no intent there, and is judged as
        `intent::unknown`. Turning that call back once more ends the answer, which puts it in the
        transcript, and the next retry carries the intent.

        Only when the engine has already asked this turn (so it enforces, and asks for intents
        at all), only when the transcript already holds an answer of the turn (so this agent
        writes it as it goes — Cursor's editor writes it at the turn's end, and turning its
        calls back would wait for nothing), and at most `MAX_INTENT_RETRIES` times a turn."""
        if not turn["answered"]:
            return False
        with Session(STATE_DIRECTORY, session_id) as session:
            # Without the lock the count cannot be kept, and an uncounted turn-back could repeat.
            if not session.locked or session.state.get("gated_turn") != turn["id"]:
                return False
            if session.state.get("intent_retries", 0) >= MAX_INTENT_RETRIES:
                return False
            session.state["intent_retries"] = session.state.get("intent_retries", 0) + 1
            session.save()
            return True

    def remember_gate(self, session_id, turn_id):
        """The engine turned a call of this turn back before its intent was known."""
        with Session(STATE_DIRECTORY, session_id) as session:
            if session.state.get("gated_turn") != turn_id:
                session.state["gated_turn"] = turn_id
                session.state["intent_retries"] = 0
                session.save()


if __name__ == "__main__":
    sys.exit(bridge.run_bridge(CursorBridge()))
