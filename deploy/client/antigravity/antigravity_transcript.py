"""Reads an Antigravity session transcript for the WithHuman Antigravity hook.

Antigravity's hooks leave out two things the engine needs: the model's answers — where a turn
states its `[의도]` line — and what each call brought in, since `PostToolUse` says only whether
the call failed. Both are in the session transcript the hooks name (`transcriptPath`), a JSONL
file Antigravity appends one step to at a time.

The step numbering is what ties them together: a hook's `stepIdx` is the transcript's
`step_index` for the same call, so a call's result is the record that carries its number.

This module is the only code that knows that format, which Antigravity does not promise to
keep; what it cannot read it leaves out rather than guesses.

Everything in the transcript is data the agent or a web page may have written. It is only
copied into events for the engine to judge, never acted on here.

Checked against Antigravity CLI 1.5.16: `USER_INPUT`, `SYSTEM_MESSAGE`, `PLANNER_RESPONSE` and
`GENERIC` records, each with `step_index`, `type` and `content`.

Python 3.8 or later, standard library only.
"""

import hashlib
import json
import re

import withhuman_bridge as bridge  # beside this file, or one directory up in the repository

ANTIGRAVITY_VERSION = "1.5.16"
#: The message a parent sends a subagent opens with this header, and `sender` is the
#: conversation it came from — the one link between a subagent and the session that delegated
#: to it. Nothing in the hook payload names it.
DELEGATION = re.compile(r"\[Message\][^\n]*?sender=([0-9a-fA-F-]{36})")
#: The record that holds a model answer.
ANSWER = "PLANNER_RESPONSE"
#: The record that holds what a call brought in.
RESULT = "GENERIC"
#: Characters of a result kept for the engine.
MAX_RESULT = 20000
#: Results kept per session, so a long session's state stays small.
MAX_RESULTS = 200


class Session(bridge.State):
    """One Antigravity conversation, as the hook remembers it between its runs.

    `turn` is a turn of this hook's own making: no Antigravity hook carries one. A turn opens
    on the invocation that starts it (`invocationNum` 0), and every event until the next one
    belongs to it.
    """

    DEFAULTS = {
        #: Bytes of the transcript already read.
        "offset": 0,
        #: The turn every event belongs to until the next prompt.
        "turn": None,
        #: The prompt that turn opened with, which is what tells a new turn from a loop that
        #: re-entered within one.
        "prompt": None,
        #: What each call brought in, by the step it ran at, until its result is sent.
        "results": {},
        #: The conversation this one was delegated from, or None once looked for and not
        #: found. `""` means it has not been looked for yet.
        "parent": "",
    }

    def skip_to(self, offset):
        """Leaves earlier history unread: a resumed conversation's answers were judged when
        they happened."""
        self.state["offset"] = offset

    def parent_of(self, path):
        """The conversation a subagent was delegated from, read from the message that started
        it; none for a session nobody delegated.

        Read once and remembered: it is in the transcript's first system message, which the
        offset has long passed by the time later events arrive.
        """
        if self.state["parent"] != "":
            return self.state["parent"]
        parent = None
        try:
            records, _ = bridge.read_records(path, 0)
        except bridge.TranscriptError:
            return None          # Nothing is assumed of a transcript that cannot be read.
        for record in records:
            if record.get("type") != "SYSTEM_MESSAGE":
                continue
            content = record.get("content")
            found = DELEGATION.search(content) if isinstance(content, str) else None
            if found:
                parent = found.group(1)
                break
        self.state["parent"] = parent
        return parent

    def result_of(self, step_idx):
        """What the call at `step_idx` brought in, if the transcript showed it."""
        if step_idx is None:
            return None
        return self.state["results"].get(str(step_idx))

    def sync(self, path, session_id):
        """The model's answers written since the last read, as Claude Code `MessageDisplay`
        events, remembering each call's result on the way.

        Antigravity writes an answer before it runs the calls that answer asked for, so a
        message read here reaches the engine before the Call it explains is judged.
        """
        records, offset = bridge.read_records(path, self.state["offset"])
        events = []
        results = dict(self.state["results"])
        for record in records:
            kind = record.get("type")
            step = record.get("step_index")
            content = record.get("content")
            if not isinstance(content, str) or not content.strip():
                continue
            if kind == RESULT and step is not None:
                results[str(step)] = content[:MAX_RESULT]
                continue
            if kind != ANSWER:
                continue
            # An answer has no id of its own; the step it was written at names it, so two
            # answers of one turn stay two messages and the same answer stays one.
            message_id = f"step-{step}" if step is not None else hashlib.sha256(
                content.encode("utf-8")).hexdigest()[:16]
            events.append(("MessageDisplay", {
                "session_id": session_id,
                "message_id": message_id,
                "index": 0,
                "delta": content,
                "final": True,
                "turn_id": self.state["turn"],
            }))
        if len(results) > MAX_RESULTS:
            for key in sorted(results, key=lambda value: int(value))[:-MAX_RESULTS]:
                del results[key]
        self.state["results"] = results
        self.state["offset"] = offset
        return events
