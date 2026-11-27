"""Tests for the Antigravity hook: python3 -m unittest discover deploy/client/antigravity

Each test installs the bridge as configure.py does and runs it as Antigravity would — one
process per event, the event's JSON on stdin — against a stand-in Collector. What is checked is
the part that is Antigravity's own: the strictly parsed answer it reads, the turn and the
answer it carries in no hook, and the result it leaves to the transcript.
"""

import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = [HERE / "withhuman-hook.py", HERE / "antigravity_transcript.py",
           HERE.parent / "hooks" / "withhuman_bridge.py",
           HERE.parent / "hooks" / "pre-tool-use.py"]

BLOCKED = "WithHuman could not check this call, so it was blocked"


class Collector(http.server.BaseHTTPRequestHandler):
    received = []
    answers = {}
    status = 200
    delay = 0.0

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        event = self.path.rsplit("/", 1)[-1]
        headers = {name.lower(): value for name, value in self.headers.items()}
        Collector.received.append((event, headers, json.loads(body)))
        time.sleep(Collector.delay)
        answer = Collector.answers.get(event, b"")
        encoded = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        try:
            self.send_response(Collector.status)
            self.end_headers()
            self.wfile.write(encoded)
        except OSError:
            pass  # The hook gave up waiting, as the timeout test wants.

    def log_message(self, *_):
        pass


def decision(value, reason="blocked by policy"):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": value,
                                   "permissionDecisionReason": reason}}


def context(event, text):
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}


class AntigravityHookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Collector.received = []
        Collector.answers = {}
        Collector.status = 200
        Collector.delay = 0.0
        self.project = Path(tempfile.mkdtemp()).resolve()
        self.plugin = self.project / "plugin"
        self.plugin.mkdir()
        for source in SOURCES:
            shutil.copyfile(source, self.plugin / source.name)
        self.transcript = self.project / "transcript.jsonl"
        self.transcript.write_text("")
        self.data = self.project / "plugin-data"
        self.data.mkdir()

    def tearDown(self):
        shutil.rmtree(self.project, ignore_errors=True)

    def wrote(self, *records):
        """Appends transcript records, as Antigravity does while it works."""
        with self.transcript.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def answer(self, text, step=2):
        return {"step_index": step, "type": "PLANNER_RESPONSE", "content": text}

    def result(self, text, step=3):
        return {"step_index": step, "type": "GENERIC", "content": text}

    def hook(self, event, body=None, url=None, **env):
        payload = {"conversationId": "conv-1", "hookEventName": event,
                   "cwd": str(self.project), "transcriptPath": str(self.transcript),
                   "lastUserInput": "do the thing", "modelName": "auto",
                   "workspacePaths": [str(self.project)], **(body or {})}
        environment = {**os.environ, "WITHHUMAN_CLIENT_ID": "lab/device-1",
                       "WITHHUMAN_REPO": "github.com/acme/app",
                       "PLUGIN_DATA": str(self.data), **env}
        environment.pop("WITHHUMAN_MODE", None) if "WITHHUMAN_MODE" not in env else None
        result = subprocess.run(
            [sys.executable, str(self.plugin / "withhuman-hook.py"), url or self.url, event],
            input=json.dumps(payload).encode(), capture_output=True, env=environment, timeout=60)
        out = json.loads(result.stdout) if result.stdout.strip() else None
        return result.returncode, out, result.stderr.decode(errors="replace")

    def call(self, name="run_command", args=None, call_id="call_1", step=3, **env):
        return self.hook("PreToolUse", {
            "toolCall": {"id": call_id, "name": name,
                         "args": args if args is not None else {"CommandLine": "ls -la"}},
            "stepIdx": step}, **env)

    def sent(self, event=None):
        return [body for name, _, body in Collector.received if event in (None, name)]

    # ---- the answer Antigravity reads ----

    def test_blocks_a_call_with_the_two_fields_antigravity_names(self):
        """Antigravity parses the answer strictly: a field its result message does not name is
        an error. The answer carries the decision and the reason, and nothing else."""
        Collector.answers["PreToolUse"] = decision("deny", "touches the hooks")
        code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertEqual(out, {"decision": "deny", "reason": "touches the hooks"})

    def test_an_allow_prints_nothing(self):
        """An empty answer is Antigravity's allow. Printing a decision it does not expect for
        the event would block the call instead."""
        Collector.answers["PreToolUse"] = decision("allow")
        self.assertEqual(self.call()[:2], (0, None))
        Collector.answers["PreToolUse"] = b""
        self.assertEqual(self.call()[:2], (0, None))

    def test_a_review_blocks_because_an_ask_is_not_a_block(self):
        """Antigravity's `ask` is answered by the session itself when it runs with
        `--dangerously-skip-permissions`, which would turn a REVIEW into an allow."""
        Collector.answers["PreToolUse"] = decision("ask", "needs a look")
        self.assertEqual(self.call()[1]["decision"], "deny")

    def test_the_engines_instruction_is_injected_as_a_step(self):
        """The intent instruction reaches the model as an injected system message, which is how
        Antigravity takes added context."""
        Collector.answers["PreInvocation"] = context("UserPromptSubmit", "state the intent")
        code, out, _ = self.hook("PreInvocation", {"invocationNum": 0, "initialNumSteps": 1})
        self.assertEqual(code, 0)
        self.assertEqual(out, {"injectSteps": [{"systemMessage":
                                                {"systemMessage": "state the intent"}}]})

    # ---- what no Antigravity hook carries ----

    def test_the_models_answer_reaches_the_engine_before_the_call_it_explains(self):
        """The `[의도]` line is in the answer, which no hook carries. Antigravity writes the
        answer to the transcript before it runs the calls that answer asked for."""
        self.hook("PreInvocation", {"invocationNum": 0})
        self.wrote(self.answer("[의도] 파일을 읽는다"))
        self.call()
        order = [name for name, _, _ in Collector.received]
        self.assertEqual(order, ["PreInvocation", "MessageDisplay", "PreToolUse"])
        message = self.sent("MessageDisplay")[0]
        self.assertEqual(message["delta"], "[의도] 파일을 읽는다")
        self.assertEqual(message["message_id"], "step-2")

    def test_each_answer_of_a_turn_is_its_own_message(self):
        """A turn has as many answers as the model took passes, and the step each was written
        at names it — so two answers stay two messages and a repeated one stays one."""
        self.hook("PreInvocation", {"invocationNum": 0})
        self.wrote(self.answer("[의도] 같은 의도", 2))
        self.call(call_id="call_1", step=3)
        self.wrote(self.answer("[의도] 같은 의도", 4))
        self.call(call_id="call_2", step=5)
        ids = [message["message_id"] for message in self.sent("MessageDisplay")]
        self.assertEqual(ids, ["step-2", "step-4"])

    def test_the_prompt_is_the_turn_not_the_invocation(self):
        """No Antigravity hook carries a turn, and the invocation count is not one: a turn that
        waits for a subagent re-enters the loop at invocation 0 with the same prompt. Minting a
        turn there would split one turn into two, so the prompt is what opens one.

        Measured against Antigravity CLI 1.5.16, where one prompt's events held two invocations
        numbered 0.
        """
        self.hook("PreInvocation", {"invocationNum": 0})
        self.call(call_id="call_1")
        first = self.sent("PreToolUse")[0]["withhuman_turn"]
        self.assertTrue(first)
        self.assertIs(self.sent("PreInvocation")[0]["withhuman_new_turn"], True)
        # A later invocation of the same turn does not open a new one.
        self.hook("PreInvocation", {"invocationNum": 1})
        self.call(call_id="call_2")
        self.assertEqual(self.sent("PreToolUse")[1]["withhuman_turn"], first)
        # Nor does the loop re-entering at 0 with the same prompt.
        self.hook("PreInvocation", {"invocationNum": 0})
        self.call(call_id="call_3")
        self.assertEqual(self.sent("PreToolUse")[2]["withhuman_turn"], first)
        self.assertNotIn("withhuman_new_turn", self.sent("PreInvocation")[2])
        # A prompt the session has not seen does.
        self.hook("PreInvocation", {"invocationNum": 0, "lastUserInput": "something else"})
        self.call(call_id="call_4", step=9)
        self.assertNotEqual(self.sent("PreToolUse")[3]["withhuman_turn"], first)

    def test_a_subagents_events_name_the_session_it_was_delegated_from(self):
        """Nothing in a subagent's hook payload names the session that delegated to it; the
        message that started it does, in its own transcript."""
        self.wrote({"step_index": 0, "type": "SYSTEM_MESSAGE", "content":
                    "<SYSTEM_MESSAGE>\n[Message] timestamp=2026-11-25T00:00:00Z "
                    "sender=a24df09b-2841-4e46-8ead-fc31f850ce7d priority=MESSAGE_PRIORITY_HIGH "
                    "content=Count the lines in data.txt\n</SYSTEM_MESSAGE>"})
        self.call(call_id="call_1")
        sent = self.sent("PreToolUse")[0]
        self.assertEqual(sent["withhuman_parent_session"],
                         "a24df09b-2841-4e46-8ead-fc31f850ce7d")
        # A session nobody delegated carries none.
        shutil.rmtree(self.data); self.data.mkdir()
        self.transcript.write_text("")
        self.wrote(self.answer("just an answer", 0))
        self.call(call_id="call_2")
        self.assertNotIn("withhuman_parent_session", self.sent("PreToolUse")[1])

    def test_a_finished_call_carries_what_it_brought_in(self):
        """`PostToolUse` says only whether the call failed; what it brought in is in the
        transcript, under the step number the hook carries."""
        self.hook("PreInvocation", {"invocationNum": 0})
        self.wrote(self.result("Command exited with code 0.\n\nCommand output:\nsecrets", 3))
        self.hook("PostToolUse", {
            "toolCall": {"id": "call_1", "name": "run_command", "args": {"CommandLine": "cat s"}},
            "stepIdx": 3, "error": ""})
        sent = self.sent("PostToolUse")[0]
        self.assertIn("secrets", sent["withhuman_result"])
        # A call whose result the transcript does not show carries none.
        self.hook("PostToolUse", {
            "toolCall": {"id": "call_2", "name": "run_command", "args": {"CommandLine": "x"}},
            "stepIdx": 99, "error": ""})
        self.assertNotIn("withhuman_result", self.sent("PostToolUse")[1])

    def test_a_resumed_conversation_does_not_resend_its_history(self):
        self.wrote(self.answer("[의도] 지난 턴", 0))
        self.hook("SessionStart")
        self.hook("PreInvocation", {"invocationNum": 0})
        self.assertEqual(self.sent("MessageDisplay"), [])

    # ---- what the client alone can see ----

    def test_a_shell_call_carries_the_programs_it_could_run(self):
        script = self.project / "deploy.sh"
        script.write_text("#!/bin/sh\necho deploying\n")
        self.call(args={"CommandLine": "./deploy.sh"})
        programs = self.sent("PreToolUse")[0].get("withhuman_programs") or []
        self.assertEqual([program["path"] for program in programs], [str(script)])
        # A call that runs no program carries none.
        self.call(name="read_file", args={"Path": "a"}, call_id="call_2")
        self.assertNotIn("withhuman_programs", self.sent("PreToolUse")[1])

    # ---- every failure ends in a decision ----

    def test_a_call_nobody_could_judge_is_blocked(self):
        """Antigravity blocks a call whose hook fails or runs late, but a deny of our own says
        why, and in time."""
        for label, setup in (
            ("engine unreachable", lambda: {"url": "http://127.0.0.1:9"}),
            ("engine refuses", lambda: (setattr(Collector, "status", 500), {})[1]),
            ("engine too slow", lambda: (setattr(Collector, "delay", 3.0),
                                         {"WITHHUMAN_HOOK_TIMEOUT": "0.3"})[1]),
        ):
            with self.subTest(label):
                Collector.status, Collector.delay = 200, 0.0
                code, out, _ = self.call(**setup())
                self.assertEqual(code, 0, label)
                self.assertEqual(out, {"decision": "deny", "reason": BLOCKED}, label)

    def test_an_event_that_blocks_nothing_reports_a_failure_without_blocking(self):
        Collector.status = 500
        code, out, stderr = self.hook("PostToolUse", {
            "toolCall": {"id": "call_1", "name": "read_file", "args": {"Path": "a"}},
            "stepIdx": 3, "error": ""})
        self.assertEqual((code, out), (0, None))
        self.assertIn("WithHuman", stderr)

    def test_observe_mode_never_blocks(self):
        Collector.status = 500
        self.assertEqual(self.call(WITHHUMAN_MODE="observe")[:2], (0, None))

    def test_the_local_audit_records_the_decision_in_the_plugins_own_data(self):
        """The only evidence of a deny the engine could not store, kept where Antigravity gives
        the plugin room for it."""
        Collector.answers["PreToolUse"] = decision("deny", "touches the hooks")
        self.call()
        rows = [json.loads(line) for line in
                (self.data / "audit.jsonl").read_text().splitlines()]
        self.assertEqual([row["decision"] for row in rows], ["deny"])

    def test_the_local_audit_names_the_session_and_the_call(self):
        """Found on Windows with Antigravity CLI 1.5.18: every row named neither, read under
        Claude Code's field names, so a row could not be matched to what the engine kept."""
        Collector.answers["PreToolUse"] = decision("deny", "touches the hooks")
        self.call(call_id="call_7")
        row = json.loads((self.data / "audit.jsonl").read_text().splitlines()[-1])
        self.assertEqual((row["session_id"], row["tool_use_id"]), ("conv-1", "call_7"))

    def test_the_check_reports_the_engine_knows_antigravity(self):
        Collector.answers["PreToolUse"] = b'{"error": "invalid_antigravity_hook"}'
        Collector.status = 400
        result = subprocess.run(
            [sys.executable, str(self.plugin / "withhuman-hook.py"), "--check", self.url],
            capture_output=True, timeout=60,
            env={**os.environ, "PLUGIN_DATA": str(self.data)})
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn("Antigravity support", result.stdout.decode())

    def test_the_check_fails_where_the_engine_has_no_antigravity_route(self):
        Collector.status = 404
        result = subprocess.run(
            [sys.executable, str(self.plugin / "withhuman-hook.py"), "--check", self.url],
            capture_output=True, timeout=60,
            env={**os.environ, "PLUGIN_DATA": str(self.data)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("no Antigravity route", result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
