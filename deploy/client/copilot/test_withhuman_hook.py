"""Tests for the Copilot hook: python3 -m unittest discover deploy/client/copilot

Each test installs the bridge as configure.py does (into <project>/.copilot/hooks) and runs it
as Copilot would — one process per event, the event's JSON on stdin — against a stand-in
Collector. What is checked is the part that is Copilot's own: the shape of its answers, the
turn and the answer it carries in no hook, and the rule that keeps a call from running
unjudged where a timeout would let it.
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
SOURCES = [HERE / "withhuman-hook.py", HERE / "copilot_transcript.py",
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


class CopilotHookTest(unittest.TestCase):
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
        self.home = self.project / ".copilot"
        self.hooks = self.home / "hooks"
        self.hooks.mkdir(parents=True)
        for source in SOURCES:
            shutil.copyfile(source, self.hooks / source.name)
        self.transcript = self.home / "session-state" / "sess-1" / "events.jsonl"
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text("")

    def tearDown(self):
        shutil.rmtree(self.project, ignore_errors=True)

    def wrote(self, *records):
        """Appends transcript records, as Copilot does while the model answers."""
        with self.transcript.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def answer(self, text, message_id="m1"):
        return {"type": "assistant.message",
                "data": {"messageId": message_id, "content": text}}

    def hook(self, event, body=None, url=None, **env):
        payload = {"session_id": "sess-1", "cwd": str(self.project),
                   "hook_event_name": event, **(body or {})}
        environment = {**os.environ, "WITHHUMAN_CLIENT_ID": "lab/device-1",
                       "WITHHUMAN_REPO": "github.com/acme/app",
                       "COPILOT_HOME": str(self.home), **env}
        environment.pop("WITHHUMAN_MODE", None) if "WITHHUMAN_MODE" not in env else None
        result = subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), url or self.url, event],
            input=json.dumps(payload).encode(), capture_output=True, env=environment, timeout=60)
        out = json.loads(result.stdout) if result.stdout.strip() else None
        return result.returncode, out, result.stderr.decode(errors="replace")

    def call(self, tool_name="Bash", tool_input=None, call_id="call_1", **env):
        return self.hook("PreToolUse", {
            "tool_name": tool_name, "tool_use_id": call_id,
            "tool_input": tool_input if tool_input is not None else {"command": "ls -la"}}, **env)

    def sent(self, event=None):
        return [body for name, _, body in Collector.received if event in (None, name)]

    # ---- the shape Copilot reads ----

    def test_blocks_a_call_in_the_shape_copilot_reads(self):
        """Copilot reads the decision at the top level of the answer. Under Claude Code's
        `hookSpecificOutput` a deny is still honoured, but `additionalContext` is not, so this
        bridge answers at the top level throughout."""
        Collector.answers["PreToolUse"] = decision("deny", "touches the hooks")
        code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertEqual(out, {"permissionDecision": "deny",
                               "permissionDecisionReason": "touches the hooks"})

    def test_an_allow_says_nothing(self):
        """A Copilot hook that prints nothing allows the call, so an allow needs no answer —
        unlike Cursor, where silence is read as a failure."""
        Collector.answers["PreToolUse"] = decision("allow")
        self.assertEqual(self.call()[:2], (0, None))
        # An empty answer from the engine is an allow too.
        Collector.answers["PreToolUse"] = b""
        self.assertEqual(self.call()[:2], (0, None))

    def test_a_review_blocks_because_the_ask_is_not_carried_through(self):
        Collector.answers["PreToolUse"] = decision("ask", "needs a look")
        self.assertEqual(self.call()[1]["permissionDecision"], "deny")

    def test_passes_the_engines_context_at_the_top_level(self):
        """The intent instruction reaches the model as a top-level `additionalContext`. Nested
        in Claude Code's shape Copilot drops it without a word, and no turn would ever state
        an intent."""
        Collector.answers["UserPromptSubmit"] = context("UserPromptSubmit", "state the intent")
        code, out, _ = self.hook("UserPromptSubmit", {"prompt": "fix the build"})
        self.assertEqual((code, out), (0, {"additionalContext": "state the intent"}))

    # ---- what no Copilot hook carries ----

    def test_the_models_answer_reaches_the_engine_before_the_call_it_explains(self):
        """The `[의도]` line is in the answer, which no hook carries. Copilot writes the answer
        to the transcript before it runs the calls that answer asked for, so the message is
        read from there and sent first."""
        self.hook("UserPromptSubmit", {"prompt": "read the file"})
        self.wrote(self.answer("[의도] 파일을 읽는다"))
        self.call(tool_name="Read", tool_input={"file_path": "/repo/a"})
        order = [name for name, _, _ in Collector.received]
        self.assertEqual(order, ["UserPromptSubmit", "MessageDisplay", "PreToolUse"])
        message = self.sent("MessageDisplay")[0]
        self.assertEqual(message["delta"], "[의도] 파일을 읽는다")
        self.assertEqual(message["message_id"], "m1")
        self.assertIs(message["final"], True)

    def test_a_message_with_no_text_is_not_sent(self):
        """A message that only asked for tools carries no text; sending it would make the turn
        look answered with nothing."""
        self.hook("UserPromptSubmit", {"prompt": "read the file"})
        self.wrote(self.answer(""), self.answer("  ", "m2"))
        self.call()
        self.assertEqual(self.sent("MessageDisplay"), [])

    def test_a_turn_covers_the_prompt_and_every_call_until_the_next(self):
        """No Copilot hook carries a turn, so one is minted when the prompt arrives. Without it
        every call of a session would be judged against one turn."""
        self.hook("UserPromptSubmit", {"prompt": "first"})
        self.call(call_id="call_1")
        first = self.sent("PreToolUse")[0]["withhuman_turn"]
        self.assertTrue(first)
        self.hook("UserPromptSubmit", {"prompt": "second"})
        self.call(call_id="call_2")
        second = self.sent("PreToolUse")[1]["withhuman_turn"]
        self.assertTrue(second)
        self.assertNotEqual(first, second, "a new prompt opens a new turn")
        # The answer belongs to the turn that was open when it was written.
        self.assertEqual(self.sent("UserPromptSubmit")[0]["withhuman_turn"], first)

    def test_a_resumed_session_does_not_resend_its_history(self):
        """A session's earlier answers were judged when they happened."""
        self.wrote(self.answer("[의도] 지난 턴"))
        self.hook("SessionStart", {"source": "resume"})
        self.hook("UserPromptSubmit", {"prompt": "next"})
        self.assertEqual(self.sent("MessageDisplay"), [])

    # ---- an MCP call ----

    def test_an_mcp_call_names_the_server_from_the_workspace_configuration(self):
        """`<server>-<tool>` cannot be taken apart without the server's name: the server's own
        holds hyphens. Copilot's MCP configuration is where it is read from."""
        (self.project / ".mcp.json").write_text(json.dumps(
            {"mcpServers": {"github-mcp-server": {"type": "http", "url": "https://e/mcp"}}}))
        self.call(tool_name="github-mcp-server-get_file_contents", tool_input={"path": "a"})
        self.assertEqual(self.sent("PreToolUse")[0]["withhuman_mcp_server"], "github-mcp-server")

    def test_a_server_named_nowhere_is_learned_from_copilots_own_mcp_hook(self):
        """A server configured where the bridge cannot see it (a plugin, one session's own)
        names itself on `preMcpToolCall`, which runs after the call was judged — so what it
        says serves the calls that follow. The first call is judged under the raw name."""
        self.call(tool_name="fixture-write_file", tool_input={"path": "a"})
        self.assertNotIn("withhuman_mcp_server", self.sent("PreToolUse")[0])
        code, out, _ = self.hook("preMcpToolCall", {"serverName": "fixture",
                                                     "toolName": "write_file"})
        self.assertEqual((code, out), (0, None))
        self.assertEqual([name for name, _, _ in Collector.received].count("preMcpToolCall"), 0,
                         "the MCP hook cannot stop a call, so nothing is sent for it")
        self.call(tool_name="fixture-write_file", tool_input={"path": "b"}, call_id="call_2")
        self.assertEqual(self.sent("PreToolUse")[1]["withhuman_mcp_server"], "fixture")

    # ---- what the client alone can see ----

    def test_a_shell_call_carries_the_programs_it_could_run(self):
        script = self.project / "deploy.sh"
        script.write_text("#!/bin/sh\necho deploying\n")
        self.call(tool_input={"command": "./deploy.sh"})
        programs = self.sent("PreToolUse")[0].get("withhuman_programs") or []
        self.assertEqual([program["path"] for program in programs], [str(script)])
        # A call that runs no program carries none.
        self.call(tool_name="Read", tool_input={"file_path": "/repo/a"}, call_id="call_2")
        self.assertNotIn("withhuman_programs", self.sent("PreToolUse")[1])

    def test_a_subagents_call_is_judged_in_the_session_it_runs_under(self):
        """A subagent's events carry its own id as the session; the turn they belong to is the
        one the session is on."""
        self.hook("UserPromptSubmit", {"prompt": "delegate it"})
        turn = self.sent("UserPromptSubmit")[0]["withhuman_turn"]
        self.hook("PreToolUse", {"session_id": "agent-1", "parent_agent_id": "sess-1",
                                 "agent_id": "agent-1", "agent_type": "explore",
                                 "tool_name": "Read", "tool_use_id": "call_9",
                                 "tool_input": {"file_path": "/repo/a"}})
        self.assertEqual(self.sent("PreToolUse")[0]["withhuman_turn"], turn)

    # ---- every failure ends in a decision ----

    def test_a_call_nobody_could_judge_is_blocked(self):
        """Copilot runs a call whose hook timed out, so the bridge must answer in time with its
        own deny rather than let Copilot's timeout decide."""
        for label, setup in (
            ("engine unreachable", lambda: {"url": "http://127.0.0.1:9"}),
            ("engine refuses", lambda: (setattr(Collector, "status", 500), {})[1]),
            ("engine too slow", lambda: (setattr(Collector, "delay", 3.0),
                                         {"WITHHUMAN_HOOK_TIMEOUT": "0.3"})[1]),
        ):
            with self.subTest(label):
                Collector.status, Collector.delay = 200, 0.0
                arguments = setup()
                code, out, _ = self.call(**arguments)
                self.assertEqual(code, 0, label)
                self.assertEqual(out, {"permissionDecision": "deny",
                                       "permissionDecisionReason": BLOCKED}, label)

    def test_an_event_that_blocks_nothing_reports_a_failure_without_blocking(self):
        Collector.status = 500
        code, out, stderr = self.hook("PostToolUse", {
            "tool_name": "Bash", "tool_use_id": "call_1", "tool_input": {"command": "ls"},
            "tool_result": {"result_type": "success", "text_result_for_llm": "ok"}})
        self.assertEqual((code, out), (0, None))
        self.assertIn("WithHuman", stderr)

    def test_observe_mode_never_blocks(self):
        Collector.status = 500
        self.assertEqual(self.call(WITHHUMAN_MODE="observe")[:2], (0, None))

    def test_the_local_audit_records_the_decision_that_was_made(self):
        """The only evidence of a deny the engine could not store. Recording it as an allow
        would make the local log say the opposite of what happened."""
        Collector.answers["PreToolUse"] = decision("deny", "touches the hooks")
        self.call()
        rows = [json.loads(line) for line in
                (self.hooks / "withhuman-state" / "audit.jsonl").read_text().splitlines()]
        self.assertEqual([row["decision"] for row in rows], ["deny"])
        self.assertEqual(rows[0]["tool_use_id"], "call_1")

    def test_the_check_reports_the_engine_knows_copilot(self):
        Collector.answers["PreToolUse"] = b'{"error": "invalid_copilot_hook"}'
        Collector.status = 400
        result = subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), "--check", self.url],
            capture_output=True, timeout=60,
            env={**os.environ, "COPILOT_HOME": str(self.home)})
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn("Copilot support", result.stdout.decode())

    def test_the_check_fails_where_the_engine_has_no_copilot_route(self):
        Collector.status = 404
        result = subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), "--check", self.url],
            capture_output=True, timeout=60,
            env={**os.environ, "COPILOT_HOME": str(self.home)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("no Copilot route", result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
