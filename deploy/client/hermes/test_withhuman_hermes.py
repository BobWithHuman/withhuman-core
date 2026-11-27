"""Tests for the Hermes plugin and its bridge: python3 -m unittest discover deploy/client/hermes

The plugin is driven as Hermes drives it, with a hook's keyword arguments, and runs the real
bridge against a stand-in Collector, so what is shown is what reaches the engine and what Hermes
reads back.
"""

import http.server
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
BLOCKED = "WithHuman could not check this call, so it was blocked"


def installed():
    """The plugin as the setup installs it, in a folder of its own: the bridge keeps its state and
    audit log beside itself, never in the checkout."""
    folder = Path(tempfile.mkdtemp()).resolve() / "withhuman"
    folder.mkdir()
    for name in ("__init__.py", "plugin.yaml", "withhuman-hook.py"):
        shutil.copyfile(HERE / name, folder / name)
    for name in ("withhuman_bridge.py", "pre-tool-use.py"):
        shutil.copyfile(HERE.parent / "hooks" / name, folder / name)
    return folder


def load_plugin(folder):
    spec = importlib.util.spec_from_file_location("withhuman_hermes_plugin", folder / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Context:
    """What Hermes hands a plugin: here only the session's directory."""

    def __init__(self, cwd):
        self.cwd = cwd
        self.hooks = {}

    def session_cwd(self):
        return self.cwd

    def register_hook(self, name, callback):
        self.hooks[name] = callback


class Collector(http.server.BaseHTTPRequestHandler):
    received = []
    answers = {}
    status = 200

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
        Collector.received.append((self.path, body))
        answer = Collector.answers.get(self.path.rsplit("/", 1)[-1], b"")
        self.send_response(Collector.status)
        self.end_headers()
        self.wfile.write(answer if isinstance(answer, bytes) else json.dumps(answer).encode())

    def log_message(self, *_):
        pass


class HermesPluginTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.folder = installed()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.folder.parent, ignore_errors=True)

    def setUp(self):
        Collector.received = []
        Collector.answers = {}
        Collector.status = 200
        self.env = mock.patch.dict(os.environ, {
            "WITHHUMAN_SERVER": self.url, "WITHHUMAN_CLIENT_ID": "lab/device-1",
            "WITHHUMAN_MODE": "enforce"})
        self.env.start()
        self.plugin = load_plugin(self.folder)
        self.ctx = Context("C:\\proj")
        self.plugin.register(self.ctx)

    def tearDown(self):
        self.env.stop()

    def hook(self, name, **kwargs):
        return self.ctx.hooks[name](**kwargs)

    def sent(self, hook):
        return [body for path, body in Collector.received if path == f"/v1/hooks/hermes/{hook}"]

    def deny(self, reason):
        Collector.answers["pre_tool_call"] = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": reason}}

    def call(self, **kwargs):
        base = {"tool_name": "read_file", "args": {"path": "a"}, "session_id": "s1",
                "conversation_id": "s1", "tool_call_id": "c1", "turn_id": "t1"}
        return self.hook("pre_tool_call", **{**base, **kwargs})

    # ---- what Hermes reads back ----

    def test_asks_for_the_intent_line_as_context_for_the_users_message(self):
        Collector.answers["pre_llm_call"] = {"hookSpecificOutput": {
            "hookEventName": "pre_llm_call", "additionalContext": "[의도] 줄을 쓸 것"}}
        answer = self.hook("pre_llm_call", session_id="s1", user_message="fix it",
                           conversation_history=[{"role": "user"}], platform="cli")
        self.assertEqual(answer, {"context": "[의도] 줄을 쓸 것"})
        body = self.sent("pre_llm_call")[0]
        self.assertEqual(body["withhuman_session_id"], "s1")
        self.assertEqual(body["cwd"], "C:\\proj")
        self.assertNotIn("conversation_history", body)

    def test_blocks_a_denied_call_with_the_engines_reason(self):
        self.deny("이 호출은 요청과 관계없습니다")
        self.assertEqual(self.call(), {"action": "block", "message": "이 호출은 요청과 관계없습니다"})

    def test_lets_an_allowed_call_run(self):
        self.assertIsNone(self.call())

    def test_blocks_when_the_engine_cannot_judge_and_lets_through_when_observing(self):
        Collector.status = 503
        self.assertEqual(self.call(), {"action": "block", "message": BLOCKED})
        os.environ["WITHHUMAN_MODE"] = "observe"
        self.assertIsNone(self.call())

    def test_blocks_when_no_engine_is_set(self):
        del os.environ["WITHHUMAN_SERVER"]
        self.assertEqual(self.call(), {"action": "block", "message": BLOCKED})

    # ---- what the engine sees ----

    def test_sends_the_intent_line_only_with_text(self):
        self.hook("post_api_request", session_id="s1", api_request_id="r1",
                  response={"assistant_message": {"content": None, "tool_calls": [{"id": "c1"}]}})
        self.hook("post_api_request", session_id="s1", api_request_id="r2",
                  response={"assistant_message": {"content": "[의도] 고치고 싶음"}})
        self.assertEqual([b["api_request_id"] for b in self.sent("post_api_request")], ["r2"])

    def test_follows_the_directory_a_cd_leaves_for_the_next_command(self):
        self.call(tool_name="terminal", args={"command": "cd sub"})
        self.hook("post_tool_call", tool_name="terminal", args={"command": "cd sub"},
                  session_id="s1", conversation_id="s1", tool_call_id="c1", status="ok",
                  result=json.dumps({"output": "", "exit_code": 0, "cwd": "C:\\proj\\sub"}))
        self.call(tool_name="terminal", args={"command": "ls"}, tool_call_id="c2")
        workdirs = [b["withhuman_workdir"] for b in self.sent("pre_tool_call")]
        self.assertEqual(workdirs, ["C:\\proj", "C:\\proj\\sub"])
        # A command given its own workdir does not move the session.
        self.hook("post_tool_call", tool_name="terminal", args={"command": "pwd", "workdir": "/x"},
                  session_id="s1", conversation_id="s1", tool_call_id="c3", status="ok",
                  result=json.dumps({"output": "/x", "exit_code": 0, "cwd": "/x"}))
        self.call(tool_name="terminal", args={"command": "ls"}, tool_call_id="c4")
        self.assertEqual(self.sent("pre_tool_call")[-1]["withhuman_workdir"], "C:\\proj\\sub")

    def test_keeps_one_engine_session_across_compression_and_subagents(self):
        self.call()
        self.hook("post_compaction", session_id="s2", old_session_id="s1")
        self.hook("pre_llm_call", session_id="s2", user_message="go on", platform="cli")
        self.assertEqual(self.sent("pre_llm_call")[0]["withhuman_session_id"], "s1")

        self.hook("subagent_start", parent_session_id="s2", child_session_id="child",
                  child_subagent_id="sa-0", child_role="leaf")
        self.call(session_id="child", conversation_id="s1", task_id="sa-0", tool_call_id="c9")
        start = self.sent("subagent_start")[0]
        child = self.sent("pre_tool_call")[-1]
        self.assertEqual((start["withhuman_session_id"], start["withhuman_agent_id"]), ("s1", "child"))
        self.assertEqual((child["withhuman_session_id"], child["withhuman_agent_id"]), ("s1", "child"))

    def test_keeps_a_session_compressed_before_a_restart_in_its_conversation(self):
        # No post_compaction was seen (the gateway restarted since): the call still belongs to
        # the conversation's main agent, so the engine asks it for its intent.
        self.call(session_id="s7", conversation_id="s1")
        body = self.sent("pre_tool_call")[0]
        self.assertEqual(body["withhuman_session_id"], "s1")
        self.assertNotIn("withhuman_agent_id", body)
        self.hook("pre_llm_call", session_id="s7", user_message="go on", platform="cli")
        self.assertEqual(self.sent("pre_llm_call")[0]["withhuman_session_id"], "s1")

    def test_gives_a_scripts_call_an_id(self):
        self.call(tool_name="terminal", args={"command": "echo hi"}, tool_call_id="")
        self.assertTrue(self.sent("pre_tool_call")[0]["tool_call_id"].startswith("withhuman-script-"))

    def test_does_not_send_a_blocked_calls_result(self):
        self.hook("post_tool_call", tool_name="read_file", args={}, session_id="s1",
                  tool_call_id="c1", status="blocked", result="{}")
        self.assertEqual(self.sent("post_tool_call"), [])

    # ---- the bridge on its own ----

    def test_bridge_check_finds_the_hermes_route(self):
        Collector.status = 400
        Collector.answers["pre_tool_call"] = {"error": "invalid_hermes_hook"}
        result = subprocess.run(
            [sys.executable, str(self.folder / "withhuman-hook.py"), "--check", self.url],
            capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"Hermes hook OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
