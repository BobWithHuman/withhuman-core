"""Tests for the OpenClaw hook: python3 -m unittest discover deploy/client/openclaw

Each test installs the bridge as configure.py does and runs it as the plugin does — one process
per hook, the hook's JSON on stdin, the event named as the only argument — against a stand-in
Collector. What is checked is the part that is OpenClaw's own: the shape of the answers
`index.js` reads, the directory the tool hooks leave out, the session OpenClaw never announces,
and the call a dispatch already carried.

The plugin itself is checked separately (`test_index.py`), since only node can run it.
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
SOURCES = [HERE / "withhuman-hook.py",
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


class OpenClawHookTest(unittest.TestCase):
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
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.hooks = self.home / "extensions" / "withhuman"
        self.hooks.mkdir(parents=True)
        for source in SOURCES:
            shutil.copyfile(source, self.hooks / source.name)
        # The installer writes the engine's address beside the hook; the plugin passes the
        # event alone.
        (self.hooks / "server").write_text(self.url + "\n", encoding="utf-8")
        # The bridge keeps its state in OpenClaw's state directory, not beside itself: what the
        # Gateway loads may be a built copy of the plugin. Pointed at a temporary one here, so a
        # test never writes into the state of the OpenClaw on this machine.
        self.state = self.home / "withhuman-state"

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def hook(self, event, body=None, **env):
        payload = {"sessionId": "s-1", "sessionKey": "agent:main:main", "runId": "r-1",
                   "agentId": "main", "hook_event_name": event, **(body or {})}
        environment = {**os.environ, "WITHHUMAN_CLIENT_ID": "lab/device-1",
                       "WITHHUMAN_REPO": "github.com/acme/app",
                       "WITHHUMAN_STATE_DIR": str(self.state), **env}
        result = subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), event],
            input=json.dumps(payload).encode(), capture_output=True, env=environment, timeout=60)
        out = json.loads(result.stdout) if result.stdout.strip() else None
        return result.returncode, out, result.stderr.decode(errors="replace")

    def call(self, tool_name="exec", params=None, call_id="call_1|fc_1", **env):
        return self.hook("before_tool_call", {
            "toolName": tool_name, "toolCallId": call_id,
            "params": params if params is not None else {"command": "ls -la",
                                                         "workdir": str(self.home)}}, **env)

    def sent(self, event=None):
        return [body for name, _, body in Collector.received if event in (None, name)]

    # ---- the shape `index.js` reads ----

    def test_blocks_a_call_in_the_shape_the_plugin_reads(self):
        Collector.answers["before_tool_call"] = decision("deny", "touches the hooks")
        code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertEqual(out, {"action": "block", "reason": "touches the hooks"})

    def test_puts_a_review_to_the_user(self):
        """OpenClaw pauses a call until the user answers and blocks it on a deny or a timeout,
        so a REVIEW is asked rather than denied."""
        Collector.answers["before_tool_call"] = decision("ask", "the user has not asked for this")
        code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertEqual(out, {"action": "ask", "reason": "the user has not asked for this"})

    def test_an_allow_is_nothing_at_all(self):
        """The plugin reads an empty answer as an allow, as Claude Code and Codex do."""
        Collector.answers["before_tool_call"] = decision("allow", "")
        code, out, _ = self.call()
        self.assertEqual((code, out), (0, None))

    def test_an_engine_that_does_not_answer_blocks_the_call(self):
        Collector.status = 500
        code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertEqual(out, {"action": "block", "reason": BLOCKED})

    def test_observe_mode_lets_a_call_through(self):
        Collector.status = 500
        code, out, _ = self.call(WITHHUMAN_MODE="observe")
        self.assertEqual((code, out), (0, None))

    def test_an_event_that_decides_nothing_never_blocks(self):
        Collector.status = 500
        code, out, _ = self.hook("after_tool_call", {"toolName": "exec", "toolCallId": "c1"})
        self.assertEqual((code, out), (0, None))

    def test_hands_the_turns_instruction_to_the_plugin(self):
        """The engine asks each turn to state its intent and sends that instruction back with
        the prompt — after OpenClaw has already built that prompt. A plugin hook answers a turn
        with a gate, not with text, so the instruction is handed over for the turns after."""
        Collector.answers["before_agent_run"] = {
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                   "additionalContext": "[의도] 줄을 먼저 쓸 것"}}
        code, out, _ = self.hook("before_agent_run", {"prompt": "fix the build"})
        self.assertEqual(code, 0)
        self.assertEqual(out, {"action": "context", "text": "[의도] 줄을 먼저 쓸 것"})

    def test_says_so_when_the_engine_asks_for_no_intent(self):
        """Intent capture off: the plugin is told, rather than left repeating the last
        instruction it saw."""
        code, out, _ = self.hook("before_agent_run", {"prompt": "fix the build"})
        self.assertEqual((code, out), (0, {"action": "context", "text": ""}))

    # ---- what the hooks leave out ----

    def test_a_tool_hook_gets_the_directory_of_its_turn(self):
        """Only the turn's hooks carry `workspaceDir`. Without it a relative path in a call
        resolves against nothing, so it is remembered from the turn and filled in."""
        self.hook("before_agent_run", {"prompt": "fix the build", "workspaceDir": "/work/project"})
        self.call(params={"command": "ls"})
        call = self.sent("before_tool_call")[-1]
        self.assertEqual(call["workspaceDir"], "/work/project")

    def test_a_shell_calls_own_directory_is_kept(self):
        self.hook("before_agent_run", {"prompt": "p", "workspaceDir": "/work/project"})
        self.call(params={"command": "ls", "workdir": "/work/project/sub"})
        call = self.sent("before_tool_call")[-1]
        self.assertEqual(call["params"]["workdir"], "/work/project/sub")

    def test_opens_the_session_openclaw_never_announced(self):
        """`session_start` did not fire in any recorded OpenClaw session, so the first event of
        one opens it."""
        self.hook("before_agent_run", {"prompt": "fix the build", "workspaceDir": "/work"})
        names = [name for name, _, _ in Collector.received]
        self.assertEqual(names, ["session_start", "before_agent_run"])
        opening = self.sent("session_start")[0]
        self.assertTrue(opening["withhuman_synthesized"])
        self.assertEqual(opening["sessionId"], "s-1")

    def test_opens_a_session_once(self):
        self.hook("before_agent_run", {"prompt": "one", "workspaceDir": "/work"})
        self.hook("before_agent_run", {"prompt": "two", "workspaceDir": "/work"})
        names = [name for name, _, _ in Collector.received]
        self.assertEqual(names.count("session_start"), 1)

    def test_openclaws_own_session_start_is_not_doubled(self):
        self.hook("session_start", {"workspaceDir": "/work"})
        self.hook("before_agent_run", {"prompt": "p", "workspaceDir": "/work"})
        names = [name for name, _, _ in Collector.received]
        self.assertEqual(names, ["session_start", "before_agent_run"])

    # ---- what must not be sent twice ----

    def test_a_dispatched_call_is_not_sent(self):
        """`dispatch_action` carries the real tool and its arguments, and blocking it keeps the
        action from running, so the call it dispatches is the duplicate of one already judged."""
        code, out, _ = self.call(tool_name="agents_list", call_id="tool_call:call_1_fc_1:agents_list:1",
                                 params={})
        self.assertEqual((code, out), (0, None))
        self.assertEqual(self.sent("before_tool_call"), [])

    def test_the_dispatch_itself_is_sent(self):
        self.call(tool_name="dispatch_action",
                  params={"id": "openclaw:core:agents_list", "args": {}})
        self.assertEqual(len(self.sent("before_tool_call")), 1)

    # ---- what the client adds ----

    def test_attaches_the_programs_a_shell_command_may_run(self):
        program = self.home / "deploy.sh"
        program.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
        os.chmod(program, 0o755)
        self.call(params={"command": "./deploy.sh", "workdir": str(self.home)})
        call = self.sent("before_tool_call")[-1]
        self.assertTrue(any(found["path"].endswith("deploy.sh")
                            for found in call.get("withhuman_programs", [])))

    def test_sends_the_shell_it_runs_commands_in(self):
        self.call()
        _, headers, _ = Collector.received[-1]
        self.assertIn(headers["x-withhuman-shell"], ("posix", "powershell"))

    def test_sends_the_device_and_the_repository(self):
        self.call()
        _, headers, _ = Collector.received[-1]
        self.assertEqual(headers["x-withhuman-client"], "lab/device-1")
        self.assertEqual(headers["x-withhuman-repo"], "github.com/acme/app")

    # ---- the local evidence ----

    def test_records_its_own_decision_in_the_audit_log(self):
        """The audit log is the only local evidence when the engine cannot store a verdict, so
        a block must not be recorded as an allow."""
        Collector.answers["before_tool_call"] = decision("deny", "touches the hooks")
        self.call()
        log = (self.state / "audit.jsonl").read_text(encoding="utf-8")
        rows = [json.loads(line) for line in log.splitlines() if line.strip()]
        self.assertEqual(rows[-1]["decision"], "deny")
        self.assertEqual(rows[-1]["event"], "before_tool_call")

    def test_the_audit_row_names_the_session_and_the_call(self):
        """OpenClaw names the session and the call its own way (`sessionId`, `toolCallId`), and
        a row naming neither could not be matched to what the engine recorded. Found by reading
        the log of a real session, where every row named nothing."""
        Collector.answers["before_tool_call"] = decision("deny", "touches the hooks")
        self.call(call_id="call_abc|fc_def")
        rows = [json.loads(line)
                for line in (self.state / "audit.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()]
        self.assertEqual(rows[-1]["session_id"], "s-1")
        self.assertEqual(rows[-1]["tool_use_id"], "call_abc|fc_def")

    def test_records_an_ask_as_an_ask(self):
        Collector.answers["before_tool_call"] = decision("ask", "the user decides")
        self.call()
        log = (self.state / "audit.jsonl").read_text(encoding="utf-8")
        rows = [json.loads(line) for line in log.splitlines() if line.strip()]
        self.assertEqual(rows[-1]["decision"], "ask")

    # ---- where the state lives ----

    def test_keeps_its_state_in_openclaws_state_directory(self):
        """Not beside the hook: OpenClaw builds a package of a plugin when it installs one, and
        what the Gateway loads may be a copy of it, which state beside the file would follow and
        be lost with. The engine blocks an agent's changes to OpenClaw's state directory, so the
        audit log is no less protected there."""
        Collector.answers["before_tool_call"] = decision("deny", "touches the hooks")
        self.call()
        self.assertTrue((self.state / "audit.jsonl").is_file())
        self.assertFalse((self.hooks / "withhuman-state").exists())

    def test_openclaws_own_state_directory_decides_where_that_is(self):
        """A named profile and `--dev` move OpenClaw's state directory; the bridge follows."""
        elsewhere = self.home / "profile-dev"
        environment = {**os.environ, "OPENCLAW_STATE_DIR": str(elsewhere)}
        environment.pop("WITHHUMAN_STATE_DIR", None)
        result = subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), "after_tool_call"],
            input=json.dumps({"sessionId": "s-1", "toolName": "exec",
                              "toolCallId": "c1"}).encode(),
            capture_output=True, env=environment, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertTrue((elsewhere / "withhuman-state" / "audit.jsonl").is_file())

    # ---- the setup's own check ----

    def test_the_check_reads_the_address_beside_the_hook(self):
        """`configure.py` writes the address there and the plugin passes the event alone, so
        `--check` has to find it the same way."""
        Collector.status = 400
        Collector.answers["before_tool_call"] = {"error": "invalid_openclaw_hook"}
        result = subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), "--check"],
            capture_output=True, timeout=60,
            env={**os.environ, "WITHHUMAN_CLIENT_ID": "lab/device-1"})
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn("OpenClaw", result.stdout.decode())


if __name__ == "__main__":
    unittest.main()
