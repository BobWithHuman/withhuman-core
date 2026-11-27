"""Tests for the shared client bridge: python3 -m unittest discover deploy/client/hooks

What adding an agent takes, as a test: a `Bridge` subclass with a `kind`, a `name` and a `run`,
and nothing else. The agent here is deliberately the simplest possible one — it forwards the
hook as it stands — so what the tests show is the shared machinery's doing: the route it posts
to, the deny every failure ends in, the answer the agent reads, the local audit log and the
self-check.
"""

import http.server
import json
import os
import subprocess
import sys
import tempfile
import shutil
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
# A bridge of its own, written as deploy/client/<kind>/ ones are.
DEMO = '''
import json, os, sys
sys.path.insert(0, {hooks!r})
import withhuman_bridge as bridge


class DemoBridge(bridge.Bridge):
    kind = "demo"
    name = "Demo"
    deadlines = {{"PreToolUse": 3.0}}
    state_directory = {state!r}

    def run(self, collector, event_name, payload):
        return collector.post(event_name, json.loads(payload))


if __name__ == "__main__":
    sys.exit(bridge.run_bridge(DemoBridge()))
'''

BLOCKED = "WithHuman could not check this call, so it was blocked"


class Collector(http.server.BaseHTTPRequestHandler):
    received = []
    answers = {}
    status = 200
    delay = 0.0

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        headers = {name.lower(): value for name, value in self.headers.items()}
        Collector.received.append((self.path, headers, json.loads(body)))
        time.sleep(Collector.delay)
        answer = Collector.answers.get(self.path.rsplit("/", 1)[-1], b"")
        encoded = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        try:
            self.send_response(Collector.status)
            self.end_headers()
            self.wfile.write(encoded)
        except OSError:
            pass  # The hook gave up waiting, as the timeout test wants.

    def log_message(self, *_):
        pass


class BridgeTest(unittest.TestCase):
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
        self.folder = Path(tempfile.mkdtemp()).resolve()
        self.state = self.folder / "withhuman-state"
        self.hook = self.folder / "withhuman-demo.py"
        self.hook.write_text(
            DEMO.format(hooks=str(HERE), state=str(self.state)), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.folder, ignore_errors=True)

    def hook_run(self, event, body=None, url=None, **env):
        payload = {"session_id": "s1", "tool_use_id": "call_1", **(body or {})}
        result = subprocess.run(
            [sys.executable, str(self.hook), url or self.url, event],
            input=json.dumps(payload).encode(), capture_output=True, timeout=30,
            env={**os.environ, "WITHHUMAN_CLIENT_ID": "lab/device-1", **env})
        out = json.loads(result.stdout) if result.stdout.strip() else None
        return result.returncode, out, result.stderr.decode(errors="replace")

    def decision(self, value, reason="blocked by policy"):
        Collector.answers["PreToolUse"] = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": value,
            "permissionDecisionReason": reason}}

    # ---- the route and the headers are the shared bridge's ----

    def test_posts_to_the_agents_own_route(self):
        self.assertEqual(self.hook_run("PreToolUse")[:2], (0, None))
        path, headers, body = Collector.received[0]
        self.assertEqual(path, "/v1/hooks/demo/PreToolUse")
        self.assertEqual(headers["x-withhuman-client"], "lab/device-1")
        self.assertEqual(body["session_id"], "s1")

    # ---- the answer the agent reads ----

    def test_passes_a_deny_on_and_keeps_an_allow_quiet(self):
        self.decision("deny", "touches the hooks")
        code, out, _ = self.hook_run("PreToolUse")
        self.assertEqual(code, 0)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecisionReason"],
                         "touches the hooks")
        self.decision("allow")
        self.assertEqual(self.hook_run("PreToolUse")[:2], (0, None))

    def test_passes_additional_context_on_a_result(self):
        Collector.answers["PostToolUse"] = {"hookSpecificOutput": {
            "hookEventName": "PostToolUse", "additionalContext": "state the intent"}}
        code, out, _ = self.hook_run("PostToolUse")
        self.assertEqual((code, out["hookSpecificOutput"]["additionalContext"]),
                         (0, "state the intent"))

    # ---- every failure on a blocking event ends in a decision ----

    def test_denies_when_the_engine_cannot_be_reached(self):
        code, out, _ = self.hook_run("PreToolUse", url="http://127.0.0.1:9")
        self.assertEqual((code, out["hookSpecificOutput"]["permissionDecisionReason"]),
                         (0, BLOCKED))

    def test_denies_on_an_error_answer_and_on_one_that_does_not_parse(self):
        Collector.status = 500
        self.assertEqual(self.hook_run("PreToolUse")[1]["hookSpecificOutput"][
            "permissionDecision"], "deny")
        Collector.status = 200
        Collector.answers["PreToolUse"] = b"not json"
        self.assertEqual(self.hook_run("PreToolUse")[1]["hookSpecificOutput"][
            "permissionDecision"], "deny")

    def test_denies_a_slow_engine_before_the_agent_gives_up(self):
        Collector.delay = 5.0
        started = time.monotonic()
        self.assertEqual(self.hook_run("PreToolUse", WITHHUMAN_HOOK_TIMEOUT="1")[1][
            "hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertLess(time.monotonic() - started, 4.0)

    def test_denies_input_that_does_not_parse(self):
        result = subprocess.run(
            [sys.executable, str(self.hook), self.url, "PreToolUse"],
            input=b"not json", capture_output=True, timeout=30)
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"][
            "permissionDecision"], "deny")

    def test_lets_failures_through_in_observe_mode(self):
        Collector.status = 500
        self.assertEqual(self.hook_run("PreToolUse", WITHHUMAN_MODE="observe")[:2], (0, None))

    def test_an_event_that_blocks_nothing_only_reports_its_failure(self):
        Collector.status = 500
        code, out, stderr = self.hook_run("SessionStart")
        self.assertEqual((code, out), (0, None))
        self.assertIn("Collector answered 500", stderr)

    # ---- evidence of its own ----

    def test_writes_every_decision_to_the_local_audit_log(self):
        self.decision("deny", "touches the hooks")
        self.hook_run("PreToolUse")
        self.hook_run("PreToolUse", url="http://127.0.0.1:9")
        rows = [json.loads(line) for line in
                (self.state / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([(row["decision"], row["source"]) for row in rows],
                         [("deny", "collector"), ("deny", "bridge_error")])
        self.assertEqual(rows[0]["tool_use_id"], "call_1")

    # ---- the self-check ----

    def test_checks_the_engine_knows_this_agent(self):
        Collector.status = 400
        Collector.answers["PreToolUse"] = {"error": "invalid_hook"}
        result = subprocess.run([sys.executable, str(self.hook), "--check", self.url],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reachable with Demo support", result.stdout)

    def test_check_fails_on_an_engine_without_this_agent(self):
        Collector.status = 404
        result = subprocess.run([sys.executable, str(self.hook), "--check", self.url],
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no Demo route", result.stderr)


class StateTest(unittest.TestCase):
    """The session state file, under an extension of an agent's own."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import withhuman_bridge
        self.bridge = withhuman_bridge
        self.directory = tempfile.mkdtemp()

        class Kept(withhuman_bridge.State):
            SUFFIX = ".state"

        self.Kept = Kept

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_carries_an_earlier_json_state_over(self):
        legacy = self.Kept(self.directory, "s1").legacy_path
        with open(legacy, "w", encoding="utf-8") as file:
            json.dump({"outbox": None, "resync_required": False, "turn": "t1"}, file)
        with self.Kept(self.directory, "s1") as session:
            self.assertEqual(session.state["turn"], "t1")
        self.assertFalse(os.path.exists(legacy))

    def test_a_failed_carry_over_releases_the_lock(self):
        """`__exit__` does not run when `__enter__` raises; a lock left behind would turn back
        every later call of the session."""
        session = self.Kept(self.directory, "s2")
        with open(session.legacy_path, "w", encoding="utf-8") as file:
            file.write("{}")
        from unittest import mock
        with mock.patch.object(self.bridge.os, "replace", side_effect=PermissionError("busy")):
            with self.assertRaises(PermissionError):
                with session:
                    pass
        self.assertFalse(os.path.exists(session.lock_path))
        with self.Kept(self.directory, "s2") as again:
            self.assertTrue(again.locked)


if __name__ == "__main__":
    unittest.main()
