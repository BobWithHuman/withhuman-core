"""Tests for pre-tool-use.py: python3 -m unittest discover deploy/client/hooks"""

import http.server
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pre-tool-use.py")


class Collector(http.server.BaseHTTPRequestHandler):
    received = []
    answer = b""

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        # Header names are compared without case, as HTTP has them.
        headers = {name.lower(): value for name, value in self.headers.items()}
        Collector.received.append((headers, json.loads(body)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(Collector.answer)

    def log_message(self, *_):
        pass


class PreToolUseHookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), Collector)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/v1/hooks/PreToolUse"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Collector.received.clear()
        Collector.answer = b""
        self.workspace = tempfile.mkdtemp()
        self.write("scripts/run.py", "print('run')\n")
        self.write("skill/tool.sh", "echo tool\n")
        self.write("secret.txt", "AWS_KEY=x\n")
        self.write("bin/helper", "#!/bin/sh\necho helper\n", executable=True)
        self.write("bin/data", "#!/bin/sh\nnot executable\n")
        self.write("big.py", "x = 1\n" * 20_000)
        with open(os.path.join(self.workspace, "blob.py"), "wb") as file:
            file.write(b"\0\1\2")

    def write(self, name, text, executable=False):
        path = os.path.join(self.workspace, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as file:
            file.write(text)
        if executable:
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)

    def run_hook(self, event, url=None, client_id="team/device"):
        env = dict(os.environ)
        env.pop("WITHHUMAN_CLIENT_ID", None)
        if client_id:
            env["WITHHUMAN_CLIENT_ID"] = client_id
        return subprocess.run(
            [sys.executable, HOOK, url or self.url],
            input=json.dumps(event).encode(),
            capture_output=True,
            env=env,
            timeout=30,
        )

    def bash(self, command):
        return {
            "session_id": "s",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "t",
            "cwd": self.workspace,
        }

    def attached(self, command):
        result = self.run_hook(self.bash(command))
        self.assertEqual(result.returncode, 0, result.stderr)
        _, body = Collector.received[-1]
        return {
            os.path.relpath(program["path"], self.workspace): program
            for program in body.get("withhuman_programs", [])
        }

    def test_attaches_the_programs_a_command_may_run(self):
        found = self.attached(
            "cd skill && bash tool.sh; python3 ../scripts/run.py > out.txt && ../bin/helper"
        )
        self.assertEqual(sorted(found), ["bin/helper", "scripts/run.py", "skill/tool.sh"])
        run = found["scripts/run.py"]
        self.assertEqual(run["content"], "print('run')\n")
        self.assertEqual(run["size"], 13)
        self.assertEqual(len(run["sha256"]), 64)
        self.assertNotIn("truncated", run)

    def test_never_reads_files_a_command_could_not_run(self):
        self.assertEqual(self.attached("cat secret.txt bin/data blob.py"), {})

    def test_cuts_a_long_program_and_keeps_its_hash(self):
        big = self.attached("python big.py")["big.py"]
        self.assertTrue(big["truncated"])
        self.assertEqual(len(big["content"]), 64 * 1024)
        self.assertEqual(big["size"], 6 * 20_000)
        self.assertEqual(len(big["sha256"]), 64)

    def test_forwards_the_event_and_the_collectors_answer(self):
        Collector.answer = b'{"hookSpecificOutput":{"permissionDecision":"deny"}}'
        event = {"session_id": "s", "tool_name": "Read", "tool_input": {"file_path": "/x"},
                 "tool_use_id": "t", "cwd": self.workspace}
        result = self.run_hook(event)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, Collector.answer)
        headers, body = Collector.received[-1]
        self.assertEqual(body, event)
        self.assertEqual(headers["x-withhuman-client"], "team/device")
        self.assertEqual(headers["content-type"], "application/json")

        self.run_hook(event, client_id=None)
        self.assertNotIn("x-withhuman-client", Collector.received[-1][0])

    def test_fails_without_blocking_when_the_collector_is_unreachable(self):
        result = self.run_hook(self.bash("ls"), url="http://127.0.0.1:9/v1/hooks/PreToolUse")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"unreachable", result.stderr)


if __name__ == "__main__":
    unittest.main()
