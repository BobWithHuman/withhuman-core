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
    # The exceptions the engine answers; None answers 500.
    exceptions = []
    fetched = []

    def do_GET(self):
        Collector.fetched.append(self.path)
        if Collector.exceptions is None:
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(Collector.exceptions).encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        # Header names are compared without case, as HTTP has them.
        headers = {name.lower(): value for name, value in self.headers.items()}
        headers[":path"] = self.path
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
        Collector.fetched.clear()
        Collector.answer = b""
        Collector.exceptions = []
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

    def run_marked(self, event, home, project):
        """Runs the hook as the device-wide setup does, for any event."""
        env = {**os.environ, "HOME": home, "USERPROFILE": home, "CLAUDE_PROJECT_DIR": project,
               "WITHHUMAN_CLIENT_ID": "team/device"}
        env.pop("WITHHUMAN_KEY", None)
        server = self.url.rsplit("/v1/hooks/", 1)[0]
        return subprocess.run([sys.executable, HOOK, "--withhuman-hook", server],
                              input=json.dumps(event).encode(), capture_output=True, env=env,
                              timeout=30)

    def run_hook(self, event, url=None, client_id="team/device", key=None, home=None):
        # A home of its own, so the setup files of whoever runs the tests are not read.
        home = home or tempfile.mkdtemp()
        env = {**os.environ, "HOME": home, "USERPROFILE": home}
        env.pop("WITHHUMAN_CLIENT_ID", None)
        env.pop("WITHHUMAN_KEY", None)
        if client_id:
            env["WITHHUMAN_CLIENT_ID"] = client_id
        if key:
            env["WITHHUMAN_KEY"] = key
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

        self.assertNotIn("authorization", headers)

        self.run_hook(event, client_id=None)
        self.assertNotIn("x-withhuman-client", Collector.received[-1][0])

    def test_sends_the_key_and_reads_the_setups_files_without_the_environment(self):
        event = {"session_id": "s", "tool_name": "Read", "tool_input": {"file_path": "/x"},
                 "tool_use_id": "t", "cwd": self.workspace}
        self.run_hook(event, key="whk_k")
        self.assertEqual(Collector.received[-1][0]["authorization"], "Bearer whk_k")
        # Claude Code started from an IDE or app has neither variable; the setup's files stand in.
        home = tempfile.mkdtemp()
        config = os.path.join(home, ".config", "withhuman")
        os.makedirs(config)
        for name, value in (("client-id", "team/from-file\n"), ("key", "whk_file\n")):
            with open(os.path.join(config, name), "w") as file:
                file.write(value)
        self.run_hook(event, client_id=None, home=home)
        headers = Collector.received[-1][0]
        self.assertEqual(headers["x-withhuman-client"], "team/from-file")
        self.assertEqual(headers["authorization"], "Bearer whk_file")
        # The environment comes first.
        self.run_hook(event, key="whk_env", home=home)
        headers = Collector.received[-1][0]
        self.assertEqual(headers["x-withhuman-client"], "team/device")
        self.assertEqual(headers["authorization"], "Bearer whk_env")

    def test_fails_without_blocking_when_the_collector_is_unreachable(self):
        result = self.run_hook(self.bash("ls"), url="http://127.0.0.1:9/v1/hooks/PreToolUse")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"unreachable", result.stderr)

    def session(self, home, project, folder_events=("SessionStart", "UserPromptSubmit", "PostToolUse")):
        sent = []
        for name in folder_events:
            event = {"session_id": "s", "hook_event_name": name, "cwd": project, "source": "startup",
                     "prompt": "secret plan", "tool_name": "Read", "tool_response": "secret"}
            before = len(Collector.received)
            result = self.run_marked(event, home, project)
            self.assertEqual(result.returncode, 0, result.stderr)
            sent.append(Collector.received[before:])
        return sent

    def test_posts_every_event_to_its_route(self):
        home = tempfile.mkdtemp()
        sent = self.session(home, "/work/app")
        self.assertEqual([batch[0][0][":path"] for batch in sent],
                         ["/v1/hooks/SessionStart", "/v1/hooks/UserPromptSubmit", "/v1/hooks/PostToolUse"])
        self.assertEqual(sent[1][0][1]["prompt"], "secret plan")
        self.assertIn("client_id=team%2Fdevice", Collector.fetched[0])

    def test_an_excepted_folder_sends_only_that_the_session_started(self):
        Collector.exceptions = [{"id": 4, "folder": "/work/secret", "created_at": 1}]
        home = tempfile.mkdtemp()
        start, prompt, result = self.session(home, "/work/secret/app")
        self.assertEqual(start[0][1], {"session_id": "s", "hook_event_name": "SessionStart",
                                       "source": "startup", "cwd": "/work/secret/app",
                                       "withhuman_exception": 4})
        self.assertEqual((prompt, result), ([], []))
        # Elsewhere on the device everything is sent.
        start, prompt, _ = self.session(home, "/work/secretive")
        self.assertNotIn("withhuman_exception", start[0][1])
        self.assertEqual(prompt[0][1]["prompt"], "secret plan")

    def test_sends_everything_when_the_list_cannot_be_fetched(self):
        Collector.exceptions = [{"id": 4, "folder": "/work/secret", "created_at": 1}]
        home = tempfile.mkdtemp()
        self.session(home, "/work/secret/app", ("SessionStart",))
        Collector.exceptions = None
        Collector.received.clear()
        sent = self.session(home, "/work/secret/app")
        self.assertEqual([len(batch) for batch in sent], [1, 1, 1])
        self.assertNotIn("withhuman_exception", sent[0][0][1])
        self.assertFalse(os.path.exists(os.path.join(home, ".config", "withhuman", "exceptions.json")))

    def test_a_stale_or_broken_cache_covers_nothing(self):
        home = tempfile.mkdtemp()
        cache = os.path.join(home, ".config", "withhuman", "exceptions.json")
        os.makedirs(os.path.dirname(cache))
        for content in ({"fetched_at": 0, "client_id": "team/device",
                         "exceptions": [{"id": 4, "folder": "/work/secret"}]},
                        {"fetched_at": 9e12, "client_id": "team/other",
                         "exceptions": [{"id": 4, "folder": "/work/secret"}]},
                        "not json"):
            with open(cache, "w") as file:
                file.write(content if isinstance(content, str) else json.dumps(content))
            sent = self.session(home, "/work/secret/app", ("UserPromptSubmit",))
            self.assertEqual(len(sent[0]), 1, content)


if __name__ == "__main__":
    unittest.main()
