"""Tests for the Codex hook: python3 -m unittest discover deploy/client/codex

Each test installs the hook as configure.py does (into <project>/.codex/hooks) and runs it as
Codex would, against a stand-in Collector.
"""

import http.server
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = [HERE / "withhuman-hook.py", HERE / "codex_transcript.py",
           HERE.parent / "hooks" / "pre-tool-use.py"]

DENY = "deny"
INTENT = "[의도] 테스트 파일을 고친다"


class Collector(http.server.BaseHTTPRequestHandler):
    received = []
    answers = {}
    delay = 0.0
    status = 200
    receipts = {}
    drop_event = None

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        event = self.path.rsplit("/", 1)[-1]
        headers = {name.lower(): value for name, value in self.headers.items()}
        delivery = headers.get("x-withhuman-event")
        if delivery in Collector.receipts:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(Collector.receipts[delivery])
            return
        Collector.received.append((event, headers, json.loads(body)))
        time.sleep(Collector.delay)
        answer = Collector.answers.get(event, b"")
        encoded = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        if Collector.status == 200 and delivery:
            Collector.receipts[delivery] = encoded
        if Collector.drop_event == event:
            Collector.drop_event = None
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        try:
            self.send_response(Collector.status)
            self.end_headers()
            self.wfile.write(encoded)
        except OSError:
            pass  # The hook gave up waiting, as the timeout test wants.

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, *_):
        pass


def decision(value, reason="blocked by policy"):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": value,
                                   "permissionDecisionReason": reason}}


def item(kind, payload):
    return {"timestamp": "2026-11-07T00:00:00Z", "type": kind, "payload": payload}


def message(message_id, text, turn="turn-1"):
    return item("response_item", {
        "type": "message", "id": message_id, "role": "assistant", "phase": "commentary",
        "content": [{"type": "output_text", "text": text}],
        "internal_chat_message_metadata_passthrough": {"turn_id": turn}})


def shell_call(call_id, command, workdir):
    return item("response_item", {
        "type": "function_call", "name": "exec_command", "call_id": call_id,
        "arguments": json.dumps({"cmd": command, "workdir": workdir})})


def shell_done(call_id, exit_code, cwd):
    return item("event_msg", {"type": "item_completed", "item": {
        "type": "CommandExecution", "id": call_id, "status": "completed" if exit_code == 0 else "failed",
        "exit_code": exit_code, "cwd": cwd}})


def output(call_id, text="Process exited with code 0", custom=False):
    return item("response_item", {
        "type": "custom_tool_call_output" if custom else "function_call_output",
        "call_id": call_id, "output": text})


class CodexHookTest(unittest.TestCase):
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
        Collector.delay = 0.0
        Collector.receipts = {}
        Collector.drop_event = None
        Collector.status = 200
        self.project = Path(tempfile.mkdtemp()).resolve()
        self.hooks = self.project / ".codex" / "hooks"
        self.hooks.mkdir(parents=True)
        for source in SOURCES:
            shutil.copyfile(source, self.hooks / source.name)
        self.transcript = self.project / "rollout.jsonl"
        self.transcript.write_text("")
        self.nested = str(self.project / "nested")
        os.makedirs(self.nested)

    def tearDown(self):
        shutil.rmtree(self.project, ignore_errors=True)

    def append(self, *records):
        with open(self.transcript, "a", encoding="utf-8") as file:
            for record in records:
                file.write(json.dumps(record, ensure_ascii=False) + "\n")

    def hook(self, event, body, url=None, **env):
        payload = {"session_id": "s1", "turn_id": "turn-1", "cwd": str(self.project),
                   "transcript_path": str(self.transcript), "hook_event_name": event, **body}
        environment = {**os.environ, "WITHHUMAN_CLIENT_ID": "lab/device-1",
                       "WITHHUMAN_REPO": "github.com/acme/app", **env}
        environment.pop("WITHHUMAN_MODE", None) if "WITHHUMAN_MODE" not in env else None
        started = time.monotonic()
        result = subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), url or self.url, event],
            input=json.dumps(payload).encode(), capture_output=True, env=environment, timeout=30)
        self.elapsed = time.monotonic() - started
        out = json.loads(result.stdout) if result.stdout.strip() else None
        return result.returncode, out, result.stderr.decode(errors="replace")

    def pre(self, call_id="call_1", tool_name="Bash", tool_input=None, **env):
        return self.hook("PreToolUse", {"tool_name": tool_name, "tool_use_id": call_id,
                                        "tool_input": tool_input or {"command": "Get-ChildItem"}},
                         **env)

    def sent(self, event=None):
        return [(name, body) for name, _, body in Collector.received if event in (None, name)]

    def assert_denied(self, result):
        code, out, _ = result
        self.assertEqual(code, 0)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], DENY)
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")

    # ---- answers ----

    def test_turns_a_review_into_a_deny(self):
        self.append(shell_call("call_1", "Get-ChildItem", str(self.project)))
        Collector.answers["PreToolUse"] = decision("ask", "needs a look")
        result = self.pre()
        self.assert_denied(result)
        self.assertEqual(result[1]["hookSpecificOutput"]["permissionDecisionReason"], "needs a look")

    def test_passes_an_allow_and_a_deny_on(self):
        self.append(shell_call("call_1", "Get-ChildItem", str(self.project)))
        self.assertEqual(self.pre(), (0, None, ""))
        Collector.answers["PreToolUse"] = decision("deny")
        self.assert_denied(self.pre())

    def test_passes_additional_context_to_codex(self):
        Collector.answers["UserPromptSubmit"] = {"hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit", "additionalContext": "state your intent"}}
        code, out, _ = self.hook("UserPromptSubmit", {"prompt": "fix it"})
        self.assertEqual(code, 0)
        self.assertEqual(out, {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                                      "additionalContext": "state your intent"}})

    def test_sends_the_client_repository_and_shell(self):
        self.hook("SessionStart", {"source": "startup"}, WITHHUMAN_KEY="whk_codex")
        _, headers, _ = Collector.received[0]
        self.assertEqual(headers["authorization"], "Bearer whk_codex")
        self.assertEqual(headers["x-withhuman-client"], "lab/device-1")
        self.assertEqual(headers["x-withhuman-repo"], "github.com/acme/app")
        self.assertEqual(headers["x-withhuman-shell"], "powershell" if os.name == "nt" else "posix")
        self.assertEqual(Collector.received[0][0], "SessionStart")

    # ---- failures end in a deny ----

    def test_denies_when_the_collector_is_unreachable(self):
        self.append(shell_call("call_1", "Get-ChildItem", str(self.project)))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = f"http://127.0.0.1:{probe.getsockname()[1]}"
        self.assert_denied(self.hook("PreToolUse", {
            "tool_name": "Bash", "tool_use_id": "call_1", "tool_input": {"command": "ls"}},
            url=closed))
        # Nothing to block for other events: Codex goes on.
        self.assertEqual(self.hook("PostToolUse", {"tool_name": "Bash", "tool_use_id": "call_1",
                                                    "tool_response": ""}, url=closed)[:2], (0, None))

    def test_denies_on_an_error_answer(self):
        self.append(shell_call("call_1", "Get-ChildItem", str(self.project)))
        Collector.status = 502
        self.assert_denied(self.pre())

    def test_denies_on_an_answer_that_does_not_parse(self):
        self.append(shell_call("call_1", "Get-ChildItem", str(self.project)))
        Collector.answers["PreToolUse"] = b"<html>proxy error</html>"
        self.assert_denied(self.pre())
        Collector.answers["PreToolUse"] = {"hookSpecificOutput": {"permissionDecision": "maybe"}}
        self.assert_denied(self.pre())

    def test_denies_before_codex_gives_up_on_a_slow_engine(self):
        self.append(shell_call("call_1", "Get-ChildItem", str(self.project)))
        Collector.delay = 3.0
        result = self.pre(WITHHUMAN_HOOK_TIMEOUT="1")
        self.assert_denied(result)
        self.assertLess(self.elapsed, 2.5)

    def test_denies_input_that_does_not_parse(self):
        result = subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), self.url, "PreToolUse"],
            input=b"not json", capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], DENY)

    def test_denies_when_its_own_files_are_missing(self):
        (self.hooks / "codex_transcript.py").unlink()
        self.assert_denied(self.pre())

    def test_lets_failures_through_in_observe_mode(self):
        Collector.status = 500
        self.assertEqual(self.pre(WITHHUMAN_MODE="observe")[:2], (0, None))

    # ---- what the transcript adds ----

    def test_sends_the_turns_message_before_its_first_call(self):
        self.append(message("msg_intent", INTENT + "\n고치겠습니다."),
                    shell_call("call_1", "Set-Content a.txt x", self.nested))
        self.assertEqual(self.pre(tool_input={"command": "Set-Content a.txt x"})[:2], (0, None))
        names = [name for name, _ in self.sent()]
        self.assertEqual(names, ["MessageDisplay", "PreToolUse"])
        display = self.sent("MessageDisplay")[0][1]
        self.assertEqual(display["message_id"], "msg_intent")
        self.assertEqual(display["delta"], INTENT + "\n고치겠습니다.")
        self.assertEqual((display["index"], display["final"], display["turn_id"]), (0, True, "turn-1"))
        # The shell runs in a subfolder; the engine resolves relative paths there.
        self.assertEqual(self.sent("PreToolUse")[0][1]["withhuman_workdir"], self.nested)
        # Sent once.
        self.pre(call_id="call_1")
        self.assertEqual(len(self.sent("MessageDisplay")), 1)

    def test_closes_the_batch_when_a_new_response_follows_results(self):
        self.append(message("m1", INTENT), shell_call("call_1", "a", str(self.project)))
        self.pre()
        self.append(shell_done("call_1", 0, "file:///" + str(self.project).replace("\\", "/")),
                    output("call_1"), message("m2", "다음 단계"),
                    shell_call("call_2", "b", str(self.project)))
        self.pre(call_id="call_2")
        names = [name for name, _ in self.sent()]
        self.assertEqual(names, ["MessageDisplay", "PreToolUse", "PostToolBatch", "MessageDisplay",
                                 "PreToolUse"])
        self.assertEqual(self.sent("PostToolBatch")[0][1], {"session_id": "s1", "tool_calls": [{"tool_use_id": "call_1"}]})

    def test_denies_a_call_whose_directory_it_cannot_tell(self):
        # Not in the transcript: judged as running in the session folder, marked by the
        # Collector since no directory is sent.
        self.assert_denied(self.pre(call_id="call_missing"))
        self.assertEqual(self.sent("PreToolUse"), [])
        # The same with no transcript at all.
        self.transcript.unlink()
        self.assert_denied(self.pre(call_id="call_missing"))

    def test_denies_a_call_of_unknown_directory_that_names_a_safeguard(self):
        for command in ["Set-Content hooks.json '{}'", "cd .codex; ni x", "echo > .CLAUDE/x",
                        "cp a settings.local.json", "rm withhuman-hook.py",
                        "Set-Content requirements.toml x"]:
            Collector.received = []
            self.assert_denied(self.pre(call_id="call_missing", tool_input={"command": command}))
            self.assertEqual(self.sent("PreToolUse"), [], command)
        self.transcript.unlink()
        self.assert_denied(self.pre(call_id="call_missing",
                                    tool_input={"command": "Set-Content config.toml x"}))

    # ---- code mode: shells called inside an `exec` script ----

    LIVE_COMMAND = ("New-Item -ItemType Directory -Path nested -Force -ErrorAction Stop | Out-Null\n"
                    "[System.IO.File]::WriteAllText((Join-Path (Get-Location) 'nested\\hello.txt'),"
                    " 'hello')\nWrite-Output 'hello.txt created'\n"
                    "[System.IO.File]::WriteAllText((Join-Path (Get-Location) "
                    "'nested\\.codex\\hooks.json'), '{}')\nWrite-Output 'hooks.json updated'")

    def live_fixture(self, upto_type=None):
        """The masked transcript of a real Codex 0.154 (ChatGPT) session on Windows whose shell
        runs inside a code-mode script, up to the record of `upto_type`."""
        text = (HERE / "fixtures" / "live-code-mode-windows.jsonl").read_text(encoding="utf-8")
        text = text.replace("<project>", json.dumps(str(self.project))[1:-1])
        records = []
        for line in text.splitlines():
            records.append(json.loads(line))
            if upto_type and records[-1].get("payload", {}).get("type") == upto_type:
                break
        self.append(*records)

    def test_finds_the_directory_of_a_shell_call_in_a_code_mode_script(self):
        self.live_fixture(upto_type="custom_tool_call")
        # The hook names the call `exec-…`; the transcript only has the script (`call_…`).
        result = self.pre(call_id="exec-live-1", tool_input={"command": self.LIVE_COMMAND})
        self.assertEqual(result[:2], (0, None), result[2])
        names = [name for name, _ in self.sent()]
        self.assertEqual(names, ["MessageDisplay", "PreToolUse"])
        self.assertTrue(self.sent("MessageDisplay")[0][1]["delta"].startswith("[의도]"))
        # No workdir argument: Codex runs it in the turn's directory.
        self.assertEqual(self.sent("PreToolUse")[0][1]["withhuman_workdir"], str(self.project))

    def test_matches_each_shell_call_of_a_script_to_its_hook(self):
        nested = self.nested.replace("\\", "\\\\")
        script = ('const a = await tools.exec_command({cmd:"Write-Output one"});\n'
                  f"await tools.exec_command({{'cmd': 'Write-Output two', workdir: \"{nested}\"}});\n"
                  'await tools.exec_command({cmd:"Write-Output one", "workdir":"' + nested + '"});\n'
                  "await tools.exec_command({cmd: someVariable});\n")
        self.append(item("turn_context", {"turn_id": "turn-1", "cwd": str(self.project)}),
                    item("response_item", {"type": "custom_tool_call", "name": "exec",
                                           "call_id": "call_script", "input": script}))
        self.pre(call_id="exec-1", tool_input={"command": "Write-Output two"})
        self.assert_denied(self.pre(call_id="exec-2", tool_input={"command": "Write-Output one"}))
        self.assert_denied(self.pre(call_id="exec-3", tool_input={"command": "Write-Output one"}))
        # The same hook asked again keeps its match.
        self.assert_denied(self.pre(call_id="exec-2", tool_input={"command": "Write-Output one"}))
        workdirs = [body["withhuman_workdir"] for _, body in self.sent("PreToolUse")]
        self.assertEqual(workdirs, [self.nested])
        # A command given by a variable is never matched by guess: judged in the session folder.
        self.assert_denied(self.pre(call_id="exec-4", tool_input={"command": "Write-Output three"}))
        self.assertEqual(len(self.sent("PreToolUse")), 1)

    def test_marks_a_failed_shell_call_of_a_code_mode_script(self):
        self.live_fixture(upto_type="custom_tool_call")
        self.pre(call_id="exec-live-1", tool_input={"command": self.LIVE_COMMAND})
        self.append(item("event_msg", {"type": "item_completed", "item": {
            "type": "CommandExecution", "id": "exec-live-1", "status": "failed", "exit_code": 1,
            "cwd": "file:///" + str(self.project).replace("\\", "/")}}))
        self.hook("PostToolUse", {"tool_name": "Bash", "tool_use_id": "exec-live-1",
                                  "tool_input": {"command": self.LIVE_COMMAND},
                                  "tool_response": ""})
        post = self.sent("PostToolUse")[0][1]
        self.assertEqual(post["withhuman_failure"], "exit code 1")
        self.assertEqual(post["withhuman_workdir"], str(self.project))

    def test_runs_a_call_without_a_directory_in_the_session_folder(self):
        self.append(item("response_item", {"type": "function_call", "name": "exec_command",
                                           "call_id": "call_1",
                                           "arguments": json.dumps({"cmd": "Get-ChildItem"})}))
        self.assertEqual(self.pre()[:2], (0, None))
        self.assertEqual(self.sent("PreToolUse")[0][1]["withhuman_workdir"], str(self.project))

    def test_marks_a_failed_command(self):
        self.append(shell_call("call_1", "exit 7", str(self.project)))
        self.pre()
        self.append(shell_done("call_1", 7, str(self.project)))
        self.hook("PostToolUse", {"tool_name": "Bash", "tool_use_id": "call_1",
                                  "tool_input": {"command": "exit 7"}, "tool_response": ""})
        post = self.sent("PostToolUse")[0][1]
        self.assertEqual(post["withhuman_failure"], "exit code 7")
        self.assertEqual(post["withhuman_workdir"], str(self.project))

    def test_reports_a_failed_mcp_call_that_had_no_post_hook(self):
        self.append(item("response_item", {"type": "function_call", "name": "record",
                                           "namespace": "mcp__c0", "call_id": "call_m",
                                           "arguments": json.dumps({"marker": "x"})}))
        self.pre(call_id="call_m", tool_name="mcp__c0__record", tool_input={"marker": "x"})
        self.append(item("event_msg", {"type": "item_completed", "item": {
                        "type": "McpToolCall", "id": "call_m", "server": "c0", "tool": "record",
                        "arguments": {"marker": "x"}, "status": "failed",
                        "result": {"content": [{"type": "text", "text": "boom"}], "isError": True}}}),
                    output("call_m", [{"type": "input_text", "text": "boom"}]),
                    message("final", "끝"))
        self.hook("Stop", {"last_assistant_message": "끝", "stop_hook_active": False})
        names = [name for name, _ in self.sent()]
        self.assertEqual(names, ["PreToolUse", "PostToolUse", "PostToolBatch", "MessageDisplay"])
        failure = self.sent("PostToolUse")[0][1]
        self.assertEqual((failure["tool_name"], failure["tool_use_id"], failure["withhuman_failure"]),
                         ("mcp__c0__record", "call_m", "boom"))

    def test_records_web_searches_only_where_they_have_no_hook(self):
        search = item("response_item", {
            "type": "custom_tool_call", "name": "exec", "call_id": "call_w",
            "input": 'const r = await tools.web__run({search_query:[{q:"codex hooks"}]});text(r);'})
        self.append(search, output("call_w", [{"type": "input_text", "text": "result text"}],
                                   custom=True))
        self.hook("Stop", {"last_assistant_message": "", "stop_hook_active": False})
        pre, post = self.sent("PreToolUse")[0][1], self.sent("PostToolUse")[0][1]
        self.assertTrue(pre["withhuman_record"])
        self.assertEqual(pre["tool_input"], {"search_query": [{"q": "codex hooks"}]})
        self.assertEqual(post["tool_response"], "result text")
        # A session whose searches run through the webrun hook was judged already.
        Collector.received = []
        self.hook("PreToolUse", {"tool_name": "webrun", "tool_use_id": "exec-1",
                                 "tool_input": {"search_query": [{"q": "x"}]}})
        search["payload"]["call_id"] = "call_w2"
        self.append(search, output("call_w2", "r", custom=True))
        self.hook("Stop", {"last_assistant_message": "", "stop_hook_active": False})
        self.assertFalse(any(body.get("withhuman_record") for _, body in self.sent()))

    def test_sends_the_final_message_codex_has_not_written_yet(self):
        self.hook("Stop", {"last_assistant_message": "다 했습니다", "stop_hook_active": False})
        display = self.sent("MessageDisplay")[0][1]
        self.assertEqual(display["delta"], "다 했습니다")
        self.assertEqual([name for name, _ in self.sent()], ["MessageDisplay"])

    def test_attaches_the_programs_a_command_runs(self):
        script = Path(self.nested) / "run.py"
        script.write_bytes(b"print('hi')\n")
        self.append(shell_call("call_1", "python run.py", self.nested))
        self.pre(tool_input={"command": "python run.py"})
        programs = self.sent("PreToolUse")[0][1]["withhuman_programs"]
        self.assertEqual(programs[0]["path"], str(script))
        self.assertEqual(programs[0]["content"], "print('hi')\n")

    def test_starts_a_session_after_its_history(self):
        self.append(message("old", "[의도] 예전 의도"))
        self.hook("SessionStart", {"source": "resume"})
        self.append(shell_call("call_1", "a", str(self.project)))
        self.pre()
        self.assertEqual(self.sent("MessageDisplay"), [])

    def test_lost_reply_keeps_cursor_unconfirmed_then_reuses_the_receipt(self):
        self.append(message("m1", INTENT), shell_call("call_1", "Get-ChildItem", str(self.project)))
        Collector.drop_event = "MessageDisplay"
        self.assert_denied(self.pre())
        state_path = next((self.hooks / "withhuman-state").glob("*.json"))
        state = json.loads(state_path.read_text())
        self.assertEqual(state["offset"], 0)
        self.assertIsNotNone(state["outbox"])
        self.assertEqual(self.sent("PreToolUse"), [])
        self.assertEqual(self.pre()[:2], (0, None))
        self.assertEqual(len(self.sent("MessageDisplay")), 1)
        self.assertGreater(json.loads(state_path.read_text())["offset"], 0)

    def test_an_unconfirmed_server_error_requires_a_new_session(self):
        self.append(message("m1", INTENT), shell_call("call_1", "Get-ChildItem", str(self.project)))
        Collector.status = 502
        self.assert_denied(self.pre())
        Collector.status = 200
        self.assert_denied(self.pre())
        self.assertEqual(self.sent("PreToolUse"), [])
        self.assertEqual(len(self.sent("MessageDisplay")), 1)

    def test_cannot_take_a_session_lock_means_deny(self):
        directory = self.hooks / "withhuman-state"
        directory.mkdir()
        lock = directory / (hashlib.sha256(b"s1").hexdigest()[:32] + ".json.lock")
        lock.write_text("")
        self.assert_denied(self.pre())
        self.assertEqual(self.sent(), [])

    def test_malformed_decision_object_is_not_an_allow(self):
        self.append(shell_call("call_1", "Get-ChildItem", str(self.project)))
        Collector.answers["PreToolUse"] = {}
        self.assert_denied(self.pre())

    def test_batches_name_only_finished_calls_and_repeated_stop_is_quiet(self):
        self.append(shell_call("call_1", "a", str(self.project)),
                    shell_call("call_2", "b", str(self.project)))
        self.pre()
        self.pre(call_id="call_2")
        self.append(output("call_1"), message("m1", "one done"))
        self.hook("Stop", {"last_assistant_message":"one done"})
        batches = self.sent("PostToolBatch")
        self.assertEqual(batches[0][1]["tool_calls"], [{"tool_use_id":"call_1"}])
        self.hook("Stop", {"last_assistant_message":"one done"})
        self.assertEqual(self.sent("PostToolBatch"), batches)

    def test_same_text_in_a_new_turn_gets_its_own_intent_message(self):
        self.append(item("turn_context", {"turn_id":"t1"}), message(None, INTENT, "t1"))
        self.hook("Stop", {"turn_id":"t1", "last_assistant_message":INTENT})
        self.append(item("turn_context", {"turn_id":"t2"}), message(None, INTENT, "t2"))
        self.hook("Stop", {"turn_id":"t2", "last_assistant_message":INTENT})
        self.assertEqual(len(self.sent("MessageDisplay")), 2)
        self.assertNotEqual(self.sent("MessageDisplay")[0][1]["message_id"],
                            self.sent("MessageDisplay")[1][1]["message_id"])

    def test_subagent_does_not_submit_main_agents_intent(self):
        self.append(message("main", INTENT), shell_call("subcall", "x", self.nested))
        self.hook("PreToolUse", {"agent_id":"child", "tool_name":"Bash", "tool_use_id":"subcall",
                                  "tool_input":{"command":"x"}})
        self.assertEqual(self.sent("MessageDisplay"), [])
        self.assertEqual(self.sent("PreToolUse")[0][1]["withhuman_workdir"], self.nested)

    def test_invalid_transcript_cannot_drop_the_intent_and_continue(self):
        self.transcript.write_text('{broken\n', encoding="utf-8")
        self.assert_denied(self.pre(tool_name="apply_patch", tool_input={"command":"patch"}))
        self.assertEqual(self.sent(), [])

    def test_attaches_powershell_paths_without_eating_backslashes(self):
        script = Path(self.nested) / "run.ps1"
        script.write_bytes(b"Write-Output 'hi'\n")
        command = "pwsh -NoProfile -File '.\\run.ps1'" if os.name == "nt" else "pwsh -NoProfile -File './run.ps1'"
        self.append(shell_call("call_1", command, self.nested))
        self.pre(tool_input={"command":command})
        programs = self.sent("PreToolUse")[0][1]["withhuman_programs"]
        self.assertEqual(programs[0]["path"], str(script))
        self.assertEqual(programs[0]["content"], "Write-Output 'hi'\n")

    def check(self):
        return subprocess.run(
            [sys.executable, str(self.hooks / "withhuman-hook.py"), "--check", self.url],
            capture_output=True, text=True, timeout=30)

    def test_checks_it_can_run(self):
        # The engine rejects the empty probe event, which proves its Codex route is there.
        Collector.status = 400
        Collector.answers["PreToolUse"] = {"error": "invalid_json"}
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reachable with Codex support", result.stdout)
        event, _, body = Collector.received[-1]
        self.assertEqual((event, body), ("PreToolUse", {}))

    def test_check_reports_a_key_the_engine_refused(self):
        Collector.status = 200
        Collector.answers["PreToolUse"] = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "revoked"}}
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refused this device's WithHuman key: revoked", result.stderr)

    def test_check_fails_on_an_engine_without_codex_support(self):
        Collector.status = 404
        Collector.answers["PreToolUse"] = b"route not found"
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no Codex route", result.stderr)
        # Anything else is no Codex engine either.
        Collector.status = 200
        Collector.answers["PreToolUse"] = b""
        self.assertNotEqual(self.check().returncode, 0)


if __name__ == "__main__":
    unittest.main()
