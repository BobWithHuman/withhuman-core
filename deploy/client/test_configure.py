"""Tests for configure.py: python3 -m unittest discover deploy/client"""

import http.server
import json
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
CONFIGURE = HERE / "configure.py"

SERVER = "https://withhuman.example.com"
# An earlier setup pointed at a different engine; it still has to be recognised and replaced.
OLD_HTTP = {"type": "http", "url": "https://old.example.com/v1/hooks/PreToolUse",
            "headers": {"x-withhuman-client": "$WITHHUMAN_CLIENT_ID"}}
OTHER = {"type": "command", "command": "echo mine"}
KEY = "whk_0123456789abcdef_" + "ab" * 32
HEADERS = {"x-withhuman-client": "$WITHHUMAN_CLIENT_ID", "Authorization": "Bearer $WITHHUMAN_KEY"}


class Engine(http.server.BaseHTTPRequestHandler):
    """The engine's registration endpoint, answering `status` and `body`."""
    received = []
    status = 200
    body = b'{"client_id": "x"}'
    # A field this engine does not know yet, refused with 422 as a strict JSON body is.
    unknown = None

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Engine.received.append((self.path, {k.lower(): v for k, v in self.headers.items()},
                                body))
        self.send_response(422 if Engine.unknown in body else Engine.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(Engine.body)

    def log_message(self, *_):
        pass


class Setup(unittest.TestCase):
    def setUp(self):
        # Resolved, because configure.py resolves --project: on macOS the temporary directory is
        # /var/folders/... through a symlink to /private/var/folders/..., and comparing the two
        # spellings fails on nothing real.
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.project = Path(tempfile.mkdtemp()).resolve()
        (self.home / ".claude").mkdir()
        (self.project / ".claude").mkdir()

    def write(self, path, value):
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)

    def read(self, path):
        return json.loads(path.read_text())

    def configure(self, *extra, server=SERVER, register=False):
        # WITHHUMAN_SERVER and WITHHUMAN_KEY are dropped so the developer's own environment cannot
        # stand in for what is under test. Registering is left to the tests about it.
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home), "SHELL": "/bin/zsh"}
        env.pop("WITHHUMAN_SERVER", None)
        env.pop("WITHHUMAN_KEY", None)
        arguments = ["--project", str(self.project), "--team", "lab"]
        if not register:
            arguments.append("--no-register")
        if os.name == "nt":
            arguments.append("--no-persist")  # Never setx in a unit test.
        if server is not None:
            arguments += ["--server", server]
        return subprocess.run(
            [sys.executable, str(CONFIGURE), *arguments, *extra],
            capture_output=True, text=True, env=env, timeout=30,
        )



class ConfigureTest(Setup):
    @unittest.skipIf(os.name == "nt", "POSIX profile persistence; covered on Linux")
    def test_replaces_an_earlier_setup_and_keeps_everything_else(self):
        # User settings from an earlier setup.sh merge, beside the user's own hook and settings.
        self.write(self.home / ".claude" / "settings.json", {
            "model": "opus",
            "hooks": {"PreToolUse": [{"hooks": [OLD_HTTP, OTHER]}],
                      "PostToolUse": [{"hooks": [dict(OLD_HTTP, url="https://x/v1/hooks/PostToolUse")]}]},
        })
        # The project's all-HTTP settings from the earlier snippet.
        self.write(self.project / ".claude" / "settings.json", {
            "permissions": {"allow": ["Bash(ls:*)"]},
            "hooks": {"PreToolUse": [{"hooks": [OLD_HTTP]}], "Stop": [{"hooks": [OTHER]}]},
        })
        self.write(self.project / ".claude" / "settings.local.json",
                   {"hooks": {"SessionStart": [{"hooks": [dict(OLD_HTTP, url="https://x/v1/hooks/SessionStart")]}]}})
        (self.home / ".zshrc").write_text("alias ll='ls -l'\n# WithHuman client ID\nexport WITHHUMAN_CLIENT_ID=$(cat '/old/id')\n")

        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)

        user = self.read(self.home / ".claude" / "settings.json")
        self.assertEqual(user, {"model": "opus", "hooks": {"PreToolUse": [{"hooks": [OTHER]}]}})
        self.assertEqual(self.read(self.project / ".claude" / "settings.local.json"), {})

        settings = self.read(self.project / ".claude" / "settings.json")
        self.assertEqual(settings["permissions"], {"allow": ["Bash(ls:*)"]})
        self.assertEqual(settings["hooks"]["Stop"], [{"hooks": [OTHER]}])
        self.assertEqual(len(settings["hooks"]), 12)
        pre = settings["hooks"]["PreToolUse"]
        self.assertEqual(len(pre), 1)
        command = pre[0]["hooks"][0]
        hook = self.project / ".claude" / "hooks" / "pre-tool-use.py"
        self.assertEqual(command["type"], "command")
        self.assertEqual(command["command"], f'"{Path(sys.executable).as_posix()}" "{hook.as_posix()}" '
                                             f"{SERVER}/v1/hooks/PreToolUse")
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertEqual(hook.read_text(), (HERE / "hooks" / "pre-tool-use.py").read_text())
        post = settings["hooks"]["PostToolUse"][0]["hooks"][0]
        self.assertEqual(post["url"], f"{SERVER}/v1/hooks/PostToolUse")
        self.assertEqual(post["headers"], HEADERS)
        self.assertEqual(post["allowedEnvVars"], ["WITHHUMAN_CLIENT_ID", "WITHHUMAN_KEY"])
        end = settings["hooks"]["SessionEnd"][0]["hooks"][0]
        self.assertEqual((end["type"], end["url"]), ("http", f"{SERVER}/v1/hooks/SessionEnd"))

        # Each file changed was kept as it was.
        for folder, name in [(self.home / ".claude", "settings.json"), (self.project / ".claude", "settings.json"),
                             (self.project / ".claude", "settings.local.json"), (self.home, ".zshrc")]:
            self.assertEqual(len(list(folder.glob(f"{name}.bak-*"))), 1, name)

        client_id = (self.home / ".config" / "withhuman" / "client-id").read_text().strip()
        self.assertRegex(client_id, r"^lab/[0-9a-f-]{36}$")
        profile = (self.home / ".zshrc").read_text()
        self.assertIn("alias ll='ls -l'", profile)
        self.assertNotIn("/old/id", profile)
        self.assertEqual(profile.count("export WITHHUMAN_CLIENT_ID="), 1)
        self.assertIn(client_id, result.stdout)

    @unittest.skipIf(os.name == "nt", "POSIX profile persistence; covered on Linux")
    def test_gives_the_same_result_when_run_again(self):
        self.assertEqual(self.configure().returncode, 0)
        settings = (self.project / ".claude" / "settings.json").read_text()
        profile = (self.home / ".zshrc").read_text()
        client_id = (self.home / ".config" / "withhuman" / "client-id").read_text()

        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.project / ".claude" / "settings.json").read_text(), settings)
        self.assertEqual((self.home / ".zshrc").read_text(), profile)
        self.assertEqual((self.home / ".config" / "withhuman" / "client-id").read_text(), client_id)

    def test_leaves_a_broken_settings_file_alone(self):
        broken = self.project / ".claude" / "settings.json"
        broken.write_text("{ not json")
        result = self.configure()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not valid JSON", result.stderr)
        self.assertEqual(broken.read_text(), "{ not json")

    def test_leaves_the_profile_alone_when_asked(self):
        self.assertEqual(self.configure("--no-persist").returncode, 0)
        self.assertFalse((self.home / ".zshrc").exists())

    def test_refuses_to_guess_the_engine_address(self):
        """WithHuman is self-hosted: no default server, so no device reports to someone else's."""
        result = self.configure(server=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--server is required", result.stderr)
        self.assertFalse((self.project / ".claude" / "settings.json").exists())

    def test_takes_the_address_from_the_environment(self):
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home), "SHELL": "/bin/zsh",
               "WITHHUMAN_SERVER": "http://127.0.0.1:3000/"}
        result = subprocess.run(
            [sys.executable, str(CONFIGURE), "--project", str(self.project), "--team", "lab", "--no-persist",
             "--no-register"],
            capture_output=True, text=True, env=env, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = self.read(self.project / ".claude" / "settings.json")
        # The trailing slash is dropped rather than doubled into the hook URLs.
        self.assertEqual(settings["hooks"]["PostToolUse"][0]["hooks"][0]["url"],
                         "http://127.0.0.1:3000/v1/hooks/PostToolUse")

    def test_rejects_an_address_that_is_not_a_url(self):
        result = self.configure(server="withhuman.example.com")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an http(s) URL", result.stderr)


    def test_uninstall_takes_out_only_withhuman(self):
        self.write(self.project / ".claude" / "settings.json", {
            "permissions": {"allow": ["Bash(ls:*)"]}, "hooks": {"Stop": [{"hooks": [OTHER]}]}})
        self.assertEqual(self.configure("--no-persist").returncode, 0)
        result = self.configure("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.read(self.project / ".claude" / "settings.json"), {
            "permissions": {"allow": ["Bash(ls:*)"]}, "hooks": {"Stop": [{"hooks": [OTHER]}]}})
        self.assertFalse((self.project / ".claude" / "hooks" / "pre-tool-use.py").exists())


class KeyAndRegistrationTest(Setup):
    """--key and the registration with the engine."""

    @classmethod
    def setUpClass(cls):
        cls.engine = http.server.HTTPServer(("127.0.0.1", 0), Engine)
        threading.Thread(target=cls.engine.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.engine.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.engine.shutdown()

    def setUp(self):
        super().setUp()
        Engine.received.clear()
        Engine.status = 200
        Engine.body = b'{"client_id": "x"}'

    @unittest.skipIf(os.name == "nt", "POSIX file modes and profile")
    def test_keeps_the_key_private_and_exports_it(self):
        result = self.configure("--key", KEY)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = self.home / ".config" / "withhuman" / "key"
        self.assertEqual(path.read_text().strip(), KEY)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        profile = (self.home / ".zshrc").read_text()
        self.assertIn(f"export WITHHUMAN_KEY=\"$(cat '{path}')\"", profile)
        self.assertNotIn(KEY, profile + result.stdout)
        # Run again without --key: the kept key stays, and nothing changes.
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.home / ".zshrc").read_text(), profile)
        self.assertEqual(path.read_text().strip(), KEY)

    def test_rejects_a_malformed_key_before_changing_anything(self):
        result = self.configure("--key", "sk-not-ours")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a WithHuman key", result.stderr)
        self.assertFalse((self.project / ".claude" / "settings.json").exists())
        self.assertFalse((self.home / ".config" / "withhuman" / "key").exists())

    def test_registers_the_device_with_its_key(self):
        result = self.configure("--key", KEY, server=self.url, register=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Device registered", result.stdout)
        path, headers, body = Engine.received[0]
        self.assertEqual(path, "/v1/clients/register")
        self.assertEqual(headers["authorization"], f"Bearer {KEY}")
        client_id = (self.home / ".config" / "withhuman" / "client-id").read_text().strip()
        self.assertEqual(body["client_id"], client_id)
        self.assertEqual((body["team"], body["agent"], body["project"]),
                         ("lab", "claude", str(self.project)))
        for field in ("hostname", "os", "os_user"):
            self.assertTrue(body[field], field)
        self.assertRegex(body["hook_version"], r"^[0-9a-f]{12}$")
        # Present only where this machine lets the user read it; never empty.
        self.assertTrue(body.get("serial", "a serial"))

    def test_completes_the_setup_when_registration_fails(self):
        Engine.status = 401
        Engine.body = b'{"error": "key_required"}'
        result = self.configure(server=self.url, register=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WARNING: the device was not registered", result.stdout)
        self.assertIn("requires a WithHuman key", result.stdout)
        self.assertNotIn("authorization", Engine.received[0][1])
        self.assertTrue((self.project / ".claude" / "settings.json").exists())
        result = self.configure(server="http://127.0.0.1:9", register=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("could not be reached", result.stdout)

    def register(self, serial, others=()):
        """The registration sent from a machine whose serial numbers read as `serial` (the
        motherboard's) and `others`."""
        spec = importlib.util.spec_from_file_location("withhuman_configure", CONFIGURE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(module, "hardware_serial", lambda: serial), \
                mock.patch.object(module, "other_serials", lambda: list(others)):
            problem = module.register(self.url, "lab/1", "lab", None, "claude", self.project, "v")
        self.assertIsNone(problem)
        return Engine.received[-1][2]

    def test_sends_the_serial_number_it_read(self):
        self.assertEqual(self.register("C02TEST1234")["serial"], "C02TEST1234")

    def test_leaves_the_serial_number_out_when_there_is_none(self):
        self.assertNotIn("serial", self.register(None))

    def test_sends_the_other_serial_numbers_beside_the_motherboards(self):
        body = self.register("PUXJV048", ["5CD5479", "PUXJV048"])
        self.assertEqual(body["serial"], "PUXJV048")
        self.assertEqual(body["other_serials"], ["5CD5479"])
        self.assertNotIn("other_serials", self.register("PUXJV048", ["PUXJV048"]))
        self.assertEqual(self.register(None, ["5CD5479"])["other_serials"], ["5CD5479"])

    def test_registers_with_an_engine_from_before_the_other_serials(self):
        Engine.unknown = "other_serials"
        try:
            body = self.register("PUXJV048", ["5CD5479"])
        finally:
            Engine.unknown = None
        self.assertEqual(body["serial"], "PUXJV048")
        self.assertNotIn("other_serials", body)
        self.assertIn("other_serials", Engine.received[-2][2])


class HardwareSerialTest(unittest.TestCase):
    """The hardware serial number the registration carries."""

    IOREG = (
        '+-o Root  <class IORegistryEntry, id 0x100000100, retain 30>\n'
        '  {\n'
        '    "IOPlatformUUID" = "00000000-0000-0000-0000-000000000000"\n'
        '    "IOPlatformSerialNumber" = "C02TEST1234"\n'
        '    "manufacturer" = <"Apple Inc.">\n'
        '  }\n')

    def setUp(self):
        spec = importlib.util.spec_from_file_location("withhuman_configure", CONFIGURE)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def serial(self, platform, run=None, os_name="posix", read=None):
        """`hardware_serial()` (or `read`) on `platform`, its commands answered by `run`."""
        ran = []

        def fake(command, **_):
            ran.append(command)
            if run is None:
                raise FileNotFoundError(command[0])
            code, output = run(command)
            return subprocess.CompletedProcess(command, code, stdout=output, stderr="")

        with mock.patch.object(self.module.sys, "platform", platform), \
                mock.patch.object(self.module.os, "name", os_name), \
                mock.patch.object(self.module.subprocess, "run", fake):
            return (read or self.module.hardware_serial)(), ran

    def test_reads_the_serial_number_on_macos(self):
        serial, ran = self.serial("darwin", lambda _: (0, self.IOREG))
        self.assertEqual(serial, "C02TEST1234")
        self.assertEqual(ran, [["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]])

    def test_has_none_when_the_command_fails_is_missing_or_hangs(self):
        self.assertIsNone(self.serial("darwin", lambda _: (1, self.IOREG))[0])
        self.assertIsNone(self.serial("darwin", lambda _: (0, "no such entry"))[0])
        self.assertIsNone(self.serial("darwin")[0])

        def hangs(command):
            raise subprocess.TimeoutExpired(command, 1)
        self.assertIsNone(self.serial("darwin", hangs)[0])

    def test_reads_the_serial_number_on_linux_only_when_readable(self):
        folder = Path(tempfile.mkdtemp())
        readable = folder / "board_serial"
        readable.write_text("PF2TEST9\n")
        with mock.patch.object(self.module, "LINUX_SERIAL", readable):
            self.assertEqual(self.serial("linux")[0], "PF2TEST9")
        # Root-only or absent (a container): left out, and no command is tried instead.
        with mock.patch.object(self.module, "LINUX_SERIAL", folder / "absent"):
            serial, ran = self.serial("linux", lambda _: (0, "machine-id"))
        self.assertIsNone(serial)
        self.assertEqual(ran, [])

    def test_takes_no_placeholder_for_a_serial_number(self):
        folder = Path(tempfile.mkdtemp())
        for value in ("", "0", "To Be Filled By O.E.M.", "Default string", "System Serial Number"):
            (folder / "board_serial").write_text(value + "\n")
            with mock.patch.object(self.module, "LINUX_SERIAL", folder / "board_serial"):
                self.assertIsNone(self.serial("linux")[0], value)

    def test_reads_the_serial_number_on_windows(self):
        serial, ran = self.serial("win32", lambda _: (0, "PW0TEST7\r\n"), os_name="nt")
        self.assertEqual(serial, "PW0TEST7")
        self.assertEqual(ran[0][0], "powershell")
        # The motherboard's, as Wazuh's hardware inventory reports it, not the BIOS's.
        self.assertIn("Win32_BaseBoard", ran[0][-1])
        self.assertEqual(len(ran), 1)

        # Without PowerShell's answer, `wmic` is asked.
        def wmic_only(command):
            return (0, "SerialNumber  \r\n\r\nPW0TEST8  \r\n") if command[0] == "wmic" else (1, "")
        serial, ran = self.serial("win32", wmic_only, os_name="nt")
        self.assertEqual(serial, "PW0TEST8")
        self.assertEqual([command[0] for command in ran], ["powershell", "wmic"])
        self.assertEqual(ran[1][1], "baseboard")
        self.assertIsNone(self.serial("win32", os_name="nt")[0])


    def test_reads_the_other_serial_numbers(self):
        others = self.module.other_serials
        # Windows: the BIOS's.
        serials, ran = self.serial("win32", lambda _: (0, "5CD5479KD6\r\n"), os_name="nt", read=others)
        self.assertEqual(serials, ["5CD5479KD6"])
        self.assertIn("Win32_BIOS", ran[0][-1])
        self.assertEqual(self.serial("win32", lambda _: (0, "Default string"), os_name="nt", read=others)[0], [])
        self.assertEqual(self.serial("win32", os_name="nt", read=others)[0], [])
        # Linux: the system's, when readable.
        folder = Path(tempfile.mkdtemp())
        (folder / "product_serial").write_text("PF9SYS1\n")
        with mock.patch.object(self.module, "LINUX_OTHER_SERIALS", (folder / "product_serial", folder / "absent")):
            self.assertEqual(self.serial("linux", read=others), (["PF9SYS1"], []))
        # macOS has one.
        self.assertEqual(self.serial("darwin", read=others), ([], []))


class CodexConfigureTest(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.project = Path(tempfile.mkdtemp()).resolve()

    def configure(self, *extra):
        # USERPROFILE as well as HOME: on Windows the home folder comes from it.
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "SHELL": "/bin/zsh"}
        env.pop("WITHHUMAN_SERVER", None)
        env.pop("WITHHUMAN_KEY", None)
        return subprocess.run(
            [sys.executable, str(CONFIGURE), "--agent", "codex", "--project", str(self.project),
             "--team", "lab", "--server", SERVER, "--no-persist", "--skip-check", "--no-register",
             *extra],
            capture_output=True, text=True, env=env, timeout=30,
        )

    def test_reports_a_localized_hook_failure_without_a_decoder_error(self):
        hook = self.project / "localized-hook.py"
        hook.write_text("import sys\nsys.stderr.write('\\uc5f0\\uacb0 \\uc624\\ub958')\nsys.exit(2)\n",
                        encoding="utf-8")
        spec = importlib.util.spec_from_file_location("withhuman_configure", CONFIGURE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        ok, output = module.check_agent(hook, SERVER)
        self.assertFalse(ok)
        self.assertIn("\uc5f0\uacb0 \uc624\ub958", output)

    def test_writes_the_project_hooks_and_keeps_others(self):
        hooks_json = self.project / ".codex" / "hooks.json"
        hooks_json.parent.mkdir()
        old = {"type": "command", "command": "python3 /old/withhuman-hook.py https://old PreToolUse"}
        hooks_json.write_text(json.dumps({"hooks": {
            "PreToolUse": [{"hooks": [old, OTHER]}], "Stop": [{"hooks": [OTHER]}]}}))
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(hooks_json.read_text())
        hooks = config["hooks"]
        self.assertEqual(sorted(hooks), sorted(["SessionStart", "UserPromptSubmit", "PreToolUse",
                                                "PostToolUse", "Stop", "SubagentStart",
                                                "SubagentStop"]))
        # The user's own hooks stay; the earlier WithHuman one is replaced.
        self.assertEqual(hooks["PreToolUse"][0]["hooks"], [OTHER])
        self.assertEqual(hooks["Stop"][0]["hooks"], [OTHER])
        ours = hooks["PreToolUse"][1]["hooks"][0]
        installed = (self.project / ".codex" / "hooks" / "withhuman-hook.py").as_posix()
        python = Path(sys.executable).as_posix()
        self.assertEqual(ours["command"], f'"{python}" "{installed}" {SERVER} PreToolUse')
        self.assertEqual(ours["commandWindows"],
                         f'& "{python}" "{installed}" {SERVER} PreToolUse; exit $LASTEXITCODE')
        self.assertGreaterEqual(ours["timeout"], 10)
        for event in ("SessionStart", "UserPromptSubmit", "PostToolUse", "SubagentStart"):
            self.assertEqual(hooks[event][-1]["hooks"][0]["timeout"], 5)
        self.assertEqual(hooks["Stop"][1]["hooks"][0]["timeout"], 5)
        for name in ("withhuman-hook.py", "codex_transcript.py", "pre-tool-use.py",
                     "withhuman_bridge.py"):
            self.assertTrue((self.project / ".codex" / "hooks" / name).is_file(), name)
        self.assertIn("/hooks", result.stdout)
        # The user's own Codex folder is never touched.
        self.assertFalse((self.home / ".codex").exists())

    def test_gives_the_same_result_when_run_again(self):
        self.assertEqual(self.configure().returncode, 0)
        first = (self.project / ".codex" / "hooks.json").read_text()
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual((self.project / ".codex" / "hooks.json").read_text(), first)

    def test_fails_when_the_installed_hook_cannot_reach_the_engine(self):
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home)}
        result = subprocess.run(
            [sys.executable, str(CONFIGURE), "--agent", "codex", "--project", str(self.project),
             "--server", "http://127.0.0.1:9", "--no-persist", "--no-register"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not run", result.stderr)

    def test_uninstall_takes_out_only_withhuman(self):
        hooks_json = self.project / ".codex" / "hooks.json"
        hooks_json.parent.mkdir()
        hooks_json.write_text(json.dumps({"other": True, "hooks": {
            "PreToolUse": [{"hooks": [OTHER]}], "Stop": [{"hooks": [OTHER]}]}}))
        (self.project / "src.py").write_text("print(1)\n")
        self.assertEqual(self.configure().returncode, 0)
        (self.project / ".codex" / "hooks" / "mine.sh").write_text("echo mine\n")
        # Bytecode the hook's own check leaves, beside another module's.
        cache = self.project / ".codex" / "hooks" / "__pycache__"
        cache.mkdir(exist_ok=True)
        for name in ("codex_transcript.cpython-311.pyc", "pre-tool-use.cpython-311.pyc",
                     "mine.cpython-311.pyc"):
            (cache / name).write_bytes(b"")
        result = self.configure("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(hooks_json.read_text())
        self.assertEqual(config, {"other": True, "hooks": {
            "PreToolUse": [{"hooks": [OTHER]}], "Stop": [{"hooks": [OTHER]}]}})
        hooks_dir = self.project / ".codex" / "hooks"
        self.assertEqual(sorted(p.name for p in hooks_dir.iterdir()), ["__pycache__", "mine.sh"])
        self.assertEqual([p.name for p in cache.iterdir()], ["mine.cpython-311.pyc"])
        self.assertEqual((self.project / "src.py").read_text(), "print(1)\n")
        self.assertTrue(list((self.project / ".codex").glob("hooks.json.bak-*")))
        # Nothing left to take out the second time.
        again = self.configure("--uninstall")
        self.assertIn("Nothing of WithHuman", again.stdout)

    def test_uninstall_needs_no_server(self):
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home)}
        env.pop("WITHHUMAN_SERVER", None)
        result = subprocess.run(
            [sys.executable, str(CONFIGURE), "--uninstall", "--agent", "codex",
             "--project", str(self.project)],
            capture_output=True, text=True, env=env, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)



class CursorConfigureTest(unittest.TestCase):
    """--agent cursor: the project's own .cursor/hooks.json, whose shape is Cursor's."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.project = Path(tempfile.mkdtemp()).resolve()
        self.hooks_json = self.project / ".cursor" / "hooks.json"

    def configure(self, *extra):
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "SHELL": "/bin/zsh"}
        env.pop("WITHHUMAN_SERVER", None)
        env.pop("WITHHUMAN_KEY", None)
        return subprocess.run(
            [sys.executable, str(CONFIGURE), "--agent", "cursor", "--project", str(self.project),
             "--team", "lab", "--server", SERVER, "--no-persist", "--skip-check", "--no-register",
             *extra],
            capture_output=True, text=True, env=env, timeout=30,
        )

    def test_writes_the_project_hooks_in_cursors_own_shape(self):
        self.hooks_json.parent.mkdir()
        old = {"command": "python3 /old/.cursor/hooks/withhuman-hook.py https://old preToolUse"}
        self.hooks_json.write_text(json.dumps({
            "version": 1,
            "hooks": {"preToolUse": [old, OTHER], "afterFileEdit": [OTHER]}}))
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.hooks_json.read_text())
        # Cursor reads the file by its version, and holds entries directly under the event.
        self.assertEqual(config["version"], 1)
        hooks = config["hooks"]
        self.assertEqual(sorted(hooks), sorted([
            "sessionStart", "sessionEnd", "beforeSubmitPrompt", "preToolUse",
            "beforeMCPExecution", "postToolUse", "postToolUseFailure", "beforeReadFile",
            "afterAgentResponse", "stop", "afterFileEdit"]))
        # The user's own hooks stay; the earlier WithHuman one is replaced.
        self.assertEqual(hooks["afterFileEdit"], [OTHER])
        self.assertEqual(hooks["preToolUse"][0], OTHER)
        ours = hooks["preToolUse"][1]
        installed = (self.project / ".cursor" / "hooks" / "withhuman-hook.py").as_posix()
        python = Path(sys.executable).as_posix()
        self.assertEqual(ours["command"], f'"{python}" "{installed}" preToolUse')
        # Cursor takes one command; there is no separate Windows form to write.
        self.assertNotIn("commandWindows", ours)
        # The engine's address is kept beside the hook, never in the command: see below.
        self.assertEqual(
            (self.project / ".cursor" / "hooks" / "server").read_text().strip(), SERVER)
        self.assertGreaterEqual(ours["timeout"], 10)
        self.assertEqual(hooks["stop"][0]["timeout"], 5)
        for name in ("withhuman-hook.py", "pre-tool-use.py", "withhuman_bridge.py"):
            self.assertTrue((self.project / ".cursor" / "hooks" / name).is_file(), name)
        self.assertFalse((self.home / ".cursor").exists())

    def test_no_command_holds_the_engines_address(self):
        """Cursor 2026.11.22 runs no hook of a file whose command holds an `http://` address —
        the whole file, silently, so every call goes unjudged. Verified against the real client:
        the same hooks fire without the address and none fire with it, quoted or not."""
        self.assertEqual(self.configure().returncode, 0)
        hooks = json.loads(self.hooks_json.read_text())["hooks"]
        for event, entries in hooks.items():
            for entry in entries:
                self.assertNotIn("http", entry["command"], event)
        # The bridge finds it beside itself instead.
        self.assertTrue((self.project / ".cursor" / "hooks" / "server").is_file())

    def test_uninstall_takes_the_address_file_too(self):
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual(self.configure("--uninstall").returncode, 0)
        self.assertFalse((self.project / ".cursor" / "hooks").exists())

    def test_fails_closed_exactly_where_a_judgment_is_pending(self):
        self.assertEqual(self.configure().returncode, 0)
        hooks = json.loads(self.hooks_json.read_text())["hooks"]
        # Cursor lets a call through when a hook fails, which would lift the control just when
        # it is needed. The events that only report must not stop the agent.
        closed = {event for event, entries in hooks.items() if entries[0]["failClosed"]}
        self.assertEqual(closed, {"preToolUse", "beforeMCPExecution"})

    def test_running_again_changes_nothing(self):
        self.assertEqual(self.configure().returncode, 0)
        first = self.hooks_json.read_text()
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual(self.hooks_json.read_text(), first)

    def test_uninstall_leaves_only_what_was_not_ours(self):
        self.hooks_json.parent.mkdir()
        self.hooks_json.write_text(json.dumps({
            "other": True, "version": 1, "hooks": {"preToolUse": [OTHER]}}))
        self.assertEqual(self.configure().returncode, 0)
        mine = self.project / ".cursor" / "hooks" / "mine.sh"
        mine.write_text("echo mine\n")
        result = self.configure("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.hooks_json.read_text()),
                         {"other": True, "version": 1, "hooks": {"preToolUse": [OTHER]}})
        hooks_dir = self.project / ".cursor" / "hooks"
        self.assertEqual([p.name for p in hooks_dir.iterdir()], ["mine.sh"])
        self.assertTrue(list((self.project / ".cursor").glob("hooks.json.bak-*")))
        again = self.configure("--uninstall")
        self.assertIn("Nothing of WithHuman", again.stdout)

    def test_reset_takes_both_agents_out_of_a_folder(self):
        self.assertEqual(self.configure().returncode, 0)
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home)}
        env.pop("WITHHUMAN_SERVER", None)
        result = subprocess.run(
            [sys.executable, str(CONFIGURE), "--reset", str(self.project)],
            capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.hooks_json.read_text())["hooks"], {})

class HermesConfigureTest(unittest.TestCase):
    """Hermes takes WithHuman as a plugin of its profile; a stand-in `hermes` records the CLI
    calls the setup makes."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.hermes_home = Path(tempfile.mkdtemp()).resolve()
        self.bin = Path(tempfile.mkdtemp()).resolve()
        self.calls = self.bin / "calls.txt"
        if os.name == "nt":
            (self.bin / "hermes.cmd").write_text(
                f'@echo %* %HERMES_HOME%>> "{self.calls}"\r\n', encoding="utf-8")
        else:
            script = self.bin / "hermes"
            script.write_text(f'#!/bin/sh\necho "$* $HERMES_HOME" >> "{self.calls}"\n')
            script.chmod(0o755)

    def configure(self, *extra, hermes=True):
        # The device's own Hermes, if one is installed, is kept out of reach.
        path = os.pathsep.join(entry for entry in os.environ.get("PATH", "").split(os.pathsep)
                               if entry and not shutil.which("hermes", path=entry))
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "HERMES_HOME": str(self.hermes_home), "SHELL": "/bin/zsh",
               "PATH": (str(self.bin) + os.pathsep if hermes else "") + path}
        env.pop("WITHHUMAN_SERVER", None)
        env.pop("WITHHUMAN_KEY", None)
        return subprocess.run(
            [sys.executable, str(CONFIGURE), "--agent", "hermes", "--team", "lab",
             "--server", SERVER, "--no-persist", "--skip-check", "--no-register", *extra],
            capture_output=True, text=True, env=env, timeout=60,
        )

    def calls_made(self):
        return self.calls.read_text().split("\n") if self.calls.exists() else []

    def test_installs_the_plugin_in_the_profile_and_enables_it(self):
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        plugin = self.hermes_home / "plugins" / "withhuman"
        for name in ("__init__.py", "plugin.yaml", "withhuman-hook.py", "withhuman_bridge.py",
                     "pre-tool-use.py"):
            self.assertTrue((plugin / name).is_file(), name)
        self.assertEqual(json.loads((plugin / "withhuman.json").read_text()), {"server": SERVER})
        self.assertTrue((plugin / "withhuman-state").is_dir())
        self.assertIn("plugins enable withhuman", self.calls_made()[0])
        self.assertIn(str(self.hermes_home), self.calls_made()[0])
        self.assertIn("hermes gateway restart", result.stdout)

    def test_says_how_to_enable_it_without_the_hermes_command(self):
        result = self.configure(hermes=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("hermes plugins enable withhuman", result.stdout)

    def test_takes_the_plugin_out_again(self):
        self.configure()
        result = self.configure("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.hermes_home / "plugins" / "withhuman").exists())
        self.assertTrue(any("plugins disable withhuman" in line for line in self.calls_made()),
                        self.calls_made())

    def test_finds_the_profile_where_hermes_keeps_it(self):
        spec = importlib.util.spec_from_file_location("withhuman_configure", CONFIGURE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        local = self.home / "AppData" / "Local"
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
            os.environ.pop("HERMES_HOME", None)
            expected = local / "hermes" if os.name == "nt" else Path.home() / ".hermes"
            self.assertEqual(module.hermes_home(), expected)
            os.environ["HERMES_HOME"] = str(self.hermes_home)
            self.assertEqual(module.hermes_home(), self.hermes_home)

    def test_takes_no_scope(self):
        result = self.configure("--scope", "user")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("per profile", result.stderr)



class CopilotConfigureTest(unittest.TestCase):
    """--agent copilot: the repository's own .github/hooks file, whose shape is Copilot's."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.project = Path(tempfile.mkdtemp()).resolve()
        self.hooks_json = self.project / ".github" / "hooks" / "withhuman-copilot.json"

    def configure(self, *extra):
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "SHELL": "/bin/zsh"}
        env.pop("WITHHUMAN_SERVER", None)
        env.pop("WITHHUMAN_KEY", None)
        return subprocess.run(
            [sys.executable, str(CONFIGURE), "--agent", "copilot", "--project", str(self.project),
             "--team", "lab", "--server", SERVER, "--no-persist", "--skip-check", "--no-register",
             *extra],
            capture_output=True, text=True, env=env, timeout=30,
        )

    def test_writes_the_repository_hooks_in_copilots_own_shape(self):
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.hooks_json.read_text())
        # Copilot reads the file by its version, and holds entries directly under the event.
        self.assertEqual(config["version"], 1)
        hooks = config["hooks"]
        self.assertEqual(sorted(hooks), sorted([
            "SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse",
            "PostToolUseFailure", "SubagentStart", "SubagentStop", "Stop", "preMcpToolCall"]))
        ours = hooks["PreToolUse"][0]
        installed = (self.project / ".github" / "hooks" / "withhuman-hook.py").as_posix()
        python = Path(sys.executable).as_posix()
        self.assertEqual(ours["type"], "command")
        # Copilot runs `bash` on macOS and Linux and `powershell` on Windows, and reads
        # `timeoutSec` rather than Claude Code's `timeout`.
        self.assertEqual(ours["bash"], f'"{python}" "{installed}" PreToolUse')
        self.assertIn("exit $LASTEXITCODE", ours["powershell"])
        self.assertGreaterEqual(ours["timeoutSec"], 10)
        self.assertEqual(hooks["Stop"][0]["timeoutSec"], 5)
        self.assertNotIn("timeout", ours)
        for name in ("withhuman-hook.py", "copilot_transcript.py", "pre-tool-use.py",
                     "withhuman_bridge.py", "server"):
            self.assertTrue((self.project / ".github" / "hooks" / name).is_file(), name)
        self.assertFalse((self.home / ".copilot").exists())

    def test_the_claude_code_names_are_the_ones_registered(self):
        """Under Claude Code's event names Copilot sends Claude Code's field names and tool
        names, which is what the engine judges. Under its own it sends `toolArgs` and `bash`,
        and the translation would have to undo them."""
        self.assertEqual(self.configure().returncode, 0)
        events = set(json.loads(self.hooks_json.read_text())["hooks"])
        self.assertIn("PreToolUse", events)
        self.assertNotIn("preToolUse", events)
        # `preMcpToolCall` has no Claude Code name; it is where a server names itself.
        self.assertIn("preMcpToolCall", events)

    def test_the_engines_address_is_kept_beside_the_hook(self):
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual(
            (self.project / ".github" / "hooks" / "server").read_text().strip(), SERVER)
        hooks = json.loads(self.hooks_json.read_text())["hooks"]
        for event, entries in hooks.items():
            self.assertNotIn("http", entries[0]["bash"], event)

    def test_running_again_changes_nothing(self):
        self.assertEqual(self.configure().returncode, 0)
        first = self.hooks_json.read_text()
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual(self.hooks_json.read_text(), first)

    def test_uninstall_leaves_only_what_was_not_ours(self):
        self.hooks_json.parent.mkdir(parents=True)
        self.hooks_json.write_text(json.dumps({
            "other": True, "version": 1, "hooks": {"PreToolUse": [OTHER]}}))
        self.assertEqual(self.configure().returncode, 0)
        result = self.configure("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.hooks_json.read_text()),
                         {"other": True, "version": 1, "hooks": {"PreToolUse": [OTHER]}})
        self.assertFalse((self.project / ".github" / "hooks" / "withhuman-hook.py").exists())



class AntigravityConfigureTest(unittest.TestCase):
    """--agent antigravity: the project's own .agents/hooks.json, whose shape is Antigravity's."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.project = Path(tempfile.mkdtemp()).resolve()
        self.hooks_json = self.project / ".agents" / "hooks.json"

    def configure(self, *extra):
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "SHELL": "/bin/zsh"}
        env.pop("WITHHUMAN_SERVER", None)
        env.pop("WITHHUMAN_KEY", None)
        return subprocess.run(
            [sys.executable, str(CONFIGURE), "--agent", "antigravity",
             "--project", str(self.project), "--team", "lab", "--server", SERVER,
             "--no-persist", "--skip-check", "--no-register", *extra],
            capture_output=True, text=True, env=env, timeout=30,
        )

    def test_writes_the_project_hooks_in_antigravitys_own_shape(self):
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.hooks_json.read_text())
        # Antigravity names hooks at the top level, so ours sit under one name of our own.
        self.assertEqual(list(config), ["withhuman"])
        hooks = config["withhuman"]
        self.assertEqual(sorted(hooks), sorted(
            ["SessionStart", "PreInvocation", "PreToolUse", "PostToolUse", "Stop"]))
        installed = (self.project / ".agents" / "hooks" / "withhuman-hook.py").as_posix()
        python = Path(sys.executable).as_posix()
        # The tool events take a matcher group; an empty matcher is every tool.
        gated = hooks["PreToolUse"][0]
        self.assertEqual(gated["matcher"], "")
        handler = gated["hooks"][0]
        self.assertEqual(handler["command"], f'"{python}" "{installed}" PreToolUse')
        self.assertEqual(handler["type"], "command")
        # Seconds, not Claude Code's milliseconds, and under the 30 Antigravity kills a hook at.
        self.assertGreaterEqual(handler["timeout"], 20)
        self.assertLess(handler["timeout"], 30)
        # The rest take handlers directly, with no matcher.
        self.assertEqual(hooks["Stop"][0]["type"], "command")
        self.assertNotIn("matcher", hooks["Stop"][0])
        self.assertNotIn("hooks", hooks["Stop"][0])
        for name in ("withhuman-hook.py", "antigravity_transcript.py", "pre-tool-use.py",
                     "withhuman_bridge.py", "server"):
            self.assertTrue((self.project / ".agents" / "hooks" / name).is_file(), name)
        self.assertFalse((self.home / ".agents").exists())

    def test_the_engines_address_is_kept_beside_the_hook(self):
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual(
            (self.project / ".agents" / "hooks" / "server").read_text().strip(), SERVER)
        hooks = json.loads(self.hooks_json.read_text())["withhuman"]
        for event, entries in hooks.items():
            handlers = entries[0].get("hooks", [entries[0]])
            for handler in handlers:
                self.assertNotIn("http", handler["command"], event)

    def test_running_again_changes_nothing(self):
        self.assertEqual(self.configure().returncode, 0)
        first = self.hooks_json.read_text()
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual(self.hooks_json.read_text(), first)

    def test_uninstall_leaves_the_other_named_hooks_alone(self):
        """Antigravity's file holds every hook by name, including other people's."""
        self.hooks_json.parent.mkdir(parents=True)
        theirs = {"lint-checker": {"PostToolUse": [
            {"matcher": "run_command", "hooks": [{"command": "./lint.sh"}]}]}}
        self.hooks_json.write_text(json.dumps(theirs))
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual(sorted(json.loads(self.hooks_json.read_text())), ["lint-checker", "withhuman"])
        result = self.configure("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.hooks_json.read_text()), theirs)
        self.assertFalse((self.project / ".agents" / "hooks" / "withhuman-hook.py").exists())

    def test_uninstall_takes_an_earlier_hook_of_ours_out_under_any_name(self):
        """A hook of ours an older version wrote under another name is still ours."""
        self.hooks_json.parent.mkdir(parents=True)
        mine = {"withhuman-guard": {"PreToolUse": [
            {"matcher": "", "hooks": [{"command": "python3 /old/withhuman-hook.py PreToolUse"}]}]}}
        self.hooks_json.write_text(json.dumps(mine))
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual(list(json.loads(self.hooks_json.read_text())), ["withhuman"])


class OpenClawConfigureTest(unittest.TestCase):
    """OpenClaw takes WithHuman as a plugin of its state directory, installed by its own CLI; a
    stand-in `openclaw` records the calls the setup makes.

    Unlike Hermes', the files are not copied into place here: `openclaw` keeps a registry of what
    is installed and the configuration that records a plugin is also where it is allowed to read
    a turn, so the files are staged and that CLI installs them from there.
    """

    def setUp(self):
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.state = Path(tempfile.mkdtemp()).resolve()
        self.bin = Path(tempfile.mkdtemp()).resolve()
        self.calls = self.bin / "calls.txt"
        if os.name == "nt":
            (self.bin / "openclaw.cmd").write_text(
                f'@echo %* %OPENCLAW_STATE_DIR%>> "{self.calls}"\r\n', encoding="utf-8")
        else:
            script = self.bin / "openclaw"
            script.write_text(f'#!/bin/sh\necho "$* $OPENCLAW_STATE_DIR" >> "{self.calls}"\n')
            script.chmod(0o755)

    def configure(self, *extra, openclaw=True, refusing=False):
        if refusing and os.name == "nt":
            # Windows runs the `.cmd` stand-in; a shell script beside it never runs.
            (self.bin / "openclaw.cmd").write_text(
                f'@echo %* %OPENCLAW_STATE_DIR%>> "{self.calls}"\r\n'
                '@if "%1 %2"=="config set" (echo The state owner has no Gateway listener.'
                ' 1>&2 & exit /b 1)\r\n', encoding="utf-8")
        elif refusing:
            script = self.bin / "openclaw"
            script.write_text(
                '#!/bin/sh\n'
                f'echo "$* $OPENCLAW_STATE_DIR" >> "{self.calls}"\n'
                'case "$1 $2" in "config set") '
                'echo "The state owner has no Gateway listener." >&2; exit 1 ;; esac\n')
            script.chmod(0o755)
        # The device's own OpenClaw, if one is installed, is kept out of reach.
        path = os.pathsep.join(entry for entry in os.environ.get("PATH", "").split(os.pathsep)
                               if entry and not shutil.which("openclaw", path=entry))
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "OPENCLAW_STATE_DIR": str(self.state), "SHELL": "/bin/zsh",
               "PATH": (str(self.bin) + os.pathsep if openclaw else "") + path}
        env.pop("WITHHUMAN_SERVER", None)
        env.pop("WITHHUMAN_KEY", None)
        return subprocess.run(
            [sys.executable, str(CONFIGURE), "--agent", "openclaw", "--team", "lab",
             "--server", SERVER, "--no-persist", "--skip-check", "--no-register", *extra],
            capture_output=True, text=True, env=env, timeout=60,
        )

    def calls_made(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_stages_the_plugin_and_installs_it_with_openclaws_own_cli(self):
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        staged = self.state / "withhuman-setup"
        for name in ("index.js", "withhuman-hook.py", "openclaw.plugin.json", "package.json",
                     "withhuman_bridge.py", "pre-tool-use.py"):
            self.assertTrue((staged / name).is_file(), name)
        # The engine's address is kept beside the hook, as Cursor's is.
        self.assertEqual((staged / "server").read_text().strip(), SERVER)
        calls = self.calls_made()
        self.assertIn(f"plugins install {staged} --force", calls[0])
        self.assertIn("--accept-capabilities", calls[0])
        # Installed from where it was staged, never from the folder OpenClaw installs into:
        # that would be installing a folder over itself.
        self.assertNotIn("extensions", calls[0])
        self.assertIn(str(self.state), calls[0])
        self.assertIn("openclaw chat", result.stdout)

    def test_allows_the_plugin_the_turn_it_judges_calls_against(self):
        """Without this OpenClaw refuses the plugin the hooks that carry a turn: the calls are
        still judged, but the prompt, its intent and the answer never arrive."""
        self.assertEqual(self.configure().returncode, 0)
        calls = self.calls_made()
        self.assertTrue(any("plugins enable withhuman" in line for line in calls), calls)
        self.assertTrue(
            any("config set plugins.entries.withhuman.hooks.allowConversationAccess true" in line
                for line in calls), calls)

    def test_keeps_the_state_where_a_rebuilt_plugin_cannot_take_it(self):
        """OpenClaw builds a package of a plugin when it installs one, and what the Gateway
        loads may be a copy of it; state beside the plugin followed that copy and was lost with
        it, which left no audit log at all."""
        self.assertEqual(self.configure().returncode, 0)
        self.assertEqual((self.state / "withhuman-state" / ".gitignore").read_text().strip(), "*")
        self.assertFalse((self.state / "withhuman-setup" / "withhuman-state").exists())

    def test_a_gateway_holding_the_configuration_stops_the_setup(self):
        """`openclaw config set` is refused while a Gateway owns the state, and the setup cannot
        finish without it, so the message has to say what to do about it."""
        result = self.configure(refusing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Stop OpenClaw first", result.stdout + result.stderr)

    def test_says_so_without_the_openclaw_command(self):
        result = self.configure(openclaw=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not on PATH", result.stdout + result.stderr)

    def test_takes_the_plugin_out_again(self):
        self.configure()
        result = self.configure("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / "withhuman-setup").exists())
        self.assertFalse((self.state / "withhuman-state").exists())
        self.assertTrue(any("plugins uninstall withhuman --force" in line
                            for line in self.calls_made()), self.calls_made())

    def test_finds_the_state_directory_where_openclaw_keeps_it(self):
        spec = importlib.util.spec_from_file_location("withhuman_configure", CONFIGURE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.dict(os.environ, {}):
            os.environ.pop("OPENCLAW_STATE_DIR", None)
            self.assertEqual(module.openclaw_home(), Path.home() / ".openclaw")
            os.environ["OPENCLAW_STATE_DIR"] = str(self.state)
            self.assertEqual(module.openclaw_home(), self.state)

    def test_takes_no_scope(self):
        result = self.configure("--scope", "user")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("per state directory", result.stderr)


class GlobalSetupTest(Setup):
    """--scope user and --scope managed: every folder of the user, or of every user."""

    def setUp(self):
        super().setUp()
        self.managed = Path(tempfile.mkdtemp()).resolve()
        self.device = Path(tempfile.mkdtemp()).resolve() / "WithHuman"

    def run_scope(self, scope, *extra, env=None):
        environment = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
                       "SHELL": "/bin/zsh", "WITHHUMAN_MANAGED_DIR": str(self.managed),
                       "WITHHUMAN_DEVICE_DIR": str(self.device), **(env or {})}
        for name in ("WITHHUMAN_SERVER", "WITHHUMAN_KEY", "SUDO_USER"):
            environment.pop(name, None)
        arguments = ["--scope", scope, "--team", "lab", "--no-register", "--server", SERVER]
        if os.name == "nt":
            arguments.append("--no-persist")
        return subprocess.run([sys.executable, str(CONFIGURE), *arguments, *extra],
                              capture_output=True, text=True, env=environment, timeout=30)

    def http_hooks(self, settings):
        return [group["hooks"][0] for event, groups in settings["hooks"].items()
                for group in groups if event != "PreToolUse" and configure_module().is_withhuman(group["hooks"][0])]

    def test_user_scope_writes_the_users_settings_with_the_client_id(self):
        self.write(self.home / ".claude" / "settings.json",
                   {"model": "opus", "hooks": {"PreToolUse": [{"hooks": [OLD_HTTP, OTHER]}]}})
        result = self.run_scope("user")
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = self.read(self.home / ".claude" / "settings.json")
        self.assertEqual(settings["model"], "opus")
        client = (self.home / ".config" / "withhuman" / "client-id").read_text().strip()
        self.assertTrue(client.startswith("lab/"))
        # The earlier hook is replaced, the user's own kept, the ID written into each header.
        pre = [hook for group in settings["hooks"]["PreToolUse"] for hook in group["hooks"]]
        self.assertIn(OTHER, pre)
        self.assertNotIn(OLD_HTTP, pre)
        hook = self.home / ".config" / "withhuman" / "hooks" / "pre-tool-use.py"
        self.assertTrue(any(str(hook.as_posix()) in h.get("command", "") for h in pre))
        for http in self.http_hooks(settings):
            self.assertEqual(http["headers"]["x-withhuman-client"], client)
            self.assertEqual(http["allowedEnvVars"], ["WITHHUMAN_KEY"])
        self.assertTrue(hook.is_file())
        # No project was touched.
        self.assertFalse((self.project / ".claude" / "settings.json").exists())

        result = self.run_scope("user", "--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = self.read(self.home / ".claude" / "settings.json")
        self.assertEqual(settings["hooks"], {"PreToolUse": [{"hooks": [OTHER]}]})
        self.assertFalse(hook.exists())

    def test_managed_scope_writes_a_policy_file_of_its_own(self):
        # The organisation's own policy is left alone.
        (self.managed / "managed-settings.json").write_text('{"model": "opus"}')
        # The device keeps the identity the user's own setup gave it.
        config = self.home / ".config" / "withhuman"
        config.mkdir(parents=True)
        (config / "client-id").write_text("lab/earlier\n")
        result = self.run_scope("managed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.managed / "managed-settings.json").read_text(), '{"model": "opus"}')
        policy = self.managed / "managed-settings.d" / "50-withhuman.json"
        settings = self.read(policy)
        self.assertNotIn("allowManagedHooksOnly", settings)
        self.assertEqual(sorted(settings["hooks"]), sorted(configure_module().EVENTS))
        self.assertEqual((self.device / "client-id").read_text().strip(), "lab/earlier")
        for http in self.http_hooks(settings):
            self.assertEqual(http["headers"]["x-withhuman-client"], "lab/earlier")
        hook = self.device / "hooks" / "pre-tool-use.py"
        command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn(hook.as_posix(), command)
        self.assertTrue(command.endswith(f"{SERVER}/v1/hooks/PreToolUse"))
        if os.name != "nt":
            # Readable by every user, changeable by the administrator alone.
            self.assertEqual(stat.S_IMODE(policy.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((self.device / "client-id").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(hook.stat().st_mode), 0o755)
        # No user's profile or key was touched.
        self.assertFalse((self.home / ".zshrc").exists())

        result = self.run_scope("managed", "--managed-hooks-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.read(policy)["allowManagedHooksOnly"])

        result = self.run_scope("managed", "--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(policy.exists())
        self.assertFalse(hook.exists())
        self.assertTrue((self.device / "client-id").exists())

    def test_managed_scope_takes_out_the_user_setup_it_would_run_beside(self):
        result = self.run_scope("user")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.write(self.home / ".claude" / "settings.json",
                   {**self.read(self.home / ".claude" / "settings.json"), "model": "opus"})
        user_hook = self.home / ".config" / "withhuman" / "hooks" / "pre-tool-use.py"
        self.assertTrue(user_hook.is_file())
        result = self.run_scope("managed")
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = self.read(self.home / ".claude" / "settings.json")
        self.assertEqual(settings, {"model": "opus"})
        self.assertFalse(user_hook.exists())
        # Still the one device.
        self.assertEqual((self.device / "client-id").read_text().strip(),
                         (self.home / ".config" / "withhuman" / "client-id").read_text().strip())

    def test_reset_takes_every_setup_out_and_keeps_the_device(self):
        self.write(self.home / ".claude" / "settings.json", {"hooks": {"PreToolUse": [{"hooks": [OTHER]}]}})
        self.assertEqual(self.run_scope("user").returncode, 0)
        client = (self.home / ".config" / "withhuman" / "client-id").read_text().strip()
        self.assertEqual(self.run_scope("managed").returncode, 0)
        # A project set up by itself, Claude Code's and Codex's.
        self.assertEqual(self.configure().returncode, 0)
        project_settings = self.project / ".claude" / "settings.json"
        self.assertTrue(configure_module().remove_withhuman(self.read(project_settings)))
        self.assertEqual(self.run_scope("user").returncode, 0)

        result = self.run_scope("user", "--reset", str(self.project))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.managed / "managed-settings.d" / "50-withhuman.json").exists())
        self.assertFalse((self.device / "hooks" / "pre-tool-use.py").exists())
        self.assertFalse((self.home / ".config" / "withhuman" / "hooks" / "pre-tool-use.py").exists())
        self.assertFalse((self.project / ".claude" / "hooks" / "pre-tool-use.py").exists())
        self.assertEqual(self.read(self.home / ".claude" / "settings.json"),
                         {"hooks": {"PreToolUse": [{"hooks": [OTHER]}]}})
        self.assertNotIn("hooks", self.read(project_settings))
        # The device keeps its identity.
        self.assertEqual((self.device / "client-id").read_text().strip(), client)
        self.assertEqual((self.home / ".config" / "withhuman" / "client-id").read_text().strip(), client)
        self.assertIn("Start Claude Code again", result.stdout)

        result = self.run_scope("user", "--reset")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Nothing of WithHuman was found.", result.stdout)

    def test_refuses_what_a_global_setup_cannot_do(self):
        for extra, said in ((("--key", KEY), "takes no key"),
                            (("--agent", "codex"), "per project")):
            result = self.run_scope("managed" if extra[0] == "--key" else "user", *extra)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(said, result.stderr)
        result = subprocess.run([sys.executable, str(CONFIGURE), "--managed-hooks-only",
                                 "--server", SERVER, "--no-register"],
                                capture_output=True, text=True, timeout=30)
        self.assertIn("goes with --scope managed", result.stderr)
        self.assertFalse((self.managed / "managed-settings.d").exists())

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs a folder this user cannot write")
    def test_says_a_managed_setup_needs_an_administrator(self):
        self.managed.chmod(0o555)
        try:
            result = self.run_scope("managed")
        finally:
            self.managed.chmod(0o755)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("administrator", result.stderr)


def configure_module():
    spec = importlib.util.spec_from_file_location("configure", CONFIGURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

if __name__ == "__main__":
    unittest.main()
