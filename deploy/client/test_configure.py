"""Tests for configure.py: python3 -m unittest discover deploy/client"""

import http.server
import json
import importlib.util
import os
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

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Engine.received.append((self.path, {k.lower(): v for k, v in self.headers.items()},
                                json.loads(body)))
        self.send_response(Engine.status)
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

    def register(self, serial):
        """The registration sent from a machine whose serial number reads as `serial`."""
        spec = importlib.util.spec_from_file_location("withhuman_configure", CONFIGURE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(module, "hardware_serial", lambda: serial):
            problem = module.register(self.url, "lab/1", "lab", None, "claude", self.project, "v")
        self.assertIsNone(problem)
        return Engine.received[-1][2]

    def test_sends_the_serial_number_it_read(self):
        self.assertEqual(self.register("C02TEST1234")["serial"], "C02TEST1234")

    def test_leaves_the_serial_number_out_when_there_is_none(self):
        self.assertNotIn("serial", self.register(None))


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

    def serial(self, platform, run=None, os_name="posix"):
        """`hardware_serial()` on `platform`, its commands answered by `run`."""
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
            return self.module.hardware_serial(), ran

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
        ok, output = module.check_codex(hook, SERVER)
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
        for name in ("withhuman-hook.py", "codex_transcript.py", "pre-tool-use.py"):
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
