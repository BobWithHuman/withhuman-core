"""Tests for configure.py: python3 -m unittest discover deploy/client"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIGURE = HERE / "configure.py"

SERVER = "https://withhuman.example.com"
# An earlier setup pointed at a different engine; it still has to be recognised and replaced.
OLD_HTTP = {"type": "http", "url": "https://old.example.com/v1/hooks/PreToolUse",
            "headers": {"x-withhuman-client": "$WITHHUMAN_CLIENT_ID"}}
OTHER = {"type": "command", "command": "echo mine"}


class ConfigureTest(unittest.TestCase):
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

    def configure(self, *extra, server=SERVER):
        # WITHHUMAN_SERVER is dropped so the developer's own environment cannot stand in for the
        # address under test, nor hide a missing one.
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home), "SHELL": "/bin/zsh"}
        env.pop("WITHHUMAN_SERVER", None)
        arguments = ["--project", str(self.project), "--team", "lab"]
        if os.name == "nt":
            arguments.append("--no-persist")  # Never setx in a unit test.
        if server is not None:
            arguments += ["--server", server]
        return subprocess.run(
            [sys.executable, str(CONFIGURE), *arguments, *extra],
            capture_output=True, text=True, env=env, timeout=30,
        )

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
        self.assertEqual(len(settings["hooks"]), 11)
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
        self.assertEqual(post["headers"], {"x-withhuman-client": "$WITHHUMAN_CLIENT_ID"})

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
            [sys.executable, str(CONFIGURE), "--project", str(self.project), "--team", "lab", "--no-persist"],
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


class CodexConfigureTest(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.project = Path(tempfile.mkdtemp()).resolve()

    def configure(self, *extra):
        # USERPROFILE as well as HOME: on Windows the home folder comes from it.
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "SHELL": "/bin/zsh"}
        env.pop("WITHHUMAN_SERVER", None)
        return subprocess.run(
            [sys.executable, str(CONFIGURE), "--agent", "codex", "--project", str(self.project),
             "--team", "lab", "--server", SERVER, "--no-persist", "--skip-check", *extra],
            capture_output=True, text=True, env=env, timeout=30,
        )

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
             "--server", "http://127.0.0.1:9", "--no-persist"],
            capture_output=True, text=True, env=env, timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not run", result.stderr)


if __name__ == "__main__":
    unittest.main()
