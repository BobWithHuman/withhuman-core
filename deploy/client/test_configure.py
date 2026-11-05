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

OLD_HTTP = {"type": "http", "url": "https://54.252.92.35/v1/hooks/PreToolUse",
            "headers": {"x-withhuman-client": "$WITHHUMAN_CLIENT_ID"}}
OTHER = {"type": "command", "command": "echo mine"}


class ConfigureTest(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.project = Path(tempfile.mkdtemp())
        (self.home / ".claude").mkdir()
        (self.project / ".claude").mkdir()

    def write(self, path, value):
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)

    def read(self, path):
        return json.loads(path.read_text())

    def configure(self, *extra):
        env = {**os.environ, "HOME": str(self.home), "SHELL": "/bin/zsh"}
        return subprocess.run(
            [sys.executable, str(CONFIGURE), "--project", str(self.project), "--team", "lab", *extra],
            capture_output=True, text=True, env=env, timeout=30,
        )

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
                                             "https://54.252.92.35/v1/hooks/PreToolUse")
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertEqual(hook.read_text(), (HERE / "hooks" / "pre-tool-use.py").read_text())
        post = settings["hooks"]["PostToolUse"][0]["hooks"][0]
        self.assertEqual(post["url"], "https://54.252.92.35/v1/hooks/PostToolUse")
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


if __name__ == "__main__":
    unittest.main()
