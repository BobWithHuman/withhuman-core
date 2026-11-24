#!/usr/bin/env python3
"""Sets up WithHuman for Claude Code in a project folder, replacing any earlier WithHuman setup.

usage: configure.py --server URL [--project DIR] [--team NAME] [--key KEY] [--hook FILE]
                    [--no-persist] [--no-register] [--scope project|user|managed]
                    [--managed-hooks-only]

WithHuman is self-hosted, so --server (or WITHHUMAN_SERVER) has no default: it is the address of
the engine this device reports to, and every hook below is written against it.

1. Takes every WithHuman hook out of the user's Claude Code settings (~/.claude/settings.json)
   and the project's own (.claude/settings.json, .claude/settings.local.json), so an earlier
   setup, an all-HTTP PreToolUse hook especially, does not run beside this one. Other settings
   and other hooks are kept, and each file changed is first copied to <file>.bak-<time>.
2. Writes WithHuman's eleven hooks into the project's .claude/settings.json: ten HTTP hooks and
   a PreToolUse command hook, installed at .claude/hooks/pre-tool-use.py and run with this
   Python. Each sends the client ID and the user's WithHuman key (`Authorization: Bearer`).
3. Gives the device a stable client ID (~/.config/withhuman/client-id, `<team>/<uuid>`) and,
   unless --no-persist, sets WITHHUMAN_CLIENT_ID for new shells: in the shell profile on macOS
   and Linux, as a user environment variable on Windows.
4. With --key (or WITHHUMAN_KEY), keeps the key the security team issued in
   ~/.config/withhuman/key, readable by the user only, and sets WITHHUMAN_KEY for new shells
   alike. Without one, a key kept by an earlier run is used.
5. Registers the device with the engine (POST /v1/clients/register): client ID, team, host
   name, OS, OS user, hook version, agent, project folder and, when it can be read without
   administrator rights, the machine's hardware serial number. The setup still completes when
   that fails, and says so; --no-register skips it.

The setup-project.sh and setup-project.ps1 wrappers fetch this file and the hook, then run it.

With --scope user or --scope managed it sets Claude Code up for every folder instead of one
project (Codex is set up per project only; Hermes Agent, --agent hermes, per Hermes profile, as a
plugin in $HERMES_HOME/plugins/withhuman that every session of the profile loads):

- user: the hooks go in the user's own settings (~/.claude/settings.json) and the hook in
  ~/.config/withhuman/hooks, for every folder this user works in; no administrator rights, and the
  user can take them out again.
- managed (run as root, or as administrator on Windows): the hooks go in the policy an
  administrator sets for Claude Code, in a file of its own in managed-settings.d beside
  managed-settings.json (/Library/Application Support/ClaudeCode on macOS, /etc/claude-code on
  Linux, C:\\Program Files\\ClaudeCode on Windows), so the organisation's own policy file is left
  alone. The hook and the device's client ID go in a folder only an administrator can change
  (/Library/Application Support/WithHuman, /opt/withhuman, C:\\Program Files\\WithHuman). They
  apply to every user and folder on the device and a user cannot turn them off.
  --managed-hooks-only also sets allowManagedHooksOnly, so Claude Code runs no user, project or
  plugin hooks beside the administrator's: no WithHuman hook a project setup left runs twice, and
  none of the user's own can stand beside it.

Hooks of all levels run together, so a device set up both ways reports each event twice: take a
project setup out (--uninstall in that project) where a global one is in place. A project setup
in turn takes WithHuman's hooks out of the user's settings, as above, and a managed setup takes
out the user setup of the user who ran it (the hook entries and the hook file).

With --reset [FOLDER ...] it takes every WithHuman setup out at once, whatever made it: the
managed one (as an administrator), the user one of the user who ran it, and the project ones of
the folders named (Claude Code's and every other agent's). Other hooks and settings stay, each file changed
is first copied to <file>.bak-<time>, and the device's client ID is kept, so a setup made after
is the same device. --server is not needed then.

A global setup writes the device's client ID into the HTTP hooks' header itself, rather than
leaving it to WITHHUMAN_CLIENT_ID, which Claude Code started from an IDE or by another user does
not have; the PreToolUse hook reads it from the file beside its folder. The WithHuman key stays
the user's own (WITHHUMAN_KEY or ~/.config/withhuman/key): a managed setup takes none.
Safe to run again: the result is the same, the client ID is kept and the registration updated.

With --agent <other agent> (`--agent codex`) it sets that agent up instead of Claude Code,
per project only (step 3 as above). Each is described by an `AgentSetup`, and adding one takes
no change to the steps below:

1. Copies its bridge and the files every bridge shares (hooks/withhuman_bridge.py and
   hooks/pre-tool-use.py) to the project's <agent folder>/hooks/, such as .codex/hooks/.
2. Writes its hooks into the agent's own hooks file there, replacing earlier WithHuman entries
   and keeping other hooks: each runs the bridge with this Python, as `command` on macOS and
   Linux and `commandWindows` on Windows, with the agent's own timeout per event (Codex: 15
   seconds for PreToolUse, 5 for the rest). The user's own folder is left alone.
3. Runs the installed bridge's self-check against the engine, then prints whatever that agent
   still needs from you (Codex: trust the hooks in /hooks, which it skips until you do).
4. Keeps the key and registers the device, as above.

With --uninstall (and --agent claude or another agent) it takes WithHuman out of the project only (with
--scope user or managed, out of that scope instead): its
hook entries in the project's settings or hooks.json (other hooks and settings are kept, each
file changed is first copied to <file>.bak-<time>) and the hook files it installed. --server is
not needed then.
"""

import argparse
import datetime
import getpass
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

EVENTS = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "SubagentStart",
    "SubagentStop",
    "ConfigChange",
    "MessageDisplay",
    "PostToolBatch",
    "SessionEnd",
]
HOOK_NAME = "pre-tool-use.py"
PROFILE_MARK = "# WithHuman client ID"
KEY_MARK = "# WithHuman key"
# A WithHuman key as the engine issues it.
KEY_PATTERN = re.compile(r"whk_[0-9a-f]{16}_[0-9a-f]{64}")
REGISTER_TIMEOUT = 10
SERIAL_TIMEOUT = 10
# Where Linux shows the motherboard's serial number, the one Wazuh's hardware inventory reports
# (`board_serial`); on most distributions only root can read it.
LINUX_SERIAL = Path("/sys/class/dmi/id/board_serial")
# The system's serial on Linux: often readable by root alone.
LINUX_OTHER_SERIALS = (Path("/sys/class/dmi/id/product_serial"),)
# What firmware reports when the manufacturer set no serial number: not a serial.
NO_SERIAL = {"", "0", "none", "default string", "not specified", "not applicable",
             "system serial number", "to be filled by o.e.m."}
# Where Claude Code reads the policy an administrator sets, and where a managed setup keeps the
# hook and the device's client ID, by system. WITHHUMAN_MANAGED_DIR and WITHHUMAN_DEVICE_DIR put
# them elsewhere (a test, an unusual layout).
MANAGED_DIRS = {"darwin": "/Library/Application Support/ClaudeCode", "linux": "/etc/claude-code",
                "windows": "C:\\Program Files\\ClaudeCode"}
DEVICE_DIRS = {"darwin": "/Library/Application Support/WithHuman", "linux": "/opt/withhuman",
               "windows": "C:\\Program Files\\WithHuman"}
MANAGED_FILE = "50-withhuman.json"
NEEDS_ADMIN = ("a managed setup (--scope managed, or --reset where one is) is written where "
               "only an administrator can: run it with sudo (macOS, Linux) or from an "
               "administrator PowerShell (Windows)")
# Files every bridge shares, kept in deploy/client/hooks and copied beside the agent's own.
SHARED_FILES = (HOOK_NAME, "withhuman_bridge.py")


class AgentSetup:
    """What setting up one coding agent other than Claude Code takes.

    Claude Code has no entry here: it posts to the engine itself, with hooks in its own
    settings (`withhuman_hooks`), and the rest of this file is about that. Every other agent
    runs a bridge beside WithHuman's shared one, so what differs between them is only this
    description and, where its hooks file has a shape of its own, `entry`, `insert` and `strip`.

    Adding an agent: write its bridge in `deploy/client/<kind>/` on `withhuman_bridge.py`,
    subclass this, and name it in `AGENTS`. `setup_agent`, `check_agent` and `uninstall` need
    nothing more.
    """

    #: `--agent <kind>`, and the route the engine reads its hooks on.
    kind = ""
    #: What messages call it.
    name = ""
    #: Where it keeps a project's settings, under the project folder.
    directory = ""
    #: Its hooks file in there.
    config = "hooks.json"
    #: The bridge's entry script, in `<directory>/hooks`.
    hook = ""
    #: Everything copied to `<directory>/hooks`; the shared files come from deploy/client/hooks.
    files = ()
    #: The events its bridge handles.
    events = ()
    #: Seconds the agent gives one hook, by event, and for the rest. PreToolUse waits for a
    #: judgment (intent wait and decision budget), so it gets more; the bridge ends itself
    #: before these limits, since a hook that times out lets the call run.
    timeouts = {}
    timeout = 5
    #: Printed once the setup is written.
    notes = ()
    #: Printed once it is taken out again.
    uninstall_notes = ()
    #: Set up in a project folder, as Claude Code's project setup is. An agent that keeps its
    #: setup elsewhere (a profile of its own) overrides `install` and `remove`.
    per_project = True

    def install(self, args, project, stamp, report):
        """Sets the agent up; returns where its setup was written and the installed bridge."""
        return setup_agent(self, args, project, stamp, report)

    def remove(self, project, stamp, report):
        """Takes the agent's setup out again; see [`uninstall_agent`]."""
        uninstall_agent(self, project, stamp, report)

    #: A file the setup writes beside the hook, for an agent whose command cannot carry the
    #: engine's address. None when the command carries it.
    server_file = None

    def installed(self, args, installed):
        """Anything else this agent needs in its hooks folder, once the files are copied."""

    def source(self, name):
        """Where a file of `files` is copied from."""
        here = Path(__file__).resolve().parent
        return here / ("hooks" if name in SHARED_FILES else self.kind) / name

    def entry(self, python, hook, server, event):
        """One hook of ours, as the agent's hooks file holds it. PowerShell runs
        `commandWindows`; `exit $LASTEXITCODE` passes the hook's exit code on, so its exit 2
        still blocks."""
        return {
            "type": "command",
            "command": f'"{python}" "{hook}" {server} {event}',
            "commandWindows": f'& "{python}" "{hook}" {server} {event}; exit $LASTEXITCODE',
            "timeout": self.timeouts.get(event, self.timeout),
        }

    def groups(self, python, hook, server):
        """Our hooks by event."""
        return {event: {"hooks": [self.entry(python, hook, server, event)]}
                for event in self.events}

    def is_ours(self, hook):
        return isinstance(hook, dict) and self.hook in str(hook.get("command", "")) + str(
            hook.get("commandWindows", ""))

    def insert(self, config, groups):
        """Puts our hooks into the agent's config, keeping everyone else's."""
        hooks = config.get("hooks") if isinstance(config.get("hooks"), dict) else {}
        for event, group in groups.items():
            hooks.setdefault(event, []).append(group)
        config["hooks"] = hooks

    def strip(self, config):
        """Takes our entries out of the agent's config in place; the number taken out."""
        hooks = config.get("hooks") if isinstance(config.get("hooks"), dict) else {}
        removed = 0
        for event in list(hooks):
            groups = hooks[event] if isinstance(hooks[event], list) else []
            kept_groups = []
            for group in groups:
                inner = group.get("hooks") if isinstance(group, dict) else None
                if not isinstance(inner, list):
                    kept_groups.append(group)
                    continue
                kept = [hook for hook in inner if not self.is_ours(hook)]
                removed += len(inner) - len(kept)
                if kept:
                    group["hooks"] = kept
                    kept_groups.append(group)
            if kept_groups:
                hooks[event] = kept_groups
            else:
                del hooks[event]
        config["hooks"] = hooks
        return removed


class CodexSetup(AgentSetup):
    kind = "codex"
    name = "Codex"
    directory = ".codex"
    hook = "withhuman-hook.py"
    files = ("withhuman-hook.py", "codex_transcript.py") + SHARED_FILES
    events = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop",
              "SubagentStart", "SubagentStop")
    timeouts = {"PreToolUse": 15}
    notes = ("Next: run codex in this project, open /hooks and trust the WithHuman hooks.",
             "Codex skips project hooks until they are trusted, and again after hooks.json",
             "changes (as after an update that changed it): until you trust them, this",
             "project is not protected.")
    uninstall_notes = (
        "WithHuman is removed from this project. Codex may list the hooks as changed in",
        "/hooks; nothing of WithHuman runs any more.")


class CursorSetup(AgentSetup):
    kind = "cursor"
    name = "Cursor"
    directory = ".cursor"
    hook = "withhuman-hook.py"
    files = ("withhuman-hook.py",) + SHARED_FILES
    # The events the engine judges or records, and `beforeReadFile`, whose text the bridge
    # keeps for the result Cursor leaves it out of. `beforeShellExecution` and the Tab hooks
    # are deliberately not here: the first repeats `preToolUse` for the same call, and the
    # others are Cursor Tab's own file access rather than an agent's Call.
    events = ("sessionStart", "sessionEnd", "beforeSubmitPrompt", "preToolUse",
              "beforeMCPExecution", "postToolUse", "postToolUseFailure", "beforeReadFile",
              "afterAgentResponse", "stop")
    # A judged call waits for the engine; the bridge ends itself before this.
    timeouts = {"preToolUse": 15, "beforeMCPExecution": 15}
    notes = ("Next: run cursor-agent in this project and trust the workspace when it asks.",
             "Cursor runs no project hook until you do, and until then this project is not",
             "protected.")
    uninstall_notes = ("WithHuman is removed from this project. Nothing of it runs any more.",)
    #: Written beside the hook, since the command cannot carry the address; see `entry`.
    server_file = "server"

    def entry(self, python, hook, server, event):
        """One hook of ours, as Cursor's hooks.json holds it: a flat entry per event, with no
        separate Windows command (Cursor takes one `command`).

        The engine's address is **not** in the command. Cursor 2026.11.22 runs no hook at all
        from a file whose command holds an `http://` address — not that one hook, the whole
        file, and silently, so every call goes unjudged. `server_file` below keeps the address
        beside the hook instead, and the bridge reads it there.

        `failClosed` goes on the events whose answer decides a Call. Cursor lets a call through
        when a hook crashes or times out, which would lift the control exactly when it is
        needed; on the events that only report, a failure costs the engine that record and must
        not stop the agent.
        """
        return {
            "command": f'"{python}" "{hook}" {event}',
            "timeout": self.timeouts.get(event, self.timeout),
            "failClosed": event in ("preToolUse", "beforeMCPExecution"),
        }

    def installed(self, args, installed):
        """The engine's address, where the bridge looks for it."""
        (installed / self.server_file).write_text(args.server + "\n", encoding="utf-8")

    def groups(self, python, hook, server):
        return {event: self.entry(python, hook, server, event) for event in self.events}

    def is_ours(self, hook):
        return isinstance(hook, dict) and self.hook in str(hook.get("command", ""))

    def insert(self, config, groups):
        # Cursor reads the file by its version; without it the hooks are ignored.
        config["version"] = 1
        hooks = config.get("hooks") if isinstance(config.get("hooks"), dict) else {}
        for event, entry in groups.items():
            hooks.setdefault(event, []).append(entry)
        config["hooks"] = hooks

    def strip(self, config):
        """Takes our entries out of a Cursor hooks.json in place; the number taken out. Cursor
        holds the entries directly under the event, without Claude Code's group."""
        hooks = config.get("hooks") if isinstance(config.get("hooks"), dict) else {}
        removed = 0
        for event in list(hooks):
            entries = hooks[event] if isinstance(hooks[event], list) else []
            kept = [entry for entry in entries if not self.is_ours(entry)]
            removed += len(entries) - len(kept)
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
        config["hooks"] = hooks
        return removed


def hermes_home():
    """The Hermes profile being set up, as Hermes finds it: HERMES_HOME, else its platform
    default, %LOCALAPPDATA%\\hermes on Windows (where the desktop app keeps it) and ~/.hermes
    elsewhere."""
    home = os.environ.get("HERMES_HOME", "").strip()
    if home:
        return Path(os.path.expandvars(home)).expanduser().resolve()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "").strip()
        return (Path(local) if local else Path.home() / "AppData" / "Local") / "hermes"
    return Path.home() / ".hermes"


class HermesSetup(AgentSetup):
    """Hermes Agent runs every session of a profile in one gateway, which loads plugins from the
    profile and never from a project folder: WithHuman is a plugin of the profile, for every
    folder its sessions run in. The plugin keeps the engine's address beside itself."""

    kind = "hermes"
    name = "Hermes"
    hook = "withhuman-hook.py"
    #: The plugin's folder name and the name `hermes plugins enable` takes.
    plugin = "withhuman"
    files = ("__init__.py", "plugin.yaml", "withhuman-hook.py") + SHARED_FILES
    per_project = False
    notes = ("Next: restart Hermes (hermes gateway restart) so it loads the plugin. It then runs",
             "for every session of this profile, in every folder; another profile (HERMES_HOME)",
             "is set up on its own.")
    uninstall_notes = ("WithHuman is removed from this Hermes profile; restart Hermes "
                       "(hermes gateway restart) for it to stop.",)

    def folder(self):
        return hermes_home() / "plugins" / self.plugin

    def hermes(self, *words):
        """Runs the Hermes CLI on this profile; whether it ran and what it said."""
        command = shutil.which("hermes")
        if not command:
            return False, "the hermes command is not on PATH"
        try:
            result = subprocess.run([command, *words], capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=300,
                                    env={**os.environ, "HERMES_HOME": str(hermes_home())})
        except subprocess.TimeoutExpired:
            return False, f"`hermes {' '.join(words)}` did not finish in 300 seconds"
        except OSError as error:
            return False, f"the hermes command could not run: {error}"
        return result.returncode == 0, (result.stdout + result.stderr).strip()

    def install(self, args, project, stamp, report):
        installed = self.folder()
        if installed.exists() and installed.is_dir():
            report.append(f"{installed}: earlier WithHuman plugin replaced")
        installed.mkdir(parents=True, exist_ok=True)
        for name in self.files:
            source = self.source(name)
            if not source.is_file():
                sys.exit(f"hook file not found: {source}")
            shutil.copyfile(source, installed / name)
        (installed / self.hook).chmod(0o755)
        state = installed / "withhuman-state"
        state.mkdir(exist_ok=True)
        (state / ".gitignore").write_text("*\n", encoding="utf-8")
        save(installed / "withhuman.json", {"server": args.server})
        enabled, output = self.hermes("plugins", "enable", self.plugin)
        if not enabled:
            report.append(f"Hermes plugin not enabled ({output.splitlines()[-1] if output else 'no output'}): "
                          f"run `hermes plugins enable {self.plugin}` for this profile")
        return installed, installed / self.hook

    def remove(self, project, stamp, report):
        installed = self.folder()
        if not (installed / "plugin.yaml").is_file():
            return
        self.hermes("plugins", "disable", self.plugin)
        shutil.rmtree(installed)
        report.append(f"{installed}: removed")


#: Every agent but Claude Code, by `--agent` value.
AGENTS = {agent.kind: agent for agent in (CodexSetup(), CursorSetup(), HermesSetup())}


def is_withhuman(hook):
    """A hook an earlier WithHuman setup added: posting to /v1/hooks/, or running our hook."""
    if not isinstance(hook, dict):
        return False
    return "/v1/hooks/" in str(hook.get("url", "")) or HOOK_NAME in str(hook.get("command", ""))


def remove_withhuman(settings):
    """Takes WithHuman hooks out of `settings` in place; the number taken out."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    removed = 0
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            inner = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(inner, list):
                kept_groups.append(group)
                continue
            kept = [hook for hook in inner if not is_withhuman(hook)]
            removed += len(inner) - len(kept)
            if kept:
                group["hooks"] = kept
                kept_groups.append(group)
        if kept_groups:
            hooks[event] = kept_groups
        else:
            del hooks[event]
    if not hooks:
        del settings["hooks"]
    return removed


def withhuman_hooks(server, command, client=None):
    """Our hooks by event: HTTP with the client ID header, PreToolUse through `command`. With
    `client`, the header carries that ID as written instead of WITHHUMAN_CLIENT_ID."""
    def http(event):
        # Claude Code puts only listed variables into headers; an unset WITHHUMAN_KEY leaves
        # `Bearer `, which the engine takes as no key.
        if client:
            return {
                "type": "http",
                "url": f"{server}/v1/hooks/{event}",
                "headers": {"x-withhuman-client": client, "Authorization": "Bearer $WITHHUMAN_KEY"},
                "allowedEnvVars": ["WITHHUMAN_KEY"],
            }
        return {
            "type": "http",
            "url": f"{server}/v1/hooks/{event}",
            "headers": {"x-withhuman-client": "$WITHHUMAN_CLIENT_ID",
                        "Authorization": "Bearer $WITHHUMAN_KEY"},
            "allowedEnvVars": ["WITHHUMAN_CLIENT_ID", "WITHHUMAN_KEY"],
        }

    return {
        event: {"hooks": [{"type": "command", "command": command} if event == "PreToolUse" else http(event)]}
        for event in EVENTS
    }


def load(path):
    if not path.exists():
        return {}
    try:
        settings = json.loads(path.read_text(encoding="utf-8") or "{}")
    except ValueError as error:
        sys.exit(f"{path} is not valid JSON ({error}); fix or move it, then run again")
    if not isinstance(settings, dict):
        sys.exit(f"{path} does not hold a JSON object; fix or move it, then run again")
    return settings


def backup(path, stamp):
    copy = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, copy)
    return copy


def save(path, settings):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def clean(path, stamp, report):
    """Takes WithHuman hooks out of the settings file at `path`, keeping a copy if it changes."""
    settings = load(path)
    removed = remove_withhuman(settings)
    if removed:
        report.append(f"{path}: {removed} earlier WithHuman hook(s) removed, copy at {backup(path, stamp)}")
        save(path, settings)


def client_id(team):
    """The device's client ID, made once and kept in ~/.config/withhuman/client-id."""
    path = Path.home() / ".config" / "withhuman" / "client-id"
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return path, path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    value = f"{team}/{uuid.uuid4()}"
    path.write_text(value + "\n", encoding="utf-8")
    return path, value


def config_dir():
    return Path.home() / ".config" / "withhuman"


def system():
    if sys.platform == "darwin":
        return "darwin"
    return "windows" if os.name == "nt" else "linux"


def managed_settings():
    """The file of WithHuman's own in the drop-in folder of Claude Code's managed settings."""
    folder = os.environ.get("WITHHUMAN_MANAGED_DIR") or MANAGED_DIRS[system()]
    return Path(folder) / "managed-settings.d" / MANAGED_FILE


def device_dir():
    return Path(os.environ.get("WITHHUMAN_DEVICE_DIR") or DEVICE_DIRS[system()])


def user_homes():
    """The homes a device-wide step reads or tidies: the user who ran sudo's, then this
    account's."""
    homes = []
    if os.environ.get("SUDO_USER"):
        homes.append(Path(os.path.expanduser("~" + os.environ["SUDO_USER"])))
    homes.append(Path.home())
    return list(dict.fromkeys(homes))


def device_client_id(team):
    """The device's client ID for a managed setup, kept in the device folder. A first setup takes
    the one the user's own setup gave this device, so the device keeps one identity: the user who
    ran sudo's, else this account's; else it makes one."""
    path = device_dir() / "client-id"
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return path, path.read_text(encoding="utf-8").strip()
    value = None
    for home in user_homes():
        earlier = home / ".config" / "withhuman" / "client-id"
        try:
            value = earlier.read_text(encoding="utf-8").strip() or None
        except OSError:
            value = None
        if value:
            break
    value = value or f"{team}/{uuid.uuid4()}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o644)
    return path, value


def install_hook(source, hook):
    """Copies the PreToolUse hook to `hook`, runnable, and readable by every user."""
    hook.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != hook.resolve():
        shutil.copyfile(source, hook)
    hook.chmod(0o755)


def keep_key(given):
    """The user's WithHuman key: `given`, kept in ~/.config/withhuman/key (mode 0600), or the one
    an earlier run kept. None when there is neither."""
    path = config_dir() / "key"
    if given is None:
        if path.exists() and path.read_text(encoding="utf-8").strip():
            return path, path.read_text(encoding="utf-8").strip()
        return path, None
    given = given.strip()
    if not KEY_PATTERN.fullmatch(given):
        sys.exit("--key is not a WithHuman key (whk_<16 hex>_<64 hex>); copy it again from the "
                 "security team's message")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Created unreadable to others before the key is written into it.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        file.write(given + "\n")
    path.chmod(0o600)
    return path, given


def profile():
    """The shell profile new terminals read."""
    shell = os.environ.get("SHELL", "")
    if shell.endswith("zsh") or (not shell and sys.platform == "darwin"):
        return Path.home() / ".zshrc"
    return Path.home() / ".bashrc"


def persist(id_path, value, stamp, report, name="WITHHUMAN_CLIENT_ID", mark=PROFILE_MARK):
    """Sets `name` (the client ID, or the key) for new shells from the file at `id_path`,
    replacing any line an earlier setup wrote."""
    if os.name == "nt":
        result = subprocess.run(["setx", name, value], capture_output=True)
        if result.returncode != 0:
            sys.exit(f"setx failed: {result.stderr.decode(errors='replace').strip()}")
        report.append(f"{name} set as a user environment variable (new windows)")
        return
    path = profile()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    earlier = re.compile(rf"^\s*export\s+{name}=")
    block = [mark, f"export {name}=\"$(cat '{id_path}')\""]
    # An earlier line is replaced where it stands, so the profile's other WithHuman line keeps
    # its place and a second run changes nothing.
    wanted, placed = [], False
    for line in lines:
        if line.strip() == mark:
            continue
        if earlier.match(line):
            if not placed:
                wanted += block
                placed = True
            continue
        wanted.append(line)
    if not placed:
        while wanted and not wanted[-1].strip():
            wanted.pop()
        wanted += [""] + block
    if wanted != lines:
        if path.exists():
            backup(path, stamp)
        path.write_text("\n".join(wanted) + "\n", encoding="utf-8")
        report.append(f"{path}: exports {name} (new shells)")


def hook_version(paths):
    """The installed hook files' version: the start of their SHA-256, so the inventory shows
    which devices run an old hook."""
    digest = hashlib.sha256()
    for path in paths:
        digest.update(Path(path).read_bytes())
    return digest.hexdigest()[:12]


def command_output(command):
    """What `command` printed, or "" when it is missing, fails or takes too long."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=SERIAL_TIMEOUT)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def hardware_serial():
    """The machine's hardware serial number as Wazuh's hardware inventory reports it
    (`board_serial`), read as the current user; None when it cannot be read or the firmware has
    none. The engine matches the device with the EDR's by this value, and two serials that
    differ keep two machines apart, so it is the motherboard's on Linux and Windows (not the
    system's or the BIOS's, which a PC often numbers otherwise) and the platform's on macOS, as
    Wazuh reads them. Nothing else stands in for it."""
    serial = ""
    if sys.platform == "darwin":
        output = command_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        found = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]*)"', output)
        serial = found.group(1) if found else ""
    elif sys.platform.startswith("linux"):
        try:
            serial = LINUX_SERIAL.read_text(encoding="utf-8", errors="replace")
        except OSError:
            serial = ""
    elif os.name == "nt":
        serial = command_output(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                 "(Get-CimInstance -ClassName Win32_BaseBoard).SerialNumber"])
        if not serial.strip():
            # Older Windows: `wmic` prints a `SerialNumber` heading, then the value.
            lines = [line.strip() for line in
                     command_output(["wmic", "baseboard", "get", "serialnumber"]).splitlines()]
            serial = next((line for line in lines
                           if line and line.lower() != "serialnumber"), "")
    serial = serial.strip()
    return None if serial.lower() in NO_SERIAL else serial


def other_serials():
    """The machine's other hardware serial numbers, beside the motherboard's: the BIOS's on
    Windows, the system's on Linux (when this user can read it). A PC often numbers these
    otherwise than its motherboard, and an EDR may report one of them; the engine matches the
    device by any. None on macOS, where there is one."""
    found = []
    if sys.platform.startswith("linux"):
        for path in LINUX_OTHER_SERIALS:
            try:
                found.append(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    elif os.name == "nt":
        found.append(command_output(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                     "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"]))
    serials = []
    for serial in (s.strip() for s in found):
        if serial.lower() not in NO_SERIAL and serial not in serials:
            serials.append(serial)
    return serials


def register(server, client, team, key, agent, project, version):
    """Registers the device with the engine; the problem as text when that fails, else None."""
    body = {
        "client_id": client,
        "team": team,
        "hostname": socket.gethostname(),
        "os": f"{platform.system().lower()} {platform.release()}".strip(),
        "os_user": getpass.getuser(),
        "hook_version": version,
        "agent": agent,
        "project": str(project),
    }
    serial = hardware_serial()
    if serial:
        body["serial"] = serial
    others = [other for other in other_serials() if other != serial]
    if others:
        body["other_serials"] = others
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    def post(body):
        request = urllib.request.Request(f"{server}/v1/clients/register",
                                         data=json.dumps(body).encode("utf-8"),
                                         headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=REGISTER_TIMEOUT) as response:
            response.read()

    try:
        try:
            post(body)
        except urllib.error.HTTPError as error:
            # An engine from before `other_serials` refuses a field it does not know: it is
            # registered without them.
            if not others or error.code not in (400, 422):
                raise
            post({name: value for name, value in body.items() if name != "other_serials"})
        return None
    except urllib.error.HTTPError as error:
        try:
            reason = json.loads(error.read() or b"{}").get("error")
        except (ValueError, AttributeError):
            reason = None
        explained = {
            "key_required": "the engine requires a WithHuman key: run again with --key",
            "key_invalid": "the engine does not know this key: check it, then run again with --key",
            "key_revoked": "this key was revoked: ask the security team for a new one",
        }
        return explained.get(reason, f"the engine answered {error.code}"
                             + (f" ({reason})" if reason else ""))
    except (urllib.error.URLError, OSError, ValueError) as error:
        return f"the engine could not be reached ({getattr(error, 'reason', error)})"


def finish(args, client, key_path, key, agent, project, version, stamp, report):
    """Keeps the key for new shells and registers the device; returns the lines to print."""
    if key and not args.no_persist and args.scope != "managed":
        persist(key_path, key, stamp, report, name="WITHHUMAN_KEY", mark=KEY_MARK)
    lines = []
    if args.scope == "managed":
        lines.append("Each user's own WithHuman key (WITHHUMAN_KEY, or ~/.config/withhuman/key) "
                     "goes with their calls.")
    elif key:
        lines.append(f"WithHuman key kept in {key_path}")
    else:
        lines.append("No WithHuman key: hooks report no user. If the security team gave you one, "
                     "run again with --key.")
    if args.no_register:
        return lines
    problem = register(args.server, client, args.team, key, agent, project, version)
    if problem:
        lines.append(f"WARNING: the device was not registered: {problem}. The hooks are "
                     "installed; run this setup again to register.")
    else:
        lines.append(f"Device registered with {args.server}")
    return lines


def setup_agent(agent, args, project, stamp, report):
    """Sets one agent up in a project: its bridge files beside each other, and our hooks in its
    own hooks file. Returns that file and the installed bridge."""
    directory = project / agent.directory
    installed = directory / "hooks"
    installed.mkdir(parents=True, exist_ok=True)
    for name in agent.files:
        source = agent.source(name)
        if not source.is_file():
            sys.exit(f"hook file not found: {source}")
        if source.resolve() != (installed / name).resolve():
            shutil.copyfile(source, installed / name)
    (installed / agent.hook).chmod(0o755)
    agent.installed(args, installed)
    # Session state the bridge keeps; inside the agent's hooks folder, where the engine blocks
    # an agent's changes as it does to the hooks themselves.
    state = installed / "withhuman-state"
    state.mkdir(exist_ok=True)
    (state / ".gitignore").write_text("*\n", encoding="utf-8")

    path = directory / agent.config
    config = load(path)
    removed = agent.strip(config)
    if path.exists():
        report.append(f"{path}: copy at {backup(path, stamp)}"
                      + (f", {removed} earlier WithHuman hook(s) replaced" if removed else ""))
    hook = (installed / agent.hook).as_posix()
    agent.insert(config, agent.groups(Path(sys.executable).as_posix(), hook, args.server))
    save(path, config)
    return path, installed / agent.hook


def uninstall_user(home, stamp, report):
    """Takes the user setup of the user at `home` out: the WithHuman hooks of their settings and
    the hook in ~/.config/withhuman/hooks. Their client ID is kept."""
    clean(home / ".claude" / "settings.json", stamp, report)
    hook = home / ".config" / "withhuman" / "hooks" / HOOK_NAME
    if hook.is_file():
        hook.unlink()
        report.append(f"{hook}: removed")


def uninstall_global(scope, stamp, report):
    """Takes a global setup out: the user's settings' WithHuman hooks and the hook in
    ~/.config/withhuman/hooks, or the managed settings file of WithHuman's own and the device's
    hook. The device's client ID is kept, as a project uninstall keeps it."""
    if scope == "user":
        uninstall_user(Path.home(), stamp, report)
        return
    for path in (managed_settings(), device_dir() / "hooks" / HOOK_NAME):
        if path.is_file():
            path.unlink()
            report.append(f"{path}: removed")


def reset(projects, stamp, report):
    """Takes every WithHuman setup out, whatever made it: the managed one, the user ones of
    [`user_homes`], and Claude Code's and Codex's in each of `projects`. Client IDs are kept."""
    uninstall_global("managed", stamp, report)
    for home in user_homes():
        uninstall_user(home, stamp, report)
    for agent in AGENTS.values():
        if not agent.per_project:
            agent.remove(None, stamp, report)
    for project in projects:
        for kind in ("claude", *(k for k, agent in AGENTS.items() if agent.per_project)):
            uninstall(kind, project, stamp, report)


def setup_global(args, hook_source, key_path, key, stamp, report):
    """Sets Claude Code up for every folder: the user's (`--scope user`) or the device's
    (`--scope managed`). Returns the settings file, the hook and the client ID."""
    managed = args.scope == "managed"
    if managed:
        id_path, value = device_client_id(args.team)
        hook = device_dir() / "hooks" / HOOK_NAME
    else:
        id_path, value = client_id(args.team)
        hook = config_dir() / "hooks" / HOOK_NAME
    install_hook(hook_source, hook)
    # Quoted absolute paths run alike from bash, zsh, cmd and PowerShell.
    command = f'"{Path(sys.executable).as_posix()}" "{hook.as_posix()}" {args.server}/v1/hooks/PreToolUse'
    ours = withhuman_hooks(args.server, command, client=value)
    if managed:
        # A file of WithHuman's own: written whole, so nothing of the organisation's is in it.
        path = managed_settings()
        settings = {"hooks": {event: [group] for event, group in ours.items()}}
        if args.managed_hooks_only:
            settings["allowManagedHooksOnly"] = True
        if path.exists():
            report.append(f"{path}: replaced, copy at {backup(path, stamp)}")
        save(path, settings)
        path.chmod(0o644)
        # A user setup left beside it would report each event a second time.
        for home in user_homes():
            uninstall_user(home, stamp, report)
    else:
        path = Path.home() / ".claude" / "settings.json"
        settings = load(path)
        removed = remove_withhuman(settings)
        if path.exists():
            report.append(f"{path}: copy at {backup(path, stamp)}"
                          + (f", {removed} earlier WithHuman hook(s) replaced" if removed else ""))
        hooks = settings.setdefault("hooks", {})
        for event, group in ours.items():
            hooks.setdefault(event, []).append(group)
        save(path, settings)
        if not args.no_persist:
            persist(id_path, value, stamp, report)
    return path, hook, value


def uninstall(kind, project, stamp, report):
    """Takes WithHuman out of the project: its hook entries (other hooks and settings stay, the
    file changed is first copied to <file>.bak-<time>) and the hook files it installed. The
    device's client ID and the user's own settings are left alone."""
    agent = AGENTS.get(kind)
    if agent:
        agent.remove(project, stamp, report)
        return
    for path in (project / ".claude" / "settings.json", project / ".claude" / "settings.local.json"):
        clean(path, stamp, report)
    installed = project / ".claude" / "hooks"
    remove_files(installed, [installed / HOOK_NAME], report)


def uninstall_agent(agent, project, stamp, report):
    """Takes an agent's project setup out: its entries in the agent's hooks file and the bridge
    files and session state it installed."""
    path = project / agent.directory / agent.config
    if path.exists():
        config = load(path)
        removed = agent.strip(config)
        if removed:
            report.append(f"{path}: {removed} WithHuman hook(s) removed, copy at {backup(path, stamp)}")
            save(path, config)
    installed = project / agent.directory / "hooks"
    state = installed / "withhuman-state"
    if state.is_dir():
        shutil.rmtree(state)
        report.append(f"{state}: removed")
    files = [installed / name for name in agent.files]
    if agent.server_file:
        files.append(installed / agent.server_file)
    remove_files(installed, files, report)


def remove_files(installed, files, report):
    """Removes the hook files WithHuman installed in `installed`, their compiled copies, and the
    folder once nothing else is left in it."""
    for path in files:
        if path.is_file():
            path.unlink()
            report.append(f"{path}: removed")
    # Python's compiled copies of the hook files; anyone else's stay.
    cache = installed / "__pycache__"
    if cache.is_dir():
        stems = {Path(path.name).stem for path in files}
        for compiled in cache.glob("*.pyc"):
            if compiled.name.split(".")[0] in stems:
                compiled.unlink()
        if not any(cache.iterdir()):
            cache.rmdir()
    if installed.is_dir() and not any(installed.iterdir()):
        installed.rmdir()


def check_agent(hook, server):
    """Runs the installed bridge the way the agent will, so a broken interpreter path or
    quoting shows now rather than as hooks the agent silently fails to run."""
    commands = [[sys.executable, str(hook), "--check", server]]
    if os.name == "nt":
        commands.append(["powershell", "-NoProfile", "-Command",
                         f'& "{Path(sys.executable).as_posix()}" "{Path(hook).as_posix()}" '
                         f"--check {server}; exit $LASTEXITCODE"])
    for command in commands:
        # Python and the Windows terminal can use different encodings. A localized connection
        # error must remain a failed self-check, rather than crashing the installer's decoder.
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace",
                                env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        output = (result.stdout + result.stderr).strip()
        if result.returncode != 0:
            return False, output
    return True, output


def main():
    parser = argparse.ArgumentParser(description="Set up WithHuman for Claude Code in a project.")
    parser.add_argument("--agent", choices=["claude", *AGENTS], default="claude",
                        help="the coding agent to set up (default: claude)")
    parser.add_argument("--skip-check", action="store_true",
                        help="other agents: do not run the installed bridge against the engine")
    parser.add_argument("--project", default=os.getcwd(), help="project folder (default: here)")
    parser.add_argument("--team", default="default", help="team part of a new client ID")
    parser.add_argument(
        "--server",
        default=os.environ.get("WITHHUMAN_SERVER"),
        help="WithHuman engine address, such as http://127.0.0.1:3000 or https://withhuman.example.com",
    )
    parser.add_argument("--hook", default=str(Path(__file__).resolve().parent / "hooks" / HOOK_NAME))
    parser.add_argument("--no-persist", action="store_true", help="leave shell profiles alone")
    parser.add_argument("--key", default=os.environ.get("WITHHUMAN_KEY"),
                        help="your WithHuman key from the security team (or set WITHHUMAN_KEY)")
    parser.add_argument("--no-register", action="store_true",
                        help="do not register the device with the engine")
    parser.add_argument("--uninstall", action="store_true",
                        help="take WithHuman out of the project (other hooks and files stay)")
    parser.add_argument("--scope", choices=["project", "user", "managed"], default="project",
                        help="claude: one project (default), every folder of this user, or every "
                             "user and folder of the device (managed; needs administrator rights)")
    parser.add_argument("--reset", nargs="*", metavar="FOLDER",
                        help="take every WithHuman setup out: the managed one, this user's, and "
                             "the project ones of the folders named; client IDs are kept")
    parser.add_argument("--managed-hooks-only", action="store_true",
                        help="with --scope managed: run no user, project or plugin hooks beside "
                             "the administrator's")
    args = parser.parse_args()
    if sys.version_info < (3, 8):
        sys.exit("WithHuman's hook needs Python 3.8 or later")
    if args.scope != "project" and args.agent != "claude":
        agent = AGENTS[args.agent]
        sys.exit("--scope user and managed are for Claude Code; " + (
            f"{agent.name} is set up per project" if agent.per_project
            else f"{agent.name} is set up per profile (HERMES_HOME)"))
    if args.managed_hooks_only and args.scope != "managed":
        sys.exit("--managed-hooks-only goes with --scope managed")
    if args.scope == "managed" and args.key:
        sys.exit("a managed setup is for every user of the device and takes no key: each user "
                 "keeps their own (WITHHUMAN_KEY, or a setup with --key in their own account)")
    if args.reset is not None:
        report = []
        try:
            reset([Path(folder).resolve() for folder in args.reset],
                  datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), report)
        except PermissionError:
            sys.exit(NEEDS_ADMIN)
        for line in report or ["Nothing of WithHuman was found."]:
            print(line)
        if report:
            print("Start Claude Code again for the change to apply.")
        return
    if args.uninstall and args.scope != "project":
        report = []
        try:
            uninstall_global(args.scope, datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), report)
        except PermissionError:
            sys.exit(NEEDS_ADMIN)
        for line in report or [f"Nothing of WithHuman was found for --scope {args.scope}."]:
            print(line)
        return
    if args.uninstall:
        report = []
        uninstall(args.agent, Path(args.project).resolve(),
                  datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), report)
        for line in report or ["Nothing of WithHuman was found in this project."]:
            print(line)
        if report:
            for line in AGENTS[args.agent].uninstall_notes if args.agent in AGENTS else ():
                print(line)
        return
    if not re.fullmatch(r"[A-Za-z0-9._-]+", args.team):
        sys.exit(f"team must match [A-Za-z0-9._-]+: {args.team}")
    # No default: pointing a device at someone else's engine would ship this project's prompts
    # and commands there, so the address is always the operator's own choice.
    if not args.server:
        sys.exit(
            "--server is required (or set WITHHUMAN_SERVER): the address of your own engine.\n"
            "  personal Docker host:  http://127.0.0.1:3000\n"
            "  EKS deployment:        https://<the Ingress host>"
        )
    args.server = args.server.rstrip("/")
    if not re.fullmatch(r"https?://[^\s/]+(/[^\s]*)?", args.server):
        sys.exit(f"--server must be an http(s) URL: {args.server}")
    if args.agent != "claude":
        agent = AGENTS[args.agent]
        project = Path(args.project).resolve()
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        report = []
        key_path, key = keep_key(args.key)
        path, hook = agent.install(args, project, stamp, report)
        id_path, value = client_id(args.team)
        if not args.no_persist:
            persist(id_path, value, stamp, report)
        version = hook_version(hook.parent / name for name in agent.files)
        # An agent set up outside a project is registered with where its setup lives.
        where = project if agent.per_project else path
        notes = finish(args, value, key_path, key, agent.kind, where, version, stamp, report)
        for line in report:
            print(line)
        print(f"WithHuman {agent.name} hooks written to {path}")
        print(f"Hook: {hook} (run with {sys.executable if agent.per_project else agent.name + ' Python'})")
        print(f"WITHHUMAN_CLIENT_ID={value}")
        for line in notes:
            print(line)
        if not args.skip_check:
            ok, output = check_agent(hook, args.server)
            print(output)
            if not ok:
                sys.exit("The installed hook did not run; fix the problem above, then run again.")
        for line in agent.notes:
            print(line)
        return
    hook_source = Path(args.hook)
    if not hook_source.is_file():
        sys.exit(f"hook not found: {hook_source}")
    # A managed setup runs as an administrator, for every user: it keeps no one's key.
    key_path, key = keep_key(args.key) if args.scope != "managed" else (None, None)
    if args.scope != "project":
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        report = []
        try:
            path, hook, value = setup_global(args, hook_source, key_path, key, stamp, report)
        except PermissionError:
            sys.exit(NEEDS_ADMIN)
        notes = finish(args, value, key_path, key, "claude", f"({args.scope})",
                       hook_version([hook]), stamp, report)
        for line in report:
            print(line)
        print(f"WithHuman hooks written to {path}, for every folder"
              + (" of every user on this device" if args.scope == "managed" else " of this user"))
        print(f"PreToolUse hook: {hook} (run with {sys.executable})")
        print(f"WITHHUMAN_CLIENT_ID={value}")
        for line in notes:
            print(line)
        if not args.managed_hooks_only:
            print("Take WithHuman out of projects set up one by one (--uninstall there), or each "
                  "event is reported twice."
                  + (" --managed-hooks-only stops them running instead." if args.scope == "managed"
                     else ""))
        print("Start Claude Code again for the hooks to apply.")
        return

    project = Path(args.project).resolve()
    claude = project / ".claude"
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    report = []

    clean(Path.home() / ".claude" / "settings.json", stamp, report)
    clean(claude / "settings.local.json", stamp, report)

    hook = claude / "hooks" / HOOK_NAME
    hook.parent.mkdir(parents=True, exist_ok=True)
    if hook_source.resolve() != hook.resolve():
        shutil.copyfile(hook_source, hook)
    hook.chmod(0o755)

    settings_path = claude / "settings.json"
    settings = load(settings_path)
    removed = remove_withhuman(settings)
    if settings_path.exists():
        report.append(f"{settings_path}: copy at {backup(settings_path, stamp)}"
                      + (f", {removed} earlier WithHuman hook(s) replaced" if removed else ""))
    # Quoted absolute paths run alike from bash, zsh, cmd and PowerShell.
    command = f'"{Path(sys.executable).as_posix()}" "{hook.as_posix()}" {args.server}/v1/hooks/PreToolUse'
    hooks = settings.setdefault("hooks", {})
    for event, group in withhuman_hooks(args.server, command).items():
        hooks.setdefault(event, []).append(group)
    save(settings_path, settings)

    id_path, value = client_id(args.team)
    if not args.no_persist:
        persist(id_path, value, stamp, report)
    notes = finish(args, value, key_path, key, "claude", project, hook_version([hook]), stamp,
                   report)

    for line in report:
        print(line)
    print(f"WithHuman hooks written to {settings_path}")
    print(f"PreToolUse hook: {hook} (run with {sys.executable})")
    print(f"WITHHUMAN_CLIENT_ID={value}")
    for line in notes:
        print(line)
    if os.name == "nt":
        print("Open a new terminal (or keep this one if the setup script set it), then run claude here.")
    else:
        print(f"Open a new terminal or run: source {profile()}   then run claude here.")


if __name__ == "__main__":
    main()
