#!/usr/bin/env python3
"""Sets up WithHuman for Claude Code in a project folder, replacing any earlier WithHuman setup.

usage: configure.py --server URL [--project DIR] [--team NAME] [--key KEY] [--hook FILE]
                    [--no-persist] [--no-register] [--no-checkin]
                    [--scope project|user|managed] [--managed-hooks-only]

WithHuman is self-hosted, so --server (or WITHHUMAN_SERVER) has no default: it is the address of
the engine this device reports to, and every hook below is written against it.

1. Takes every WithHuman hook out of the user's Claude Code settings (~/.claude/settings.json)
   and the project's own (.claude/settings.json, .claude/settings.local.json), so an earlier
   setup, an all-HTTP PreToolUse hook especially, does not run beside this one. Other settings
   and other hooks are kept, and each file changed is first copied to <file>.bak-<time>.
2. Writes WithHuman's eleven hooks into the project's .claude/settings.json. The events that
   carry content (SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, PostToolUseFailure) go
   through the command hook, installed at .claude/hooks/pre-tool-use.py and run with this Python,
   which leaves out a session the security team excepted; the rest are HTTP hooks. Each sends
   the client ID and the user's WithHuman key (`Authorization: Bearer`). Our hooks carry a mark
   (`x-withhuman-hook` on an HTTP hook, `--withhuman-hook` in a command), and only they, or the
   exact shapes of setups before the mark, are taken out again; other tools' hooks stay.
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

Both also schedule a daily check-in (checkin.py, beside the hook: launchd, a systemd timer or
cron, the Task Scheduler; --no-checkin skips it). It reports the projects Claude Code ran in and
their last use, read with stat only (POST /v1/clients/checkin), so the inventory shows the
projects the hooks never reached. A managed setup on Windows schedules none (it would be per
user).
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
import ipaddress
import json
import os
import platform
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses redirects: urllib would send the WithHuman key on to wherever one points."""

    def redirect_request(self, *args, **kwargs):  # noqa: ARG002
        return None


# Every request that carries the key goes through this: a redirect is an error, not a new host.
OPENER = urllib.request.build_opener(_NoRedirect)

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
CHECKIN_NAME = "checkin.py"
# Events whose hook carries content: they go through the command hook, which keeps a session the
# security team excepted. The rest are HTTP hooks.
COMMAND_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
                  "PostToolUseFailure")
# The mark of WithHuman's hooks.
MARK_HEADER = "x-withhuman-hook"
MARK_ARG = "--withhuman-hook"
# Events earlier setups installed, to recognise their hooks.
LEGACY_EVENTS = re.compile(
    r"/v1/hooks/(SessionStart|SessionEnd|UserPromptSubmit|PreToolUse|PostToolUse|"
    r"PostToolUseFailure|SubagentStart|SubagentStop|ConfigChange|MessageDisplay|PostToolBatch|"
    r"InstructionsLoaded|FileChanged)$")
SCHEDULE_LABEL = "com.withhuman.checkin"
SCHEDULE_UNIT = "withhuman-checkin"
SCHEDULE_TASK = "WithHumanCheckin"
CRON_MARK = "# withhuman-checkin"
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
#: OpenClaw's plugin id, which is also the key its configuration records it under.
OPENCLAW_PLUGIN = "withhuman"
OPENCLAW_TIMEOUT = 120


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
    #: What that elsewhere is called, for the message a `--scope` it has no use for gets.
    scope_note = "project"

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


class FlatHooksFile(AgentSetup):
    """An agent whose hooks file holds its entries directly under the event name, with a
    `version` it reads the file by — Cursor's shape, and Copilot's. Claude Code's and Codex's
    wrap them in a group instead, which is what `AgentSetup` writes.
    """

    def groups(self, python, hook, server):
        return {event: self.entry(python, hook, server, event) for event in self.events}

    def is_ours(self, hook):
        if not isinstance(hook, dict):
            return False
        return self.hook in "".join(
            str(hook.get(key, "")) for key in ("command", "commandWindows", "bash", "powershell"))

    def insert(self, config, groups):
        # The file is read by its version; without one the hooks are ignored.
        config["version"] = 1
        hooks = config.get("hooks") if isinstance(config.get("hooks"), dict) else {}
        for event, entry in groups.items():
            hooks.setdefault(event, []).append(entry)
        config["hooks"] = hooks

    def strip(self, config):
        """Takes our entries out in place; the number taken out."""
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


class AntigravitySetup(AgentSetup):
    kind = "antigravity"
    name = "Antigravity"
    #: Antigravity reads a project's hooks from its customization root, which also holds the
    #: agents, skills and rules that steer it.
    directory = ".agents"
    config = "hooks.json"
    hook = "withhuman-hook.py"
    files = ("withhuman-hook.py", "antigravity_transcript.py") + SHARED_FILES
    # Antigravity's six events. `PostInvocation` is deliberately not here: the turn's calls are
    # judged on their own events and its answer is read from the transcript, so there is
    # nothing to do on it and every event registered is one more process per turn.
    events = ("SessionStart", "PreInvocation", "PreToolUse", "PostToolUse", "Stop")
    #: Antigravity's events that take a `matcher` group rather than handlers directly.
    grouped = ("PreToolUse", "PostToolUse")
    # Seconds, not Claude Code's milliseconds. Antigravity kills a hook that runs past this and
    # blocks the call, so the limit is generous and the bridge ends itself well inside it.
    timeouts = {"PreToolUse": 25}
    timeout = 10
    #: The one top-level hook of ours; everything under it is this agent's.
    name_key = "withhuman"
    notes = ("Next: trust this folder, or Antigravity runs none of these hooks and the project",
             "is not protected. It says so when a session starts, and `--skip-trust` or",
             "GEMINI_CLI_TRUST_WORKSPACE=true trusts it in an automated run.",
             "The hooks live in .agents, which is part of the repository: add it to",
             ".gitignore if these are only for your device.")
    uninstall_notes = ("WithHuman is removed from this project. Nothing of it runs any more.",)
    #: Written beside the hook, so the command carries the event alone.
    server_file = "server"

    def entry(self, python, hook, server, event):
        """One handler of ours, as Antigravity's hooks.json holds it. `timeout` is in seconds,
        and there is no separate Windows command: Antigravity runs the command through the
        platform's own shell."""
        return {
            "type": "command",
            "command": f'"{python}" "{hook}" {event}',
            "timeout": self.timeouts.get(event, self.timeout),
        }

    def groups(self, python, hook, server):
        """Our events under one named hook. `PreToolUse` and `PostToolUse` take a `matcher`
        group — an empty matcher is every tool — and the rest take handlers directly."""
        found = {}
        for event in self.events:
            handler = self.entry(python, hook, server, event)
            found[event] = (
                [{"matcher": "", "hooks": [handler]}] if event in self.grouped else [handler]
            )
        return found

    def installed(self, args, installed):
        """The engine's address, where the bridge looks for it."""
        (installed / self.server_file).write_text(args.server + "\n", encoding="utf-8")

    def is_ours(self, hook):
        return isinstance(hook, dict) and self.hook in str(hook.get("command", ""))

    def _holds_ours(self, events):
        """Whether a named hook's events hold a handler of ours."""
        if not isinstance(events, dict):
            return False
        for entries in events.values():
            for entry in entries if isinstance(entries, list) else []:
                if self.is_ours(entry):
                    return True
                inner = entry.get("hooks") if isinstance(entry, dict) else None
                if any(self.is_ours(hook) for hook in inner or []):
                    return True
        return False

    def insert(self, config, groups):
        """Puts our hooks in under our own name, keeping everyone else's. Antigravity's file is
        named hooks at the top level, so ours need not be woven into theirs."""
        config[self.name_key] = groups

    def strip(self, config):
        """Takes our named hook out in place; the number taken out. A hook of ours left under
        another name by an earlier version goes too."""
        removed = 0
        for name in list(config):
            if name == self.name_key or self._holds_ours(config.get(name)):
                del config[name]
                removed += 1
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


class CursorSetup(FlatHooksFile):
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


class CopilotSetup(FlatHooksFile):
    kind = "copilot"
    name = "Copilot"
    #: Copilot reads a repository's hooks from `.github/hooks/*.json`, once the folder is
    #: trusted. The bridge's own files sit in the same folder, where Copilot ignores them:
    #: it reads the JSON files alone.
    directory = ".github"
    config = "hooks/withhuman-copilot.json"
    hook = "withhuman-hook.py"
    files = ("withhuman-hook.py", "copilot_transcript.py") + SHARED_FILES
    # Claude Code's names, which Copilot answers with Claude Code's own fields and tool names,
    # and `preMcpToolCall`, which has no Claude Code name. The events that only tell the user
    # something (`Notification`, `PermissionRequest`, `ErrorOccurred`, `PreCompact`,
    # `userPromptTransformed`) are deliberately not here: the engine judges nothing on them,
    # and every event registered is one more process per turn.
    events = ("SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse",
              "PostToolUseFailure", "SubagentStart", "SubagentStop", "Stop", "preMcpToolCall")
    # A judged call waits for the engine; the bridge ends itself before this. It has to:
    # Copilot runs a call whose hook timed out.
    timeouts = {"PreToolUse": 15}
    # Copilot's own `config.json` is the file that trusts a folder, and it says it is managed
    # automatically — and holds comments, which writing JSON back to it would drop. So the
    # setup does not touch it; it says what to do instead.
    notes = ("Next: trust this folder, or Copilot runs none of these hooks and the project is",
             "not protected. Copilot says so at the start of a session, and there are two ways:",
             '  - add the project to "trustedFolders" in ~/.copilot/config.json, or',
             "  - answer the trust question Copilot asks in an interactive session.",
             "`--allow-all-tools` does not trust a folder; COPILOT_ALLOW_ALL=true does, but it",
             "approves every tool as well. `/env` in a session lists the hooks it loaded.",
             "The hooks live in .github/hooks, which is part of the repository: add it to",
             ".gitignore if these are only for your device.")
    uninstall_notes = ("WithHuman is removed from this project. Nothing of it runs any more.",)
    #: Written beside the hook, so the command carries the event alone.
    server_file = "server"

    def entry(self, python, hook, server, event):
        """One hook of ours, as Copilot's hooks file holds it: `bash` on macOS and Linux,
        `powershell` on Windows, and `timeoutSec` rather than Claude Code's `timeout`.

        There is no `failClosed` to set, and none is needed on a failure: Copilot denies a call
        whose hook fails. A hook that **times out** is another matter — Copilot runs the call —
        so the bridge answers on a deadline of its own, inside the one written here.
        """
        return {
            "type": "command",
            "bash": f'"{python}" "{hook}" {event}',
            "powershell": f'& "{python}" "{hook}" {event}; exit $LASTEXITCODE',
            "timeoutSec": self.timeouts.get(event, self.timeout),
        }

    def installed(self, args, installed):
        """The engine's address, where the bridge looks for it."""
        (installed / self.server_file).write_text(args.server + "\n", encoding="utf-8")


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
    scope_note = "profile (HERMES_HOME)"
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


def openclaw_home():
    """The OpenClaw state directory being set up, as OpenClaw finds it: OPENCLAW_STATE_DIR, else
    `~/.openclaw`. A named profile and `--dev` move it, and the variable follows them."""
    configured = os.environ.get("OPENCLAW_STATE_DIR", "").strip()
    if configured:
        return Path(os.path.expandvars(configured)).expanduser().resolve()
    return Path.home() / ".openclaw"


class OpenClawSetup(AgentSetup):
    """OpenClaw runs every session of a state directory in one Gateway, which loads plugins
    recorded in that directory's configuration and never from a project folder: WithHuman is a
    plugin of the device, for every folder its sessions run in.

    Unlike Hermes', the plugin is not copied into place here. `openclaw` keeps a registry of
    what is installed and refuses a configuration change while a Gateway holds it, and the
    configuration is where the plugin is both recorded and allowed to read a turn. So the files
    are staged and OpenClaw's own CLI installs them from there.
    """

    kind = "openclaw"
    name = "OpenClaw"
    hook = "withhuman-hook.py"
    #: The plugin's id, the folder OpenClaw installs it into, and the key its configuration
    #: records it under.
    plugin = OPENCLAW_PLUGIN
    files = ("index.js", "withhuman-hook.py", "openclaw.plugin.json",
             "package.json") + SHARED_FILES
    #: Written beside the hook; the plugin passes the event alone, as Cursor's does.
    server_file = "server"
    per_project = False
    scope_note = "state directory (OPENCLAW_STATE_DIR)"
    notes = (
        "Next: start OpenClaw again (`openclaw chat`, or restart its Gateway service). A plugin",
        "is loaded when the Gateway starts, so until then this device is not protected. The",
        "setup is the device's, not one project's: every session of this OpenClaw is judged,",
        "whichever folder it runs in; another state directory (OPENCLAW_STATE_DIR) is set up on",
        "its own.")
    uninstall_notes = (
        "WithHuman is removed from this OpenClaw. Start it again for the plugin to be gone from",
        "a Gateway that is still running.")

    def folder(self):
        """Where the files are staged. Not `extensions/<id>`, which is where OpenClaw installs a
        plugin to: installing a folder from there would be installing it over itself."""
        return openclaw_home() / "withhuman-setup"

    def openclaw(self, *words):
        """Runs the OpenClaw CLI on this state directory; whether it ran and what it said."""
        command = shutil.which("openclaw")
        if not command:
            return False, "the openclaw command is not on PATH"
        try:
            result = subprocess.run([command, *words], capture_output=True, text=True,
                                    encoding="utf-8", errors="replace",
                                    timeout=OPENCLAW_TIMEOUT,
                                    env={**os.environ,
                                         "OPENCLAW_STATE_DIR": str(openclaw_home())})
        except subprocess.TimeoutExpired:
            return False, (f"`openclaw {' '.join(words)}` did not finish in "
                           f"{OPENCLAW_TIMEOUT} seconds")
        except OSError as error:
            return False, f"the openclaw command could not run: {error}"
        return result.returncode == 0, (result.stdout + result.stderr).strip()

    def install(self, args, project, stamp, report):
        installed = self.folder()
        if installed.exists() and installed.is_dir():
            report.append(f"{installed}: earlier WithHuman staging replaced")
        installed.mkdir(parents=True, exist_ok=True)
        for name in self.files:
            source = self.source(name)
            if not source.is_file():
                sys.exit(f"hook file not found: {source}")
            shutil.copyfile(source, installed / name)
        (installed / self.hook).chmod(0o755)
        (installed / self.server_file).write_text(args.server + "\n", encoding="utf-8")
        # The bridge keeps its state in OpenClaw's state directory rather than beside itself:
        # OpenClaw builds a package of a plugin when it installs one, and what the Gateway loads
        # may be a copy, which state beside the file would follow and be lost with.
        state = openclaw_home() / "withhuman-state"
        state.mkdir(parents=True, exist_ok=True)
        (state / ".gitignore").write_text("*\n", encoding="utf-8")

        for words, needed in (
            (("plugins", "install", str(installed), "--force", "--accept-capabilities",
              "--acknowledge-install-policy-warning"), True),
            (("plugins", "enable", self.plugin), True),
            # Without this OpenClaw refuses the plugin the hooks that carry a turn: the calls are
            # still judged, but the prompt, its intent and the answer never arrive.
            (("config", "set",
              f"plugins.entries.{self.plugin}.hooks.allowConversationAccess", "true"), True),
            (("config", "set", f"plugins.entries.{self.plugin}.config.server",
              json.dumps(args.server)), False),
        ):
            ok, output = self.openclaw(*words)
            last = output.splitlines()[-1] if output else "no output"
            if ok:
                report.append(f"openclaw {' '.join(words[:3])}: done")
                continue
            if not needed:
                report.append(f"openclaw {' '.join(words[:3])}: skipped ({last}); the engine's "
                              f"address is kept beside the hook as well")
                continue
            hint = ""
            if "Gateway listener" in output or "state owner" in output:
                hint = (" Stop OpenClaw first: its Gateway owns the configuration and refuses a "
                        "change to it while it runs.")
            sys.exit(f"`openclaw {' '.join(words)}` failed: {last}{hint}")
        return installed, installed / self.hook

    def remove(self, project, stamp, report):
        """Takes the plugin out again. Nothing is asked of OpenClaw when this setup left nothing
        behind: `--reset` runs this for every state directory it knows, and an OpenClaw that
        WithHuman was never installed into is not one to go changing."""
        installed = self.folder()
        if not (installed / "openclaw.plugin.json").is_file():
            return
        ok, output = self.openclaw("plugins", "uninstall", self.plugin, "--force")
        if not ok:
            report.append(f"openclaw plugins uninstall {self.plugin}: skipped "
                          f"({output.splitlines()[-1] if output else 'no output'}); run it "
                          f"yourself for this state directory")
        shutil.rmtree(installed)
        report.append(f"{installed}: removed")
        state = openclaw_home() / "withhuman-state"
        if state.is_dir():
            shutil.rmtree(state)
            report.append(f"{state}: removed")


#: Every agent but Claude Code, by `--agent` value.
AGENTS = {agent.kind: agent for agent in (
    AntigravitySetup(), CodexSetup(), CopilotSetup(), CursorSetup(), HermesSetup(),
    OpenClawSetup())}


def is_withhuman(hook):
    """A hook a WithHuman setup added: one with our mark, or, from setups before the mark, an
    HTTP hook posting an event to /v1/hooks/ with our client header, or our PreToolUse command.
    Another tool's hook on a similar address or with a similar file name is not ours."""
    if not isinstance(hook, dict):
        return False
    headers = hook.get("headers") if isinstance(hook.get("headers"), dict) else {}
    names = {str(name).lower() for name in headers}
    if MARK_HEADER in names:
        return True
    command = str(hook.get("command", ""))
    if MARK_ARG in command.split() or f"{MARK_ARG} " in command:
        return True
    url = str(hook.get("url", ""))
    if hook.get("type") == "http" and LEGACY_EVENTS.search(url) and "x-withhuman-client" in names:
        return True
    return HOOK_NAME in command and "/v1/hooks/PreToolUse" in command


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
    """Our hooks by event: the events with content through `command`, the rest over HTTP with
    the client ID header, the key and our mark. With `client`, the header carries that ID as
    written instead of WITHHUMAN_CLIENT_ID."""
    def http(event):
        # Claude Code puts only listed variables into headers; an unset WITHHUMAN_KEY leaves
        # `Bearer `, which the engine takes as no key.
        if client:
            return {
                "type": "http",
                "url": f"{server}/v1/hooks/{event}",
                "headers": {"x-withhuman-client": client, "Authorization": "Bearer $WITHHUMAN_KEY",
                            MARK_HEADER: "1"},
                "allowedEnvVars": ["WITHHUMAN_KEY"],
            }
        return {
            "type": "http",
            "url": f"{server}/v1/hooks/{event}",
            "headers": {"x-withhuman-client": "$WITHHUMAN_CLIENT_ID",
                        "Authorization": "Bearer $WITHHUMAN_KEY",
                        MARK_HEADER: "1"},
            "allowedEnvVars": ["WITHHUMAN_CLIENT_ID", "WITHHUMAN_KEY"],
        }

    return {
        event: {"hooks": [{"type": "command", "command": command} if event in COMMAND_EVENTS
                          else http(event)]}
        for event in EVENTS
    }


def encrypted_or_local(server):
    """The engine is reached over https, or over plain http on this machine only."""
    parts = urllib.parse.urlsplit(server)
    if parts.scheme == "https":
        return True
    host = (parts.hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def hook_command(script, server):
    """Quoted absolute paths run alike from bash, zsh, cmd and PowerShell."""
    return f'"{Path(sys.executable).as_posix()}" "{Path(script).as_posix()}" {MARK_ARG} {server}'


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
    """The device's client ID, made once and kept in ~/.config/withhuman/client-id. A
    WITHHUMAN_CLIENT_ID already set, as a container passes the host's in, is kept rather than a
    new one made."""
    path = Path.home() / ".config" / "withhuman" / "client-id"
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return path, path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    given = os.environ.get("WITHHUMAN_CLIENT_ID", "").strip()
    value = given if re.fullmatch(r"[^\s]{1,512}", given) else f"{team}/{uuid.uuid4()}"
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


def register(server, client, team, key, agent, project, version, scope=None):
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
    if scope:
        body["scope"] = scope
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
        with OPENER.open(request, timeout=REGISTER_TIMEOUT) as response:
            response.read()

    try:
        try:
            post(body)
        except urllib.error.HTTPError as error:
            # An engine from before `other_serials` or `scope` refuses a field it does not know:
            # it is registered without them.
            optional = ("other_serials", "scope")
            if not any(name in body for name in optional) or error.code not in (400, 422):
                raise
            post({name: value for name, value in body.items() if name not in optional})
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
    problem = register(args.server, client, args.team, key, agent, project, version,
                       args.scope if agent == "claude" else None)
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


def write_text(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def write_config(folder, server, scope, version):
    """What the check-in reads beside the client ID: the engine, the install scope and the hook
    version."""
    write_text(folder / "server", server + "\n")
    write_text(folder / "scope", scope + "\n")
    write_text(folder / "hook-version", version + "\n")


def checkin_source():
    return Path(__file__).resolve().parent / CHECKIN_NAME


def remove_user_schedule(home, report):
    """Takes out the daily check-in another user's setup scheduled: its files only, as their
    session's launchctl or systemctl cannot be reached from here. It stops at their next login."""
    for unit in (home / "Library" / "LaunchAgents" / f"{SCHEDULE_LABEL}.plist",
                 home / ".config" / "systemd" / "user" / f"{SCHEDULE_UNIT}.service",
                 home / ".config" / "systemd" / "user" / f"{SCHEDULE_UNIT}.timer"):
        if unit.is_file():
            unit.unlink()
            report.append(f"{unit}: removed")


def schedule(script, config, system, report, remove=False):
    """Runs the check-in once a day for this user (or, with `system`, every user), or stops it.
    WITHHUMAN_SCHEDULER=dry writes the schedule's files without running launchctl, systemctl,
    crontab or schtasks; `none` skips it."""
    mode = os.environ.get("WITHHUMAN_SCHEDULER", "auto")
    if mode == "none":
        return
    dry = mode == "dry"

    def run(command):
        if dry:
            return 0
        try:
            return subprocess.run(command, capture_output=True, timeout=30).returncode
        except (OSError, subprocess.SubprocessError):
            return 1

    argv = [Path(sys.executable).as_posix(), Path(script).as_posix(), "--config",
            Path(config).as_posix()]
    override = os.environ.get("WITHHUMAN_SCHEDULER_DIR")
    if sys.platform == "darwin":
        folder = Path(override) if override else (
            Path("/Library/LaunchAgents") if system else Path.home() / "Library" / "LaunchAgents")
        plist = folder / f"{SCHEDULE_LABEL}.plist"
        domain = f"gui/{os.getuid()}" if hasattr(os, "getuid") else None
        if plist.exists() and not system:
            run(["launchctl", "bootout", domain, str(plist)])
        if remove:
            if plist.exists():
                plist.unlink()
                report.append(f"{plist}: removed")
            return
        folder.mkdir(parents=True, exist_ok=True)
        plist.write_bytes(plistlib.dumps({"Label": SCHEDULE_LABEL, "ProgramArguments": argv,
                                          "StartInterval": 86400, "RunAtLoad": True}))
        if not system:
            run(["launchctl", "bootstrap", domain, str(plist)])
        report.append(f"{plist}: daily check-in" + (" for every user, from their next login"
                                                     if system else ""))
        return
    if os.name == "nt":
        if system:
            if not remove:
                report.append("Windows: a managed setup schedules no daily check-in (it runs "
                              "per user)")
            return
        if remove:
            run(["schtasks", "/Delete", "/F", "/TN", SCHEDULE_TASK])
            return
        code = run(["schtasks", "/Create", "/F", "/SC", "DAILY", "/TN", SCHEDULE_TASK,
                    "/TR", subprocess.list2cmdline(argv)])
        report.append(f"Task Scheduler: {SCHEDULE_TASK} daily" if code == 0 else
                      "WARNING: the daily check-in could not be scheduled (schtasks failed)")
        return
    folder = Path(override) if override else (
        Path("/etc/systemd/user") if system else Path.home() / ".config" / "systemd" / "user")
    service, timer = folder / f"{SCHEDULE_UNIT}.service", folder / f"{SCHEDULE_UNIT}.timer"
    systemd = dry or (shutil.which("systemctl") is not None and (
        system or run(["systemctl", "--user", "show-environment"]) == 0))
    scope = ["--global"] if system else ["--user"]
    if remove:
        if systemd and timer.exists():
            run(["systemctl", *scope, "disable", *([] if system else ["--now"]), timer.name])
        for unit in (service, timer):
            if unit.exists():
                unit.unlink()
                report.append(f"{unit}: removed")
        if not system:
            uncron(run, dry, report)
        return
    if systemd:
        command = " ".join(f'"{part}"' for part in argv)
        write_text(service, "[Unit]\nDescription=WithHuman daily check-in\n\n"
                            f"[Service]\nType=oneshot\nExecStart={command}\n")
        write_text(timer, "[Unit]\nDescription=WithHuman daily check-in\n\n"
                          "[Timer]\nOnCalendar=daily\nPersistent=true\nRandomizedDelaySec=1h\n\n"
                          "[Install]\nWantedBy=timers.target\n")
        if system:
            run(["systemctl", "--global", "enable", timer.name])
        else:
            run(["systemctl", "--user", "daemon-reload"])
            run(["systemctl", "--user", "enable", "--now", timer.name])
        report.append(f"{timer}: daily check-in")
        return
    if system:
        report.append("WARNING: no systemd, so the check-in is not scheduled for every user")
        return
    # No systemd user session: a crontab line, replacing an earlier one.
    current = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    lines = [line for line in (current.stdout.splitlines() if current.returncode == 0 else [])
             if CRON_MARK not in line]
    lines.append(f"{17 + (os.getpid() % 40)} 10 * * * {' '.join(argv)} {CRON_MARK}")
    result = subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True,
                            capture_output=True)
    report.append("crontab: daily check-in" if result.returncode == 0 else
                  "WARNING: the daily check-in could not be scheduled (crontab failed)")


def uncron(run, dry, report):
    if dry or shutil.which("crontab") is None:
        return
    current = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if current.returncode != 0 or CRON_MARK not in current.stdout:
        return
    kept = [line for line in current.stdout.splitlines() if CRON_MARK not in line]
    subprocess.run(["crontab", "-"], input="\n".join(kept) + "\n", text=True,
                   capture_output=True)
    report.append("crontab: daily check-in removed")


def first_checkin(script, config, report):
    """Runs the check-in once now, so the engine has the device's projects from the start."""
    try:
        result = subprocess.run([sys.executable, str(script), "--config", str(config)],
                                capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        report.append(f"WARNING: the first check-in did not run ({error})")
        return
    if result.returncode != 0:
        report.append(f"WARNING: the first check-in failed: {result.stderr.strip()}")


def uninstall_user(home, stamp, report):
    """Takes the user setup of the user at `home` out: the WithHuman hooks of their settings and
    the hook in ~/.config/withhuman/hooks. Their client ID is kept."""
    clean(home / ".claude" / "settings.json", stamp, report)
    config = home / ".config" / "withhuman"
    if home == Path.home():
        schedule(config / CHECKIN_NAME, config, False, report, remove=True)
    else:
        remove_user_schedule(home, report)
    for path in (config / "hooks" / HOOK_NAME, config / CHECKIN_NAME):
        if path.is_file():
            path.unlink()
            report.append(f"{path}: removed")


def uninstall_global(scope, stamp, report):
    """Takes a global setup out: the user's settings' WithHuman hooks and the hook in
    ~/.config/withhuman/hooks, or the managed settings file of WithHuman's own and the device's
    hook. The device's client ID is kept, as a project uninstall keeps it."""
    if scope == "user":
        uninstall_user(Path.home(), stamp, report)
        return
    if managed_settings().is_file() or (device_dir() / CHECKIN_NAME).is_file():
        schedule(device_dir() / CHECKIN_NAME, device_dir(), True, report, remove=True)
    for path in (managed_settings(), device_dir() / "hooks" / HOOK_NAME, device_dir() / CHECKIN_NAME):
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
    (`--scope managed`), with the daily check-in. Returns the settings file, the hook, the client
    ID, the hook version and the installed check-in (None when it is not scheduled)."""
    managed = args.scope == "managed"
    if managed:
        id_path, value = device_client_id(args.team)
        folder = device_dir()
    else:
        id_path, value = client_id(args.team)
        folder = config_dir()
    hook = folder / "hooks" / HOOK_NAME
    install_hook(hook_source, hook)
    checkin = None
    if not args.no_checkin:
        if checkin_source().is_file():
            checkin = folder / CHECKIN_NAME
            install_hook(checkin_source(), checkin)
        else:
            report.append(f"WARNING: {checkin_source()} not found, so no daily check-in is "
                          "scheduled; fetch it beside configure.py and run again")
    ours = withhuman_hooks(args.server, hook_command(hook, args.server), client=value)
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
    version = hook_version([hook] + ([checkin] if checkin else []))
    write_config(folder, args.server, args.scope, version)
    if checkin:
        schedule(checkin, folder, managed, report)
    return path, hook, value, version, checkin


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
    parser.add_argument("--allow-insecure-http", action="store_true",
                        help="allow a plain http --server that is not on this machine (the key "
                             "and every event then travel unencrypted)")
    parser.add_argument("--no-checkin", action="store_true",
                        help="with --scope user or managed: do not schedule the daily check-in")
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
            else f"{agent.name} is set up per {agent.scope_note}"))
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
    if not encrypted_or_local(args.server) and not args.allow_insecure_http:
        sys.exit("--server must use https unless the engine runs on this machine (127.0.0.1, "
                 "localhost, ::1): over plain http the WithHuman key, and every prompt and "
                 f"command, cross the network unencrypted: {args.server}\n"
                 "  --allow-insecure-http sets it up anyway.")
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
            path, hook, value, version, checkin = setup_global(args, hook_source, key_path, key,
                                                               stamp, report)
        except PermissionError:
            sys.exit(NEEDS_ADMIN)
        notes = finish(args, value, key_path, key, "claude", f"({args.scope})", version, stamp,
                       report)
        if checkin and not args.no_register and args.scope == "user":
            first_checkin(checkin, checkin.parent, notes)
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
    hooks = settings.setdefault("hooks", {})
    for event, group in withhuman_hooks(args.server, hook_command(hook, args.server)).items():
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
