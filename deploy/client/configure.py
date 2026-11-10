#!/usr/bin/env python3
"""Sets up WithHuman for Claude Code on this device, replacing any earlier WithHuman setup.

usage: configure.py --server URL [--team NAME] [--key KEY] [--managed | --scope project]
                    [--project DIR] [--no-persist] [--no-register] [--no-checkin]
       configure.py --key-only --key KEY
       configure.py --uninstall [--managed | --scope project]

WithHuman is self-hosted, so --server (or WITHHUMAN_SERVER) has no default: it is the address of
the engine this device reports to, and every hook below is written against it.

By default the hooks go into the user's Claude Code settings (~/.claude/settings.json), so every
project the user opens, including ones made later, runs them:

1. Takes every WithHuman hook out of those settings and out of the projects Claude Code knows
   (~/.claude.json) and the one given with --project: their .claude/settings.json and
   .claude/settings.local.json, and the hook file an earlier per-project setup copied there.
   Other settings and other tools' hooks are kept; each file changed is first copied to
   <file>.bak-<time>. WithHuman's hooks are told apart by their mark: the header
   `x-withhuman-hook` on an HTTP hook, `--withhuman-hook` in a command (and, from setups before
   the mark, an HTTP hook posting to /v1/hooks/<event> with `x-withhuman-client`, or our
   pre-tool-use.py posting to /v1/hooks/PreToolUse).
2. Writes WithHuman's hooks: the events that carry content (SessionStart, UserPromptSubmit,
   PreToolUse, PostToolUse, PostToolUseFailure) through the command hook, installed at
   ~/.config/withhuman/hooks/pre-tool-use.py and run with this Python, which leaves out a session
   the security team excepted; the rest as HTTP hooks. Each sends the client ID and the user's
   WithHuman key (`Authorization: Bearer`). The settings' `env` sets WITHHUMAN_CLIENT_ID, so the
   hooks carry it even when Claude Code starts from an app or IDE without the shell's variables.
3. Gives the device a stable client ID (~/.config/withhuman/client-id, `<team>/<uuid>`, or
   WITHHUMAN_CLIENT_ID when set, as in a container) and, unless --no-persist, sets
   WITHHUMAN_CLIENT_ID for new shells: in the shell profile on macOS and Linux, as a user
   environment variable on Windows.
4. With --key (or WITHHUMAN_KEY), keeps the key the security team issued in
   ~/.config/withhuman/key, readable by the user only, and sets WITHHUMAN_KEY for new shells
   alike. The key is never written into a settings file. Without one, a key kept earlier is used.
5. Schedules the daily check-in (checkin.py: launchd, a systemd user timer or cron, the Task
   Scheduler; --no-checkin skips it) and registers the device with the engine
   (POST /v1/clients/register). The setup still completes when registering fails, and says so;
   --no-register skips it and the first check-in.

--managed puts the hooks into Claude Code's managed settings instead, for every user of the
device: the drop-in managed-settings.d/50-withhuman.json in /Library/Application Support/
ClaudeCode (macOS), /etc/claude-code (Linux) or C:\\Program Files\\ClaudeCode (Windows), run as
root or Administrator. The hooks, the check-in and the device's client ID live in its withhuman/
folder. User settings files are not touched; projects of the user who ran sudo are cleaned as
above, and WithHuman hooks left in that user's own settings are reported. Keys stay per user:
each user runs `configure.py --key-only --key ...`.

--scope project writes the hooks into the project's .claude/settings.json only, as earlier
setups did, with the command hook in .claude/hooks.

The setup-project.sh and setup-project.ps1 wrappers fetch this file, the hook and the check-in,
then run it. Safe to run again: the result is the same, the client ID is kept and the
registration updated.

With --agent codex it sets up Codex CLI in the project instead (steps 3 and 4 as above):

1. Copies the Codex hook (codex/withhuman-hook.py, codex/codex_transcript.py and
   hooks/pre-tool-use.py) to the project's .codex/hooks/.
2. Writes its hooks into the project's .codex/hooks.json, replacing earlier WithHuman entries and
   keeping other hooks: each runs the hook with this Python, as `command` on macOS and Linux and
   `commandWindows` on Windows, with a 15-second timeout for PreToolUse and 5 for the rest. The
   user's ~/.codex is left alone.
3. Runs the installed hook's self-check against the engine, then tells you to trust the hooks
   in Codex (/hooks): Codex skips project hooks until they are trusted.

With --uninstall it takes WithHuman out again: from the user's settings and the given project
(the default), the managed drop-in (--managed) or the project (--scope project, or --agent
codex). Other hooks and settings stay, each file changed is first copied to <file>.bak-<time>.
The client ID and the key are kept. --server is not needed then.
"""

import argparse
import datetime
import plistlib
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
DROP_IN = "50-withhuman.json"
SCHEDULE_LABEL = "com.withhuman.checkin"
SCHEDULE_UNIT = "withhuman-checkin"
SCHEDULE_TASK = "WithHumanCheckin"
CRON_MARK = "# withhuman-checkin"
PROFILE_MARK = "# WithHuman client ID"
KEY_MARK = "# WithHuman key"
HEADERS_MARK = "# WithHuman model request headers"
# A WithHuman key as the engine issues it.
KEY_PATTERN = re.compile(r"whk_[0-9a-f]{16}_[0-9a-f]{64}")
REGISTER_TIMEOUT = 10
CODEX_HOOK = "withhuman-hook.py"
CODEX_FILES = (CODEX_HOOK, "codex_transcript.py", HOOK_NAME)
# Codex events the hook handles. PreToolUse waits for a judgment (intent wait and decision
# budget), so it gets more time; the hook ends itself before these limits.
CODEX_EVENTS = ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop",
                "SubagentStart", "SubagentStop"]
CODEX_TIMEOUTS = {"PreToolUse": 15}
CODEX_TIMEOUT = 5


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


def withhuman_hooks(server, command):
    """Our hooks by event: the events with content through `command`, the rest over HTTP with
    the client ID, the key and our mark."""
    def http(event):
        # Claude Code puts only listed variables into headers; an unset WITHHUMAN_KEY leaves
        # `Bearer `, which the engine takes as no key.
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


def client_id(team, path=None):
    """The device's client ID, made once and kept in ~/.config/withhuman/client-id (or `path`).
    A WITHHUMAN_CLIENT_ID already set, as a container passes the host's in, is kept rather than
    a new one made."""
    path = path or Path.home() / ".config" / "withhuman" / "client-id"
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return path, path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    given = os.environ.get("WITHHUMAN_CLIENT_ID", "").strip()
    value = given if re.fullmatch(r"[^\s]{1,512}", given) else f"{team}/{uuid.uuid4()}"
    path.write_text(value + "\n", encoding="utf-8")
    return path, value


def config_dir():
    return Path.home() / ".config" / "withhuman"


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


def persist_model_headers(key_path, id_path, stamp, report):
    """With the model route on, Claude Code sends the key and the client ID on its model
    requests (ANTHROPIC_CUSTOM_HEADERS), read from their files when a shell starts: the key is
    never written into a settings file. A Claude Code started without the shell's variables
    sends no key, which the engine refuses when keys are required."""
    if os.name == "nt":
        # One header only: a user environment variable holds no line break.
        key = Path(key_path).read_text(encoding="utf-8").strip()
        result = subprocess.run(["setx", "ANTHROPIC_CUSTOM_HEADERS", f"x-withhuman-key: {key}"],
                                capture_output=True)
        if result.returncode == 0:
            report.append("ANTHROPIC_CUSTOM_HEADERS set as a user environment variable")
        return
    path = profile()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    line = (f"export ANTHROPIC_CUSTOM_HEADERS=\"x-withhuman-key: $(cat '{key_path}')\""
            f"$'\\n'\"x-withhuman-client: $(cat '{id_path}')\"")
    kept = [item for item in lines if item.strip() != HEADERS_MARK
            and not item.lstrip().startswith("export ANTHROPIC_CUSTOM_HEADERS=")]
    wanted = list(kept)
    while wanted and not wanted[-1].strip():
        wanted.pop()
    wanted += ["", HEADERS_MARK, line]
    if lines[-2:] != [HEADERS_MARK, line]:
        if path.exists():
            backup(path, stamp)
        path.write_text("\n".join(wanted) + "\n", encoding="utf-8")
        report.append(f"{path}: exports ANTHROPIC_CUSTOM_HEADERS with the WithHuman key (new shells)")


def hook_version(paths):
    """The installed hook files' version: the start of their SHA-256, so the inventory shows
    which devices run an old hook."""
    digest = hashlib.sha256()
    for path in paths:
        digest.update(Path(path).read_bytes())
    return digest.hexdigest()[:12]


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
        "project": str(project) if project else None,
        "scope": scope,
    }
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    request = urllib.request.Request(f"{server}/v1/clients/register",
                                     data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=REGISTER_TIMEOUT) as response:
            response.read()
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


def finish(args, client, key_path, key, agent, project, version, stamp, report, scope=None):
    """Keeps the key for new shells and registers the device; returns the lines to print."""
    if key and not args.no_persist:
        persist(key_path, key, stamp, report, name="WITHHUMAN_KEY", mark=KEY_MARK)
        if args.model_proxy:
            persist_model_headers(key_path, config_dir() / "client-id", stamp, report)
    lines = []
    if key:
        lines.append(f"WithHuman key kept in {key_path}")
    else:
        lines.append("No WithHuman key: hooks report no user. If the security team gave you one, "
                     "run again with --key.")
    if args.no_register:
        return lines
    problem = register(args.server, client, args.team, key, agent, project, version, scope)
    if problem:
        lines.append(f"WARNING: the device was not registered: {problem}. The hooks are "
                     "installed; run this setup again to register.")
    else:
        lines.append(f"Device registered with {args.server}")
    return lines


def write_text(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def install(source, target, mode=0o755):
    target.parent.mkdir(parents=True, exist_ok=True)
    if Path(source).resolve() != target.resolve():
        shutil.copyfile(source, target)
    target.chmod(mode)


def claude_projects(home):
    """The project folders Claude Code knows (~/.claude.json), as they are written there."""
    try:
        listed = json.loads((home / ".claude.json").read_text(encoding="utf-8")).get("projects")
    except (OSError, ValueError, AttributeError):
        return []
    return [path for path in listed if isinstance(path, str)] if isinstance(listed, dict) else []


def our_hook_file(path):
    try:
        return path.is_file() and "WithHuman" in path.read_text(encoding="utf-8")[:400]
    except (OSError, UnicodeDecodeError):
        return False


def clean_projects(folders, stamp, report):
    """Takes earlier per-project setups out of `folders`: our hooks in their settings, and the
    hook file copied into .claude/hooks. Everything else stays."""
    seen = set()
    for folder in folders:
        claude = Path(folder) / ".claude"
        if claude in seen or not claude.is_dir():
            continue
        seen.add(claude)
        for name in ("settings.json", "settings.local.json"):
            clean(claude / name, stamp, report)
        hook = claude / "hooks" / HOOK_NAME
        if our_hook_file(hook):
            hook.unlink()
            report.append(f"{hook}: removed (the hook now runs from the device-wide setup)")
            if not any(hook.parent.iterdir()):
                hook.parent.rmdir()


def set_env(settings, name, value):
    env = settings.get("env") if isinstance(settings.get("env"), dict) else {}
    env[name] = value
    settings["env"] = env


def drop_env(settings, name):
    env = settings.get("env")
    if isinstance(env, dict) and name in env:
        del env[name]
        if not env:
            del settings["env"]


def write_config(folder, server, scope, version, client=None):
    """What the check-in reads: the engine, the install scope and the hook version."""
    write_text(folder / "server", server + "\n")
    write_text(folder / "scope", scope + "\n")
    write_text(folder / "hook-version", version + "\n")
    if client:
        write_text(folder / "client-id", client + "\n")


def managed_dir():
    """Claude Code's managed settings folder (WITHHUMAN_MANAGED_DIR stands in for it in tests)."""
    if os.environ.get("WITHHUMAN_MANAGED_DIR"):
        return Path(os.environ["WITHHUMAN_MANAGED_DIR"])
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    if os.name == "nt":
        return Path(r"C:\Program Files\ClaudeCode")
    return Path("/etc/claude-code")


def invoking_home():
    """The home of the user who ran sudo, else this user's."""
    user = os.environ.get("SUDO_USER")
    if user and os.name != "nt":
        try:
            import pwd
            return Path(pwd.getpwnam(user).pw_dir)
        except (ImportError, KeyError):
            pass
    return Path.home()


def schedule(script, config, system, report, remove=False):
    """Runs the check-in once a day, or stops it. WITHHUMAN_SCHEDULER=dry writes the schedule's
    files without running launchctl, systemctl, crontab or schtasks; `none` skips it."""
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
            report.append("Windows: the daily check-in runs per user; each user runs "
                          "configure.py --key-only to schedule theirs")
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


def setup_user(args, here, stamp, report):
    """The hooks in the user's settings, for every project."""
    home = Path.home()
    config = config_dir()
    hook = config / "hooks" / HOOK_NAME
    checkin = config / CHECKIN_NAME
    install(args.hook, hook)
    install(here / CHECKIN_NAME, checkin)
    id_path, value = client_id(args.team)

    settings_path = home / ".claude" / "settings.json"
    settings = load(settings_path)
    removed = remove_withhuman(settings)
    if settings_path.exists():
        report.append(f"{settings_path}: copy at {backup(settings_path, stamp)}"
                      + (f", {removed} earlier WithHuman hook(s) replaced" if removed else ""))
    hooks = settings.setdefault("hooks", {})
    for event, group in withhuman_hooks(args.server, hook_command(hook, args.server)).items():
        hooks.setdefault(event, []).append(group)
    set_env(settings, "WITHHUMAN_CLIENT_ID", value)
    if args.model_proxy:
        set_env(settings, "ANTHROPIC_BASE_URL", args.server)
    save(settings_path, settings)

    clean_projects([*claude_projects(home), args.project], stamp, report)
    version = hook_version([hook, checkin])
    write_config(config, args.server, "user", version)
    if not args.no_checkin:
        schedule(checkin, config, False, report)
    return settings_path, hook, id_path, value, version, checkin, config


def setup_managed(args, here, stamp, report):
    """The hooks in Claude Code's managed settings, for every user of the device."""
    folder = managed_dir()
    own = folder / "withhuman"
    try:
        own.mkdir(parents=True, exist_ok=True)
        (own / ".write-test").write_text("", encoding="utf-8")
        (own / ".write-test").unlink()
    except OSError:
        sys.exit(f"{folder} is not writable: run the managed setup as root (sudo) or "
                 "Administrator")
    hook = own / "hooks" / HOOK_NAME
    checkin = own / CHECKIN_NAME
    install(args.hook, hook)
    install(here / CHECKIN_NAME, checkin)
    # One ID for the device: kept, else the one the user who ran sudo already has.
    user_home = invoking_home()
    earlier = user_home / ".config" / "withhuman" / "client-id"
    path = own / "client-id"
    if not (path.exists() and path.read_text(encoding="utf-8").strip()) and earlier.is_file():
        write_text(path, earlier.read_text(encoding="utf-8").strip() + "\n")
    id_path, value = client_id(args.team, path)
    path.chmod(0o644)

    drop_in = folder / "managed-settings.d" / DROP_IN
    settings = {"hooks": {event: [group] for event, group in
                          withhuman_hooks(args.server, hook_command(hook, args.server)).items()},
                "env": {"WITHHUMAN_CLIENT_ID": value}}
    if args.model_proxy:
        # Every model request goes through the engine's gateway; a managed key cannot be
        # overridden. Bedrock, Vertex and Foundry requests do not go this way.
        settings["env"]["ANTHROPIC_BASE_URL"] = args.server
    if drop_in.exists():
        report.append(f"{drop_in}: replaced, copy at {backup(drop_in, stamp)}")
    save(drop_in, settings)
    drop_in.chmod(0o644)

    # Projects set up one by one before would run the hooks a second time.
    clean_projects([*claude_projects(user_home), args.project], stamp, report)
    left = remove_withhuman(load(user_home / ".claude" / "settings.json"))
    if left:
        report.append(f"WARNING: {user_home / '.claude' / 'settings.json'} still holds {left} "
                      "WithHuman hook(s) of a per-user setup, which would run beside these: as "
                      "that user, run configure.py --uninstall")
    version = hook_version([hook, checkin])
    write_config(own, args.server, "managed", version)
    if not args.no_checkin:
        schedule(checkin, own, True, report)
    return drop_in, hook, id_path, value, version, checkin, own


def setup_project(args, here, stamp, report):
    """The hooks in the project's own settings, as earlier setups did."""
    project = Path(args.project).resolve()
    claude = project / ".claude"
    clean(Path.home() / ".claude" / "settings.json", stamp, report)
    clean(claude / "settings.local.json", stamp, report)
    hook = claude / "hooks" / HOOK_NAME
    install(args.hook, hook)
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
    return settings_path, hook, id_path, value, hook_version([hook]), None, None


def uninstall_claude(args, stamp, report):
    """Takes WithHuman's Claude Code setup out of the chosen scope."""
    project = Path(args.project).resolve()
    if args.managed:
        folder = managed_dir()
        drop_in = folder / "managed-settings.d" / DROP_IN
        if drop_in.exists():
            drop_in.unlink()
            report.append(f"{drop_in}: removed")
        own = folder / "withhuman"
        schedule(own / CHECKIN_NAME, own, True, report, remove=True)
        for path in (own / "hooks" / HOOK_NAME, own / CHECKIN_NAME):
            if path.is_file():
                path.unlink()
                report.append(f"{path}: removed")
        return
    if args.scope == "project":
        uninstall("claude", project, stamp, report)
        return
    settings_path = Path.home() / ".claude" / "settings.json"
    if settings_path.exists():
        settings = load(settings_path)
        removed = remove_withhuman(settings)
        env = settings.get("env") if isinstance(settings.get("env"), dict) else {}
        ours = env.get("WITHHUMAN_CLIENT_ID") is not None
        if removed or ours:
            report.append(f"{settings_path}: {removed} WithHuman hook(s) removed, copy at "
                          f"{backup(settings_path, stamp)}")
            drop_env(settings, "WITHHUMAN_CLIENT_ID")
            if env.get("ANTHROPIC_BASE_URL") and args.server and env["ANTHROPIC_BASE_URL"] == args.server:
                drop_env(settings, "ANTHROPIC_BASE_URL")
            save(settings_path, settings)
    config = config_dir()
    schedule(config / CHECKIN_NAME, config, False, report, remove=True)
    for path in (config / "hooks" / HOOK_NAME, config / CHECKIN_NAME):
        if path.is_file():
            path.unlink()
            report.append(f"{path}: removed")
    uninstall("claude", project, stamp, report)


def is_codex_withhuman(hook):
    return isinstance(hook, dict) and CODEX_HOOK in str(hook.get("command", "")) + str(
        hook.get("commandWindows", ""))


def codex_hooks(python, hook, server):
    """Our Codex hooks by event. PowerShell runs `commandWindows`; `exit $LASTEXITCODE` passes
    the hook's exit code on, so its exit 2 still blocks."""
    def entry(event):
        posix = f'"{python}" "{hook}" {server} {event}'
        return {
            "type": "command",
            "command": posix,
            "commandWindows": f'& "{python}" "{hook}" {server} {event}; exit $LASTEXITCODE',
            "timeout": CODEX_TIMEOUTS.get(event, CODEX_TIMEOUT),
        }

    return {event: {"hooks": [entry(event)]} for event in CODEX_EVENTS}


def setup_codex(args, project, stamp, report):
    codex = project / ".codex"
    installed = codex / "hooks"
    installed.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent
    for name in CODEX_FILES:
        source = here / ("hooks" if name == HOOK_NAME else "codex") / name
        if not source.is_file():
            sys.exit(f"hook file not found: {source}")
        if source.resolve() != (installed / name).resolve():
            shutil.copyfile(source, installed / name)
    (installed / CODEX_HOOK).chmod(0o755)
    # Session state the hook keeps; inside .codex/hooks, where the engine blocks an agent's
    # changes as it does to the hooks themselves.
    state = installed / "withhuman-state"
    state.mkdir(exist_ok=True)
    (state / ".gitignore").write_text("*\n", encoding="utf-8")

    path = codex / "hooks.json"
    config = load(path)
    removed = strip_codex(config)
    hooks = config["hooks"]
    if path.exists():
        report.append(f"{path}: copy at {backup(path, stamp)}"
                      + (f", {removed} earlier WithHuman hook(s) replaced" if removed else ""))
    python = Path(sys.executable).as_posix()
    hook = (installed / CODEX_HOOK).as_posix()
    for event, group in codex_hooks(python, hook, args.server).items():
        hooks.setdefault(event, []).append(group)
    config["hooks"] = hooks
    save(path, config)
    return path, installed / CODEX_HOOK


def strip_codex(config):
    """Takes WithHuman's entries out of a Codex hooks.json in place; the number taken out."""
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
            kept = [hook for hook in inner if not is_codex_withhuman(hook)]
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


def uninstall(agent, project, stamp, report):
    """Takes WithHuman out of the project: its hook entries (other hooks and settings stay, the
    file changed is first copied to <file>.bak-<time>) and the hook files it installed. The
    device's client ID and the user's own settings are left alone."""
    if agent == "codex":
        path = project / ".codex" / "hooks.json"
        if path.exists():
            config = load(path)
            removed = strip_codex(config)
            if removed:
                report.append(f"{path}: {removed} WithHuman hook(s) removed, copy at {backup(path, stamp)}")
                save(path, config)
        installed = project / ".codex" / "hooks"
        files = [installed / name for name in CODEX_FILES]
    else:
        for path in (project / ".claude" / "settings.json", project / ".claude" / "settings.local.json"):
            clean(path, stamp, report)
        installed = project / ".claude" / "hooks"
        files = [installed / HOOK_NAME]
    for path in files:
        if path.is_file():
            path.unlink()
            report.append(f"{path}: removed")
    state = installed / "withhuman-state"
    if agent == "codex" and state.is_dir():
        shutil.rmtree(state)
        report.append(f"{state}: removed")
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


def check_codex(hook, server):
    """Runs the installed hook the way Codex will, so a broken interpreter path or quoting
    shows now rather than as hooks Codex silently fails to run."""
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
    parser.add_argument("--agent", choices=["claude", "codex"], default="claude",
                        help="the coding agent to set up (default: claude)")
    parser.add_argument("--skip-check", action="store_true",
                        help="codex: do not run the installed hook against the engine")
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
                        help="take WithHuman out again (other hooks and files stay)")
    parser.add_argument("--managed", action="store_true",
                        help="claude: put the hooks into Claude Code's managed settings, for "
                             "every user of the device (run as root or Administrator)")
    parser.add_argument("--scope", choices=["user", "project"], default="user",
                        help="claude: the user's settings, every project (default), or only "
                             "this project's")
    parser.add_argument("--key-only", action="store_true",
                        help="only keep the key and export it, as each user does after a "
                             "managed setup")
    parser.add_argument("--no-checkin", action="store_true",
                        help="do not schedule the daily check-in")
    parser.add_argument("--model-proxy", action="store_true",
                        default=os.environ.get("WITHHUMAN_MODEL_PROXY", "").lower() in ("on", "true", "1"),
                        help="send Claude Code's model requests through the engine's gateway "
                             "(ANTHROPIC_BASE_URL), with the key in ANTHROPIC_CUSTOM_HEADERS")
    args = parser.parse_args()
    if sys.version_info < (3, 8):
        sys.exit("WithHuman's hook needs Python 3.8 or later")
    if args.managed and (args.agent != "claude" or args.scope == "project"):
        sys.exit("--managed sets up Claude Code for the whole device; leave out --agent codex "
                 "and --scope project")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.key_only:
        if not args.key:
            sys.exit("--key-only needs --key (or WITHHUMAN_KEY)")
        report = []
        key_path, key = keep_key(args.key)
        if not args.no_persist:
            persist(key_path, key, stamp, report, name="WITHHUMAN_KEY", mark=KEY_MARK)
            if args.model_proxy:
                managed_id = managed_dir() / "withhuman" / "client-id"
                persist_model_headers(key_path, managed_id if managed_id.is_file()
                                      else config_dir() / "client-id", stamp, report)
        for line in report + [f"WithHuman key kept in {key_path}"]:
            print(line)
        return
    if args.uninstall:
        report = []
        if args.agent == "claude":
            uninstall_claude(args, stamp, report)
        else:
            uninstall(args.agent, Path(args.project).resolve(), stamp, report)
        for line in report or ["Nothing of WithHuman was found."]:
            print(line)
        if args.agent == "codex" and report:
            print("WithHuman is removed from this project. Codex may list the hooks as changed in")
            print("/hooks; nothing of WithHuman runs any more.")
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
    if args.agent == "codex":
        project = Path(args.project).resolve()
        report = []
        key_path, key = keep_key(args.key)
        path, hook = setup_codex(args, project, stamp, report)
        id_path, value = client_id(args.team)
        if not args.no_persist:
            persist(id_path, value, stamp, report)
        version = hook_version(hook.parent / name for name in CODEX_FILES)
        notes = finish(args, value, key_path, key, "codex", project, version, stamp, report)
        for line in report:
            print(line)
        print(f"WithHuman Codex hooks written to {path}")
        print(f"Hook: {hook} (run with {sys.executable})")
        print(f"WITHHUMAN_CLIENT_ID={value}")
        for line in notes:
            print(line)
        if not args.skip_check:
            ok, output = check_codex(hook, args.server)
            print(output)
            if not ok:
                sys.exit("The installed hook did not run; fix the problem above, then run again.")
        print("Next: run codex in this project, open /hooks and trust the WithHuman hooks.")
        print("Codex skips project hooks until they are trusted, and again after hooks.json")
        print("changes (as after an update that changed it): until you trust them, this")
        print("project is not protected.")
        return
    if not Path(args.hook).is_file():
        sys.exit(f"hook not found: {args.hook}")
    here = Path(__file__).resolve().parent
    if args.scope == "user" and not (here / CHECKIN_NAME).is_file():
        sys.exit(f"check-in not found: {here / CHECKIN_NAME}")
    if args.managed and args.key:
        sys.exit("Keys are per user: run the managed setup without --key, then each user runs "
                 "configure.py --key-only --key <their key>")
    key_path, key = (None, None) if args.managed else keep_key(args.key)
    report = []
    setup = setup_managed if args.managed else (
        setup_project if args.scope == "project" else setup_user)
    where, hook, id_path, value, version, checkin, config = setup(args, here, stamp, report)
    if not args.no_persist and not args.managed:
        persist(id_path, value, stamp, report)
    scope = "managed" if args.managed else args.scope
    project = Path(args.project).resolve() if scope == "project" else None
    notes = []
    if args.managed:
        if not args.no_register:
            problem = register(args.server, value, args.team, None, "claude", None, version,
                               scope)
            notes.append(f"WARNING: the device was not registered: {problem}." if problem
                         else f"Device registered with {args.server}")
        notes.append("Each user keeps their key with: configure.py --key-only --key <their key>")
    else:
        notes = finish(args, value, key_path, key, "claude", project, version, stamp, report,
                       scope)
    if checkin and not args.no_register and not args.no_checkin and not args.managed:
        first_checkin(checkin, config, notes)

    for line in report:
        print(line)
    print(f"WithHuman hooks written to {where}")
    print(f"Command hook: {hook} (run with {sys.executable})")
    print(f"WITHHUMAN_CLIENT_ID={value}")
    for line in notes:
        print(line)
    if scope == "user":
        print("Every Claude Code session of this user runs the hooks from now on, in any folder.")
    elif scope == "managed":
        print("Every Claude Code session on this device runs the hooks from now on.")
    elif os.name == "nt":
        print("Open a new terminal (or keep this one if the setup script set it), then run claude here.")
    else:
        print(f"Open a new terminal or run: source {profile()}   then run claude here.")

if __name__ == "__main__":
    main()
