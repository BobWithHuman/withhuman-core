#!/usr/bin/env python3
"""Sets up WithHuman for Claude Code in a project folder, replacing any earlier WithHuman setup.

usage: configure.py --server URL [--project DIR] [--team NAME] [--hook FILE] [--no-persist]

WithHuman is self-hosted, so --server (or WITHHUMAN_SERVER) has no default: it is the address of
the engine this device reports to, and every hook below is written against it.

1. Takes every WithHuman hook out of the user's Claude Code settings (~/.claude/settings.json)
   and the project's own (.claude/settings.json, .claude/settings.local.json), so an earlier
   setup, an all-HTTP PreToolUse hook especially, does not run beside this one. Other settings
   and other hooks are kept, and each file changed is first copied to <file>.bak-<time>.
2. Writes WithHuman's ten hooks into the project's .claude/settings.json: nine HTTP hooks and a
   PreToolUse command hook, installed at .claude/hooks/pre-tool-use.py and run with this Python.
3. Gives the device a stable client ID (~/.config/withhuman/client-id, `<team>/<uuid>`) and,
   unless --no-persist, sets WITHHUMAN_CLIENT_ID for new shells: in the shell profile on macOS
   and Linux, as a user environment variable on Windows.

The setup-project.sh and setup-project.ps1 wrappers fetch this file and the hook, then run it.
Safe to run again: the result is the same and the client ID is kept.

With --agent codex it sets up Codex CLI instead (step 3 as above):

1. Copies the Codex hook (codex/withhuman-hook.py, codex/codex_transcript.py and
   hooks/pre-tool-use.py) to the project's .codex/hooks/.
2. Writes its hooks into the project's .codex/hooks.json, replacing earlier WithHuman entries and
   keeping other hooks: each runs the hook with this Python, as `command` on macOS and Linux and
   `commandWindows` on Windows, with a 15-second timeout for PreToolUse and 5 for the rest. The
   user's ~/.codex is left alone.
3. Runs the installed hook's self-check against the engine, then tells you to trust the hooks
   in Codex (/hooks): Codex skips project hooks until they are trusted.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
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
]
HOOK_NAME = "pre-tool-use.py"
PROFILE_MARK = "# WithHuman client ID"
CODEX_HOOK = "withhuman-hook.py"
CODEX_FILES = (CODEX_HOOK, "codex_transcript.py", HOOK_NAME)
# Codex events the hook handles. PreToolUse waits for a judgment (intent wait and decision
# budget), so it gets more time; the hook ends itself before these limits.
CODEX_EVENTS = ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop",
                "SubagentStart", "SubagentStop"]
CODEX_TIMEOUTS = {"PreToolUse": 15}
CODEX_TIMEOUT = 5


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


def withhuman_hooks(server, command):
    """Our hooks by event: HTTP with the client ID header, PreToolUse through `command`."""
    def http(event):
        return {
            "type": "http",
            "url": f"{server}/v1/hooks/{event}",
            "headers": {"x-withhuman-client": "$WITHHUMAN_CLIENT_ID"},
            "allowedEnvVars": ["WITHHUMAN_CLIENT_ID"],
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


def profile():
    """The shell profile new terminals read."""
    shell = os.environ.get("SHELL", "")
    if shell.endswith("zsh") or (not shell and sys.platform == "darwin"):
        return Path.home() / ".zshrc"
    return Path.home() / ".bashrc"


def persist(id_path, value, stamp, report):
    """Sets WITHHUMAN_CLIENT_ID for new shells, replacing any line an earlier setup wrote."""
    if os.name == "nt":
        result = subprocess.run(["setx", "WITHHUMAN_CLIENT_ID", value], capture_output=True)
        if result.returncode != 0:
            sys.exit(f"setx failed: {result.stderr.decode(errors='replace').strip()}")
        report.append("WITHHUMAN_CLIENT_ID set as a user environment variable (new windows)")
        return
    path = profile()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    earlier = re.compile(r"^\s*export\s+WITHHUMAN_CLIENT_ID=")
    kept = [line for line in lines if line.strip() != PROFILE_MARK and not earlier.match(line)]
    wanted = kept + [PROFILE_MARK, f"export WITHHUMAN_CLIENT_ID=\"$(cat '{id_path}')\""]
    if wanted != lines:
        if path.exists():
            backup(path, stamp)
        while kept and not kept[-1].strip():
            kept.pop()
        path.write_text("\n".join(kept + ["", PROFILE_MARK, wanted[-1]]) + "\n", encoding="utf-8")
        report.append(f"{path}: exports WITHHUMAN_CLIENT_ID (new shells)")


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


def check_codex(hook, server):
    """Runs the installed hook the way Codex will, so a broken interpreter path or quoting
    shows now rather than as hooks Codex silently fails to run."""
    commands = [[sys.executable, str(hook), "--check", server]]
    if os.name == "nt":
        commands.append(["powershell", "-NoProfile", "-Command",
                         f'& "{Path(sys.executable).as_posix()}" "{Path(hook).as_posix()}" '
                         f"--check {server}; exit $LASTEXITCODE"])
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True)
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
    args = parser.parse_args()
    if sys.version_info < (3, 8):
        sys.exit("WithHuman's hook needs Python 3.8 or later")
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
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        report = []
        path, hook = setup_codex(args, project, stamp, report)
        id_path, value = client_id(args.team)
        if not args.no_persist:
            persist(id_path, value, stamp, report)
        for line in report:
            print(line)
        print(f"WithHuman Codex hooks written to {path}")
        print(f"Hook: {hook} (run with {sys.executable})")
        print(f"WITHHUMAN_CLIENT_ID={value}")
        if not args.skip_check:
            ok, output = check_codex(hook, args.server)
            print(output)
            if not ok:
                sys.exit("The installed hook did not run; fix the problem above, then run again.")
        print("Next: start codex in this project, open /hooks and trust the WithHuman hooks.")
        print("Codex skips project hooks until they are trusted (and again after hooks.json")
        print("changes), so until then this project is not protected.")
        return
    hook_source = Path(args.hook)
    if not hook_source.is_file():
        sys.exit(f"hook not found: {hook_source}")

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

    for line in report:
        print(line)
    print(f"WithHuman hooks written to {settings_path}")
    print(f"PreToolUse hook: {hook} (run with {sys.executable})")
    print(f"WITHHUMAN_CLIENT_ID={value}")
    if os.name == "nt":
        print("Open a new terminal (or keep this one if the setup script set it), then run claude here.")
    else:
        print(f"Open a new terminal or run: source {profile()}   then run claude here.")


if __name__ == "__main__":
    main()
