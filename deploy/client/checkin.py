#!/usr/bin/env python3
"""WithHuman's daily check-in: tells the engine this device is there, and where Claude Code ran.

usage: checkin.py --config DIR [--dry-run]

The setup schedules it once a day (launchd, a systemd user timer or cron, the Task Scheduler).
It sends the device's client ID, host name, OS, OS user and hook version, and the projects
Claude Code ran in with when each was last used. The engine marks a project in which its hooks
never ran as unprotected.

The projects are the folders ~/.claude.json lists. Their last use is the newest modification
time in the matching ~/.claude/projects/<folder> directory, read with stat: no conversation is
opened, and nothing of one is sent.

DIR holds what the setup wrote: `server`, `client-id`, `scope` and `hook-version`. The key comes
from WITHHUMAN_KEY or ~/.config/withhuman/key, the client ID from WITHHUMAN_CLIENT_ID when DIR
has none. Python 3.8 or later, standard library only.
"""

import argparse
import getpass
import json
import os
import platform
import re
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 20
# Claude Code names a project's directory after its path, every other character than a letter or
# digit made `-`, and cuts a longer name to this many characters.
NAME_LIMIT = 200


def read(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def encoded(path):
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def last_use(directory):
    """The newest modification time in `directory` and its files, epoch milliseconds."""
    newest = None
    try:
        entries = [directory, *directory.iterdir()]
    except OSError:
        return None
    for entry in entries:
        try:
            mtime = entry.stat().st_mtime
        except OSError:
            continue
        newest = mtime if newest is None else max(newest, mtime)
    return int(newest * 1000) if newest is not None else None


def projects(home):
    """The projects Claude Code ran in, with when each was last used."""
    try:
        listed = json.loads((home / ".claude.json").read_text(encoding="utf-8")).get("projects")
    except (OSError, ValueError, AttributeError):
        listed = None
    if not isinstance(listed, dict):
        return []
    store = home / ".claude" / "projects"
    try:
        directories = {entry.name: entry for entry in store.iterdir() if entry.is_dir()}
    except OSError:
        directories = {}
    found = []
    for path in listed:
        if not isinstance(path, str) or not path:
            continue
        name = encoded(path)
        directory = directories.get(name)
        if directory is None and len(name) > NAME_LIMIT:
            # A long name ends in a hash of the path, which only Claude Code computes.
            directory = next((entry for key, entry in directories.items()
                              if key.startswith(name[:NAME_LIMIT])), None)
        found.append({"path": path,
                      "last_used_at": last_use(directory) if directory is not None else None})
    return found


def checkin(config, home):
    server = read(config / "server")
    client_id = read(config / "client-id") or os.environ.get("WITHHUMAN_CLIENT_ID", "").strip()
    if not server or not client_id:
        raise SystemExit(f"{config} has no server or client ID; run the WithHuman setup again")
    return server.rstrip("/"), {
        "client_id": client_id,
        "hostname": socket.gethostname(),
        "os": f"{platform.system().lower()} {platform.release()}".strip(),
        "os_user": getpass.getuser(),
        "hook_version": read(config / "hook-version"),
        "scope": read(config / "scope"),
        "projects": projects(home),
    }


def main():
    parser = argparse.ArgumentParser(description="WithHuman's daily check-in.")
    parser.add_argument("--config", required=True, help="the folder the setup wrote")
    parser.add_argument("--dry-run", action="store_true", help="print what would be sent")
    args = parser.parse_args()
    home = Path.home()
    server, body = checkin(Path(args.config), home)
    if args.dry_run:
        print(json.dumps(body, indent=2))
        return 0
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("WITHHUMAN_KEY", "").strip() or read(home / ".config" / "withhuman" / "key")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    request = urllib.request.Request(f"{server}/v1/clients/checkin",
                                     data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            response.read()
    except urllib.error.HTTPError as error:
        print(f"WithHuman check-in: the engine answered {error.code}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError) as error:
        print(f"WithHuman check-in: the engine could not be reached ({error})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
