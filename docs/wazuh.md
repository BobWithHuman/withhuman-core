# Devices from Wazuh

With `WITHHUMAN_WAZUH_URL` set, the Generator reads the company's device list from a Wazuh
manager every `WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS` and keeps it in `edr_devices`, one row per
Wazuh agent: `agent_id`, `name`, `os`, `status` (`active`, `disconnected`, `never_connected`,
`pending`), `serial` (the board serial of the hardware inventory), `last_seen`, `agent`,
`running_at` and `synced_at`. The table mirrors the manager: a device it no longer lists is removed, and a sync
that fails changes nothing and is tried again at the next interval. Without the URL nothing runs.

Each sync then matches the registered devices: `clients.edr_agent_id` and `clients.edr_status`
name the Wazuh agent of a client and its status, or are NULL. Two serial numbers that are both
known must be equal (firmware placeholders such as `To Be Filled By O.E.M.` count as unknown);
when either is unknown, the hostnames decide, compared without case or domain (`Mac-1.local` is
`mac-1`). Every client row of a machine, one per OS account, gets the same agent. The setup
reports the serial Wazuh does: the motherboard's on Linux (`/sys/class/dmi/id/board_serial`) and
Windows (`Win32_BaseBoard`), the platform's on macOS. Beside it, it reports the others it can
read (`other_serials`: the BIOS's on Windows, the system's on Linux when readable), which a PC
often numbers otherwise, and the Wazuh agent whose serial equals any of them is the device's: a
Wazuh build or a machine that reports another of its numbers still finds it. A Linux or Windows
device set up before either reported the system's or the BIOS's alone, and stays apart from its
Wazuh agent until it is set up again.

`edr_devices.agent` is `claude-code`, `codex`, `cursor` or `openclaw` (Claude Code first, else whichever
the scan showed first):

- from a process running at the agent's last inventory scan, when it is exactly that program:
  its `name` is `claude`, `codex`, `cursor-agent` or `openclaw` (`claude.exe` on Windows), or its `cmd` or
  one of its `argvs` is a path whose last segment is that name, a path into Claude Code's native
  install (`~/.local/share/claude/versions/2.1.3`, which runs under its version's name) or
  Cursor's (`~/.local/share/cursor-agent/versions/2026.11.22/index.js`), or a path into the npm
  package `@anthropic-ai/claude-code` or `@openai/codex`, or a path into OpenClaw's npm install
  (`…/node_modules/openclaw/…`, which its Gateway runs out of) — all three run under `node`.
  Case counts, so the Claude desktop app's processes (`Claude`, `Claude Helper (Renderer)`) are
  not Claude Code;
- otherwise from an installed package with `claude` or `codex` in its name in any case
  (`@anthropic-ai/claude-code`, `claude-code`, `codex`, `Codex CLI`), except the desktop app's
  (`Claude`, or `Claude ` followed by anything but `Code`), or one named after Cursor (`Cursor`,
  `cursor-agent`, `Cursor CLI`), or one named after OpenClaw (`openclaw`, `OpenClaw CLI`). A
  plugin of OpenClaw's (`openclaw-plugin-…`) does not count: that says a plugin was built, not
  that the agent runs here.

Cursor's CLI is found by the folder it runs from rather than by its name: it runs under `node`
with the name it was started as, and the setup leaves that as both `cursor-agent` and `agent`.
Its editor counts as the same agent — it reads the same hooks — so its own binary (`Cursor`,
`Cursor.exe`, `cursor`) is matched whatever the case, while its helper processes and everything
else that merely holds the word are not: macOS's own `CursorUIViewService` and a Linux desktop's
`libxcursor` and `xcursor-themes` are no coding agent.

`edr_devices.running_at` is when such a process was last seen running: the latest `scan.time`
of the processes that pass, epoch milliseconds. It is NULL when none was running at the last
scan, including when only a package shows the program; a viewer can set it against the
device's Hook sessions to find a coding agent running without them. NULL in either column means
only that nothing was seen: the agent's process inventory is a snapshot every scan interval
(an hour by default), a program installed outside a package manager Wazuh reads leaves no trace
while it is not running, and on macOS Wazuh reports a process's name only, without its command
line, so Claude Code or Codex installed with npm (`node`) is not seen running there.

`edr_sightings` keeps what `running_at` overwrites: one row per device and process scan that
found a coding agent running, `agent_id`, `running_at` (the scan's time), `agent`, `name` (the
device's name then), `synced_at` (the sync that first saw it) and `command`, keyed by `agent_id`
and `running_at`. `command` is the command line of the process the scan found (`claude -p …`,
`claude --resume <session>`, `codex exec …`): its `cmd` and `argvs` joined by spaces, cut to
1000 characters; among several processes of the scan, one of the agent named and with
arguments. What Wazuh reports differs by system: Linux gives the whole command line, Windows
the executable's path only and macOS the process's name only, so there `command` is a path or
NULL. A scan seen again by a later sync adds nothing and keeps the command line first seen, a
device with `running_at` NULL adds nothing, and a device the manager no longer lists keeps its
rows. Each sync deletes the
rows whose scan is more than 30 days before it (`SIGHTING_RETENTION`). The engine only records
the scans: telling them apart from Hook sessions, and grouping consecutive ones, is the
viewer's.

| Variable | Default | |
|---|---|---|
| `WITHHUMAN_WAZUH_URL` | empty: no sync | The Wazuh server API, `https://<manager>:55000` |
| `WITHHUMAN_WAZUH_USER`, `WITHHUMAN_WAZUH_PASSWORD` | required with the URL | An API user that may read agents and their inventory (`agent:read`, `syscollector:read`): the default role `readonly` |
| `WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS` | `120` | At least 60 |
| `WITHHUMAN_WAZUH_MAX_REQUESTS_PER_MINUTE` | `150` | The manager refuses everyone past its own limit (300 by default); `0` for no pacing |
| `WITHHUMAN_WAZUH_CA_FILE` | empty: public authorities | A PEM file trusted instead: authorities, or the manager's own self-signed certificate |
| `WITHHUMAN_WAZUH_TLS_SKIP_VERIFY` | `0` | `1` skips verifying the certificate, with a warning at start; not with a CA file |

A sync costs one login, one request per 500 agents and up to three per agent. Generators
running together take turns: one syncs at a time, and none repeats a sync finished less than
half an interval ago.
