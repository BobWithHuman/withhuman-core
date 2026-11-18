# WithHuman

WithHuman records an agent's intent and checks tool calls against it. Collector, Generator and
Decision run with PostgreSQL and Redis; AgentGateway is the single HTTP entry point.

## Personal Docker deployment

Docker 24+ with the Compose plugin 2.20 or later is required. Set `GATEWAY_BIND=127.0.0.1` for
local-only access.

```sh
git clone https://github.com/BobWithHuman/withhuman-core.git
cd withhuman-core
cp .env.example .env
# Replace both secrets in .env. IMAGE_TAG already follows main.
docker compose up --detach --wait
curl --fail http://127.0.0.1:3000/healthz
```

The Compose profile pulls published amd64 or arm64 images automatically. It does not compile the
Rust workspace, so `--build` is unnecessary. PostgreSQL and Redis data live in named Docker volumes;
`docker compose down` preserves them and `docker compose down --volumes` deletes them.

`IMAGE_TAG` defaults to `edge`, which follows `main`. Compose reuses the image it already has, so
an update is a pull:

```sh
docker compose pull && docker compose up --detach --wait
```

Set `IMAGE_TAG` to a release (`0.1.0`) or a full commit SHA to stay on one build instead.

### PostgreSQL graph store

PostgreSQL 16 starts with Compose. Set a URL-safe `POSTGRES_PASSWORD` in `.env`. Outside Compose,
set `DATABASE_URL` (and optionally `DATABASE_POOL_SIZE`, default 16) on Generator and Decision.
Both services initialize the schema on startup.

If PostgreSQL was already enabled, use the same Compose project, volume and password.

### Upgrading an existing Neo4j deployment

1. Pause every writer to the old graph, including experiment stacks. Keep the old images, Compose
   file and volumes for rollback, and take a Neo4j backup before changing the deployment.
2. With the old Neo4j instance still readable, use its HTTP Query API to export a snapshot. Set
   `NEO4J_URL`, `NEO4J_PASSWORD` and, if needed, `NEO4J_USER` and `NEO4J_DATABASE` in the shell.
   Save the snapshot outside the repository with restricted access.
3. Start only the new PostgreSQL service (`docker compose up -d --wait postgres`). Keep the engine
   services stopped during import. Set `DATABASE_URL` to the fresh PostgreSQL target and run the
   commands below. Run import and verify from the private database network. Install Psycopg 3 in
   that environment (`python3 -m pip install "psycopg[binary]>=3.2,<4"`).

```sh
python3 deploy/docker/scripts/migrate-neo4j.py export /private/path/graph.jsonl
python3 deploy/docker/scripts/migrate-neo4j.py import /private/path/graph.jsonl
python3 deploy/docker/scripts/migrate-neo4j.py verify /private/path/graph.jsonl
```

Import commits only after an exact row comparison and requires an empty target. Once verification
passes, deploy matching PostgreSQL-only images and run `docker compose up -d --wait`. Check a new
session and a decision before reopening traffic. Stop the old Neo4j service through its original
Compose project and keep its volume and backup through the rollback window. If cutover fails before
traffic resumes, restore the old stack. After new writes are accepted, back up PostgreSQL and
reconcile those writes before rolling back.

The PostgreSQL `reindex-paragraphs` command runs with the Generator and Decision stopped. It replaces
paragraphs and removes their old classifications and paragraph-level cause links. It retains
original token keys and result-level links.

Passwords and generic API keys are recognized only by a label (`password: X`, `"api_key":"X"`).
When the Generator recognizes one for the first time in a session, it looks for the same value,
standalone, in everything the session stored before: commits, node payloads, Decision's traces and
paragraphs. It masks every copy as the token is masked and records each earlier node as mentioning
it, in the slot of who wrote it there (`user` for a prompt, `external` for a tool result), so a
password typed into a prompt is no longer kept in clear nor shown as written by the agent. The
value is only held in memory for the search. Values shorter than six characters, or made of one
kind of character and shorter than 16, are not looked for, since they would match unrelated text.
The PostgreSQL `backtrack-secrets` command does the same for sessions recorded before: for each
password, API key or JWT whose first mention in its session is the agent's, it finds the value
again from the token's masked ends and key hash, then masks and records as above. It can run with
the Generator and Decision up, one token per transaction under its session's lock, and a second
run changes nothing. It prints counts only.

Configure a Claude Code project against the local gateway:

```sh
python3 deploy/client/configure.py \
  --project /path/to/project --team personal --server http://127.0.0.1:3000 \
  --hook "$PWD/deploy/client/hooks/pre-tool-use.py"
```

### Keys and the agent inventory

The engine records which device and which user run each agent session. Every setup registers
its device (`POST /v1/clients/register`: client ID, team, host name, OS, OS user, hook version,
project folder and, where the user may read it, the hardware serial number); a setup that cannot
reach the engine still completes and says so.

Per-user keys tie Hooks to a person and let the security team stop that person's agents. Set
`WITHHUMAN_ADMIN_TOKEN` in `.env`, then issue a key and hand it to the user:

```sh
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"actor": "security@example.com"}' http://127.0.0.1:3000/v1/admin/users/ana@example.com/keys
```

The user sets the project up with it, `--key whk_...` (or `WITHHUMAN_KEY=whk_...` for the
one-line installers). The key is kept in `~/.config/withhuman/key`, readable by the user only, and
exported as `WITHHUMAN_KEY`. The engine stores keys as SHA-256 hashes only.

Revoking a key (`POST /v1/admin/keys/<key_id>/revoke`) or all of a user's keys
(`POST /v1/admin/users/<email>/revoke`), each with `{"actor": ..., "reason": ...}`, denies every
tool call the user's agents make from then on (within `WITHHUMAN_KEY_CACHE_MS`, 5 s by default).
Hooks without a valid key are taken without a user unless `WITHHUMAN_REQUIRE_KEY=on`, which
denies their tool calls and refuses their other Hooks; turn it on before relying on revocation,
since otherwise a user could drop the key.

The inventory keeps two people for a device: `user`, whoever's key it presented last, and
`owner`, the person the security team names for the machine. Name or clear the owner with
`POST /v1/admin/clients/<client_id>/owner` and `{"owner": "<email>" | null, "actor": ...}`. A
client ID holds a slash (`<team>/<uuid>`), sent as one path segment: `team%2F<uuid>`.

```sh
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"owner": "ana@example.com", "actor": "security@example.com"}' \
  http://127.0.0.1:3000/v1/admin/clients/platform%2F6f1c0d1e-0000-4000-8000-000000000000/owner
```

The security team can also stop one device: `POST /v1/admin/clients/<client_id>/stop` with
`{"stopped": true, "actor": ..., "reason": ...}` denies every tool call whose Hook carries that
client ID, in every mode, until `{"stopped": false}` releases it. The device's other Hooks are
still recorded. An unknown device is a 404; a device already stopped keeps its first stop. The
stop applies at once on the Collector that took it and within `WITHHUMAN_KEY_CACHE_MS` on the
others; a tool call already past its PreToolUse Hook is not interrupted. The device shows a fixed
message, never the team's `reason`. `clients.stopped_at`, `stopped_by` and `stop_reason` hold the
stop (all null while the device runs), and `stop_denied_count` and `stop_last_denied_at` the calls
refused for it.

```sh
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"stopped": true, "actor": "security@example.com", "reason": "lost laptop"}' \
  http://127.0.0.1:3000/v1/admin/clients/platform%2F6f1c0d1e-0000-4000-8000-000000000000/stop
```

A stop is not a lock on the machine. The client ID is a header the device's own Hooks send
(`~/.config/withhuman/client-id`), so a device that sends another ID, or none, or whose Hooks were
removed, is not stopped, and `WITHHUMAN_REQUIRE_KEY` does not change that: a key names a person,
not a machine. It stops a device that keeps running its installed Hooks. To stop a person
whatever they run, revoke their keys with `WITHHUMAN_REQUIRE_KEY=on`. Tool calls that reach the
engine through AgentGateway alone (MCP, without a Hook) are not covered, as with a revoked key.

The security team can also stop one session (`POST /v1/admin/sessions/<id>/stop`, released
with `.../release`), review calls after the fact (`POST /v1/admin/reviews`) and issue keys to
automations (`{"kind": "service"}`). A call is checked against a revoked key first, then its
device's stop, then its session's. Revoked keys and session stops (released ones kept) are in the
`stop_audit` view; a device's stop is on its `clients` row. Benchmark runs name their client
`bench/...` so the inventory can leave them out (`clients.test`).

### Triage

The security team records what it decided about a session it looked at, for the whole team:
`session_marks` and `distrusted_sources` in PostgreSQL, which the viewer reads. Both are set
through the admin API. A mark is a record only. A distrusted source also holds what it causes:
when the engine traces a tool call to a tool result (`cause.link` is `segment`) and the call that
produced that result is on a distrusted source, a call the engine would otherwise allow is put to
the user for review instead (rule `source::distrusted`), or denied with
`WITHHUMAN_DISTRUSTED_SOURCE_DENY=1`. The rule only makes a verdict stricter: a call already
denied or held keeps its verdict and rule. Reading the source is not blocked, only what its
content then causes. A result's source is the path, URL or folder-relative path its call named, or
its tool's name, as the evidence shows it. A source distrusted now holds the calls decided from
now on; the list is read for each such call, so there is nothing to wait out. If the list cannot
be read within 250 ms the call is decided without it, with a warning in Decision's log and
`source.error` in the call's trace. The matched source is kept in the call's trace
(`nodes.trace_json`, `source.distrusted`) and never shown to the agent.

`POST /v1/admin/sessions/<session_id>/mark` with `{"state": ..., "actor": ...}` marks a session
`reviewing`, `attack`, `benign` or `closed`, replaces its mark, or with `"state": null` takes it
off (a session without a mark was not handled yet); a session the engine does not hold is a 404.
`POST /v1/admin/sessions/mark` with `{"session_ids": [...], "state": ..., "actor": ...}` does the
same for up to 1000 sessions together and answers with `sessions` (each with its mark) and
`unknown`, the ones the engine does not hold, which it leaves alone. `POST /v1/admin/sources/distrust` with
`{"source": ..., "on": true | false, "actor": ..., "session_id": ..., "seq": ...}` distrusts a
source (a document's path, a URL or a tool's name) or with `on: false` trusts it again;
`session_id` and `seq`, the tool call that showed the source, are optional. The source goes in
the body as written, since it may be a URL or a path.

```sh
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"state": "attack", "actor": "security@example.com"}' \
  http://127.0.0.1:3000/v1/admin/sessions/0b9f6c1e-0000-4000-8000-000000000001/mark
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"source": "https://example.com/setup.md", "on": true, "actor": "security@example.com"}' \
  http://127.0.0.1:3000/v1/admin/sources/distrust
```

`GET /v1/admin/sessions/<session_id>/calls/<seq>/evidence` returns one tool call's evidence as
JSON for other systems (`"schema": "withhuman.evidence/v1"`): the call (tool, input, target,
time, device, user), the engine's decision (reason, rule, mode), the person's request before
it, what the engine traced the call to (`cause.link`: `request`, `segment` or `none`; for
`segment` the tool results in `cause.told_by`, each with the call whose result it was, the
paragraph, its text and the probability), the session's mark, and whether the cause's source
is distrusted. `seq` is the call's number in its session (`nodes.seq`). An unknown session or
call is a 404. Text is as the engine stored it, sensitive values already replaced; no key or
key hash is in it. The full shape is in the Collector's OpenAPI document (`/swagger-ui`).

### The security team's viewer

The viewer reads PostgreSQL directly, read-only, as `withhuman_viewer`. The Generator creates that
login when `WITHHUMAN_VIEWER_PASSWORD` is set, and the schema grants it SELECT on the graph,
inventory and triage tables (`api_keys` without its hash) and nothing else. The personal stack publishes
PostgreSQL on `127.0.0.1:15432` (`POSTGRES_PORT`):
`postgres://withhuman_viewer:<WITHHUMAN_VIEWER_PASSWORD>@127.0.0.1:15432/withhuman`.

### Devices from Wazuh

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
`mac-1`). Every client row of a machine, one per OS account, gets the same agent.

`edr_devices.agent` is `claude-code` or `codex` (Claude Code first when both show):

- from a process running at the agent's last inventory scan, when it is exactly that program:
  its `name` is `claude` or `codex` (`claude.exe` on Windows), or its `cmd` or one of its
  `argvs` is a path whose last segment is that name, a path into Claude Code's native install
  (`~/.local/share/claude/versions/2.1.3`, which runs under its version's name), or a path
  into the npm package `@anthropic-ai/claude-code` or `@openai/codex` (run under `node`). Case
  counts, so the Claude desktop app's processes (`Claude`, `Claude Helper (Renderer)`) are not
  Claude Code;
- otherwise from an installed package with `claude` or `codex` in its name in any case
  (`@anthropic-ai/claude-code`, `claude-code`, `codex`, `Codex CLI`), except the desktop app's
  (`Claude`, or `Claude ` followed by anything but `Code`).

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
| `WITHHUMAN_WAZUH_SYNC_INTERVAL_SECS` | `900` | At least 60 |
| `WITHHUMAN_WAZUH_MAX_REQUESTS_PER_MINUTE` | `150` | The manager refuses everyone past its own limit (300 by default); `0` for no pacing |
| `WITHHUMAN_WAZUH_CA_FILE` | empty: public authorities | A PEM file trusted instead: authorities, or the manager's own self-signed certificate |
| `WITHHUMAN_WAZUH_TLS_SKIP_VERIFY` | `0` | `1` skips verifying the certificate, with a warning at start; not with a CA file |

A sync costs one login, one request per 500 agents and up to three per agent. Generators
running together take turns: one syncs at a time, and none repeats a sync finished less than
half an interval ago.

### Judging

When the engine gives no judgment (unreachable, an error, no answer in time) a tool call is
denied: the Collector defaults to `WITHHUMAN_ON_FAILURE=closed`, and `pre-tool-use.py` denies when
it cannot reach the Collector. With `WITHHUMAN_ASK=ask` (Claude Code), a grade 2 or 3 call the
engine could not judge is put to the user instead. A stored verdict is kept 5 minutes
(`WITHHUMAN_VERDICT_TTL_SECS`).

- Each call is graded 0, 1, 2-1, 2-2, 3-1 or 3-2 by how far its effect can be undone (KISA
  agentic-AI zero-trust guide, table 2-5); the grade is recorded in the trace and sets what
  happens when judging fails.
- A file change is never cleared on the first question alone, and is asked about each line it
  adds: a document the user pointed to counts only for the task it describes. A shell command
  that writes files is checked the same way, and a change that only undoes the session's own
  earlier changes to a file is allowed.
- Jev sees a several-step shell command step by step, and text built from base64, character
  codes or joined literals.
- A `---`, `***` or `___` line starts a new paragraph, so a note appended after it is traced
  apart from the text before; a Codex shell command that exits non-zero is recorded with its
  output, as Claude Code records a failed Bash command.
- After `WITHHUMAN_DEGRADED_FAILURES` (3) Jev failures in a row, or at once on 401/402/403/429,
  the rules judge alone for `WITHHUMAN_DEGRADED_SECONDS` (60): grade 0 and 1 are allowed (except a
  secret read, a web fetch or an edit of CI or hooks), grade 2 and 3 are reviewed, a safeguard
  change is denied.

### Codex CLI

Set up a Codex CLI project with the same one-line installers, choosing Codex. In the folder you
start `codex` in, on Windows PowerShell:

```powershell
$env:WITHHUMAN_SERVER = "http://127.0.0.1:3000"; $env:WITHHUMAN_AGENT = "codex"
irm https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.ps1 | iex
```

or on macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.sh \
  | WITHHUMAN_SERVER=http://127.0.0.1:3000 WITHHUMAN_AGENT=codex bash
```

This installs the hook into `<project>/.codex/hooks/`, adds its entries to
`<project>/.codex/hooks.json` (other hooks are kept) and checks that the installed hook reaches
the engine; the user's `~/.codex` is left alone, and no engine secret goes on the device. Then
run `codex` in the project, open `/hooks` and trust the WithHuman hooks. Codex skips project
hooks until they are trusted, and again after `hooks.json` changes, so the project is not
protected until you do. Running the installer again updates the setup; with
`WITHHUMAN_UNINSTALL=1` it takes WithHuman out of the project instead. From a checkout,
`python3 deploy/client/configure.py --agent codex --server <engine>` does the same.

Codex cannot show a confirmation prompt, so a call that needs the user's confirmation (REVIEW)
is blocked. Approving it in the conversation does not help: the same call is reviewed and
blocked again. Make such a change yourself, or ask for a different change.

The personal Compose stack starts with the engine's `WITHHUMAN_MODE=shadow`, which records
verdicts but blocks nothing; set `WITHHUMAN_MODE=enforce` in `.env` for blocking. That engine
setting (`record`, `shadow`, `enforce`) is separate from the hook's own `WITHHUMAN_MODE`
(`enforce`, `observe`) in the environment Codex runs in.

The hook sends Codex's events to the Collector's `/v1/hooks/codex/{event}` route, which turns
them into the Claude Code hook requests the engine already judges. MCP calls are enforced by the
hook rather than by AgentGateway. When the engine cannot be reached or does not answer in time,
the hook blocks the call (the hook's `WITHHUMAN_MODE=observe` lets it through).

Known differences from Claude Code: the `[의도]` line Codex writes stays visible on screen, and
configuration changes made outside the agent are not recorded (Codex has no ConfigChange hook).
Simple literal single-file shell writes are checked as Write, and appends as Edit. Partial or
computed edits, multi-file commands and wildcard paths remain shell calls.
Unknown or ambiguous shell working directories block the call. Delivery failures block protected
calls; if the engine cannot confirm an event, start a new session after restoring the service.
Native web operations without hooks are recorded afterward, using only transcript content.
Subsequent input into an already-open shell and a hook that cannot start or is not trusted are
outside this protection. `observe` records activity without enforcing protection.
Verified on Windows with Codex CLI 0.154 and 0.167; macOS is not verified yet.

## Development

The development and E2E profile builds the services from the working tree and includes an MCP
fixture:

```sh
cp deploy/docker/.env.example deploy/docker/.env
docker compose --file deploy/docker/compose.yaml up --detach --build
```

## Deployment profiles

- Personal host: root `compose.yaml` and `.env`, the Docker deployment above. One machine, one user.
- Shared cluster: `infra/aws/staging`; EKS runs the Helm chart through Argo CD and
  `withhuman-gitops`.

Infrastructure instructions are in `infra/README.md`.
