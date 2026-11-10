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

Set Claude Code up against the local gateway, for every project of this user (the hooks go into
`~/.claude/settings.json`; earlier per-project setups are taken out):

```sh
python3 deploy/client/configure.py --team personal --server http://127.0.0.1:3000
```

`--managed` (as root or Administrator) puts the hooks into Claude Code's managed settings
instead, for every user of the device, as the drop-in `managed-settings.d/50-withhuman.json`.
`--scope project` keeps the earlier per-project setup. The setup also schedules a daily check-in
that reports the projects Claude Code ran in (paths and last use only), so projects the hooks
never reached show as unprotected. In a container, pass the host's `WITHHUMAN_CLIENT_ID` (and
`WITHHUMAN_KEY`) in, or mount `~/.config/withhuman` read-only, so the device keeps one ID.

### Keys and the agent inventory

The engine records which device and which user run each agent session. Every setup registers
its device (`POST /v1/clients/register`: client ID, team, host name, OS, OS user, hook version,
project folder); a setup that cannot reach the engine still completes and says so.

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

### The security team's viewer

The viewer reads PostgreSQL directly, read-only, as `withhuman_viewer`. The Generator creates that
login when `WITHHUMAN_VIEWER_PASSWORD` is set, and the schema grants it SELECT on the graph and
inventory tables (`api_keys` without its hash) and nothing else. The personal stack publishes
PostgreSQL on `127.0.0.1:15432` (`POSTGRES_PORT`):
`postgres://withhuman_viewer:<WITHHUMAN_VIEWER_PASSWORD>@127.0.0.1:15432/withhuman`.

The security team can also stop one session (`POST /v1/admin/sessions/<id>/stop`, released
with `.../release`), review calls after the fact (`POST /v1/admin/reviews`), issue keys to
automations (`{"kind": "service"}`), and except folders, teams or devices from protection
(`POST /v1/admin/exceptions`): an excepted session sends only that it started. Every stop is in
the `stop_audit` view. Benchmark runs name their client `bench/...` so the inventory can leave
them out (`clients.test`).

With `WITHHUMAN_MODEL_PROXY=on` and `AGENTGATEWAY_CONFIG=config.model-proxy.yaml`, the gateway
also passes Claude Code's model requests to Anthropic (`ANTHROPIC_BASE_URL` set to the gateway;
`configure.py --model-proxy`), after checking the same keys and session stops, and records each
in `model_calls` without its content. A model request whose session no hook reported shows in
`unprotected_model_calls`. Bedrock, Vertex and Foundry requests do not take this route.

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
