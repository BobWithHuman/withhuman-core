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

### Graph viewer

`tools/graph-viewer` shows each session's execution graph, verdicts, causes and paragraphs in a
browser. It reads PostgreSQL as its own `withhuman_viewer` role, which may read the graph and delete
whole sessions idle for ten minutes, and is published on `127.0.0.1` only. Set
`VIEWER_DB_PASSWORD` in `.env` (and `INFUSE_ATTACKS_DIR` to mark INFUSE attack Calls), then:

```sh
set -a; . ./.env; set +a
docker compose exec -T postgres psql -U withhuman -d withhuman \
  -v viewer_password="$VIEWER_DB_PASSWORD" < tools/graph-viewer/viewer-role.sql
docker compose --profile graph-viewer up -d --build graph-viewer
ssh -L 7480:localhost:7480 <host>   # then open http://localhost:7480
```

Run the role script after the engine or `migrate-neo4j.py import` has created the tables.

Configure a Claude Code project against the local gateway:

```sh
python3 deploy/client/configure.py \
  --project /path/to/project --team personal --server http://127.0.0.1:3000 \
  --hook "$PWD/deploy/client/hooks/pre-tool-use.py"
```

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
