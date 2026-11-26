# Deployment

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

## PostgreSQL graph store

PostgreSQL 16 starts with Compose. Set a URL-safe `POSTGRES_PASSWORD` in `.env`. Outside Compose,
set `DATABASE_URL` (and optionally `DATABASE_POOL_SIZE`, default 16) on Generator and Decision.
Both services initialize the schema on startup.

If PostgreSQL was already enabled, use the same Compose project, volume and password.

## Upgrading an existing Neo4j deployment

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

## Maintenance commands

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

## Setting up Claude Code

Configure a Claude Code project against the local gateway:

```sh
python3 deploy/client/configure.py \
  --project /path/to/project --team personal --server http://127.0.0.1:3000 \
  --hook "$PWD/deploy/client/hooks/pre-tool-use.py"
```

Or for every folder at once, instead of one project:

```sh
# Every folder this user works in (~/.claude/settings.json); no administrator rights.
python3 deploy/client/configure.py --scope user --team personal --server http://127.0.0.1:3000

# Every user and folder of the device, in the policy an administrator sets for Claude Code
# (managed-settings.d/50-withhuman.json); a user cannot turn it off.
sudo python3 deploy/client/configure.py --scope managed --team personal \
  --server http://127.0.0.1:3000 --managed-hooks-only
```

A managed setup keeps the hook and the device's client ID where only an administrator can change
them (`/Library/Application Support/WithHuman`, `/opt/withhuman`, `C:\Program Files\WithHuman`)
and writes the ID into the hooks itself, so Claude Code started from an IDE or by another user
reports the same device. `--managed-hooks-only` also sets `allowManagedHooksOnly`, so no user,
project or plugin hook runs beside it: a project set up earlier does not report each event twice,
and no hook of the user's own stands beside WithHuman's. Each user's WithHuman key stays their own.
Decision denies a Call that changes these files as it does the project's hooks. A managed setup
also takes out the user setup of the user who ran it, which would report each event twice beside
it. `--uninstall` with the same `--scope` takes the setup out again. Every other agent is set up
per project.

To start over on a device set up more than one way (an earlier hook version, a user setup and a
managed one, projects set up one by one), `--reset` takes every WithHuman setup out at once: the
managed one, the user one, and the project ones of the folders named after it (every agent's). Other hooks and settings stay, each file changed is copied first, and the device's
client ID is kept, so the setup made after is the same device:

```bash
sudo python3 deploy/client/configure.py --reset ~/src/app ~/src/api
```

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
