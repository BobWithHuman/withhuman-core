# WithHuman

WithHuman records an agent's intent and checks tool calls against it. Collector, Generator and
Decision run with Neo4j and Redis; AgentGateway is the single HTTP entry point.

## Personal Docker deployment

Docker 24+ with the Compose plugin 2.20 or later is required. The default binds the gateway to
localhost, so it is suitable for one user on the same machine.

```sh
git clone https://github.com/BobWithHuman/withhuman-core.git
cd withhuman-core
cp .env.example .env
# Replace both secrets in .env. IMAGE_TAG already follows main.
docker compose up --detach --wait
curl --fail http://127.0.0.1:3000/healthz
```

The Compose profile pulls published amd64 or arm64 images automatically. It does not compile the
Rust workspace, so `--build` is unnecessary. Neo4j and Redis data live in named Docker volumes;
`docker compose down` preserves them and `docker compose down --volumes` deletes them.

`IMAGE_TAG` defaults to `edge`, which follows `main`. Compose reuses the image it already has, so
an update is a pull:

```sh
docker compose pull && docker compose up --detach --wait
```

Set `IMAGE_TAG` to a release (`0.1.0`) or a full commit SHA to stay on one build instead.

### PostgreSQL graph store (opt-in)

Generator and Decision keep the execution graph in Neo4j by default. To keep it in PostgreSQL 16
instead, set these in `.env` before `docker compose up`:

```sh
COMPOSE_PROFILES=postgres
WITHHUMAN_GRAPH_STORE=postgres
POSTGRES_PASSWORD=replace-with-a-long-random-password
```

The services create their tables on connect. Any `WITHHUMAN_GRAPH_STORE` other than `neo4j` or
`postgres` stops them, so both always use the same store. Neo4j still starts but is unused. The
graph viewer and `generator reindex-paragraphs` work with Neo4j only, and an existing Neo4j graph
is not copied. Outside Compose, set `DATABASE_URL` (and optionally `DATABASE_POOL_SIZE`, default
16) on both services.

Configure a Claude Code project against the local gateway:

```sh
python3 deploy/client/configure.py \
  --project /path/to/project --team personal --server http://127.0.0.1:3000 \
  --hook "$PWD/deploy/client/hooks/pre-tool-use.py"
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
