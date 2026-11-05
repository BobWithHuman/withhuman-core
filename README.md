# WithHuman

WithHuman records an agent's intent and checks tool calls against it. Collector, Generator and
Decision run with Neo4j and Redis; AgentGateway is the single HTTP entry point.

## Personal Docker deployment

Docker 24+ with the Compose plugin is required. The default binds the gateway to localhost, so it
is suitable for one user on the same machine.

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

Configure a Claude Code project against the local gateway:

```sh
python3 deploy/client/configure.py \
  --project /path/to/project --team personal --server http://127.0.0.1:3000 \
  --hook "$PWD/deploy/client/hooks/pre-tool-use.py"
```

See `deploy/single-node/README.md` for operations and the Terraform-managed AWS version.

## Development

The development and E2E profile builds the services from the working tree and includes an MCP
fixture:

```sh
cp deploy/docker/.env.example deploy/docker/.env
docker compose --file deploy/docker/compose.yaml up --detach --build
```

## Deployment profiles

- Personal local host: root `compose.yaml` and `.env`.
- Personal AWS host: `infra/aws/single-node`; EC2 runs the same root `compose.yaml` and polls a
  configured branch, tag or SHA without Argo CD.
- Shared staging: `infra/aws/staging`; EKS runs the Helm chart through Argo CD and
  `withhuman-gitops`.

Infrastructure instructions are in `infra/README.md`; architecture details are in
`docs/ARCHITECTURE.md`.
