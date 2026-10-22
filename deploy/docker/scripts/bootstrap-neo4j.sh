#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
docker_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_file=${WITHHUMAN_ENV_FILE:-"$docker_dir/.env"}
project_name=${WITHHUMAN_COMPOSE_PROJECT:-withhuman-core}

docker compose \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$docker_dir/compose.yaml" \
  exec -T neo4j sh -eu -c \
  'cypher-shell --address bolt://localhost:7687 --username neo4j --password "${NEO4J_AUTH#*/}" --file /bootstrap/schema.cypher'

result=$(docker compose \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$docker_dir/compose.yaml" \
  exec -T neo4j sh -eu -c \
  'cypher-shell --format plain --address bolt://localhost:7687 --username neo4j --password "${NEO4J_AUTH#*/}" --file /bootstrap/verify-schema.cypher')

printf '%s\n' "$result"
test "$(printf '%s\n' "$result" | grep -ci '^true$')" -eq 2
