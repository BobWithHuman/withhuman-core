#!/usr/bin/env sh
# Rebuilds one Rust service and restarts it, reusing the crate downloads and build output of
# earlier runs: only the service's own code is compiled again. The image build in Dockerfile
# starts from nothing every time and compiles all four services.
#
# usage: quick-deploy.sh <service>   (collector, decision, generator or mcp-fixture)
set -eu

service=${1:?usage: quick-deploy.sh <collector|decision|generator|mcp-fixture>}
binary="withhuman-$service"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
docker_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_dir=$(CDPATH= cd -- "$docker_dir/../.." && pwd)
project_name=${WITHHUMAN_COMPOSE_PROJECT:-withhuman-core}
out_dir="$repo_dir/target/quick-deploy/$service"

mkdir -p "$out_dir"

# The builder matches the runtime's Debian, so the binary runs there.
docker run --rm \
  --volume "$repo_dir:/workspace:ro" \
  --volume withhuman-cargo-registry:/usr/local/cargo/registry \
  --volume withhuman-cargo-target:/target \
  --volume "$out_dir:/out" \
  --workdir /workspace \
  --env CARGO_TARGET_DIR=/target \
  rust:1.87-bookworm \
  sh -eu -c "cargo build --locked --release --package $binary \
    && cp /target/release/$binary /out/service \
    && chown $(id -u):$(id -g) /out/service"

docker build --quiet \
  --file "$docker_dir/Dockerfile.runtime" \
  --tag "$project_name-$service" \
  "$out_dir"

docker compose \
  --project-name "$project_name" \
  --file "$docker_dir/compose.yaml" \
  up --detach --no-deps --no-build "$service"
