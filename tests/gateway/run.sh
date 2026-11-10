#!/usr/bin/env bash
# Checks one AgentGateway image against the engine, without building images: the engine's
# binaries run on this host (cargo build --workspace first), PostgreSQL and the gateway in
# containers on fresh, free ports. Nothing reuses a running stack's names or ports.
#
#   AGENTGATEWAY_IMAGE=cr.agentgateway.dev/agentgateway:v1.7.0 tests/gateway/run.sh
#
# It checks what the deployment relies on: Hooks pass through to the Collector, and an MCP tool
# call is allowed or denied by the verdict its PreToolUse got (extAuthz). It also reports how the
# image treats an extAuthz `includeRequestBody: {}` (AgentGateway 1.6.0 answered 413 to any request
# with a body).
#
# DATABASE_URL may name a PostgreSQL to use; otherwise one is started and removed.
set -euo pipefail

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
image=${AGENTGATEWAY_IMAGE:-cr.agentgateway.dev/agentgateway:v1.7.0}
bin=${CARGO_TARGET_DIR:-$repo/target}/debug
work=$(mktemp -d)
pids=()
containers=()

for command in docker curl jq python3; do
  command -v "$command" >/dev/null || { echo "required: $command" >&2; exit 1; }
done
for binary in withhuman-collector withhuman-generator withhuman-decision withhuman-mcp-fixture; do
  [ -x "$bin/$binary" ] || { echo "build first: $bin/$binary is missing" >&2; exit 1; }
done

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    for log in "$work"/*.log; do
      [ -f "$log" ] && { echo "== $log" >&2; tail -n 40 "$log" >&2; }
    done
  fi
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for container in "${containers[@]}"; do docker rm -f "$container" >/dev/null 2>&1 || true; done
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

wait_for() {
  for _ in $(seq 1 60); do
    curl --silent --output /dev/null "$1" && return
    sleep 0.5
  done
  echo "not ready: $1" >&2
  return 1
}

suffix=$$
if [ -z "${DATABASE_URL:-}" ]; then
  pg_port=$(free_port)
  containers+=("wh-gateway-test-pg-$suffix")
  docker run -d --name "wh-gateway-test-pg-$suffix" -e POSTGRES_USER=withhuman \
    -e POSTGRES_PASSWORD=gateway-test -e POSTGRES_DB=withhuman \
    -p "127.0.0.1:$pg_port:5432" postgres:16.4 >/dev/null
  DATABASE_URL="postgres://withhuman:gateway-test@127.0.0.1:$pg_port/withhuman"
  for _ in $(seq 1 60); do
    docker exec "wh-gateway-test-pg-$suffix" pg_isready -h 127.0.0.1 -U withhuman >/dev/null 2>&1 && break
    sleep 0.5
  done
fi
export DATABASE_URL

decision_port=$(free_port)
generator_port=$(free_port)
collector_port=$(free_port)
authz_port=$(free_port)
fixture_port=$(free_port)
gateway_port=$(free_port)
gateway="http://127.0.0.1:$gateway_port"
decision_pid=

start_decision() {
  [ -n "$decision_pid" ] && kill "$decision_pid" 2>/dev/null && wait "$decision_pid" 2>/dev/null || true
  DECISION_ADDR="127.0.0.1:$decision_port" WITHHUMAN_ENV=test DECISION_PROVIDER=mock \
    MOCK_DECISION="$1" MOCK_DECISION_REASON="${2:-}" "$bin/withhuman-decision" >>"$work/decision.log" 2>&1 &
  decision_pid=$!
  pids+=("$decision_pid")
  wait_for "http://127.0.0.1:$decision_port/healthz"
}

start_decision ALLOW
GENERATOR_ADDR="127.0.0.1:$generator_port" DECISION_URL="http://127.0.0.1:$decision_port" \
  "$bin/withhuman-generator" >"$work/generator.log" 2>&1 &
pids+=($!)
wait_for "http://127.0.0.1:$generator_port/healthz"
COLLECTOR_ADDR="127.0.0.1:$collector_port" COLLECTOR_EXT_AUTHZ_ADDR="127.0.0.1:$authz_port" \
  GENERATOR_URL="http://127.0.0.1:$generator_port" WITHHUMAN_MODE=enforce \
  WITHHUMAN_INTENT_CAPTURE=off WITHHUMAN_MCP_ENFORCE=gateway WITHHUMAN_KEY_CACHE_MS=0 \
  "$bin/withhuman-collector" >"$work/collector.log" 2>&1 &
pids+=($!)
wait_for "http://127.0.0.1:$collector_port/healthz"
MCP_FIXTURE_ADDR="127.0.0.1:$fixture_port" "$bin/withhuman-mcp-fixture" >"$work/fixture.log" 2>&1 &
pids+=($!)
wait_for "http://127.0.0.1:$fixture_port/healthz"

# The deployment's gateway configuration, pointed at this host's services, with a probe route
# for the extAuthz body option.
sed -e "s#collector:8080#127.0.0.1:$collector_port#g" -e "s#collector:9000#127.0.0.1:$authz_port#g" \
  -e "s#port: 3000#port: $gateway_port#" "$repo/deploy/agentgateway/config.yaml" >"$work/config.yaml"
python3 - "$work/config.yaml" "$fixture_port" "$authz_port" <<'PY'
import sys
path, fixture, authz = sys.argv[1:]
text = open(path).read()
text = text.replace("  targets: []", f"  targets:\n    - name: fixture\n      mcp:\n        host: http://127.0.0.1:{fixture}/mcp")
probe = f"""  - name: body-probe
    matches:
      - path:
          pathPrefix: /probe
    policies:
      extAuthz:
        host: 127.0.0.1:{authz}
        protocol:
          grpc: {{}}
        includeRequestBody: {{}}
    backends:
      - host: 127.0.0.1:{authz}
"""
text = text.replace("\nmcp:", "\n" + probe + "\nmcp:", 1) if "\nmcp:" in text else text + probe
open(path, "w").write(text)
PY
containers+=("wh-gateway-test-agw-$suffix")
docker run -d --name "wh-gateway-test-agw-$suffix" --network host \
  -v "$work/config.yaml:/config.yaml:ro" "$image" -f /config.yaml >/dev/null
for _ in $(seq 1 60); do
  curl --silent --output /dev/null "$gateway/healthz" && break
  sleep 0.5
done
docker logs "wh-gateway-test-agw-$suffix" >"$work/gateway.log" 2>&1 || true
echo "gateway: $image"

hook() {
  curl --fail --silent --show-error "$gateway/v1/hooks/$1" \
    --header 'content-type: application/json' --data "$2"
}

pre_tool() {
  hook PreToolUse "$(jq -cn --arg session "$1" --arg tool "$2" --arg id "$3" --arg path "$4" \
    '{session_id:$session,tool_name:$tool,tool_input:{path:$path},tool_use_id:$id}')"
}

echo "- health and Hooks pass through to the Collector"
curl --fail --silent "$gateway/healthz" | jq -e '.service == "collector"' >/dev/null
hook SessionStart '{"session_id":"gw-1","cwd":"/w","source":"startup"}' | jq -e '.hookSpecificOutput.hookEventName == "SessionStart"' >/dev/null
test -z "$(pre_tool gw-1 Read gw-read /tmp/a)"

echo "- an MCP tool call follows its verdict (extAuthz)"
headers=$(mktemp -p "$work")
curl --fail --silent --show-error --dump-header "$headers" --output /dev/null "$gateway/mcp" \
  --header 'content-type: application/json' --header 'accept: application/json, text/event-stream' \
  --header 'mcp-protocol-version: 2025-03-26' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"gateway-test","version":"0"}}}'
mcp_session=$(awk 'tolower($1) == "mcp-session-id:" {gsub("\r", "", $2); print $2}' "$headers")
test -n "$mcp_session"
mcp_call() {
  curl --silent --show-error --output "$work/mcp.out" --write-out '%{http_code}' "$gateway/mcp" \
    --header 'content-type: application/json' --header 'accept: application/json, text/event-stream' \
    --header 'mcp-protocol-version: 2025-03-26' --header "mcp-session-id: $mcp_session" \
    --data "$(jq -cn --arg id "$1" --arg path "$2" \
      '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"write_file",arguments:{path:$path},_meta:{"claudecode/toolUseId":$id}}}')"
}
test -z "$(pre_tool gw-2 mcp__fixture__write_file gw-mcp-allow /tmp/allowed)"
test "$(mcp_call gw-mcp-allow /tmp/allowed)" = 200
grep -q 'fixture call accepted' "$work/mcp.out"
start_decision DENY 'blocked by the gateway test'
test -z "$(pre_tool gw-3 mcp__fixture__write_file gw-mcp-deny /tmp/denied)"
test "$(mcp_call gw-mcp-deny /tmp/denied)" = 403
grep -q 'blocked by the gateway test' "$work/mcp.out"
test "$(mcp_call gw-mcp-unknown /tmp/never)" = 403

echo "- extAuthz includeRequestBody: {} with a body"
probe=$(curl --silent --output /dev/null --write-out '%{http_code}' "$gateway/probe" \
  --header 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"ping"}')
echo "  answered $probe (413: the body was refused before the check; else the check ran)"
if [ "${EXPECT_BODY_PROBE:-}" != "" ]; then
  test "$probe" = "$EXPECT_BODY_PROBE"
fi

echo "ok"
