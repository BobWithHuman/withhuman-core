#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
compose_file="$repo_dir/deploy/docker/compose.yaml"
compose=(docker compose --file "$compose_file")
gateway_url=${AGENTGATEWAY_URL:-http://localhost:3000}
decision_url=${DECISION_URL:-http://localhost:8082}
fixture_url=${MCP_FIXTURE_URL:-http://localhost:8090}
neo4j_url=${NEO4J_URL:-http://localhost:7474}
generator_url=${GENERATOR_URL:-http://localhost:8081}
export NEO4J_PASSWORD=${NEO4J_PASSWORD:-withhuman-e2e}
export WITHHUMAN_DECISION_TIMEOUT_MS=${WITHHUMAN_DECISION_TIMEOUT_MS:-4200}

for command in docker curl jq; do
  command -v "$command" >/dev/null || {
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 1
  }
done

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    "${compose[@]}" ps >&2 || true
    "${compose[@]}" logs --no-color --tail=200 >&2 || true
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

wait_for() {
  url=$1
  for _ in $(seq 1 60); do
    if curl --fail --silent "$url" >/dev/null; then
      return
    fi
    sleep 1
  done
  printf 'service did not become ready: %s\n' "$url" >&2
  return 1
}

set_decision() {
  export MOCK_DECISION=$1
  export MOCK_DECISION_REASON=${2:-}
  export MOCK_DECISION_DELAY_MS=${3:-0}
  "${compose[@]}" up --detach --force-recreate --no-deps decision >/dev/null
  wait_for "$decision_url/healthz"
}

hook() {
  event=$1
  payload=$2
  curl --fail --silent --show-error \
    "$gateway_url/v1/hooks/$event" \
    --header 'content-type: application/json' \
    --data "$payload"
}

start_session() {
  session_id=$1
  hook SessionStart "$(jq -cn --arg session "$session_id" \
    '{session_id:$session,cwd:"/workspace",source:"e2e"}')" >/dev/null
}

pre_tool() {
  session_id=$1
  tool_name=$2
  tool_use_id=$3
  path=$4
  hook PreToolUse "$(jq -cn \
    --arg session "$session_id" \
    --arg tool "$tool_name" \
    --arg tool_use_id "$tool_use_id" \
    --arg path "$path" \
    '{session_id:$session,tool_name:$tool,tool_input:{path:$path},tool_use_id:$tool_use_id}')"
}

initialize_mcp() {
  headers=$(mktemp)
  body=$(mktemp)
  curl --fail --silent --show-error \
    --dump-header "$headers" \
    --output "$body" \
    "$gateway_url/mcp" \
    --header 'content-type: application/json' \
    --header 'accept: application/json, text/event-stream' \
    --header 'mcp-protocol-version: 2025-03-26' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"withhuman-e2e","version":"0.1.0"}}}'
  mcp_session_id=$(awk 'tolower($1) == "mcp-session-id:" {gsub("\\r", "", $2); print $2}' "$headers")
  test -n "$mcp_session_id"
  rm -f "$headers" "$body"
  printf '%s' "$mcp_session_id"
}

mcp_call() {
  mcp_session_id=$1
  tool_use_id=$2
  path=$3
  output_file=$4
  curl --silent --show-error \
    --output "$output_file" \
    --write-out '%{http_code}' \
    "$gateway_url/mcp" \
    --header 'content-type: application/json' \
    --header 'accept: application/json, text/event-stream' \
    --header 'mcp-protocol-version: 2025-03-26' \
    --header "mcp-session-id: $mcp_session_id" \
    --data "$(jq -cn --arg tool_use_id "$tool_use_id" --arg path "$path" \
      '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"write_file",arguments:{path:$path},_meta:{"claudecode/toolUseId":$tool_use_id}}}')"
}

verdict_count() {
  session_id=$1
  curl --fail --silent --show-error \
    --user "neo4j:$NEO4J_PASSWORD" \
    "$neo4j_url/db/neo4j/query/v2" \
    --header 'content-type: application/json' \
    --data "$(jq -cn --arg session "$session_id" \
      '{statement:"MATCH (:ExecutionNode {session_id: $session_id, type: \"Call\"})-[:HAS_VERDICT]->(v:Verdict {session_id: $session_id}) RETURN count(v) AS count",parameters:{session_id:$session}}')" \
    | jq -r '.data.values[0][0]'
}

printf 'Starting the complete E2E topology...\n'
"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
if [ "${WITHHUMAN_E2E_SKIP_BUILD:-0}" != 1 ]; then
  "${compose[@]}" build
fi
export MOCK_DECISION=ALLOW
export MOCK_DECISION_REASON=
export MOCK_DECISION_DELAY_MS=0
"${compose[@]}" up --detach --wait

printf 'Verifying ALLOW and graph persistence...\n'
start_session e2e-allow
test -z "$(pre_tool e2e-allow Read internal-allow /tmp/allow)"
test "$(verdict_count e2e-allow)" -ge 1

printf 'Verifying internal DENY Hook enforcement...\n'
set_decision DENY 'blocked by e2e policy' 0
start_session e2e-deny
deny_response=$(pre_tool e2e-deny Write internal-deny /tmp/deny)
test "$(jq -r '.hookSpecificOutput.permissionDecision' <<<"$deny_response")" = deny
test "$(jq -r '.hookSpecificOutput.permissionDecisionReason' <<<"$deny_response")" = 'blocked by e2e policy'

printf 'Verifying REVIEW to ask mapping...\n'
set_decision REVIEW 'human review required' 0
start_session e2e-review
review_response=$(pre_tool e2e-review Write internal-review /tmp/review)
test "$(jq -r '.hookSpecificOutput.permissionDecision' <<<"$review_response")" = ask

printf 'Verifying AgentGateway MCP ALLOW and DENY enforcement...\n'
mcp_session_id=$(initialize_mcp)
set_decision ALLOW '' 0
start_session e2e-mcp-allow
test -z "$(pre_tool e2e-mcp-allow mcp__agentgateway__write_file mcp-allow /tmp/mcp-allow)"
mcp_body=$(mktemp)
test "$(mcp_call "$mcp_session_id" mcp-allow /tmp/mcp-allow "$mcp_body")" = 200
grep -q 'fixture call accepted' "$mcp_body"
calls_before=$(curl --fail --silent "$fixture_url/calls" | jq '.calls | length')

set_decision DENY 'MCP blocked by e2e policy' 0
start_session e2e-mcp-deny
test -z "$(pre_tool e2e-mcp-deny mcp__agentgateway__write_file mcp-deny /tmp/mcp-deny)"
test "$(mcp_call "$mcp_session_id" mcp-deny /tmp/mcp-deny "$mcp_body")" = 403
grep -q 'MCP blocked by e2e policy' "$mcp_body"
calls_after=$(curl --fail --silent "$fixture_url/calls" | jq '.calls | length')
test "$calls_before" -eq "$calls_after"
rm -f "$mcp_body"

printf 'Verifying timeout and unavailable dependency failure policy...\n'
export WITHHUMAN_DECISION_TIMEOUT_MS=300
"${compose[@]}" up --detach --force-recreate --no-deps collector >/dev/null
wait_for http://localhost:8080/healthz
set_decision ALLOW '' 1000
start_session e2e-timeout
timeout_response=$(pre_tool e2e-timeout Write internal-timeout /tmp/timeout)
test "$(jq -r '.hookSpecificOutput.permissionDecision' <<<"$timeout_response")" = deny

"${compose[@]}" stop decision >/dev/null
start_session e2e-unavailable
unavailable_response=$(pre_tool e2e-unavailable Write internal-unavailable /tmp/unavailable)
test "$(jq -r '.hookSpecificOutput.permissionDecision' <<<"$unavailable_response")" = deny
set_decision ALLOW '' 0

printf 'Verifying duplicate Generator event replay...\n'
duplicate_event='{"session_id":"e2e-duplicate","order":1,"observed_at":1,"meta":{"cwd":"/workspace"},"side_pending":{"paragraphs":[],"requests":[]},"payload":{"source":"e2e"}}'
first=$(curl --fail --silent "$generator_url/v1/events/SessionStart" \
  --header 'content-type: application/json' --data "$duplicate_event")
second=$(curl --fail --silent "$generator_url/v1/events/SessionStart" \
  --header 'content-type: application/json' --data "$duplicate_event")
test "$first" = "$second"

printf 'All WithHuman E2E scenarios passed.\n'
