# The model route's checks, sourced by run.sh with WITHHUMAN_MODEL_PROXY=on. Allowed requests go
# on to Anthropic without credentials, which refuses them: anything but our 403 shows the check
# let them through.
psql_engine() {
  docker run --rm --network host postgres:16.4 psql -X -At "$DATABASE_URL" -c "$1"
}
admin() {
  curl --fail --silent --show-error "$gateway/v1/admin/$1" --header 'content-type: application/json' \
    --header 'authorization: Bearer gateway-test-admin' --data "$2"
}
model() {
  # model <key> <session> -> status; the body is in $work/model.out
  curl --silent --output "$work/model.out" --write-out '%{http_code}' "$gateway/v1/messages" \
    --header 'content-type: application/json' --header 'anthropic-version: 2023-06-01' \
    --header "x-withhuman-key: $1" --header "x-claude-code-session-id: $2" \
    --header 'x-withhuman-client: team/gateway-test' \
    --data '{"model":"claude-test-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}'
}

echo "- model requests: the user's key and session are checked first"
key=$(admin users/ana@example.com/keys '{"actor":"gateway-test"}' | jq -r .key)
session=gw-model-$suffix
hook SessionStart "$(jq -cn --arg s "$session" '{session_id:$s,source:"startup"}')" >/dev/null
status=$(model "$key" "$session")
echo "  valid key: $status ($(head -c 120 "$work/model.out"))"
test "$status" != 403
sleep 1
row=$(psql_engine "SELECT user_email || '|' || client_id || '|' || coalesce(model, '-') || '|' || (request_id IS NOT NULL) FROM model_calls WHERE session_id = '$session'")
echo "  recorded: $row"
test "${row%%|*}" = ana@example.com

admin "sessions/$session/stop" '{"actor":"gateway-test","reason":"test"}' >/dev/null
test "$(model "$key" "$session")" = 403
grep -q '세션' "$work/model.out"
admin "sessions/$session/release" '{"actor":"gateway-test"}' >/dev/null

admin users/ana@example.com/revoke '{"actor":"gateway-test"}' >/dev/null
test "$(model "$key" other-session-$suffix)" = 403
grep -q '사용자' "$work/model.out"

echo "- the gateway's request log names the record and keeps no content"
sleep 2
logged=$(psql_engine "SELECT count(*) FROM request_logs r JOIN model_calls m ON m.request_id = r.attributes_json->>'withhuman_request' WHERE m.session_id = '$session'")
test "$logged" -ge 1
test "$(psql_engine "SELECT count(*) FROM request_log_payloads")" = 0
