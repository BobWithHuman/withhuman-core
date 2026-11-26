# Administration

## Keys and the agent inventory

The engine records which device and which user run each agent session. Every setup registers
its device (`POST /v1/clients/register`: client ID, team, host name, OS, OS user, hook version,
project folder and, where the user may read it, the hardware serial number); a setup that cannot
reach the engine still completes and says so.

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

The inventory keeps two people for a device: `user`, whoever's key it presented last, and
`owner`, the person the security team names for the machine. Name or clear the owner with
`POST /v1/admin/clients/<client_id>/owner` and `{"owner": "<email>" | null, "actor": ...}`. A
client ID holds a slash (`<team>/<uuid>`), sent as one path segment: `team%2F<uuid>`.

```sh
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"owner": "ana@example.com", "actor": "security@example.com"}' \
  http://127.0.0.1:3000/v1/admin/clients/platform%2F6f1c0d1e-0000-4000-8000-000000000000/owner
```

The security team can also stop one device: `POST /v1/admin/clients/<client_id>/stop` with
`{"stopped": true, "actor": ..., "reason": ...}` denies every tool call whose Hook carries that
client ID, in every mode, until `{"stopped": false}` releases it. The device's other Hooks are
still recorded. An unknown device is a 404; a device already stopped keeps its first stop. The
stop applies at once on the Collector that took it and within `WITHHUMAN_KEY_CACHE_MS` on the
others; a tool call already past its PreToolUse Hook is not interrupted. The device shows a fixed
message, never the team's `reason`. `clients.stopped_at`, `stopped_by` and `stop_reason` hold the
stop (all null while the device runs), and `stop_denied_count` and `stop_last_denied_at` the calls
refused for it.

```sh
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"stopped": true, "actor": "security@example.com", "reason": "lost laptop"}' \
  http://127.0.0.1:3000/v1/admin/clients/platform%2F6f1c0d1e-0000-4000-8000-000000000000/stop
```

A stop is not a lock on the machine. The client ID is a header the device's own Hooks send
(`~/.config/withhuman/client-id`), so a device that sends another ID, or none, or whose Hooks were
removed, is not stopped, and `WITHHUMAN_REQUIRE_KEY` does not change that: a key names a person,
not a machine. It stops a device that keeps running its installed Hooks. To stop a person
whatever they run, revoke their keys with `WITHHUMAN_REQUIRE_KEY=on`. Tool calls that reach the
engine through AgentGateway alone (MCP, without a Hook) are not covered, as with a revoked key.

## Triage

The security team records what it decided about a session it looked at, for the whole team:
`session_marks` and `distrusted_sources` in PostgreSQL, which the viewer reads. Both are set
through the admin API. A mark is a record only. A distrusted source also holds what it causes:
when the engine traces a tool call to a tool result (`cause.link` is `segment`) and the call that
produced that result is on a distrusted source, a call the engine would otherwise allow is put to
the user for review instead (rule `source::distrusted`), or denied with
`WITHHUMAN_DISTRUSTED_SOURCE_DENY=1`. The rule only makes a verdict stricter: a call already
denied or held keeps its verdict and rule. Reading the source is not blocked, only what its
content then causes. A result's source is the path, URL or folder-relative path its call named, or
its tool's name, as the evidence shows it. A source distrusted now holds the calls decided from
now on; the list is read for each such call, so there is nothing to wait out. If the list cannot
be read within 250 ms the call is decided without it, with a warning in Decision's log and
`source.error` in the call's trace. The matched source is kept in the call's trace
(`nodes.trace_json`, `source.distrusted`) and never shown to the agent.

`POST /v1/admin/sessions/<session_id>/mark` with `{"state": ..., "actor": ...}` marks a session
`reviewing`, `attack`, `benign` or `closed`, replaces its mark, or with `"state": null` takes it
off (a session without a mark was not handled yet); a session the engine does not hold is a 404.
`POST /v1/admin/sessions/mark` with `{"session_ids": [...], "state": ..., "actor": ...}` does the
same for up to 1000 sessions together and answers with `sessions` (each with its mark) and
`unknown`, the ones the engine does not hold, which it leaves alone. `POST /v1/admin/sources/distrust` with
`{"source": ..., "on": true | false, "actor": ..., "session_id": ..., "seq": ...}` distrusts a
source (a document's path, a URL or a tool's name) or with `on: false` trusts it again;
`session_id` and `seq`, the tool call that showed the source, are optional. The source goes in
the body as written, since it may be a URL or a path.

```sh
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"state": "attack", "actor": "security@example.com"}' \
  http://127.0.0.1:3000/v1/admin/sessions/0b9f6c1e-0000-4000-8000-000000000001/mark
curl -X POST -H "Authorization: Bearer $WITHHUMAN_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"source": "https://example.com/setup.md", "on": true, "actor": "security@example.com"}' \
  http://127.0.0.1:3000/v1/admin/sources/distrust
```

`GET /v1/admin/sessions/<session_id>/calls/<seq>/evidence` returns one tool call's evidence as
JSON for other systems (`"schema": "withhuman.evidence/v1"`): the call (tool, input, target,
time, device, user), the engine's decision (reason, rule, mode), the person's request before
it, what the engine traced the call to (`cause.link`: `request`, `segment` or `none`; for
`segment` the tool results in `cause.told_by`, each with the call whose result it was, the
paragraph, its text and the probability), the session's mark, and whether the cause's source
is distrusted. `seq` is the call's number in its session (`nodes.seq`). An unknown session or
call is a 404. Text is as the engine stored it, sensitive values already replaced; no key or
key hash is in it. The full shape is in the Collector's OpenAPI document (`/swagger-ui`).

## The security team's viewer

The viewer reads PostgreSQL directly, read-only, as `withhuman_viewer`. The Generator creates that
login when `WITHHUMAN_VIEWER_PASSWORD` is set, and the schema grants it SELECT on the graph,
inventory and triage tables (`api_keys` without its hash) and nothing else. The personal stack publishes
PostgreSQL on `127.0.0.1:15432` (`POSTGRES_PORT`):
`postgres://withhuman_viewer:<WITHHUMAN_VIEWER_PASSWORD>@127.0.0.1:15432/withhuman`.
