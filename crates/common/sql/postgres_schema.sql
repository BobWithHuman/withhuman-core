-- The execution graph in PostgreSQL, the relational counterpart of neo4j/schema.cypher.
--
-- Every node kind of `node_labels!` is a row of `nodes`, its kind in `kind`. Edges that only
-- restate a node's own columns are not stored: CONTAINS and COMMITTED are `session_id`, CREATED
-- is `(session_id, "order")`, MEMBER is `subgraph`, RESULT_OF is a Call and a result sharing
-- `tool_use_id`, AGENT_SEQUENCE is `(agent_id, sequence)` and the next sequence. A node has at
-- most one structural NEXT leading to it, kept on the node as `next_seq` and `next_via`. Text
-- the services read back as JSON (`payload_json`, `event_json`, `trace_json`) stays the string
-- that was written, so its bytes match what Neo4j keeps.

CREATE TABLE IF NOT EXISTS sessions (
  session_id  text   PRIMARY KEY,
  version     bigint NOT NULL DEFAULT 0,
  created_at  bigint
);

CREATE TABLE IF NOT EXISTS event_commits (
  session_id   text    NOT NULL,
  "order"      bigint  NOT NULL,
  version      bigint  NOT NULL,
  event_name   text    NOT NULL,
  observed_at  bigint,
  client_id    text,
  event_json   text    NOT NULL,
  cwd          text,
  prompt_id    text,
  has_node     boolean NOT NULL,
  PRIMARY KEY (session_id, "order")
);
CREATE INDEX IF NOT EXISTS event_commits_observed_at ON event_commits (observed_at);

CREATE TABLE IF NOT EXISTS nodes (
  session_id   text   NOT NULL,
  seq          bigint NOT NULL,
  kind         text   NOT NULL,
  event_name   text   NOT NULL,
  "order"      bigint NOT NULL,
  observed_at  bigint,
  client_id    text,
  sequence     bigint,
  prompt_id    text,
  agent_id     text,
  agent_type   text,
  cwd          text,
  tool_use_id  text,
  turn_id      text,
  repository   text,
  intent       text,
  subgraph     bigint,
  payload_json text,
  -- The structural NEXT leading here: from the node `next_seq`, `via` call|message|request|order.
  next_seq     bigint,
  next_via     text,
  -- A Request's continuation of an earlier one (side-channel enrichment).
  continues                        bigint,
  continuation_choice              text,
  continuation_probabilities_json  text,
  continuation_jev_ms              bigint,
  continuation_error               text,
  -- A Call's verdict and trace, written by Decision.
  decision          text,
  decision_reason   text,
  decision_rule     text,
  decision_start    text,
  decision_version  bigint,
  decision_mode     text,
  decision_jev_json text,
  decided_at        bigint,
  parent            text,
  parents           text[],
  trace_json        text,
  intent_score      double precision,
  trace_error       text,
  PRIMARY KEY (session_id, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_session_order ON nodes (session_id, "order");
CREATE INDEX IF NOT EXISTS nodes_session_kind_order ON nodes (session_id, kind, "order");
CREATE INDEX IF NOT EXISTS nodes_session_subgraph_order ON nodes (session_id, subgraph, "order");
CREATE INDEX IF NOT EXISTS nodes_session_tool_use_id ON nodes (session_id, tool_use_id)
  WHERE tool_use_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS nodes_session_agent_sequence ON nodes (session_id, agent_id, sequence)
  WHERE agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS nodes_tool_use_id ON nodes (tool_use_id) WHERE kind = 'Call';

CREATE TABLE IF NOT EXISTS subgraphs (
  session_id         text   NOT NULL,
  number             bigint NOT NULL,
  parent             text,
  parents            text[],
  parent_call_seq    bigint,
  parent_call_order  bigint,
  PRIMARY KEY (session_id, number)
);

CREATE TABLE IF NOT EXISTS paragraphs (
  session_id      text    NOT NULL,
  seq             bigint  NOT NULL,
  "index"         bigint  NOT NULL,
  hash            text    NOT NULL,
  text            text,
  source          text,
  hidden          boolean,
  hidden_rules    text[],
  from_user_doc   boolean,
  long_paragraph  boolean,
  instructs       double precision,
  jev_ms          bigint,
  jev_error       text,
  PRIMARY KEY (session_id, seq, "index")
);
CREATE INDEX IF NOT EXISTS paragraphs_session_hash ON paragraphs (session_id, hash);
CREATE INDEX IF NOT EXISTS paragraphs_hidden ON paragraphs (session_id, seq) WHERE hidden;

CREATE TABLE IF NOT EXISTS tokens (
  session_id  text   NOT NULL,
  key_kind    text   NOT NULL,
  key         text   NOT NULL,
  slot        text   NOT NULL,
  node_seq    bigint NOT NULL,
  node_order  bigint NOT NULL,
  decoded     text,
  category    text,
  version     bigint,
  PRIMARY KEY (session_id, key_kind, key, slot)
);

-- MENTIONS_TOKEN: a node mentioned a token (the token's own slot is the edge's slot).
CREATE TABLE IF NOT EXISTS token_mentions (
  session_id  text   NOT NULL,
  node_seq    bigint NOT NULL,
  key_kind    text   NOT NULL,
  key         text   NOT NULL,
  slot        text   NOT NULL,
  PRIMARY KEY (session_id, node_seq, key_kind, key, slot)
);
CREATE INDEX IF NOT EXISTS token_mentions_key ON token_mentions (session_id, key_kind, key);

CREATE TABLE IF NOT EXISTS files (
  repository  text NOT NULL,
  path        text NOT NULL,
  PRIMARY KEY (repository, path)
);

-- REFERENCES_FILE
CREATE TABLE IF NOT EXISTS file_refs (
  session_id  text   NOT NULL,
  node_seq    bigint NOT NULL,
  repository  text   NOT NULL,
  path        text   NOT NULL,
  PRIMARY KEY (session_id, node_seq, repository, path)
);

-- NEXT {kind: 'cause'}: from the Call `call_seq` up to a Request, a tool result
-- (`target_index` -1) or one of its paragraphs (`target_index` the paragraph's index).
CREATE TABLE IF NOT EXISTS cause_edges (
  session_id    text   NOT NULL,
  call_seq      bigint NOT NULL,
  target_seq    bigint NOT NULL,
  target_index  bigint NOT NULL DEFAULT -1,
  probability   double precision,
  rank          bigint,
  parent        text,
  PRIMARY KEY (session_id, call_seq, target_seq, target_index)
);
CREATE INDEX IF NOT EXISTS cause_edges_target ON cause_edges (session_id, target_seq, target_index);

CREATE TABLE IF NOT EXISTS pending_paragraph_enrichments (
  session_id  text NOT NULL,
  hash        text NOT NULL,
  instructs   double precision,
  jev_ms      bigint,
  error       text,
  PRIMARY KEY (session_id, hash)
);

CREATE TABLE IF NOT EXISTS pending_request_continuations (
  session_id          text   NOT NULL,
  "order"             bigint NOT NULL,
  choice              text,
  choice_order        bigint,
  probabilities_json  text,
  jev_ms              bigint,
  error               text,
  PRIMARY KEY (session_id, "order")
);

-- Agent inventory: the devices that run agents, the users behind them and their keys.
--
-- (:Client)-[:RAN]->(:Session) is `sessions.client_id`, the first client ID the session's
-- Hooks carried; (:User)-[:HAS_KEY]->(:ApiKey) is `api_keys.user_email`. A Client exists for
-- every client ID a Hook carried (`first_seen`, `last_seen`) and for every device a setup
-- registered (`registered_at`); a Session whose Hooks carried none keeps `client_id` NULL.

-- A device. `last_seen` moves at most every 30 s, so busy devices do not queue on the row.
CREATE TABLE IF NOT EXISTS clients (
  client_id      text PRIMARY KEY,
  team           text,
  hostname       text,
  os             text,
  os_user        text,
  hook_version   text,
  agent          text,
  -- The user of the latest key the device presented.
  user_email     text,
  -- First and latest registration by a setup; NULL for a device only seen through its Hooks.
  registered_at  bigint,
  updated_at     bigint,
  -- First and latest Hook event.
  first_seen     bigint,
  last_seen      bigint
);
CREATE INDEX IF NOT EXISTS clients_last_seen ON clients (last_seen);

-- INSTALLED_IN: a project folder a setup wrote the Hooks into.
CREATE TABLE IF NOT EXISTS client_projects (
  client_id     text   NOT NULL,
  project       text   NOT NULL,
  agent         text,
  hook_version  text,
  installed_at  bigint NOT NULL,
  updated_at    bigint NOT NULL,
  PRIMARY KEY (client_id, project)
);

CREATE TABLE IF NOT EXISTS users (
  email       text   PRIMARY KEY,
  created_at  bigint NOT NULL
);

-- A WithHuman key: its id and the SHA-256 of the whole key, never the key itself.
CREATE TABLE IF NOT EXISTS api_keys (
  key_id           text   PRIMARY KEY,
  user_email       text   NOT NULL REFERENCES users (email),
  hash             text   NOT NULL,
  created_at       bigint NOT NULL,
  created_by       text,
  note             text,
  -- Moves at most once a minute.
  last_used_at     bigint,
  revoked_at       bigint,
  revoked_by       text,
  revoke_reason    text,
  -- PreToolUse calls turned back after the revocation.
  first_denied_at  bigint,
  last_denied_at   bigint,
  denied_count     bigint NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS api_keys_user ON api_keys (user_email);

-- The keys' audit trail: `issued` (actor, reason = note), `revoked` (actor, reason) and
-- `denied`, once per key and session (session_id, client_id).
CREATE TABLE IF NOT EXISTS key_events (
  id          bigserial PRIMARY KEY,
  key_id      text   NOT NULL,
  user_email  text   NOT NULL,
  kind        text   NOT NULL,
  actor       text,
  reason      text,
  session_id  text,
  client_id   text,
  at          bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS key_events_key ON key_events (key_id, kind);
CREATE INDEX IF NOT EXISTS key_events_at ON key_events (at);

-- Columns added to tables that held data before the inventory. Each table's columns are
-- added together, once: ALTER TABLE locks the table even when there is nothing to add. The
-- sessions recorded before get their client, last activity and start source from their
-- commits, and every client ID they carried becomes a Client.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                 AND table_name = 'sessions' AND column_name = 'client_id') THEN
    ALTER TABLE sessions
      ADD COLUMN client_id        text,
      ADD COLUMN user_email       text,
      -- The latest SessionStart's `source`: startup, resume, clear, compact or fork.
      ADD COLUMN start_source     text,
      -- The latest values the Hooks reported.
      ADD COLUMN permission_mode  text,
      ADD COLUMN model            text,
      ADD COLUMN last_seen_at     bigint,
      -- The latest SessionEnd, cleared by a later SessionStart.
      ADD COLUMN ended_at         bigint,
      ADD COLUMN end_reason       text;
    UPDATE sessions s SET client_id = c.client_id, last_seen_at = c.last_seen
    FROM (SELECT session_id,
                 (array_agg(client_id ORDER BY "order") FILTER (WHERE client_id IS NOT NULL))[1]
                   AS client_id,
                 max(observed_at) AS last_seen
          FROM event_commits GROUP BY session_id) c
    WHERE s.session_id = c.session_id;
    UPDATE sessions s SET start_source = x.source
    FROM (SELECT DISTINCT ON (session_id) session_id,
                 substring(event_json FROM '"source":"([^"]*)"') AS source
          FROM event_commits WHERE event_name = 'SessionStart'
          ORDER BY session_id, "order" DESC) x
    WHERE s.session_id = x.session_id;
    INSERT INTO clients (client_id, team, first_seen, last_seen)
    SELECT client_id, CASE WHEN position('/' IN client_id) > 0 THEN split_part(client_id, '/', 1) END,
           min(observed_at), max(observed_at)
    FROM event_commits WHERE client_id IS NOT NULL GROUP BY client_id
    ON CONFLICT (client_id) DO NOTHING;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                 AND table_name = 'nodes' AND column_name = 'permission_mode') THEN
    -- The values at the node's event: a Call's permission mode, and the session's model.
    ALTER TABLE nodes ADD COLUMN permission_mode text, ADD COLUMN model text;
  END IF;
END
$$;
CREATE INDEX IF NOT EXISTS sessions_client ON sessions (client_id);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_email);
CREATE INDEX IF NOT EXISTS sessions_last_seen ON sessions (last_seen_at);

-- A session the security team stopped (until `released_at`): its PreToolUse calls are denied.
-- At most one stop of a session is active; released ones stay for the audit.
CREATE TABLE IF NOT EXISTS session_stops (
  id               bigserial PRIMARY KEY,
  session_id       text   NOT NULL,
  stopped_at       bigint NOT NULL,
  stopped_by       text,
  reason           text,
  released_at      bigint,
  released_by      text,
  release_reason   text,
  first_denied_at  bigint,
  last_denied_at   bigint,
  denied_count     bigint NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS session_stops_active ON session_stops (session_id)
  WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS session_stops_stopped_at ON session_stops (stopped_at);

-- The security team's reviews of Calls after the fact, `(session_id, seq)` naming the Call.
-- Each review is kept; `call_review_latest` is the one that stands.
CREATE TABLE IF NOT EXISTS call_reviews (
  id          bigserial PRIMARY KEY,
  session_id  text   NOT NULL,
  seq         bigint NOT NULL,
  status      text   NOT NULL CHECK (status IN ('unreviewed', 'no_issue', 'issue')),
  note        text,
  actor       text,
  at          bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS call_reviews_call ON call_reviews (session_id, seq, id);

CREATE OR REPLACE VIEW call_review_latest AS
SELECT DISTINCT ON (session_id, seq) id, session_id, seq, status, note, actor, at
FROM call_reviews ORDER BY session_id, seq, id DESC;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                 AND table_name = 'users' AND column_name = 'kind') THEN
    -- `person`, or `service` for an automation (CI) with keys of its own.
    ALTER TABLE users ADD COLUMN kind text NOT NULL DEFAULT 'person';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                 AND table_name = 'clients' AND column_name = 'test') THEN
    -- Benchmark and test runs name themselves `bench/...`, so the inventory can leave them out.
    ALTER TABLE clients ADD COLUMN test boolean GENERATED ALWAYS AS (client_id LIKE 'bench/%') STORED;
  END IF;
END
$$;

-- Every stop in one place, for the audit: what was stopped (`key`: a user's key, `session`),
-- whose, by whom, when and why, when it was released, and when it first turned a call back.
CREATE OR REPLACE VIEW stop_audit AS
SELECT 'key'::text AS target, k.user_email, NULL::text AS session_id, k.key_id,
       e.actor AS stopped_by, e.reason, e.at AS stopped_at,
       NULL::bigint AS released_at, NULL::text AS released_by, NULL::text AS release_reason,
       k.first_denied_at, k.last_denied_at, k.denied_count
FROM key_events e JOIN api_keys k ON k.key_id = e.key_id
WHERE e.kind = 'revoked'
UNION ALL
SELECT 'session', s.user_email, t.session_id, NULL, t.stopped_by, t.reason, t.stopped_at,
       t.released_at, t.released_by, t.release_reason, t.first_denied_at, t.last_denied_at,
       t.denied_count
FROM session_stops t LEFT JOIN sessions s ON s.session_id = t.session_id;

-- Indexes for reading across sessions: every Call in a period, and every mention of a
-- sensitive token (any category but `address`).
CREATE INDEX IF NOT EXISTS nodes_calls_observed_at ON nodes (observed_at) WHERE kind = 'Call';
CREATE INDEX IF NOT EXISTS tokens_sensitive ON tokens (category, session_id)
  WHERE category <> 'address';

-- What the security team's viewer reads: role `withhuman_viewer`, which the Generator creates
-- when WITHHUMAN_VIEWER_PASSWORD is set. SELECT only, and only here: every table of this file
-- is listed below (a test checks it), and grants made elsewhere, such as an earlier viewer's
-- DELETE, are taken back. `api_keys` is readable without its `hash`.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'withhuman_viewer') THEN
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM withhuman_viewer', current_schema());
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM withhuman_viewer', current_schema());
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO withhuman_viewer', current_schema());
    GRANT SELECT ON
      sessions, event_commits, nodes, subgraphs, paragraphs, tokens, token_mentions, files,
      file_refs, cause_edges, pending_paragraph_enrichments, pending_request_continuations,
      clients, client_projects, users, key_events, session_stops, call_reviews,
      call_review_latest, stop_audit
    TO withhuman_viewer;
    GRANT SELECT (key_id, user_email, created_at, created_by, note, last_used_at, revoked_at,
      revoked_by, revoke_reason, first_denied_at, last_denied_at, denied_count)
    ON api_keys TO withhuman_viewer;
  END IF;
END
$$;
