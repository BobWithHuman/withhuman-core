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
