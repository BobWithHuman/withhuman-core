CREATE CONSTRAINT session_id_unique IF NOT EXISTS
FOR (session:Session)
REQUIRE session.session_id IS UNIQUE;

CREATE CONSTRAINT event_commit_order_unique IF NOT EXISTS
FOR (commit:EventCommit)
REQUIRE (commit.session_id, commit.order) IS UNIQUE;

CREATE CONSTRAINT file_repository_path_unique IF NOT EXISTS
FOR (file:File)
REQUIRE (file.repository, file.path) IS UNIQUE;

CREATE CONSTRAINT pending_paragraph_enrichment_unique IF NOT EXISTS
FOR (pending:PendingParagraphEnrichment)
REQUIRE (pending.session_id, pending.hash) IS UNIQUE;

CREATE CONSTRAINT pending_request_continuation_unique IF NOT EXISTS
FOR (pending:PendingRequestContinuation)
REQUIRE (pending.session_id, pending.order) IS UNIQUE;

CREATE CONSTRAINT token_key_unique IF NOT EXISTS
FOR (token:Token)
REQUIRE (token.session_id, token.key_kind, token.key, token.slot) IS UNIQUE;

CREATE INDEX event_commit_observed_at IF NOT EXISTS
FOR (commit:EventCommit)
ON (commit.observed_at);


// Nodes were once all `ExecutionNode` with their kind in `type`, and Decision verdicts were
// separate `Verdict` nodes. Each node now carries its kind as its only label, and the verdict
// lives on the Call.
DROP CONSTRAINT execution_node_seq_unique IF EXISTS;
DROP CONSTRAINT verdict_call_unique IF EXISTS;
DROP INDEX execution_node_type IF EXISTS;
DROP INDEX execution_node_tool_use_id IF EXISTS;
DROP INDEX execution_node_prompt_id IF EXISTS;
DROP INDEX execution_node_session_order IF EXISTS;

// Tool results were typed `Sequence` before session-wide sequences existed.
MATCH (node:ExecutionNode {type: 'Sequence'})
SET node.type = 'Segment';

MATCH (node:ExecutionNode)
CALL (node) {
  SET node:$(node.type)
  REMOVE node:ExecutionNode, node.type
} IN TRANSACTIONS OF 5000 ROWS;

MATCH (call:Call)-[:HAS_VERDICT]->(verdict:Verdict)
SET call.decision_mode = coalesce(call.decision_mode, verdict.mode),
    call.decision_jev_json = coalesce(call.decision_jev_json, verdict.jev_json),
    call.decided_at = coalesce(call.decided_at, verdict.updated_at);

MATCH (verdict:Verdict)
CALL (verdict) {
  DETACH DELETE verdict
} IN TRANSACTIONS OF 5000 ROWS;

// The groups of a Message with its Calls and their results were once `Sequence` nodes, and
// each node carried its group number as `session_sequence`. They are now `SubGraph` nodes and
// `subgraph`. Tool results from before then may still carry `Sequence` beside `Segment`. They
// are not groups and stay as they are.
DROP CONSTRAINT sequence_number_unique IF EXISTS;

MATCH (group:Sequence) WHERE NOT group:Segment
CALL (group) {
  SET group:SubGraph
  REMOVE group:Sequence
} IN TRANSACTIONS OF 5000 ROWS;

MATCH (node) WHERE node.session_sequence IS NOT NULL
CALL (node) {
  SET node.subgraph = node.session_sequence
  REMOVE node.session_sequence
} IN TRANSACTIONS OF 5000 ROWS;

// Queries reach a session's nodes through the Session's CONTAINS edges. Tool results from
// before every node got one are given theirs.
MATCH (node:Request|Intent|Message|Call|Segment|Error|ToolBatch|SubagentStart|SubagentStop|ConfigChange|ToolDescriptions)
WHERE NOT EXISTS { MATCH (:Session)-[:CONTAINS]->(node) }
MATCH (session:Session {session_id: node.session_id})
CALL (session, node) {
  MERGE (session)-[:CONTAINS]->(node)
} IN TRANSACTIONS OF 5000 ROWS;

// Edges lead from a Call up to its causes and from a tool result up to its Call, so a chain of
// causes can be followed to the prompt. Results pointed down from their Call (`RESULTED_IN`),
// and the activated ones pointed down at the Call they caused.
MATCH (result:Segment|Error) WHERE result.tool_use_id IS NOT NULL
  AND NOT EXISTS { MATCH (result)-[:RESULT_OF]->() }
MATCH (call:Call {session_id: result.session_id, tool_use_id: result.tool_use_id})
CALL (result, call) {
  MERGE (result)-[:RESULT_OF]->(call)
} IN TRANSACTIONS OF 5000 ROWS;

MATCH ()-[old:RESULTED_IN]->()
CALL (old) {
  DELETE old
} IN TRANSACTIONS OF 5000 ROWS;

MATCH (source:Segment|Error)-[old:NEXT {kind: 'cause'}]->(call:Call)
CALL (source, old, call) {
  MERGE (call)-[cause:NEXT {kind: 'cause', call_seq: old.call_seq}]->(source)
  SET cause += properties(old)
  DELETE old
} IN TRANSACTIONS OF 5000 ROWS;

// A Call traced to a prompt's SubGraph points its cause at the prompt's Request.
MATCH (current:SubGraph)-[parent:PARENT]->(:SubGraph)-[:MEMBER]->(request:Request)
MATCH (call:Call {session_id: current.session_id, seq: parent.call_seq})
CALL (parent, request, call) {
  MERGE (call)-[cause:NEXT {kind: 'cause', call_seq: parent.call_seq}]->(request)
  SET cause.probability = parent.probability, cause.rank = parent.rank,
      cause.parent = 's' + toString(parent.number)
} IN TRANSACTIONS OF 5000 ROWS;

CREATE CONSTRAINT subgraph_number_unique IF NOT EXISTS
FOR (subgraph:SubGraph)
REQUIRE (subgraph.session_id, subgraph.number) IS UNIQUE;

// InstructionsLoaded and FileChanged Hooks are no longer received. Nodes they left stay as they
// are, without a constraint or index.
DROP CONSTRAINT instructions_seq_unique IF EXISTS;
DROP CONSTRAINT file_changed_seq_unique IF EXISTS;
DROP INDEX instructions_session_order IF EXISTS;
DROP INDEX file_changed_session_order IF EXISTS;

// One constraint and one order index per node kind, the labels of `node_labels!` in
// withhuman-common.
CREATE CONSTRAINT request_seq_unique IF NOT EXISTS
FOR (node:Request) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT intent_seq_unique IF NOT EXISTS
FOR (node:Intent) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT message_seq_unique IF NOT EXISTS
FOR (node:Message) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT call_seq_unique IF NOT EXISTS
FOR (node:Call) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT segment_seq_unique IF NOT EXISTS
FOR (node:Segment) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT error_seq_unique IF NOT EXISTS
FOR (node:Error) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT tool_batch_seq_unique IF NOT EXISTS
FOR (node:ToolBatch) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT subagent_start_seq_unique IF NOT EXISTS
FOR (node:SubagentStart) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT subagent_stop_seq_unique IF NOT EXISTS
FOR (node:SubagentStop) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT config_change_seq_unique IF NOT EXISTS
FOR (node:ConfigChange) REQUIRE (node.session_id, node.seq) IS UNIQUE;
CREATE CONSTRAINT tool_descriptions_seq_unique IF NOT EXISTS
FOR (node:ToolDescriptions) REQUIRE (node.session_id, node.seq) IS UNIQUE;

CREATE INDEX request_session_order IF NOT EXISTS
FOR (node:Request) ON (node.session_id, node.order);
CREATE INDEX intent_session_order IF NOT EXISTS
FOR (node:Intent) ON (node.session_id, node.order);
CREATE INDEX message_session_order IF NOT EXISTS
FOR (node:Message) ON (node.session_id, node.order);
CREATE INDEX call_session_order IF NOT EXISTS
FOR (node:Call) ON (node.session_id, node.order);
CREATE INDEX segment_session_order IF NOT EXISTS
FOR (node:Segment) ON (node.session_id, node.order);
CREATE INDEX error_session_order IF NOT EXISTS
FOR (node:Error) ON (node.session_id, node.order);
CREATE INDEX tool_batch_session_order IF NOT EXISTS
FOR (node:ToolBatch) ON (node.session_id, node.order);
CREATE INDEX subagent_start_session_order IF NOT EXISTS
FOR (node:SubagentStart) ON (node.session_id, node.order);
CREATE INDEX subagent_stop_session_order IF NOT EXISTS
FOR (node:SubagentStop) ON (node.session_id, node.order);
CREATE INDEX config_change_session_order IF NOT EXISTS
FOR (node:ConfigChange) ON (node.session_id, node.order);
CREATE INDEX tool_descriptions_session_order IF NOT EXISTS
FOR (node:ToolDescriptions) ON (node.session_id, node.order);

CREATE INDEX call_tool_use_id IF NOT EXISTS
FOR (node:Call) ON (node.tool_use_id);

// Paragraphs were once shared by every node holding the same text, keyed by hash alone. Each
// now belongs to the one tool result it was cut from. The old ones are dropped here and rebuilt
// with `withhuman-generator reindex-paragraphs`.
DROP CONSTRAINT paragraph_hash_unique IF EXISTS;

MATCH (paragraph:Paragraph) WHERE paragraph.session_id IS NULL
CALL (paragraph) {
  DETACH DELETE paragraph
} IN TRANSACTIONS OF 5000 ROWS;

CREATE CONSTRAINT paragraph_node_unique IF NOT EXISTS
FOR (paragraph:Paragraph) REQUIRE (paragraph.session_id, paragraph.seq, paragraph.index) IS UNIQUE;

CREATE INDEX paragraph_session_hash IF NOT EXISTS
FOR (paragraph:Paragraph) ON (paragraph.session_id, paragraph.hash);
