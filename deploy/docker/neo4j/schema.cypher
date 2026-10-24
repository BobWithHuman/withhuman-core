CREATE CONSTRAINT session_id_unique IF NOT EXISTS
FOR (session:Session)
REQUIRE session.session_id IS UNIQUE;

CREATE CONSTRAINT event_commit_order_unique IF NOT EXISTS
FOR (commit:EventCommit)
REQUIRE (commit.session_id, commit.order) IS UNIQUE;

CREATE CONSTRAINT execution_node_seq_unique IF NOT EXISTS
FOR (node:ExecutionNode)
REQUIRE (node.session_id, node.seq) IS UNIQUE;

CREATE CONSTRAINT paragraph_hash_unique IF NOT EXISTS
FOR (paragraph:Paragraph)
REQUIRE paragraph.hash IS UNIQUE;

CREATE CONSTRAINT verdict_call_unique IF NOT EXISTS
FOR (verdict:Verdict)
REQUIRE (verdict.session_id, verdict.call_seq) IS UNIQUE;

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

CREATE INDEX execution_node_type IF NOT EXISTS
FOR (node:ExecutionNode)
ON (node.type);

CREATE INDEX execution_node_tool_use_id IF NOT EXISTS
FOR (node:ExecutionNode)
ON (node.tool_use_id);

CREATE INDEX execution_node_prompt_id IF NOT EXISTS
FOR (node:ExecutionNode)
ON (node.prompt_id);

CREATE INDEX event_commit_observed_at IF NOT EXISTS
FOR (commit:EventCommit)
ON (commit.observed_at);

CREATE INDEX execution_node_session_order IF NOT EXISTS
FOR (node:ExecutionNode)
ON (node.session_id, node.order);
