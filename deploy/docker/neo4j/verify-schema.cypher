SHOW CONSTRAINTS YIELD name
WHERE name IN [
  'session_id_unique',
  'event_commit_order_unique',
  'execution_node_seq_unique',
  'execution_piece_hash_unique',
  'verdict_call_unique',
  'file_repository_path_unique',
  'pending_piece_enrichment_unique',
  'pending_request_continuation_unique',
  'token_key_unique'
]
RETURN count(*) = 9 AS schema_ready;

SHOW INDEXES YIELD name
WHERE name IN [
  'execution_node_type',
  'execution_node_tool_use_id',
  'execution_node_prompt_id',
  'event_commit_observed_at'
]
RETURN count(*) = 4 AS schema_ready;
