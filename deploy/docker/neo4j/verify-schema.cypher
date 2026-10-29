SHOW CONSTRAINTS YIELD name
WHERE name IN [
  'session_id_unique',
  'event_commit_order_unique',
  'paragraph_node_unique',
  'file_repository_path_unique',
  'pending_paragraph_enrichment_unique',
  'pending_request_continuation_unique',
  'token_key_unique',
  'subgraph_number_unique',
  'request_seq_unique',
  'intent_seq_unique',
  'message_seq_unique',
  'call_seq_unique',
  'segment_seq_unique',
  'error_seq_unique',
  'tool_batch_seq_unique',
  'subagent_start_seq_unique',
  'subagent_stop_seq_unique',
  'config_change_seq_unique',
  'tool_descriptions_seq_unique'
]
RETURN count(*) = 19 AS schema_ready;

SHOW INDEXES YIELD name
WHERE name IN [
  'event_commit_observed_at',
  'call_session_order',
  'segment_session_order',
  'call_tool_use_id',
  'paragraph_session_hash'
]
RETURN count(*) = 5 AS schema_ready;
