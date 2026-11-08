-- The graph viewer's own login: it reads the graph and deletes whole sessions, nothing else.
-- Run once as the database owner, after the engine has created its tables:
--
--   docker compose exec -T postgres psql -U withhuman -d withhuman \
--     -v viewer_password="$VIEWER_DB_PASSWORD" < tools/graph-viewer/viewer-role.sql
--
-- Running it again resets the password and the grants.

SELECT format('CREATE ROLE withhuman_viewer LOGIN PASSWORD %L', :'viewer_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'withhuman_viewer') \gexec
SELECT format('ALTER ROLE withhuman_viewer LOGIN PASSWORD %L', :'viewer_password') \gexec

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM withhuman_viewer;
GRANT USAGE ON SCHEMA public TO withhuman_viewer;
GRANT SELECT ON sessions, event_commits, nodes, subgraphs, paragraphs, tokens, token_mentions,
  files, file_refs, cause_edges, pending_paragraph_enrichments, pending_request_continuations
  TO withhuman_viewer;
-- Deleting a session removes its rows from every table but `files`, which sessions share.
GRANT DELETE ON sessions, event_commits, nodes, subgraphs, paragraphs, tokens, token_mentions,
  file_refs, cause_edges, pending_paragraph_enrichments, pending_request_continuations
  TO withhuman_viewer;
