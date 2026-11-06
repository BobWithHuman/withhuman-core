//! PostgreSQL storage for the execution graph.

use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::{GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod};
use serde_json::{Value, json};
use tokio_postgres::{NoTls, Row, error::SqlState, types::ToSql};
use withhuman_contracts::events::{
    CreatedNode, EventResponse, ParagraphClassificationRequest, ParagraphClassificationResponse,
    ParagraphReference, RequestContinuationRequest, RequestContinuationResponse, SessionCursor,
    SubGraphCursor, ToolCall,
};

use crate::{
    GeneratorEvent,
    event::GraphMutation,
    repository::{GraphRepository, ReindexReport, RepositoryError},
};

/// Commits of one session queue on its row.
/// A session's first commits may race to create the row; ON CONFLICT makes the loser wait.
const INSERT_SESSION: &str = "\
INSERT INTO sessions (session_id, version, created_at) VALUES ($1::text, 0, $2::bigint) \
ON CONFLICT (session_id) DO NOTHING";

const LOCK_SESSION: &str = "\
SELECT version FROM sessions WHERE session_id = $1::text FOR UPDATE";

const FIND_COMMIT: &str = "\
SELECT version, event_json FROM event_commits WHERE session_id = $1::text AND \"order\" = $2::bigint";

// A SubagentStop of an agent no SubagentStart announced keeps a commit without a node.
const SUBAGENT_STARTED: &str = "\
SELECT EXISTS (SELECT 1 FROM nodes WHERE session_id = $1::text AND kind = 'SubagentStart' \
AND agent_id = $2::text)";

const BUMP_VERSION: &str = "\
UPDATE sessions SET version = $2::bigint WHERE session_id = $1::text";

const INSERT_COMMIT: &str = "\
INSERT INTO event_commits (session_id, \"order\", version, event_name, observed_at, client_id, \
event_json, cwd, prompt_id, has_node) \
VALUES ($1::text, $2::bigint, $3::bigint, $4::text, $5::bigint, $6::text, $7::text, $8::text, \
$9::text, $10::boolean)";

const INSERT_NODE: &str = "\
INSERT INTO nodes (session_id, seq, kind, event_name, \"order\", observed_at, client_id, \
sequence, prompt_id, agent_id, agent_type, cwd, tool_use_id, turn_id, repository, intent, \
subgraph, payload_json) \
VALUES ($1::text, $2::bigint, $3::text, $4::text, $5::bigint, $6::bigint, $7::text, $8::bigint, \
$9::text, $10::text, $11::text, $12::text, $13::text, $14::text, $15::text, $16::text, \
$17::bigint, $18::text)";

const INSERT_SUBGRAPH: &str = "\
INSERT INTO subgraphs (session_id, number) VALUES ($1::text, $2::bigint) \
ON CONFLICT (session_id, number) DO NOTHING";

// COMMIT_EVENT's relinking: the node, every node after it in order and every node of its
// SubGraph and the later ones get the one structural NEXT leading to them again. A tool result
// follows its Call (`call`); a Call or ConfigChange its SubGraph's Message (`message`), or else
// the last node of the SubGraph before (`order`); an Intent its prompt's Request (`request`);
// anything else the node before it in order, a Message the node before its SubGraph's first
// member.
const RELINK: &str = "\
WITH linked AS ( \
  SELECT seq, kind, \"order\", subgraph, tool_use_id FROM nodes \
  WHERE session_id = $1::text AND (\"order\" >= $2::bigint OR subgraph >= $3::bigint) \
), chosen AS ( \
  SELECT l.seq, l.subgraph AS linked_subgraph, \
    (SELECT c.seq FROM nodes c \
      WHERE l.kind IN ('Segment', 'Error') AND l.tool_use_id IS NOT NULL \
        AND c.session_id = $1::text AND c.kind = 'Call' AND c.tool_use_id = l.tool_use_id \
      ORDER BY c.\"order\" LIMIT 1) AS call_seq, \
    head.seq AS head_seq, head.kind AS head_kind, head.subgraph AS head_subgraph, \
    (SELECT r.seq FROM nodes r \
      WHERE l.kind = 'Intent' AND l.subgraph IS NOT NULL \
        AND r.session_id = $1::text AND r.kind = 'Request' AND r.subgraph = l.subgraph \
      ORDER BY r.\"order\" LIMIT 1) AS request_seq, \
    earlier.seq AS earlier_seq \
  FROM linked l \
  LEFT JOIN LATERAL ( \
    SELECT h.seq, h.kind, h.subgraph FROM ( \
      (SELECT m.seq, m.kind, m.subgraph, 0 AS pick FROM nodes m \
        WHERE m.session_id = $1::text AND m.kind = 'Message' AND m.subgraph = l.subgraph \
        ORDER BY m.\"order\" LIMIT 1) \
      UNION ALL \
      (SELECT p.seq, p.kind, p.subgraph, 1 FROM nodes p \
        WHERE p.session_id = $1::text AND p.subgraph < l.subgraph \
        ORDER BY p.subgraph DESC, p.\"order\" DESC LIMIT 1) \
    ) h WHERE l.kind IN ('Call', 'ConfigChange') AND l.subgraph IS NOT NULL \
    ORDER BY h.pick LIMIT 1 \
  ) head ON true \
  LEFT JOIN LATERAL ( \
    SELECT e.seq FROM nodes e \
    WHERE e.session_id = $1::text \
      AND e.\"order\" < CASE WHEN l.kind = 'Message' AND l.subgraph IS NOT NULL \
        THEN (SELECT min(member.\"order\") FROM nodes member \
              WHERE member.session_id = $1::text AND member.subgraph = l.subgraph) \
        ELSE l.\"order\" END \
      AND NOT (l.kind = 'Message' AND coalesce(e.subgraph = l.subgraph, false)) \
    ORDER BY e.\"order\" DESC LIMIT 1 \
  ) earlier ON true \
) \
UPDATE nodes n SET \
  next_seq = coalesce(c.call_seq, c.head_seq, c.request_seq, c.earlier_seq), \
  next_via = CASE \
    WHEN coalesce(c.call_seq, c.head_seq, c.request_seq, c.earlier_seq) IS NULL THEN NULL \
    WHEN c.call_seq IS NOT NULL THEN 'call' \
    WHEN c.head_kind = 'Message' AND c.head_subgraph = c.linked_subgraph THEN 'message' \
    WHEN c.request_seq IS NOT NULL THEN 'request' \
    ELSE 'order' END \
FROM chosen c \
WHERE n.session_id = $1::text AND n.seq = c.seq";

// The node a commit created, whether this commit or an earlier one with the same order.
const COMMITTED_NODE: &str = "\
SELECT seq, kind FROM nodes WHERE session_id = $1::text AND \"order\" = $2::bigint";

const REFERENCE_FILE: &str = "\
WITH file AS ( \
  INSERT INTO files (repository, path) VALUES ($3::text, $4::text) ON CONFLICT DO NOTHING \
) \
INSERT INTO file_refs (session_id, node_seq, repository, path) \
VALUES ($1::text, $2::bigint, $3::text, $4::text) ON CONFLICT DO NOTHING";

// Each paragraph belongs to the node it was cut from; one whose text the session already had
// classified takes that classification, or a classification that arrived before it. `new`
// tells whether another node of the session holds the same text. Like Cypher's clauses, every
// read here sees the paragraphs as they were before this statement.
const STORE_PARAGRAPHS: &str = "\
WITH input AS ( \
  SELECT a.ord, p.* FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS a(value, ord), \
  LATERAL jsonb_to_record(a.value) AS p(\"index\" bigint, hash text, \"text\" text, \
    source text, hidden boolean, hidden_rules jsonb, from_user_doc boolean, \
    long_paragraph boolean) \
), enriched AS ( \
  SELECT i.*, pending.session_id IS NOT NULL AS had_pending, \
    pending.instructs AS pending_instructs, pending.jev_ms AS pending_jev_ms, \
    pending.error AS pending_error, earlier.instructs AS earlier_instructs, \
    earlier.jev_ms AS earlier_jev_ms, earlier.jev_error AS earlier_error, \
    NOT EXISTS (SELECT 1 FROM paragraphs seen WHERE seen.session_id = $1::text \
                AND seen.hash = i.hash AND seen.seq <> $2::bigint) AS new \
  FROM input i \
  LEFT JOIN pending_paragraph_enrichments pending \
    ON pending.session_id = $1::text AND pending.hash = i.hash \
  LEFT JOIN LATERAL ( \
    SELECT e.instructs, e.jev_ms, e.jev_error FROM paragraphs e \
    WHERE e.session_id = $1::text AND e.hash = i.hash \
      AND (e.instructs IS NOT NULL OR e.jev_error IS NOT NULL) \
    ORDER BY e.seq LIMIT 1 \
  ) earlier ON true \
), stored AS ( \
  INSERT INTO paragraphs (session_id, seq, \"index\", hash, \"text\", source, hidden, \
    hidden_rules, from_user_doc, long_paragraph, instructs, jev_ms, jev_error) \
  SELECT $1::text, $2::bigint, \"index\", hash, \"text\", source, hidden, \
    ARRAY(SELECT jsonb_array_elements_text(hidden_rules)), from_user_doc, long_paragraph, \
    coalesce(pending_instructs, earlier_instructs), coalesce(pending_jev_ms, earlier_jev_ms), \
    coalesce(pending_error, earlier_error) \
  FROM enriched \
  ON CONFLICT (session_id, seq, \"index\") DO NOTHING \
), consumed AS ( \
  DELETE FROM pending_paragraph_enrichments d USING enriched x \
  WHERE x.had_pending AND d.session_id = $1::text AND d.hash = x.hash \
) \
SELECT hash, new FROM enriched ORDER BY ord";

// A token keeps the node of its first mention in order, which a late earlier event takes over.
const STORE_TOKENS: &str = "\
WITH input AS ( \
  SELECT * FROM jsonb_to_recordset($4::jsonb) \
    AS t(key_kind text, key text, slot text, decoded text, category text) \
), stored AS ( \
  INSERT INTO tokens (session_id, key_kind, key, slot, node_seq, node_order, decoded, \
    category, version) \
  SELECT $1::text, key_kind, key, slot, $2::bigint, $3::bigint, decoded, category, $5::bigint \
  FROM input \
  ON CONFLICT (session_id, key_kind, key, slot) DO UPDATE SET \
    node_seq = CASE WHEN EXCLUDED.node_order < tokens.node_order \
                    THEN EXCLUDED.node_seq ELSE tokens.node_seq END, \
    version = CASE WHEN EXCLUDED.node_order < tokens.node_order \
                   THEN EXCLUDED.version ELSE tokens.version END, \
    node_order = LEAST(EXCLUDED.node_order, tokens.node_order) \
) \
INSERT INTO token_mentions (session_id, node_seq, key_kind, key, slot) \
SELECT $1::text, $2::bigint, key_kind, key, slot FROM input ON CONFLICT DO NOTHING";

// A continuation that arrived before its Request.
const APPLY_PENDING_CONTINUATION: &str = "\
WITH pending AS ( \
  DELETE FROM pending_request_continuations \
  WHERE session_id = $1::text AND \"order\" = $2::bigint RETURNING * \
) \
UPDATE nodes n SET \
  continues = CASE WHEN p.choice = 'none' THEN NULL ELSE \
    (SELECT t.seq FROM nodes t WHERE t.session_id = $1::text AND t.\"order\" = p.choice_order \
     AND t.kind = 'Request') END, \
  continuation_choice = p.choice, continuation_probabilities_json = p.probabilities_json, \
  continuation_jev_ms = p.jev_ms, continuation_error = p.error \
FROM pending p WHERE n.session_id = $1::text AND n.seq = $3::bigint";

const SESSION_EXISTS: &str = "SELECT 1 FROM sessions WHERE session_id = $1::text";

const REQUEST_AT: &str = "\
SELECT seq FROM nodes WHERE session_id = $1::text AND \"order\" = $2::bigint AND kind = 'Request'";

const CLASSIFY_PARAGRAPHS: &str = "\
UPDATE paragraphs SET instructs = $3::float8, jev_ms = $4::bigint, jev_error = $5::text \
WHERE session_id = $1::text AND hash = $2::text";

const DELETE_PENDING_PARAGRAPH: &str = "\
DELETE FROM pending_paragraph_enrichments WHERE session_id = $1::text AND hash = $2::text";

const KEEP_PENDING_PARAGRAPH: &str = "\
INSERT INTO pending_paragraph_enrichments (session_id, hash, instructs, jev_ms, error) \
VALUES ($1::text, $2::text, $3::float8, $4::bigint, $5::text) \
ON CONFLICT (session_id, hash) DO UPDATE SET instructs = EXCLUDED.instructs, \
  jev_ms = EXCLUDED.jev_ms, error = EXCLUDED.error";

const CONTINUE_REQUEST: &str = "\
UPDATE nodes SET continues = $3::bigint, continuation_choice = $4::text, \
  continuation_probabilities_json = $5::text, continuation_jev_ms = $6::bigint, \
  continuation_error = $7::text \
WHERE session_id = $1::text AND seq = $2::bigint";

const DELETE_PENDING_CONTINUATION: &str = "\
DELETE FROM pending_request_continuations WHERE session_id = $1::text AND \"order\" = $2::bigint";

const KEEP_PENDING_CONTINUATION: &str = "\
INSERT INTO pending_request_continuations (session_id, \"order\", choice, choice_order, \
  probabilities_json, jev_ms, error) \
VALUES ($1::text, $2::bigint, $3::text, $4::bigint, $5::text, $6::bigint, $7::text) \
ON CONFLICT (session_id, \"order\") DO UPDATE SET choice = EXCLUDED.choice, \
  choice_order = EXCLUDED.choice_order, probabilities_json = EXCLUDED.probabilities_json, \
  jev_ms = EXCLUDED.jev_ms, error = EXCLUDED.error";

// SESSION_CURSOR: the main agent's nodes are those of no agent a SubagentStart announced.
const SESSION_CURSOR: &str = "\
WITH main AS ( \
  SELECT kind, \"order\", subgraph FROM nodes n WHERE n.session_id = $1::text \
    AND NOT EXISTS (SELECT 1 FROM nodes s WHERE s.session_id = $1::text \
                    AND s.kind = 'SubagentStart' AND s.agent_id = n.agent_id) \
), heads AS ( \
  SELECT (SELECT max(subgraph) FROM main) AS main_subgraph, \
    coalesce((SELECT max(\"order\") FROM nodes WHERE session_id = $1::text \
              AND kind = 'Request'), -1) AS last_request \
) \
SELECT \
  coalesce((SELECT max(\"order\") FROM event_commits WHERE session_id = $1::text), 0), \
  (SELECT coalesce(jsonb_agg(jsonb_build_array(agent_id, sequence)), '[]'::jsonb) FROM ( \
     SELECT agent_id, max(sequence) AS sequence FROM nodes WHERE session_id = $1::text \
     AND agent_id IS NOT NULL AND sequence IS NOT NULL GROUP BY agent_id) agents), \
  coalesce( \
    (SELECT cwd FROM event_commits WHERE session_id = $1::text AND cwd IS NOT NULL \
     ORDER BY \"order\" DESC LIMIT 1), \
    (SELECT cwd FROM nodes WHERE session_id = $1::text AND cwd IS NOT NULL \
     ORDER BY \"order\" DESC LIMIT 1)), \
  coalesce( \
    (SELECT prompt_id FROM event_commits WHERE session_id = $1::text \
     AND prompt_id IS NOT NULL ORDER BY \"order\" DESC LIMIT 1), \
    (SELECT prompt_id FROM nodes WHERE session_id = $1::text AND prompt_id IS NOT NULL \
     ORDER BY \"order\" DESC LIMIT 1)), \
  (SELECT max(subgraph) FROM nodes WHERE session_id = $1::text), \
  (SELECT intent FROM nodes WHERE session_id = $1::text AND kind IN ('Intent', 'Message') \
   AND intent IS NOT NULL AND \"order\" > h.last_request ORDER BY \"order\" LIMIT 1), \
  h.main_subgraph, \
  (SELECT max(\"order\") FROM main WHERE kind IN ('Message', 'Call') \
   AND subgraph = h.main_subgraph), \
  (SELECT max(\"order\") FROM main WHERE kind IN ('ToolBatch', 'Request') \
   AND subgraph = h.main_subgraph), \
  EXISTS (SELECT 1 FROM nodes WHERE session_id = $1::text AND kind = 'Message' \
          AND subgraph = h.main_subgraph), \
  EXISTS (SELECT 1 FROM main WHERE kind = 'Call' AND subgraph = h.main_subgraph), \
  EXISTS (SELECT 1 FROM nodes WHERE session_id = $1::text AND kind = 'Request' \
          AND subgraph = 0), \
  (SELECT coalesce(jsonb_agg(jsonb_build_array(tool_use_id, subgraph) ORDER BY \"order\" DESC), \
                   '[]'::jsonb) FROM ( \
     SELECT tool_use_id, subgraph, \"order\" FROM nodes WHERE session_id = $1::text \
     AND kind = 'Call' AND \"order\" > h.last_request AND subgraph IS NOT NULL \
     AND tool_use_id IS NOT NULL ORDER BY \"order\" DESC LIMIT 200) calls), \
  (SELECT subgraph FROM nodes WHERE session_id = $1::text AND kind = 'Request' \
   AND subgraph IS NOT NULL ORDER BY \"order\" DESC LIMIT 1) \
FROM heads h";

const TOOL_CALL: &str = "\
SELECT payload_json FROM nodes WHERE session_id = $1::text AND kind = 'Call' \
AND tool_use_id = $2::text ORDER BY \"order\" DESC LIMIT 1";

/// Serialization failures and deadlocks roll back the transaction, so they can be retried.
const TRANSIENT_ATTEMPTS: u32 = 5;

/// Taken while the schema is applied, so services starting together do not race on DDL.
const SCHEMA_LOCK: i64 = 0x5749_5448_4855;

#[derive(Clone)]
pub struct PgGraphRepository {
    pool: Pool,
}

impl PgGraphRepository {
    /// Connects to `database_url` (a libpq connection string or URL) and applies the schema.
    pub async fn connect(database_url: &str, pool_size: usize) -> Result<Self, RepositoryError> {
        let repository = Self {
            pool: pool(database_url, pool_size)?,
        };
        apply_schema(&repository.pool).await?;
        Ok(repository)
    }

    async fn client(&self) -> Result<deadpool_postgres::Object, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|error| RepositoryError::Unavailable(error.to_string()))
    }

    /// Rebuild paragraphs from committed events in one transaction.
    pub async fn reindex_paragraphs(&self) -> Result<ReindexReport, RepositoryError> {
        self.reindex_once().await.map_err(RepositoryError::from)
    }

    async fn reindex_once(&self) -> Result<ReindexReport, PgError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        // The paragraph index can change. Discard its old classifications and cause links
        // together, keeping result-level edges and the original tokens from unmasked input.
        tx.batch_execute(
            "LOCK TABLE sessions, nodes, paragraphs, pending_paragraph_enrichments, cause_edges \
             IN SHARE ROW EXCLUSIVE MODE; \
             DELETE FROM cause_edges WHERE target_index >= 0; \
             DELETE FROM pending_paragraph_enrichments; DELETE FROM paragraphs;",
        )
        .await?;
        let mut report = ReindexReport {
            scanned: 0,
            reindexed: 0,
        };
        let mut after: Option<(String, i64)> = None;
        loop {
            let (session, order) = after
                .as_ref()
                .map_or((None, None), |(s, o)| (Some(s), Some(o)));
            let rows = tx.query(
                "SELECT session_id, \"order\", version, event_name, event_json FROM event_commits \
                 WHERE has_node AND event_name NOT IN ('InstructionsLoaded', 'FileChanged') \
                   AND ($1::text IS NULL OR (session_id, \"order\") > ($1, $2::bigint)) \
                 ORDER BY session_id, \"order\" LIMIT 500",
                &[&session, &order],
            ).await?;
            if rows.is_empty() {
                break;
            }
            report.scanned += rows.len();
            for row in rows {
                let session: String = row.get(0);
                let seq: i64 = row.get(2);
                let mutation =
                    GeneratorEvent::from_json(row.get(3), row.get(4))?.into_mutation()?;
                if !mutation.paragraphs.is_empty() {
                    tx.query(
                        &prepared(&tx, STORE_PARAGRAPHS).await?,
                        &[&session, &seq, &json!(mutation.paragraphs)],
                    )
                    .await?;
                    report.reindexed += 1;
                }
                after = Some((session, row.get(1)));
            }
        }
        tx.commit().await?;
        Ok(report)
    }

    async fn commit_mutation(
        &self,
        mutation: &GraphMutation,
    ) -> Result<EventResponse, RepositoryError> {
        let mut attempt = 1;
        loop {
            match self.commit_once(mutation).await {
                Err(error) if is_transient(&error) && attempt < TRANSIENT_ATTEMPTS => {
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt * 20))).await;
                    attempt += 1;
                }
                result => return result.map_err(RepositoryError::from),
            }
        }
    }

    async fn commit_once(&self, m: &GraphMutation) -> Result<EventResponse, PgError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let session = &m.session_id;

        run(&tx, INSERT_SESSION, &[session, &m.observed_at]).await?;
        let session_version: i64 = one(&tx, LOCK_SESSION, &[session]).await?.get(0);

        let version = match optional(&tx, FIND_COMMIT, &[session, &m.order]).await? {
            Some(existing) => {
                let event_json: String = existing.get(1);
                if event_json != m.event_json {
                    return Err(PgError::Repository(RepositoryError::InvalidEvent(format!(
                        "order {} was already committed with different content",
                        m.order
                    ))));
                }
                existing.get::<_, i64>(0)
            }
            None => {
                let has_node = match m.node_type {
                    None => false,
                    Some("SubagentStop") => one(&tx, SUBAGENT_STARTED, &[session, &m.agent_id])
                        .await?
                        .get(0),
                    Some(_) => true,
                };
                let version = session_version + 1;
                run(&tx, BUMP_VERSION, &[session, &version]).await?;
                run(
                    &tx,
                    INSERT_COMMIT,
                    &[
                        session,
                        &m.order,
                        &version,
                        &m.event_name,
                        &m.observed_at,
                        &m.client_id,
                        &m.event_json,
                        &m.cwd,
                        &m.prompt_id,
                        &has_node,
                    ],
                )
                .await?;
                if has_node {
                    run(
                        &tx,
                        INSERT_NODE,
                        &[
                            session,
                            &version,
                            &m.node_type,
                            &m.event_name,
                            &m.order,
                            &m.observed_at,
                            &m.client_id,
                            &m.sequence,
                            &m.prompt_id,
                            &m.agent_id,
                            &m.agent_type,
                            &m.cwd,
                            &m.tool_use_id,
                            &m.turn_id,
                            &m.repository,
                            &m.intent,
                            &m.subgraph,
                            &m.payload_json,
                        ],
                    )
                    .await?;
                    if let Some(subgraph) = m.subgraph {
                        run(&tx, INSERT_SUBGRAPH, &[session, &subgraph]).await?;
                    }
                    run(&tx, RELINK, &[session, &m.order, &m.subgraph]).await?;
                }
                version
            }
        };

        // Like COMMIT_EVENT, a repeated commit reaches the node its first commit created and
        // links it again; every step from here on is idempotent.
        let node = optional(&tx, COMMITTED_NODE, &[session, &m.order])
            .await?
            .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)));
        let mut paragraphs = Vec::new();
        if let Some((seq, kind)) = &node {
            if let Some(path) = &m.file_path {
                let repository = m.repository.clone().unwrap_or_default();
                run(&tx, REFERENCE_FILE, &[session, seq, &repository, path]).await?;
            }
            if !m.paragraphs.is_empty() {
                let input = json!(m.paragraphs);
                for row in tx
                    .query(
                        &prepared(&tx, STORE_PARAGRAPHS).await?,
                        &[session, seq, &input],
                    )
                    .await?
                {
                    paragraphs.push(ParagraphReference {
                        hash: row.get(0),
                        seq: unsigned(*seq)?,
                        new: row.get(1),
                    });
                }
            }
            if !m.tokens.is_empty() {
                let input = json!(m.tokens);
                run(
                    &tx,
                    STORE_TOKENS,
                    &[session, seq, &m.order, &input, &version],
                )
                .await?;
            }
            if kind == "Request" {
                run(&tx, APPLY_PENDING_CONTINUATION, &[session, &m.order, seq]).await?;
            }
        }
        tx.commit().await?;

        Ok(EventResponse {
            nodes: match node {
                Some((seq, node_type)) => vec![CreatedNode {
                    seq: unsigned(seq)?,
                    node_type,
                }],
                None => Vec::new(),
            },
            paragraphs: (!paragraphs.is_empty()).then_some(paragraphs),
            version: unsigned(version)?,
            decision_response: None,
        })
    }
}

#[async_trait]
impl GraphRepository for PgGraphRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        let client = self.client().await?;
        client
            .simple_query("SELECT 1")
            .await
            .map_err(|error| RepositoryError::from(PgError::from(error)))?;
        Ok(())
    }

    async fn commit(&self, event: GeneratorEvent) -> Result<EventResponse, RepositoryError> {
        self.commit_mutation(&event.into_mutation()?).await
    }

    async fn classify_paragraph(
        &self,
        session_id: &str,
        hash: &str,
        request: ParagraphClassificationRequest,
    ) -> Result<ParagraphClassificationResponse, RepositoryError> {
        let instructs = request
            .error
            .is_none()
            .then(|| {
                request
                    .sentences
                    .iter()
                    .map(|sentence| sentence.p)
                    .reduce(f64::max)
            })
            .flatten();
        let jev_ms = request.jev_ms.map(signed).transpose()?;
        let result: Result<bool, PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            if optional(&tx, SESSION_EXISTS, &[&session_id])
                .await?
                .is_none()
            {
                return Err(PgError::Repository(RepositoryError::NotFound));
            }
            let parameters: [&(dyn ToSql + Sync); 5] =
                [&session_id, &hash, &instructs, &jev_ms, &request.error];
            let applied = tx
                .execute(&prepared(&tx, CLASSIFY_PARAGRAPHS).await?, &parameters)
                .await?
                > 0;
            if applied {
                run(&tx, DELETE_PENDING_PARAGRAPH, &[&session_id, &hash]).await?;
            } else {
                run(&tx, KEEP_PENDING_PARAGRAPH, &parameters).await?;
            }
            tx.commit().await?;
            Ok(applied)
        }
        .await;
        Ok(ParagraphClassificationResponse {
            applied: result?,
            instructs,
        })
    }

    async fn continue_request(
        &self,
        session_id: &str,
        order: u64,
        request: RequestContinuationRequest,
    ) -> Result<RequestContinuationResponse, RepositoryError> {
        let choice = request.choice.as_deref().unwrap_or("none");
        let choice_order = parse_choice_order(choice)?.map(signed).transpose()?;
        let order = signed(order)?;
        let probabilities_json = serde_json::to_string(&request.probabilities)
            .map_err(|error| RepositoryError::InvalidEvent(error.to_string()))?;
        let jev_ms = request.jev_ms.map(signed).transpose()?;
        let result: Result<Option<i64>, PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            if optional(&tx, SESSION_EXISTS, &[&session_id])
                .await?
                .is_none()
            {
                return Err(PgError::Repository(RepositoryError::NotFound));
            }
            let request_seq = optional(&tx, REQUEST_AT, &[&session_id, &order])
                .await?
                .map(|row| row.get::<_, i64>(0));
            match request_seq {
                Some(seq) => {
                    let continues = match choice_order {
                        Some(target) => optional(&tx, REQUEST_AT, &[&session_id, &target])
                            .await?
                            .map(|row| row.get::<_, i64>(0)),
                        None => None,
                    };
                    run(
                        &tx,
                        CONTINUE_REQUEST,
                        &[
                            &session_id,
                            &seq,
                            &continues,
                            &choice,
                            &probabilities_json,
                            &jev_ms,
                            &request.error,
                        ],
                    )
                    .await?;
                    run(&tx, DELETE_PENDING_CONTINUATION, &[&session_id, &order]).await?;
                }
                None => {
                    run(
                        &tx,
                        KEEP_PENDING_CONTINUATION,
                        &[
                            &session_id,
                            &order,
                            &choice,
                            &choice_order,
                            &probabilities_json,
                            &jev_ms,
                            &request.error,
                        ],
                    )
                    .await?;
                }
            }
            tx.commit().await?;
            Ok(request_seq)
        }
        .await;
        let request_seq = result?;
        Ok(RequestContinuationResponse {
            applied: request_seq.is_some(),
            request_seq: request_seq.map(unsigned).transpose()?,
        })
    }

    async fn session_cursor(&self, session_id: &str) -> Result<SessionCursor, RepositoryError> {
        let result: Result<SessionCursor, PgError> = async {
            let client = self.client().await?;
            if optional(&client, SESSION_EXISTS, &[&session_id])
                .await?
                .is_none()
            {
                return Ok(SessionCursor::default());
            }
            let row = one(&client, SESSION_CURSOR, &[&session_id]).await?;
            let last_opening: Option<i64> = row.get(7);
            let last_closing: Option<i64> = row.get(8);
            let agents: Value = row.get(1);
            let calls: Value = row.get(12);
            Ok(SessionCursor {
                last_order: unsigned(row.get(0))?,
                agent_sequences: agents
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|pair| {
                        Some((pair.get(0)?.as_str()?.to_owned(), pair.get(1)?.as_u64()?))
                    })
                    .collect(),
                cwd: row.get(2),
                prompt_id: row.get(3),
                last_subgraph: row.get::<_, Option<i64>>(4).map(unsigned).transpose()?,
                intent: row.get(5),
                subgraphs: SubGraphCursor {
                    current: row.get::<_, Option<i64>>(6).map(unsigned).transpose()?,
                    open: last_opening.is_some_and(|opening| last_closing.unwrap_or(-1) < opening),
                    has_message: row.get(9),
                    has_call: row.get(10),
                    zero_has_request: row.get(11),
                    calls: calls
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|pair| {
                            Some((pair.get(0)?.as_str()?.to_owned(), pair.get(1)?.as_u64()?))
                        })
                        .collect(),
                    request: row.get::<_, Option<i64>>(13).map(unsigned).transpose()?,
                },
            })
        }
        .await;
        Ok(result?)
    }

    async fn tool_call(
        &self,
        session_id: &str,
        tool_use_id: &str,
    ) -> Result<ToolCall, RepositoryError> {
        let result: Result<Option<String>, PgError> = async {
            let client = self.client().await?;
            Ok(optional(&client, TOOL_CALL, &[&session_id, &tool_use_id])
                .await?
                .and_then(|row| row.get(0)))
        }
        .await;
        let payload = result?.ok_or(RepositoryError::NotFound)?;
        serde_json::from_str(&payload)
            .map_err(|error| RepositoryError::InvalidResponse(error.to_string()))
    }
}

/// A pool of `size` connections to `database_url`, each preparing a statement once.
pub(crate) fn pool(database_url: &str, size: usize) -> Result<Pool, RepositoryError> {
    let config: tokio_postgres::Config = database_url
        .parse()
        .map_err(|error: tokio_postgres::Error| RepositoryError::Unavailable(error.to_string()))?;
    let manager = Manager::from_config(
        config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Pool::builder(manager)
        .max_size(size)
        .build()
        .map_err(|error| RepositoryError::Unavailable(error.to_string()))
}

pub(crate) async fn apply_schema(pool: &Pool) -> Result<(), RepositoryError> {
    let client = pool
        .get()
        .await
        .map_err(|error| RepositoryError::Unavailable(error.to_string()))?;
    let batch = format!(
        "SELECT pg_advisory_xact_lock({SCHEMA_LOCK}); {}",
        withhuman_common::POSTGRES_SCHEMA
    );
    client
        .batch_execute(&batch)
        .await
        .map_err(|error| RepositoryError::from(PgError::from(error)))
}

async fn prepared<C: GenericClient>(
    client: &C,
    statement: &str,
) -> Result<tokio_postgres::Statement, PgError> {
    Ok(client.prepare_cached(statement).await?)
}

async fn run<C: GenericClient>(
    client: &C,
    statement: &str,
    parameters: &[&(dyn ToSql + Sync)],
) -> Result<u64, PgError> {
    Ok(client
        .execute(&prepared(client, statement).await?, parameters)
        .await?)
}

async fn one<C: GenericClient>(
    client: &C,
    statement: &str,
    parameters: &[&(dyn ToSql + Sync)],
) -> Result<Row, PgError> {
    Ok(client
        .query_one(&prepared(client, statement).await?, parameters)
        .await?)
}

async fn optional<C: GenericClient>(
    client: &C,
    statement: &str,
    parameters: &[&(dyn ToSql + Sync)],
) -> Result<Option<Row>, PgError> {
    Ok(client
        .query_opt(&prepared(client, statement).await?, parameters)
        .await?)
}

fn parse_choice_order(choice: &str) -> Result<Option<u64>, RepositoryError> {
    if choice == "none" {
        return Ok(None);
    }
    choice
        .strip_prefix('o')
        .and_then(|order| order.parse().ok())
        .map(Some)
        .ok_or_else(|| RepositoryError::InvalidEvent("choice must be `none` or `o<order>`".into()))
}

fn signed(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value)
        .map_err(|_| RepositoryError::InvalidEvent(format!("{value} exceeds bigint range")))
}

fn unsigned(value: i64) -> Result<u64, PgError> {
    u64::try_from(value).map_err(|_| {
        PgError::Repository(RepositoryError::InvalidResponse(format!(
            "{value} is negative"
        )))
    })
}

fn is_transient(error: &PgError) -> bool {
    matches!(error, PgError::Postgres(error) if error.code().is_some_and(|code| {
        *code == SqlState::T_R_SERIALIZATION_FAILURE || *code == SqlState::T_R_DEADLOCK_DETECTED
    }))
}

/// An error of one attempt, kept whole until retrying has been decided.
#[derive(Debug)]
enum PgError {
    Postgres(tokio_postgres::Error),
    Repository(RepositoryError),
}

impl From<tokio_postgres::Error> for PgError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Postgres(error)
    }
}

impl From<RepositoryError> for PgError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

impl From<PgError> for RepositoryError {
    fn from(error: PgError) -> Self {
        match error {
            PgError::Repository(error) => error,
            PgError::Postgres(error) if error.is_closed() || error.code().is_none() => {
                Self::Unavailable(error.to_string())
            }
            PgError::Postgres(error) => Self::Query(match error.as_db_error() {
                Some(db) => format!("{}: {}", db.code().code(), db.message()),
                None => error.to_string(),
            }),
        }
    }
}
