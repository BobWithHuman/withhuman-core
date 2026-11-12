//! PostgreSQL storage for the execution graph.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use async_trait::async_trait;
use deadpool_postgres::{GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod};
use serde_json::Value;
use tokio_postgres::{NoTls, Row, error::SqlState, types::ToSql};
use withhuman_contracts::decisions::{DecisionRequest, DecisionResponse};

use crate::{
    check,
    repository::{DecisionRepository, RepositoryError, TraceRecord},
    trace::{
        self, CallInfo, Member, MemberKind, Paragraph, ParentKey, TOKEN_KINDS, TraceGraph, Turn,
    },
};

const VERIFY_GRAPH: &str = "\
SELECT 1 FROM sessions s JOIN nodes c ON c.session_id = s.session_id \
WHERE s.session_id = $1::text AND c.kind = 'Call' AND c.seq = $2::bigint \
  AND s.version >= $3::bigint AND c.seq <= $3::bigint";

// The verdict is kept on the Call itself with `decided_at` in milliseconds.
const WRITE_DECISION: &str = "\
UPDATE nodes c SET decision = $3::text, decision_reason = $4::text, decision_rule = $5::text, \
  decision_start = $6::text, decision_version = $7::bigint, decision_mode = $8::text, \
  decision_jev_json = $9::text, \
  decided_at = (extract(epoch FROM clock_timestamp()) * 1000)::bigint \
WHERE c.session_id = $1::text AND c.kind = 'Call' AND c.seq = $2::bigint \
  AND EXISTS (SELECT 1 FROM sessions WHERE session_id = $1::text)";

// TRACE_GRAPH: one row of the Call and what the session holds before it. A subagent is an
// agent_id a SubagentStart announced.
const TRACE_GRAPH: &str = "\
WITH call AS ( \
  SELECT * FROM nodes WHERE session_id = $1::text AND kind = 'Call' AND seq = $2::bigint \
) \
SELECT call.\"order\", call.subgraph, call.payload_json, \
  (SELECT coalesce(jsonb_agg(jsonb_build_array(g.number, ( \
      SELECT min(member.agent_id) FROM nodes member \
      WHERE member.session_id = $1::text AND member.kind = 'Call' AND member.subgraph = g.number \
        AND EXISTS (SELECT 1 FROM nodes s WHERE s.session_id = $1::text \
                    AND s.kind = 'SubagentStart' AND s.agent_id = member.agent_id)))), \
    '[]'::jsonb) \
   FROM subgraphs g WHERE g.session_id = $1::text AND g.number < call.subgraph), \
  (SELECT coalesce(jsonb_agg(DISTINCT n.subgraph), '[]'::jsonb) FROM nodes n \
   WHERE n.session_id = $1::text AND n.kind IN ('Segment', 'Error') \
     AND n.subgraph < call.subgraph AND n.\"order\" < call.\"order\" \
     AND EXISTS (SELECT 1 FROM paragraphs p WHERE p.session_id = $1::text AND p.seq = n.seq \
                 AND p.hidden)), \
  (SELECT coalesce(jsonb_agg(jsonb_build_array(latest.subgraph, EXISTS ( \
      SELECT 1 FROM token_mentions mine WHERE mine.session_id = $1::text \
        AND mine.node_seq = call.seq AND mine.key_kind = latest.key_kind \
        AND mine.key = latest.key))), '[]'::jsonb) \
   FROM ( \
     SELECT DISTINCT ON (m.key_kind, m.key) m.key_kind, m.key, n.subgraph \
     FROM token_mentions m JOIN nodes n ON n.session_id = m.session_id AND n.seq = m.node_seq \
     WHERE m.session_id = $1::text AND m.key_kind = ANY($3::text[]) \
       AND n.\"order\" < call.\"order\" AND n.subgraph < call.subgraph \
     ORDER BY m.key_kind, m.key, n.\"order\" DESC \
   ) latest), \
  (SELECT coalesce(jsonb_agg(DISTINCT jsonb_build_array(earlier.subgraph, chosen.key)), \
                   '[]'::jsonb) \
   FROM nodes earlier, unnest(coalesce(earlier.parents, ARRAY[earlier.parent])) AS chosen(key) \
   WHERE earlier.session_id = $1::text AND earlier.kind = 'Call' \
     AND earlier.subgraph < call.subgraph \
     AND earlier.parent IS NOT NULL AND earlier.parent <> 'unresolved'), \
  CASE WHEN EXISTS (SELECT 1 FROM nodes s WHERE s.session_id = $1::text \
                    AND s.kind = 'SubagentStart' AND s.agent_id = call.agent_id) \
       THEN call.agent_id END, \
  (SELECT coalesce(jsonb_agg(jsonb_build_array(r.\"order\", ( \
      SELECT stated.intent FROM nodes stated \
      WHERE stated.session_id = $1::text AND stated.kind IN ('Intent', 'Message') \
        AND stated.intent IS NOT NULL AND stated.\"order\" > r.\"order\" \
        AND stated.\"order\" < coalesce((SELECT min(next.\"order\") FROM nodes next \
             WHERE next.session_id = $1::text AND next.kind = 'Request' \
               AND next.\"order\" > r.\"order\"), call.\"order\") \
        AND stated.\"order\" < call.\"order\" \
      ORDER BY stated.\"order\" LIMIT 1), r.subgraph) ORDER BY r.\"order\"), '[]'::jsonb) \
   FROM nodes r WHERE r.session_id = $1::text AND r.kind = 'Request' \
     AND r.\"order\" < call.\"order\"), \
  (SELECT coalesce(jsonb_agg(DISTINCT n.subgraph), '[]'::jsonb) FROM nodes n \
   WHERE n.session_id = $1::text AND n.kind IN ('Segment', 'Error') \
     AND n.subgraph < call.subgraph AND n.\"order\" < call.\"order\"), \
  call.cwd, \
  (SELECT r.payload_json FROM nodes r WHERE r.session_id = $1::text AND r.kind = 'Request' \
   AND r.\"order\" < call.\"order\" ORDER BY r.\"order\" DESC LIMIT 1) \
FROM call";

// EARLIER_CHANGES: the session's earlier Calls naming a file, that ran: a PostToolUse result
// with their tool_use_id is in the graph (a denied or failed Call changed nothing).
const EARLIER_CHANGES: &str = "\
SELECT c.payload_json, c.cwd FROM nodes c WHERE c.session_id = $1::text AND c.kind = 'Call' \
AND c.\"order\" < $2::bigint AND strpos(c.payload_json, $3::text) > 0 \
AND EXISTS (SELECT 1 FROM nodes s WHERE s.session_id = c.session_id AND s.kind = 'Segment' \
            AND s.tool_use_id = c.tool_use_id) \
ORDER BY c.\"order\"";

// The session's tool results before the Call that name the file, oldest first.
const FILE_RESULTS: &str = "\
SELECT payload_json FROM nodes WHERE session_id = $1::text AND kind = 'Segment' \
AND \"order\" < $2::bigint AND strpos(payload_json, $3::text) > 0 ORDER BY \"order\"";

// SUBGRAPH_MEMBERS: a result also brings its paragraphs, and whether an earlier Call was traced
// to the result or one of them.
const SUBGRAPH_MEMBERS: &str = "\
SELECT n.subgraph, n.seq, n.\"order\", n.kind, n.payload_json, \
  (SELECT coalesce(jsonb_agg(jsonb_build_array(p.\"index\", p.\"text\", coalesce(p.hidden, false), \
      EXISTS (SELECT 1 FROM cause_edges e JOIN nodes effect \
                ON effect.session_id = e.session_id AND effect.seq = e.call_seq \
              WHERE e.session_id = $1::text AND e.target_seq = p.seq \
                AND e.target_index = p.\"index\" AND effect.\"order\" < $3::bigint)) \
      ORDER BY p.\"index\"), '[]'::jsonb) \
   FROM paragraphs p WHERE p.session_id = $1::text AND p.seq = n.seq), \
  EXISTS (SELECT 1 FROM cause_edges e JOIN nodes effect \
            ON effect.session_id = e.session_id AND effect.seq = e.call_seq \
          WHERE e.session_id = $1::text AND e.target_seq = n.seq AND e.target_index = -1 \
            AND effect.\"order\" < $3::bigint) \
FROM nodes n \
WHERE n.session_id = $1::text AND n.subgraph = ANY($2::bigint[]) \
  AND n.kind IN ('Request', 'Intent', 'Message', 'Call', 'ConfigChange', 'Segment', 'Error') \
  AND n.\"order\" < $3::bigint \
ORDER BY n.subgraph, n.\"order\"";

// Takes the session's lock as Generator commits do, so the two queue rather than interleave.
const LOCK_SESSION: &str = "\
SELECT 1 FROM sessions WHERE session_id = $1::text FOR UPDATE";

const SET_CALL_TRACE: &str = "\
UPDATE nodes SET parent = $3::text, parents = $4::text[], trace_json = $5::text, \
  intent_score = $6::float8 \
WHERE session_id = $1::text AND kind = 'Call' AND seq = $2::bigint RETURNING \"order\"";

const DELETE_CAUSES: &str = "\
DELETE FROM cause_edges WHERE session_id = $1::text AND call_seq = $2::bigint";

// The SubGraph keeps the parents of its latest Call.
const SET_SUBGRAPH_PARENT: &str = "\
INSERT INTO subgraphs AS g (session_id, number, parent, parents, parent_call_seq, \
  parent_call_order) \
VALUES ($1::text, $2::bigint, $3::text, $4::text[], $5::bigint, $6::bigint) \
ON CONFLICT (session_id, number) DO UPDATE SET parent = EXCLUDED.parent, \
  parents = EXCLUDED.parents, parent_call_seq = EXCLUDED.parent_call_seq, \
  parent_call_order = EXCLUDED.parent_call_order \
WHERE coalesce(g.parent_call_order, -1) <= EXCLUDED.parent_call_order";

// A Call traced to a prompt's SubGraph points at the prompt's Request.
const LINK_PROMPT: &str = "\
INSERT INTO cause_edges (session_id, call_seq, target_seq, target_index, probability, rank, \
  parent) \
SELECT $1::text, $2::bigint, r.seq, -1, $4::float8, $5::bigint, 's' || $3::bigint \
FROM nodes r WHERE r.session_id = $1::text AND r.kind = 'Request' AND r.subgraph = $3::bigint \
ON CONFLICT (session_id, call_seq, target_seq, target_index) DO UPDATE SET \
  probability = EXCLUDED.probability, rank = EXCLUDED.rank, parent = EXCLUDED.parent";

// An activated tool result, or its paragraph when the result has one at that index.
const LINK_SEGMENT: &str = "\
INSERT INTO cause_edges (session_id, call_seq, target_seq, target_index, probability, rank, \
  parent) \
SELECT $1::text, $2::bigint, result.seq, \
  CASE WHEN EXISTS (SELECT 1 FROM paragraphs p WHERE p.session_id = $1::text \
                    AND p.seq = result.seq AND p.\"index\" = $4::bigint) \
       THEN $4::bigint ELSE -1 END, \
  $5::float8, $6::bigint, $7::text \
FROM nodes result WHERE result.session_id = $1::text AND result.kind IN ('Segment', 'Error') \
  AND result.seq = $3::bigint \
ON CONFLICT (session_id, call_seq, target_seq, target_index) DO UPDATE SET \
  probability = EXCLUDED.probability, rank = EXCLUDED.rank, parent = EXCLUDED.parent";

const MARK_UNRESOLVED: &str = "\
UPDATE nodes SET parent = 'unresolved', trace_error = $3::text \
WHERE session_id = $1::text AND kind = 'Call' AND seq = $2::bigint";

const TRANSIENT_ATTEMPTS: u32 = 5;

#[derive(Clone)]
pub struct PgDecisionRepository {
    pool: Pool,
}

impl PgDecisionRepository {
    /// Connects to `database_url` (a libpq connection string or URL) and applies the schema.
    pub async fn connect(database_url: &str, pool_size: usize) -> Result<Self, RepositoryError> {
        let config: tokio_postgres::Config =
            database_url
                .parse()
                .map_err(|error: tokio_postgres::Error| {
                    RepositoryError::Unavailable(error.to_string())
                })?;
        let manager = Manager::from_config(
            config,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(pool_size)
            .build()
            .map_err(|error| RepositoryError::Unavailable(error.to_string()))?;
        let repository = Self { pool };
        repository
            .client()
            .await?
            .batch_execute(&format!(
                "SELECT pg_advisory_xact_lock({SCHEMA_LOCK}); {}",
                withhuman_common::POSTGRES_SCHEMA
            ))
            .await
            .map_err(failure)?;
        Ok(repository)
    }

    async fn client(&self) -> Result<deadpool_postgres::Object, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|error| RepositoryError::Unavailable(error.to_string()))
    }

    /// The content the session last saw of the file at `path` before the Call at `call_order`.
    async fn last_seen(
        &self,
        client: &deadpool_postgres::Object,
        session_id: &str,
        call_order: i64,
        path: &str,
    ) -> Result<Option<String>, RepositoryError> {
        // `path` as JSON writes it, quotes included.
        let quoted = Value::String(path.to_owned()).to_string();
        let results: Vec<Value> = query(client, FILE_RESULTS, &[&session_id, &call_order, &quoted])
            .await?
            .iter()
            .map(|row| payload(row.get(0)))
            .collect();
        Ok(trace::last_seen_content(&results, path))
    }

    async fn persist_trace_once(
        client: &mut deadpool_postgres::Object,
        request: &DecisionRequest,
        record: &TraceRecord,
    ) -> Result<(), tokio_postgres::Error> {
        let session = &request.session_id;
        let call_seq = signed(request.call_seq);
        let subgraph = signed(record.subgraph);
        let parent_keys: Vec<&str> = record
            .parents
            .iter()
            .map(|parent| parent.key.as_str())
            .collect();
        let trace_json = record.trace.to_string();

        let tx = client.transaction().await?;
        query(&tx, LOCK_SESSION, &[session]).await?;
        let Some(call) = query(
            &tx,
            SET_CALL_TRACE,
            &[
                session,
                &call_seq,
                &record.parent,
                &parent_keys,
                &trace_json,
                &record.intent_score,
            ],
        )
        .await?
        .into_iter()
        .next() else {
            return tx.commit().await;
        };
        let call_order: i64 = call.get(0);
        query(&tx, DELETE_CAUSES, &[session, &call_seq]).await?;
        query(
            &tx,
            SET_SUBGRAPH_PARENT,
            &[
                session,
                &subgraph,
                &record.parent,
                &parent_keys,
                &call_seq,
                &call_order,
            ],
        )
        .await?;
        for (index, parent) in record.parents.iter().enumerate() {
            let Some(number) = parent.number else {
                continue;
            };
            let rank = signed(index as u64 + 1);
            query(
                &tx,
                LINK_PROMPT,
                &[
                    session,
                    &call_seq,
                    &signed(number),
                    &parent.probability,
                    &rank,
                ],
            )
            .await?;
        }
        for segment in &record.segments {
            let paragraph = segment.paragraph.map(signed).unwrap_or(-1);
            query(
                &tx,
                LINK_SEGMENT,
                &[
                    session,
                    &call_seq,
                    &signed(segment.seq),
                    &paragraph,
                    &segment.probability,
                    &signed(segment.rank as u64),
                    &segment.parent,
                ],
            )
            .await?;
        }
        tx.commit().await
    }
}

/// Taken while the schema is applied, so services starting together do not race on DDL.
const SCHEMA_LOCK: i64 = 0x5749_5448_4855;

#[async_trait]
impl DecisionRepository for PgDecisionRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        self.client()
            .await?
            .simple_query("SELECT 1")
            .await
            .map_err(failure)?;
        Ok(())
    }

    async fn verify_graph(&self, request: &DecisionRequest) -> Result<(), RepositoryError> {
        let client = self.client().await?;
        let rows = query(
            &client,
            VERIFY_GRAPH,
            &[
                &request.session_id,
                &signed(request.call_seq),
                &signed(request.graph_version),
            ],
        )
        .await?;
        if rows.is_empty() {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    async fn persist(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), RepositoryError> {
        let text =
            |value: Result<Value, serde_json::Error>| -> Result<Option<String>, RepositoryError> {
                match value.map_err(|error| RepositoryError::InvalidResponse(error.to_string()))? {
                    Value::Null => Ok(None),
                    // A reason can quote the Call's input, which may carry U+0000.
                    Value::String(mut text) => {
                        withhuman_common::make_postgres_text(&mut text);
                        Ok(Some(text))
                    }
                    other => Ok(Some(other.to_string())),
                }
            };
        let jev_json = serde_json::to_string(&response.jev)
            .map_err(|error| RepositoryError::InvalidResponse(error.to_string()))?;
        let client = self.client().await?;
        let updated = client
            .execute(
                &client
                    .prepare_cached(WRITE_DECISION)
                    .await
                    .map_err(failure)?,
                &[
                    &request.session_id,
                    &signed(request.call_seq),
                    &text(serde_json::to_value(response.decision))?,
                    &text(serde_json::to_value(&response.reason))?,
                    &text(serde_json::to_value(&response.rule))?,
                    &text(serde_json::to_value(response.start))?,
                    &signed(request.graph_version),
                    &text(serde_json::to_value(request.mode))?,
                    &jev_json,
                ],
            )
            .await
            .map_err(failure)?;
        if updated == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    async fn trace_graph(&self, request: &DecisionRequest) -> Result<TraceGraph, RepositoryError> {
        let client = self.client().await?;
        let session = request.session_id.as_str();
        let rows = query(
            &client,
            TRACE_GRAPH,
            &[&session, &signed(request.call_seq), &TOKEN_KINDS],
        )
        .await?;
        let row = rows.first().ok_or(RepositoryError::NotFound)?;
        let order: i64 = row.get(0);
        let subgraph = row
            .get::<_, Option<i64>>(1)
            .and_then(|number| u64::try_from(number).ok())
            .ok_or(RepositoryError::NoSubGraph)?;
        let call_payload = payload(row.get(2));
        let subgraphs = pairs(&row.get(3))
            .filter_map(|pair| {
                Some((
                    pair.first()?.as_u64()?,
                    pair.get(1).and_then(Value::as_str).map(str::to_owned),
                ))
            })
            .collect();
        let mut tokens = BTreeSet::new();
        let mut shared_tokens = BTreeSet::new();
        for pair in pairs(&row.get(5)) {
            let Some(number) = pair.first().and_then(Value::as_u64) else {
                continue;
            };
            tokens.insert(number);
            if pair.get(1).and_then(Value::as_bool) == Some(true) {
                shared_tokens.insert(number);
            }
        }
        let mut parents: BTreeMap<u64, BTreeSet<ParentKey>> = BTreeMap::new();
        for pair in pairs(&row.get(6)) {
            let (Some(number), Some(parent)) = (
                pair.first().and_then(Value::as_u64),
                pair.get(1)
                    .and_then(Value::as_str)
                    .and_then(ParentKey::parse),
            ) else {
                continue;
            };
            parents.entry(number).or_default().insert(parent);
        }
        let mut call = CallInfo {
            seq: request.call_seq,
            order: u64::try_from(order)
                .map_err(|_| RepositoryError::InvalidResponse("negative call order".into()))?,
            subgraph,
            agent_id: row.get(7),
            tool_name: call_payload
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            tool_input: call_payload
                .get("tool_input")
                .cloned()
                .unwrap_or(Value::Null),
            prior: None,
            programs: BTreeMap::new(),
            cwd: row.get(10),
        };
        // A file the Call writes whole is shown as its change to what the session last saw.
        if let Some(path) = check::written_path(&call) {
            call.prior = self.last_seen(&client, session, order, &path).await?;
        }
        // A program the Call runs is judged by its code: as the hook read it just before the
        // Call, or else as the session last saw it.
        let attached = check::attached_programs(&call_payload);
        for path in check::run_paths(&call) {
            let code = match attached.get(&path) {
                Some(code) => Some(code.clone()),
                None => self.last_seen(&client, session, order, &path).await?,
            };
            call.programs.insert(path, code);
        }
        Ok(TraceGraph {
            call,
            subgraphs,
            hidden: numbers(&row.get(4)),
            tokens,
            shared_tokens,
            results: numbers(&row.get(9)),
            parents,
            turns: pairs(&row.get(8))
                .map(|pair| Turn {
                    intent: pair.get(1).and_then(Value::as_str).map(str::to_owned),
                    subgraph: pair.get(2).and_then(Value::as_u64),
                })
                .collect(),
            prompt: payload(row.get(11))
                .get("prompt")
                .and_then(Value::as_str)
                .filter(|prompt| !prompt.is_empty())
                .map(str::to_owned),
        })
    }

    async fn subgraph_members(
        &self,
        session_id: &str,
        numbers: &[u64],
        call_order: u64,
    ) -> Result<Vec<Member>, RepositoryError> {
        if numbers.is_empty() {
            return Ok(Vec::new());
        }
        let numbers: Vec<i64> = numbers.iter().copied().map(signed).collect();
        let client = self.client().await?;
        let rows = query(
            &client,
            SUBGRAPH_MEMBERS,
            &[&session_id, &numbers, &signed(call_order)],
        )
        .await?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                Some(Member {
                    subgraph: u64::try_from(row.get::<_, i64>(0)).ok()?,
                    seq: u64::try_from(row.get::<_, i64>(1)).ok()?,
                    order: u64::try_from(row.get::<_, i64>(2)).ok()?,
                    kind: MemberKind::from_node_type(row.get(3))?,
                    payload: payload(row.get(4)),
                    paragraphs: pairs(&row.get(5))
                        .filter_map(|values| {
                            Some(Paragraph {
                                index: values.first()?.as_u64()?,
                                text: values.get(1)?.as_str()?.to_owned(),
                                hidden: values.get(2).and_then(Value::as_bool).unwrap_or_default(),
                                caused: values.get(3).and_then(Value::as_bool).unwrap_or_default(),
                            })
                        })
                        .collect(),
                    caused: row.get(6),
                })
            })
            .collect())
    }

    async fn persist_trace(
        &self,
        request: &DecisionRequest,
        record: &TraceRecord,
    ) -> Result<(), RepositoryError> {
        let mut client = self.client().await?;
        let mut attempt = 1;
        loop {
            match Self::persist_trace_once(&mut client, request, record).await {
                Err(error) if is_transient(&error) && attempt < TRANSIENT_ATTEMPTS => {
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt) * 20)).await;
                    attempt += 1;
                }
                result => return result.map_err(failure),
            }
        }
    }

    async fn earlier_file_changes(
        &self,
        session_id: &str,
        call_order: u64,
        path: &str,
    ) -> Result<Vec<check::FileDiff>, RepositoryError> {
        let client = self.client().await?;
        // The file's name narrows the search; the paths are compared whole by the check.
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned();
        let rows = query(
            &client,
            EARLIER_CHANGES,
            &[&session_id, &signed(call_order), &name],
        )
        .await?;
        let mut diffs = Vec::new();
        for row in &rows {
            let call_payload = payload(row.get(0));
            let call = CallInfo {
                seq: 0,
                order: 0,
                subgraph: 0,
                agent_id: None,
                tool_name: call_payload
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                tool_input: call_payload
                    .get("tool_input")
                    .cloned()
                    .unwrap_or(Value::Null),
                prior: None,
                programs: BTreeMap::new(),
                cwd: row.get(1),
            };
            match check::effect(&call) {
                check::Effect::FileChange {
                    path,
                    added,
                    removed,
                } => diffs.push(check::FileDiff {
                    path,
                    added,
                    removed,
                }),
                check::Effect::FileChanges { files } => diffs.extend(files),
                _ => {}
            }
        }
        Ok(diffs)
    }

    async fn mark_unresolved(
        &self,
        request: &DecisionRequest,
        error: &str,
    ) -> Result<(), RepositoryError> {
        let client = self.client().await?;
        query(
            &client,
            MARK_UNRESOLVED,
            &[
                &request.session_id,
                &signed(request.call_seq),
                &withhuman_common::postgres_text(error),
            ],
        )
        .await?;
        Ok(())
    }
}

async fn query<C: GenericClient>(
    client: &C,
    statement: &str,
    parameters: &[&(dyn ToSql + Sync)],
) -> Result<Vec<Row>, tokio_postgres::Error> {
    let statement = client.prepare_cached(statement).await?;
    client.query(&statement, parameters).await
}

fn pairs(value: &Value) -> impl Iterator<Item = &Vec<Value>> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
}

fn numbers(value: &Value) -> BTreeSet<u64> {
    value
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default()
}

fn payload(json: Option<String>) -> Value {
    json.and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or(Value::Null)
}

/// Seqs, orders and SubGraph numbers are far below i64::MAX; one beyond it is clamped.
fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn is_transient(error: &tokio_postgres::Error) -> bool {
    error.code().is_some_and(|code| {
        *code == SqlState::T_R_SERIALIZATION_FAILURE || *code == SqlState::T_R_DEADLOCK_DETECTED
    })
}

fn failure(error: tokio_postgres::Error) -> RepositoryError {
    match error.as_db_error() {
        Some(db) => RepositoryError::Query(format!("{}: {}", db.code().code(), db.message())),
        None => RepositoryError::Unavailable(error.to_string()),
    }
}

impl From<tokio_postgres::Error> for RepositoryError {
    fn from(error: tokio_postgres::Error) -> Self {
        failure(error)
    }
}
