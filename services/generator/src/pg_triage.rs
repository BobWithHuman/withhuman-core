//! PostgreSQL storage for the security team's triage: session marks, distrusted sources and
//! one Call's evidence. Storing and serving only; nothing here is read when a Call is decided.

use serde_json::Value;
use tokio_postgres::Row;
use withhuman_contracts::triage::{
    CausedByRequest, CausedByResult, DistrustSourceRequest, EVIDENCE_SCHEMA, Evidence,
    EvidenceCall, EvidenceCause, EvidenceDecision, EvidenceDeviation, EvidenceRequest,
    MarkSessionRequest, MarkSessionsRequest, MarkState, MarkedSession, MarkedSessions, SessionMark,
    SourceTrust,
};

use crate::{
    PgGraphRepository,
    pg_repository::{PgError, optional, run, signed, unsigned},
    repository::RepositoryError,
};

const SESSION_EXISTS: &str = "SELECT 1 FROM sessions WHERE session_id = $1::text";

// The latest mark replaces the one before it.
const SET_MARK: &str = "\
INSERT INTO session_marks (session_id, state, set_by, set_at) \
SELECT $1::text, $2::text, $3::text, $4::bigint \
WHERE EXISTS (SELECT 1 FROM sessions WHERE session_id = $1::text) \
ON CONFLICT (session_id) DO UPDATE SET state = EXCLUDED.state, set_by = EXCLUDED.set_by, \
  set_at = EXCLUDED.set_at \
RETURNING state, set_by, set_at";

const CLEAR_MARK: &str = "DELETE FROM session_marks WHERE session_id = $1::text";

// One statement for a group, so its sessions are marked together or not at all.
const SET_MARKS: &str = "\
INSERT INTO session_marks (session_id, state, set_by, set_at) \
SELECT s.session_id, $2::text, $3::text, $4::bigint FROM sessions s \
WHERE s.session_id = ANY($1::text[]) \
ON CONFLICT (session_id) DO UPDATE SET state = EXCLUDED.state, set_by = EXCLUDED.set_by, \
  set_at = EXCLUDED.set_at \
RETURNING session_id, state, set_by, set_at";

// The sessions the store holds, or held a mark for, once their marks are off.
const CLEAR_MARKS: &str = "\
WITH cleared AS ( \
  DELETE FROM session_marks WHERE session_id = ANY($1::text[]) RETURNING session_id \
) \
SELECT session_id FROM cleared \
UNION SELECT session_id FROM sessions WHERE session_id = ANY($1::text[])";

const MARK: &str = "SELECT state, set_by, set_at FROM session_marks WHERE session_id = $1::text";

// Distrusting a source again keeps the latest word on it: who, when and the Call shown.
const DISTRUST: &str = "\
INSERT INTO distrusted_sources (source, set_by, set_at, session_id, seq) \
VALUES ($1::text, $2::text, $3::bigint, $4::text, $5::bigint) \
ON CONFLICT (source) DO UPDATE SET set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at, \
  session_id = EXCLUDED.session_id, seq = EXCLUDED.seq \
RETURNING source, set_by, set_at, session_id, seq";

const TRUST: &str = "DELETE FROM distrusted_sources WHERE source = $1::text";

const DISTRUSTED: &str = "SELECT source FROM distrusted_sources WHERE source = ANY($1::text[])";

// The Call with its verdict and trace, and its session's user. `agent_id` names a subagent
// only when a SubagentStart announced it, as Decision reads it.
const EVIDENCE_CALL: &str = "\
SELECT c.tool_use_id, c.payload_json, c.cwd, c.observed_at, \
  coalesce(c.client_id, s.client_id), s.user_email, \
  CASE WHEN EXISTS (SELECT 1 FROM nodes a WHERE a.session_id = c.session_id \
                    AND a.kind = 'SubagentStart' AND a.agent_id = c.agent_id) \
       THEN c.agent_id END, \
  c.permission_mode, c.model, c.decision, c.decision_reason, c.decision_rule, c.decision_mode, \
  c.decision_start, c.decided_at, c.trace_json, c.trace_error, c.parent, c.\"order\" \
FROM nodes c JOIN sessions s ON s.session_id = c.session_id \
WHERE c.session_id = $1::text AND c.kind = 'Call' AND c.seq = $2::bigint";

// The person's latest request before the Call, as Decision's trace takes it.
const EVIDENCE_REQUEST: &str = "\
SELECT seq, payload_json, observed_at FROM nodes \
WHERE session_id = $1::text AND kind = 'Request' AND \"order\" < $2::bigint \
ORDER BY \"order\" DESC LIMIT 1";

// What the Call was traced to: a Request, or a tool result (with the paragraph when the trace
// names one) and the Call whose result it was.
const EVIDENCE_CAUSES: &str = "\
SELECT e.target_seq, e.target_index, e.probability, e.rank, t.kind, t.payload_json, \
  told.seq, told.payload_json, coalesce(told.cwd, t.cwd), p.\"text\", p.hidden \
FROM cause_edges e \
JOIN nodes t ON t.session_id = e.session_id AND t.seq = e.target_seq \
LEFT JOIN LATERAL ( \
  SELECT c.seq, c.payload_json, c.cwd FROM nodes c \
  WHERE c.session_id = e.session_id AND c.kind = 'Call' AND c.tool_use_id = t.tool_use_id \
    AND t.kind IN ('Segment', 'Error') \
  ORDER BY c.\"order\" LIMIT 1 \
) told ON true \
LEFT JOIN paragraphs p ON p.session_id = e.session_id AND p.seq = e.target_seq \
  AND p.\"index\" = e.target_index \
WHERE e.session_id = $1::text AND e.call_seq = $2::bigint \
ORDER BY e.rank NULLS LAST, e.probability DESC NULLS LAST, e.target_seq, e.target_index";

/// The fields of a tool's input that say what a Call acts on, the first present one first.
const TARGET_FIELDS: [&str; 6] = ["command", "file_path", "url", "path", "pattern", "query"];
/// Those of them that name a document or a page: what a result came from.
const SOURCE_FIELDS: [&str; 3] = ["file_path", "url", "path"];

impl PgGraphRepository {
    /// Marks the session, or takes its mark off; `NotFound` for a session the store does not
    /// hold (a mark left on a session since removed can still be taken off).
    pub(crate) async fn mark(
        &self,
        session_id: &str,
        request: MarkSessionRequest,
        set_at: u64,
    ) -> Result<MarkedSession, RepositoryError> {
        let at = signed(set_at)?;
        let result: Result<Option<Option<SessionMark>>, PgError> = async {
            let client = self.client().await?;
            let Some(state) = request.state else {
                let cleared = run(&client, CLEAR_MARK, &[&session_id]).await?;
                let known = cleared > 0
                    || optional(&client, SESSION_EXISTS, &[&session_id])
                        .await?
                        .is_some();
                return Ok(known.then_some(None));
            };
            let actor = text(&request.actor);
            optional(
                &client,
                SET_MARK,
                &[&session_id, &state.as_str(), &actor, &at],
            )
            .await?
            .map(|row| session_mark(&row).map(Some))
            .transpose()
        }
        .await;
        let mark = result?.ok_or(RepositoryError::NotFound)?;
        Ok(MarkedSession {
            session_id: session_id.to_owned(),
            mark,
        })
    }

    /// Marks every named session the store holds, or takes their marks off, in one statement;
    /// the rest are returned as unknown and left alone.
    pub(crate) async fn mark_many(
        &self,
        request: MarkSessionsRequest,
        set_at: u64,
    ) -> Result<MarkedSessions, RepositoryError> {
        let at = signed(set_at)?;
        let ids = &request.session_ids;
        let result: Result<Vec<(String, Option<SessionMark>)>, PgError> = async {
            let client = self.client().await?;
            match request.state {
                Some(state) => client
                    .query(
                        &client.prepare_cached(SET_MARKS).await?,
                        &[ids, &state.as_str(), &text(&request.actor), &at],
                    )
                    .await?
                    .iter()
                    .map(|row| {
                        let mark = SessionMark {
                            state: MarkState::parse(row.get(1))
                                .ok_or_else(|| invalid("session mark"))?,
                            set_by: row.get(2),
                            set_at: millis(row, 3)?.unwrap_or_default(),
                        };
                        Ok((row.get(0), Some(mark)))
                    })
                    .collect(),
                None => Ok(client
                    .query(&client.prepare_cached(CLEAR_MARKS).await?, &[ids])
                    .await?
                    .iter()
                    .map(|row| (row.get(0), None))
                    .collect()),
            }
        }
        .await;
        let mut found: std::collections::HashMap<String, Option<SessionMark>> =
            result?.into_iter().collect();
        let mut marked = MarkedSessions {
            sessions: Vec::new(),
            unknown: Vec::new(),
        };
        for session_id in ids {
            match found.remove(session_id) {
                Some(mark) => marked.sessions.push(MarkedSession {
                    session_id: session_id.clone(),
                    mark,
                }),
                // Named twice: already listed.
                None if marked
                    .sessions
                    .iter()
                    .any(|session| &session.session_id == session_id) => {}
                None if !marked.unknown.contains(session_id) => {
                    marked.unknown.push(session_id.clone());
                }
                None => {}
            }
        }
        Ok(marked)
    }

    /// Distrusts the source, or trusts it again. Neither fails for a source already so.
    pub(crate) async fn distrust(
        &self,
        request: DistrustSourceRequest,
        set_at: u64,
    ) -> Result<SourceTrust, RepositoryError> {
        let at = signed(set_at)?;
        let seq = request.seq.map(signed).transpose()?;
        let source = withhuman_common::postgres_text(&request.source).into_owned();
        let result: Result<SourceTrust, PgError> = async {
            let client = self.client().await?;
            if !request.on {
                run(&client, TRUST, &[&source]).await?;
                return Ok(SourceTrust {
                    source,
                    distrusted: false,
                    set_by: None,
                    set_at: None,
                    session_id: None,
                    seq: None,
                });
            }
            let row = optional(
                &client,
                DISTRUST,
                &[
                    &source,
                    &text(&request.actor),
                    &at,
                    &text(&request.session_id),
                    &seq,
                ],
            )
            .await?
            .ok_or_else(|| invalid("the source was not stored"))?;
            Ok(SourceTrust {
                source: row.get(0),
                distrusted: true,
                set_by: row.get(1),
                set_at: millis(&row, 2)?,
                session_id: row.get(3),
                seq: millis(&row, 4)?,
            })
        }
        .await;
        Ok(result?)
    }

    /// The Call's evidence; `NotFound` for an unknown session or a `seq` that is not a Call.
    pub(crate) async fn call_evidence(
        &self,
        session_id: &str,
        seq: u64,
    ) -> Result<Evidence, RepositoryError> {
        let call_seq = signed(seq)?;
        let result: Result<Option<Evidence>, PgError> = async {
            let mut client = self.client().await?;
            // One snapshot, so a verdict written meanwhile cannot disagree with its trace.
            let tx = client
                .build_transaction()
                .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await?;
            let Some(call) = optional(&tx, EVIDENCE_CALL, &[&session_id, &call_seq]).await? else {
                return Ok(None);
            };
            let order: i64 = call.get(18);
            let request = optional(&tx, EVIDENCE_REQUEST, &[&session_id, &order]).await?;
            let causes = tx
                .query(
                    &tx.prepare_cached(EVIDENCE_CAUSES).await?,
                    &[&session_id, &call_seq],
                )
                .await?;
            let mark = optional(&tx, MARK, &[&session_id]).await?;

            let mut told_by = Vec::new();
            let mut traced_request = None;
            let mut names: Vec<Vec<String>> = Vec::new();
            for row in &causes {
                let kind: String = row.get(4);
                if kind == "Request" {
                    traced_request.get_or_insert(CausedByRequest {
                        seq: unsigned(row.get(0))?,
                        probability: row.get(2),
                    });
                    continue;
                }
                let (result, candidates) = caused_by_result(row, kind)?;
                told_by.push(result);
                names.push(candidates);
            }
            let all: Vec<&str> = names.iter().flatten().map(String::as_str).collect();
            let distrusted: Vec<String> = if all.is_empty() {
                Vec::new()
            } else {
                tx.query(&tx.prepare_cached(DISTRUSTED).await?, &[&all])
                    .await?
                    .iter()
                    .map(|row| row.get(0))
                    .collect()
            };
            tx.commit().await?;
            for (result, candidates) in told_by.iter_mut().zip(&names) {
                if let Some(named) = candidates.iter().find(|name| distrusted.contains(name)) {
                    result.source = Some(named.clone());
                    result.source_distrusted = true;
                }
            }

            let payload = json(call.get(1));
            let trace = json(call.get(15));
            let parent: Option<String> = call.get(17);
            let link = trace.get("link").and_then(Value::as_str).map(str::to_owned);
            let decision: Option<String> = call.get(9);
            Ok(Some(Evidence {
                schema: EVIDENCE_SCHEMA.to_owned(),
                session_id: session_id.to_owned(),
                seq,
                call: EvidenceCall {
                    tool_use_id: call.get(0),
                    tool: string(&payload, "tool_name"),
                    target: target_of(&payload, &TARGET_FIELDS),
                    input: input(&payload),
                    cwd: call.get(2),
                    at: millis(&call, 3)?,
                    client_id: call.get(4),
                    user: call.get(5),
                    agent_id: call.get(6),
                    permission_mode: call.get(7),
                    model: call.get(8),
                },
                decision: match decision {
                    Some(decision) => Some(EvidenceDecision {
                        decision,
                        reason: call.get(10),
                        rule: call.get(11),
                        mode: call.get(12),
                        start: call.get(13),
                        decided_at: millis(&call, 14)?,
                    }),
                    None => None,
                },
                request: match request {
                    Some(row) => Some(EvidenceRequest {
                        seq: unsigned(row.get(0))?,
                        text: string(&json(row.get(1)), "prompt"),
                        at: millis(&row, 2)?,
                    }),
                    None => None,
                },
                cause: EvidenceCause {
                    traced: parent.is_some_and(|parent| parent != "unresolved"),
                    // A result's SubGraph may hold a request too; it is not the cause then.
                    request: traced_request.filter(|_| link.as_deref() != Some("segment")),
                    link,
                    picked: trace.get("picked").and_then(Value::as_bool),
                    error: call.get(16),
                    source_distrusted: told_by.iter().any(|result| result.source_distrusted),
                    told_by,
                    deviation: trace
                        .get("deviation")
                        .filter(|deviation| deviation.is_object())
                        .map(|deviation| EvidenceDeviation {
                            score: deviation.get("score").and_then(Value::as_f64),
                            worst: string(deviation, "worst"),
                        }),
                },
                mark: mark.as_ref().map(session_mark).transpose()?,
            }))
        }
        .await;
        result?.ok_or(RepositoryError::NotFound)
    }
}

/// A row of `EVIDENCE_CAUSES` for a tool result, and every name its source may be distrusted
/// under: the telling Call's target, that target below its `cwd`, its document or page, and
/// its tool.
fn caused_by_result(row: &Row, kind: String) -> Result<(CausedByResult, Vec<String>), PgError> {
    let result_payload = json(row.get(5));
    let call_payload = json(row.get(7));
    // A result whose Call the session does not hold still carries the tool and its input.
    let payload = if call_payload.is_object() {
        &call_payload
    } else {
        &result_payload
    };
    let tool = string(payload, "tool_name");
    let target = target_of(payload, &TARGET_FIELDS);
    let document = target_of(payload, &SOURCE_FIELDS);
    let cwd: Option<String> = row.get(8);
    let mut candidates: Vec<String> = Vec::new();
    let mut offer = |name: Option<String>| {
        if let Some(name) = name.filter(|name| !name.trim().is_empty())
            && !candidates.contains(&name)
        {
            candidates.push(name);
        }
    };
    offer(document.clone());
    offer(target.clone());
    for name in [&document, &target] {
        offer(
            name.as_deref()
                .zip(cwd.as_deref())
                .and_then(|(name, cwd)| below(name, cwd)),
        );
    }
    offer(tool.clone());
    let index: i64 = row.get(1);
    let paragraph = (index >= 0).then(|| unsigned(index)).transpose()?;
    Ok((
        CausedByResult {
            result_seq: unsigned(row.get(0))?,
            result_kind: kind,
            call_seq: millis(row, 6)?,
            input: input(payload),
            target,
            paragraph,
            quote: paragraph.and(row.get(9)),
            hidden: paragraph.and(row.get(10)),
            probability: row.get(2),
            rank: millis(row, 3)?,
            source: document.or_else(|| tool.clone()),
            source_distrusted: false,
            tool,
        },
        candidates,
    ))
}

/// `name` as written from the folder `cwd`: `.` for the folder itself, none outside it.
fn below(name: &str, cwd: &str) -> Option<String> {
    let cwd = cwd.trim_end_matches('/');
    if cwd.is_empty() {
        return None;
    }
    if name == cwd {
        return Some(".".to_owned());
    }
    name.strip_prefix(cwd)?
        .strip_prefix('/')
        .filter(|rest| !rest.is_empty())
        .map(str::to_owned)
}

fn json(text: Option<String>) -> Value {
    text.and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null)
}

fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

/// The tool's input; an empty object when the payload has none.
fn input(payload: &Value) -> Value {
    payload
        .get("tool_input")
        .filter(|input| input.is_object())
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()))
}

fn target_of(payload: &Value, fields: &[&str]) -> Option<String> {
    let input = payload.get("tool_input")?;
    fields
        .iter()
        .find_map(|field| string(input, field).filter(|value| !value.is_empty()))
}

fn text(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(|value| withhuman_common::postgres_text(value).into_owned())
}

fn millis(row: &Row, index: usize) -> Result<Option<u64>, PgError> {
    row.get::<_, Option<i64>>(index).map(unsigned).transpose()
}

fn session_mark(row: &Row) -> Result<SessionMark, PgError> {
    let state: String = row.get(0);
    Ok(SessionMark {
        state: MarkState::parse(&state)
            .ok_or_else(|| invalid(&format!("session mark `{state}`")))?,
        set_by: row.get(1),
        set_at: millis(row, 2)?.unwrap_or_default(),
    })
}

fn invalid(what: &str) -> PgError {
    PgError::Repository(RepositoryError::InvalidResponse(what.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_target_is_the_first_field_that_says_what_the_call_acts_on() {
        let read = json!({"tool_name": "Read", "tool_input": {"file_path": "/r/a.md", "limit": 5}});
        assert_eq!(target_of(&read, &TARGET_FIELDS).as_deref(), Some("/r/a.md"));
        let fetch = json!({"tool_name": "WebFetch",
            "tool_input": {"url": "https://example.com/a", "prompt": "summarise"}});
        assert_eq!(
            target_of(&fetch, &SOURCE_FIELDS).as_deref(),
            Some("https://example.com/a")
        );
        let bash = json!({"tool_name": "Bash", "tool_input": {"command": "ls"}});
        assert_eq!(target_of(&bash, &TARGET_FIELDS).as_deref(), Some("ls"));
        assert_eq!(target_of(&bash, &SOURCE_FIELDS), None);
        assert_eq!(
            target_of(&json!({"tool_name": "Task"}), &TARGET_FIELDS),
            None
        );
        assert_eq!(input(&json!({"tool_name": "Task"})), json!({}));
    }

    #[test]
    fn a_path_is_also_named_from_the_calls_folder() {
        assert_eq!(below("/r/docs/a.md", "/r").as_deref(), Some("docs/a.md"));
        assert_eq!(below("/r/docs/a.md", "/r/").as_deref(), Some("docs/a.md"));
        assert_eq!(below("/r", "/r").as_deref(), Some("."));
        assert_eq!(below("/rr/a.md", "/r"), None);
        assert_eq!(below("https://example.com/a", "/r"), None);
        assert_eq!(below("/r/a.md", ""), None);
    }
}
