//! Tracing a sensitive value back to where the session first held it.
//!
//! Passwords and generic API keys are recognized only by a label (`password: X`,
//! `"new_password":"X"`). A person who typed the value into a prompt without one, or a tool
//! result that printed it, left it stored in clear and unindexed, so the value's first mention
//! seemed to be the later labelled one (usually the agent's Call). When the Generator recognizes
//! such a value for the first time in a session, it looks for it in what the session stored
//! before, masks every stored copy and records the earlier nodes as mentioning it, so the
//! earliest mention is the real source.
//!
//! The value itself is only in memory, for the search: it is never written, logged or sent to
//! PostgreSQL. PostgreSQL narrows the rows read by the two ends a mask keeps (`hunt…2abc`),
//! which the token already stores.

use std::collections::{BTreeMap, BTreeSet};

use deadpool_postgres::Transaction;
use serde_json::json;
use withhuman_common::tokens::{self, Secret, TRACEABLE_KINDS};

use crate::{
    PgGraphRepository,
    event::{indexed_payload, paragraph_slot, payload_slot},
    pg_repository::{PgError, STORE_TOKENS, one, optional, prepared, run},
    repository::{BacktrackReport, RepositoryError},
};

const EARLIER_TOKEN: &str = "\
SELECT EXISTS (SELECT 1 FROM tokens WHERE session_id = $1::text AND key_kind = $2::text \
AND key = $3::text AND node_order < $4::bigint)";

// Every text column of a node that can quote what the session held: the payload, the intent a
// message stated, and what Decision wrote (its trace quotes the prompt and tool results). `$2`
// and `$3`, the ends the value's mask keeps (NULL for none), narrow the rows read; the rows are
// locked so Decision's writes to them wait for the masking.
const STORED_NODES: &str = "\
SELECT seq, \"order\", event_name, payload_json, intent, trace_json, decision_reason, \
  decision_jev_json, trace_error, continuation_error \
FROM nodes WHERE session_id = $1::text AND ($2::text IS NULL OR ( \
  strpos(concat_ws(' ', payload_json, intent, trace_json, decision_reason, decision_jev_json, \
    trace_error, continuation_error), $2::text) > 0 \
  AND strpos(concat_ws(' ', payload_json, intent, trace_json, decision_reason, \
    decision_jev_json, trace_error, continuation_error), $3::text) > 0)) \
ORDER BY \"order\" FOR UPDATE";

const MASK_NODE: &str = "\
UPDATE nodes SET payload_json = $3::text, intent = $4::text, trace_json = $5::text, \
  decision_reason = $6::text, decision_jev_json = $7::text, trace_error = $8::text, \
  continuation_error = $9::text \
WHERE session_id = $1::text AND seq = $2::bigint";

const STORED_PARAGRAPHS: &str = "\
SELECT p.seq, p.\"index\", p.source, p.text, n.\"order\" FROM paragraphs p \
JOIN nodes n ON n.session_id = p.session_id AND n.seq = p.seq \
WHERE p.session_id = $1::text AND ($2::text IS NULL \
  OR (strpos(p.text, $2::text) > 0 AND strpos(p.text, $3::text) > 0)) \
ORDER BY p.seq, p.\"index\" FOR UPDATE OF p";

const MASK_PARAGRAPH: &str = "\
UPDATE paragraphs SET text = $4::text \
WHERE session_id = $1::text AND seq = $2::bigint AND \"index\" = $3::bigint";

const STORED_COMMITS: &str = "\
SELECT \"order\", event_json FROM event_commits WHERE session_id = $1::text AND ($2::text IS NULL \
  OR (strpos(event_json, $2::text) > 0 AND strpos(event_json, $3::text) > 0)) \
ORDER BY \"order\" FOR UPDATE";

const MASK_COMMIT: &str = "\
UPDATE event_commits SET event_json = $3::text WHERE session_id = $1::text AND \"order\" = $2::bigint";

// The sensitive tokens of a session whose values can be found again by their mask.
const SESSION_SECRETS: &str = "\
SELECT DISTINCT key_kind, key, decoded FROM tokens \
WHERE session_id = $1::text AND key_kind = ANY($2::text[]) AND decoded IS NOT NULL";

// Each traceable token's first mention in its session, when it is the agent's: the candidates of
// `backtrack-secrets`. A token with an earlier mention in any slot is not one.
const AGENT_FIRST: &str = "\
SELECT session_id, key_kind, key, decoded, node_order FROM ( \
  SELECT DISTINCT ON (session_id, key_kind, key) session_id, key_kind, key, slot, decoded, \
    node_order \
  FROM tokens WHERE key_kind = ANY($1::text[]) \
  ORDER BY session_id, key_kind, key, node_order, slot \
) first WHERE slot = 'agent' AND decoded IS NOT NULL \
ORDER BY session_id, node_order";

const LOCK_SESSION: &str = "SELECT 1 FROM sessions WHERE session_id = $1::text FOR UPDATE";

/// What one search changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Traced {
    /// Stored rows (nodes, paragraphs, commits) whose copy of the value was masked.
    pub(crate) masked: usize,
    /// Earlier nodes now recorded as mentioning the value.
    pub(crate) mentions: usize,
}

/// Looks for `secret`, first recognized at `first_order`, in everything `session` stored. Every
/// stored copy is masked as the token is (`decoded`), and each node before `first_order` that
/// holds it becomes a mention: in the slot of its payload (who wrote that value) or of its
/// paragraph's source, as the detector would have recorded it. A result's copy of its Call's
/// input and a Call's attached program files are masked but not mentions, as at ingest.
///
/// Does nothing when the session already has the token before `first_order`, so running it
/// again finds what the first run recorded and stops.
pub(crate) async fn backtrack(
    tx: &Transaction<'_>,
    session: &str,
    first_order: i64,
    secret: &Secret,
) -> Result<Traced, PgError> {
    let token = &secret.token;
    let mut traced = Traced::default();
    if !secret.traceable()
        || one(
            tx,
            EARLIER_TOKEN,
            &[&session, &token.kind, &token.key, &first_order],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Ok(traced);
    }
    let (head, tail) = match mask_ends(&token.decoded) {
        Some((head, tail)) => (Some(head), Some(tail)),
        None => (None, None),
    };
    let mask = |text: &str| tokens::mask_value(text, secret.value(), &token.decoded);
    // Node seq -> its order and the slots it mentions the value in.
    let mut mentions: BTreeMap<i64, (i64, BTreeSet<&'static str>)> = BTreeMap::new();

    let nodes = tx
        .query(
            &prepared(tx, STORED_NODES).await?,
            &[&session, &head, &tail],
        )
        .await?;
    for row in nodes {
        let seq: i64 = row.get(0);
        let order: i64 = row.get(1);
        let event_name: String = row.get(2);
        let mut columns: Vec<Option<String>> = (3..10).map(|index| row.get(index)).collect();
        if order < first_order {
            if let Some(payload) = &columns[0] {
                if tokens::mentions(&indexed_payload(&event_name, payload), secret.value()) {
                    mentions
                        .entry(seq)
                        .or_insert_with(|| (order, BTreeSet::new()))
                        .1
                        .insert(payload_slot(&event_name));
                }
            }
        }
        let mut changed = false;
        for column in columns.iter_mut().flatten() {
            if let Some(masked) = mask(column) {
                *column = masked;
                changed = true;
            }
        }
        if changed {
            run(
                tx,
                MASK_NODE,
                &[
                    &session,
                    &seq,
                    &columns[0],
                    &columns[1],
                    &columns[2],
                    &columns[3],
                    &columns[4],
                    &columns[5],
                    &columns[6],
                ],
            )
            .await?;
            traced.masked += 1;
        }
    }

    let paragraphs = tx
        .query(
            &prepared(tx, STORED_PARAGRAPHS).await?,
            &[&session, &head, &tail],
        )
        .await?;
    for row in paragraphs {
        let seq: i64 = row.get(0);
        let index: i64 = row.get(1);
        let source: Option<String> = row.get(2);
        let Some(text) = row.get::<_, Option<String>>(3) else {
            continue;
        };
        let order: i64 = row.get(4);
        if order < first_order && tokens::mentions(&text, secret.value()) {
            mentions
                .entry(seq)
                .or_insert_with(|| (order, BTreeSet::new()))
                .1
                .insert(paragraph_slot(source.as_deref().unwrap_or_default()));
        }
        if let Some(masked) = mask(&text) {
            run(tx, MASK_PARAGRAPH, &[&session, &seq, &index, &masked]).await?;
            traced.masked += 1;
        }
    }

    let commits = tx
        .query(
            &prepared(tx, STORED_COMMITS).await?,
            &[&session, &head, &tail],
        )
        .await?;
    for row in commits {
        let order: i64 = row.get(0);
        let event_json: String = row.get(1);
        if let Some(masked) = mask(&event_json) {
            run(tx, MASK_COMMIT, &[&session, &order, &masked]).await?;
            traced.masked += 1;
        }
    }

    for (seq, (order, slots)) in mentions {
        let input = json!(
            slots
                .iter()
                .map(|slot| json!({
                    "key_kind": token.kind,
                    "key": token.key,
                    "slot": slot,
                    "decoded": token.decoded,
                    "category": token.category.as_str(),
                }))
                .collect::<Vec<_>>()
        );
        // A node's seq is the version its commit made.
        run(tx, STORE_TOKENS, &[&session, &seq, &order, &input, &seq]).await?;
        traced.mentions += slots.len();
    }
    Ok(traced)
}

/// Whether a repeated commit's `incoming` event is the one stored as `stored`, once the values a
/// later commit traced back into it are masked as they were.
pub(crate) async fn same_after_backtrack(
    tx: &Transaction<'_>,
    session: &str,
    incoming: &str,
    stored: &str,
) -> Result<bool, PgError> {
    let kinds: Vec<&str> = TRACEABLE_KINDS.to_vec();
    let mut text = incoming.to_owned();
    for row in tx
        .query(&prepared(tx, SESSION_SECRETS).await?, &[&session, &kinds])
        .await?
    {
        let (kind, key, decoded): (String, String, String) = (row.get(0), row.get(1), row.get(2));
        let Some(secret) = tokens::recover(&text, &kind, &key, &decoded) else {
            continue;
        };
        if !secret.traceable() {
            continue;
        }
        if let Some(masked) = tokens::mask_value(&text, secret.value(), &decoded) {
            text = masked;
        }
    }
    Ok(text == stored)
}

/// The two ends `mask_ends` keeps of a value (`hunt…2abc`, after a JWT's `jwt(alg=…) `), when
/// they read the same in JSON text. PostgreSQL narrows the rows to search by them.
fn mask_ends(decoded: &str) -> Option<(String, String)> {
    let mask = decoded.split_once(") ").map_or(decoded, |(_, mask)| mask);
    let (head, tail) = mask.split_once('…')?;
    let plain = |end: &str| {
        end.chars().count() == 4 && !end.contains(|c: char| c == '"' || c == '\\' || c.is_control())
    };
    (plain(head) && plain(tail)).then(|| (head.to_owned(), tail.to_owned()))
}

impl PgGraphRepository {
    /// Traces back the values recorded before the Generator did so at ingest: each traceable
    /// token whose first mention in its session is the agent's. The value is no longer stored,
    /// so it is found again by its mask (`tokens::recover`) in the session's stored text, then
    /// traced as at ingest, one session's token per transaction under the session's lock, so it
    /// can run beside the Generator. Running it again changes nothing more.
    pub async fn backtrack_secrets(&self) -> Result<BacktrackReport, RepositoryError> {
        let kinds: Vec<&str> = TRACEABLE_KINDS.to_vec();
        let candidates = {
            let client = self.client().await?;
            client
                .query(AGENT_FIRST, &[&kinds])
                .await
                .map_err(|error| RepositoryError::from(PgError::from(error)))?
        };
        let mut report = BacktrackReport::default();
        for row in candidates {
            report.scanned += 1;
            let session: String = row.get(0);
            let kind: String = row.get(1);
            let key: String = row.get(2);
            let decoded: String = row.get(3);
            let first_order: i64 = row.get(4);
            let traced = self
                .backtrack_stored(&session, &kind, &key, &decoded, first_order)
                .await
                .map_err(RepositoryError::from)?;
            if let Some(traced) = traced {
                report.recovered += 1;
                if traced.mentions > 0 {
                    report.traced += 1;
                }
                report.masked += traced.masked;
            }
        }
        Ok(report)
    }

    /// One candidate of [`Self::backtrack_secrets`]; `None` when its value was not found again.
    async fn backtrack_stored(
        &self,
        session: &str,
        kind: &str,
        key: &str,
        decoded: &str,
        first_order: i64,
    ) -> Result<Option<Traced>, PgError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        if optional(&tx, LOCK_SESSION, &[&session]).await?.is_none() {
            return Ok(None);
        }
        let (head, tail) = match mask_ends(decoded) {
            Some((head, tail)) => (Some(head), Some(tail)),
            None => (None, None),
        };
        let mut secret = None;
        let texts = tx
            .query(
                "SELECT payload_json FROM nodes WHERE session_id = $1::text \
                 AND ($2::text IS NULL OR (strpos(payload_json, $2::text) > 0 \
                   AND strpos(payload_json, $3::text) > 0)) \
                 UNION ALL SELECT text FROM paragraphs WHERE session_id = $1::text \
                 AND ($2::text IS NULL OR (strpos(text, $2::text) > 0 \
                   AND strpos(text, $3::text) > 0)) \
                 UNION ALL SELECT event_json FROM event_commits WHERE session_id = $1::text \
                 AND ($2::text IS NULL OR (strpos(event_json, $2::text) > 0 \
                   AND strpos(event_json, $3::text) > 0))",
                &[&session, &head, &tail],
            )
            .await?;
        for row in texts {
            if let Some(text) = row.get::<_, Option<String>>(0) {
                secret = tokens::recover(&text, kind, key, decoded);
                if secret.is_some() {
                    break;
                }
            }
        }
        let Some(secret) = secret else {
            return Ok(None);
        };
        let traced = backtrack(&tx, session, first_order, &secret).await?;
        tx.commit().await?;
        Ok(Some(traced))
    }
}
