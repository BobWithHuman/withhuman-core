//! PostgreSQL storage for the agent inventory: devices, users and their keys.

use tokio_postgres::Row;
use withhuman_contracts::inventory::{
    ClientRecord, ClientRegistrationRecord, KeyDenial, KeyRecord, KeyStatus, NewKey, Review,
    ReviewRequest, RevokeKeyRequest, SessionFlags, SessionStop, SessionStopRequest, UserKind,
    VerifyKeyRequest, VerifyKeyResponse,
};

use crate::{
    PgGraphRepository,
    pg_repository::{PgError, one, optional, run, signed},
    repository::{KeyScope, RepositoryError},
};

// A registration fills what the setup reported and keeps the rest. Hook activity
// (`first_seen`, `last_seen`) is left to the Hooks.
const REGISTER_CLIENT: &str = "\
INSERT INTO clients (client_id, team, hostname, os, os_user, hook_version, agent, user_email, \
  registered_at, updated_at, install_scope) \
VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, \
  $9::bigint, $9::bigint, $10::text) \
ON CONFLICT (client_id) DO UPDATE SET \
  install_scope = coalesce(EXCLUDED.install_scope, clients.install_scope), \
  team = coalesce(EXCLUDED.team, clients.team), \
  hostname = coalesce(EXCLUDED.hostname, clients.hostname), \
  os = coalesce(EXCLUDED.os, clients.os), \
  os_user = coalesce(EXCLUDED.os_user, clients.os_user), \
  hook_version = coalesce(EXCLUDED.hook_version, clients.hook_version), \
  agent = coalesce(EXCLUDED.agent, clients.agent), \
  user_email = coalesce(EXCLUDED.user_email, clients.user_email), \
  registered_at = coalesce(clients.registered_at, EXCLUDED.registered_at), \
  updated_at = EXCLUDED.updated_at";

const INSTALL_PROJECT: &str = "\
INSERT INTO client_projects (client_id, project, agent, hook_version, installed_at, updated_at) \
VALUES ($1::text, $2::text, $3::text, $4::text, $5::bigint, $5::bigint) \
ON CONFLICT (client_id, project) DO UPDATE SET agent = EXCLUDED.agent, \
  hook_version = EXCLUDED.hook_version, updated_at = EXCLUDED.updated_at";

const CLIENTS: &str = "\
SELECT c.client_id, c.team, c.hostname, c.os, c.os_user, c.hook_version, c.user_email, \
  c.registered_at, c.updated_at, c.first_seen, c.last_seen, \
  coalesce(array_agg(p.project ORDER BY p.updated_at DESC) FILTER (WHERE p.project IS NOT NULL), \
    '{}'), c.install_scope, c.last_checkin_at \
FROM clients c LEFT JOIN client_projects p ON p.client_id = c.client_id \
WHERE $1::text IS NULL OR c.client_id = $1::text \
GROUP BY c.client_id \
ORDER BY greatest(c.last_seen, c.updated_at) DESC NULLS LAST, c.client_id \
LIMIT 10000";

// Using a key moves its `last_used_at`, at most once a minute.
const VERIFY_KEY: &str = "\
WITH found AS ( \
  SELECT user_email, revoked_at FROM api_keys WHERE key_id = $1::text AND hash = $2::text \
), used AS ( \
  UPDATE api_keys SET last_used_at = $3::bigint \
  WHERE key_id = $1::text AND hash = $2::text AND revoked_at IS NULL \
    AND (last_used_at IS NULL OR last_used_at < $3::bigint - 60000) \
) \
SELECT user_email, revoked_at IS NOT NULL FROM found";

const DENY_KEY: &str = "\
UPDATE api_keys SET first_denied_at = coalesce(first_denied_at, $2::bigint), \
  last_denied_at = greatest(coalesce(last_denied_at, 0), $2::bigint), \
  denied_count = denied_count + 1 \
WHERE key_id = $1::text RETURNING user_email";

// The audit keeps one denial per key and session: when the stop reached it.
const DENIAL_EVENT: &str = "\
INSERT INTO key_events (key_id, user_email, kind, session_id, client_id, at) \
SELECT $1::text, $2::text, 'denied', $3::text, $4::text, $5::bigint \
WHERE NOT EXISTS (SELECT 1 FROM key_events WHERE key_id = $1::text AND kind = 'denied' \
  AND session_id IS NOT DISTINCT FROM $3::text)";

// A user keeps the kind of their first key.
const INSERT_USER: &str = "\
WITH added AS ( \
  INSERT INTO users (email, created_at, kind) VALUES ($1::text, $2::bigint, $3::text) \
  ON CONFLICT DO NOTHING RETURNING kind \
) \
SELECT kind FROM added UNION ALL SELECT kind FROM users WHERE email = $1::text";

const INSERT_KEY: &str = "\
INSERT INTO api_keys (key_id, user_email, hash, created_at, created_by, note) \
VALUES ($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text)";

const KEY_EVENT: &str = "\
INSERT INTO key_events (key_id, user_email, kind, actor, reason, at) \
VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::bigint)";

const KEY_COLUMNS: &str = "k.key_id, k.user_email, k.created_at, k.created_by, k.note, \
k.last_used_at, k.revoked_at, k.revoked_by, k.revoke_reason, k.first_denied_at, \
k.last_denied_at, k.denied_count, u.kind";
const KEYS: &str = "api_keys k JOIN users u ON u.email = k.user_email";

impl PgGraphRepository {
    pub(crate) async fn register(
        &self,
        record: ClientRegistrationRecord,
    ) -> Result<ClientRecord, RepositoryError> {
        let result: Result<ClientRecord, PgError> = async {
            let r = &record.registration;
            let at = signed(record.registered_at)?;
            let text = |value: &Option<String>| {
                value
                    .as_deref()
                    .map(|value| withhuman_common::postgres_text(value).into_owned())
            };
            let client_id = withhuman_common::postgres_text(&r.client_id).into_owned();
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            run(
                &tx,
                REGISTER_CLIENT,
                &[
                    &client_id,
                    &text(&r.team),
                    &text(&r.hostname),
                    &text(&r.os),
                    &text(&r.os_user),
                    &text(&r.hook_version),
                    &text(&r.agent),
                    &record.user,
                    &at,
                    &text(&r.scope),
                ],
            )
            .await?;
            if let Some(project) = text(&r.project) {
                run(
                    &tx,
                    INSTALL_PROJECT,
                    &[
                        &client_id,
                        &project,
                        &text(&r.agent),
                        &text(&r.hook_version),
                        &at,
                    ],
                )
                .await?;
            }
            let row = one(&tx, CLIENTS, &[&Some(client_id)]).await?;
            tx.commit().await?;
            client_record(&row)
        }
        .await;
        Ok(result?)
    }

    pub(crate) async fn all_clients(&self) -> Result<Vec<ClientRecord>, RepositoryError> {
        let result: Result<Vec<ClientRecord>, PgError> = async {
            let client = self.client().await?;
            let rows = client
                .query(&client.prepare_cached(CLIENTS).await?, &[&None::<String>])
                .await?;
            rows.iter().map(client_record).collect()
        }
        .await;
        Ok(result?)
    }

    pub(crate) async fn verify(
        &self,
        request: VerifyKeyRequest,
    ) -> Result<VerifyKeyResponse, RepositoryError> {
        let used_at = signed(request.used_at)?;
        let result: Result<Option<Row>, PgError> = async {
            let client = self.client().await?;
            optional(
                &client,
                VERIFY_KEY,
                &[&request.key_id, &request.hash, &used_at],
            )
            .await
        }
        .await;
        Ok(match result? {
            Some(row) => VerifyKeyResponse {
                status: if row.get(1) {
                    KeyStatus::Revoked
                } else {
                    KeyStatus::Active
                },
                user: Some(row.get(0)),
            },
            None => VerifyKeyResponse {
                status: KeyStatus::Unknown,
                user: None,
            },
        })
    }

    pub(crate) async fn deny(
        &self,
        key_id: &str,
        denial: KeyDenial,
    ) -> Result<(), RepositoryError> {
        let at = signed(denial.denied_at)?;
        let result: Result<bool, PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            let Some(row) = optional(&tx, DENY_KEY, &[&key_id, &at]).await? else {
                return Ok(false);
            };
            let user: String = row.get(0);
            run(
                &tx,
                DENIAL_EVENT,
                &[&key_id, &user, &denial.session_id, &denial.client_id, &at],
            )
            .await?;
            tx.commit().await?;
            Ok(true)
        }
        .await;
        if result? {
            Ok(())
        } else {
            Err(RepositoryError::NotFound)
        }
    }

    pub(crate) async fn issue(&self, key: NewKey) -> Result<KeyRecord, RepositoryError> {
        let at = signed(key.created_at)?;
        let result: Result<KeyRecord, PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            let kind: String = one(&tx, INSERT_USER, &[&key.user, &at, &key.kind.as_str()])
                .await?
                .get(0);
            if kind != key.kind.as_str() {
                return Err(PgError::Repository(RepositoryError::InvalidEvent(format!(
                    "{} is a {kind}, not a {}",
                    key.user,
                    key.kind.as_str()
                ))));
            }
            run(
                &tx,
                INSERT_KEY,
                &[
                    &key.key_id,
                    &key.user,
                    &key.hash,
                    &at,
                    &key.actor,
                    &key.note,
                ],
            )
            .await?;
            run(
                &tx,
                KEY_EVENT,
                &[
                    &key.key_id,
                    &key.user,
                    &"issued",
                    &key.actor,
                    &key.note,
                    &at,
                ],
            )
            .await?;
            let row = one(
                &tx,
                &format!("SELECT {KEY_COLUMNS} FROM {KEYS} WHERE k.key_id = $1::text"),
                &[&key.key_id],
            )
            .await?;
            tx.commit().await?;
            key_record(&row)
        }
        .await;
        Ok(result?)
    }

    /// Revokes the keys in `scope` that are still active and returns every key in it; a key
    /// already revoked keeps its first revocation.
    pub(crate) async fn revoke(
        &self,
        scope: KeyScope<'_>,
        request: RevokeKeyRequest,
        revoked_at: u64,
    ) -> Result<Vec<KeyRecord>, RepositoryError> {
        let at = signed(revoked_at)?;
        let (column, value) = match scope {
            KeyScope::Key(key_id) => ("key_id", key_id),
            KeyScope::User(user) => ("user_email", user),
        };
        let result: Result<Vec<KeyRecord>, PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            let revoked = tx
                .query(
                    &tx.prepare_cached(&format!(
                        "UPDATE api_keys SET revoked_at = $2::bigint, revoked_by = $3::text, \
                         revoke_reason = $4::text \
                         WHERE {column} = $1::text AND revoked_at IS NULL \
                         RETURNING key_id, user_email"
                    ))
                    .await?,
                    &[&value, &at, &request.actor, &request.reason],
                )
                .await?;
            for row in &revoked {
                let (key_id, user): (String, String) = (row.get(0), row.get(1));
                run(
                    &tx,
                    KEY_EVENT,
                    &[
                        &key_id,
                        &user,
                        &"revoked",
                        &request.actor,
                        &request.reason,
                        &at,
                    ],
                )
                .await?;
            }
            let rows = tx
                .query(
                    &tx.prepare_cached(&format!(
                        "SELECT {KEY_COLUMNS} FROM {KEYS} WHERE k.{column} = $1::text \
                         ORDER BY k.created_at DESC, k.key_id"
                    ))
                    .await?,
                    &[&value],
                )
                .await?;
            tx.commit().await?;
            rows.iter().map(key_record).collect()
        }
        .await;
        let keys = result?;
        if keys.is_empty() {
            return Err(RepositoryError::NotFound);
        }
        Ok(keys)
    }

    pub(crate) async fn list_keys(
        &self,
        user: Option<&str>,
    ) -> Result<Vec<KeyRecord>, RepositoryError> {
        let result: Result<Vec<KeyRecord>, PgError> = async {
            let client = self.client().await?;
            let rows = client
                .query(
                    &client
                        .prepare_cached(&format!(
                            "SELECT {KEY_COLUMNS} FROM {KEYS} \
                             WHERE $1::text IS NULL OR k.user_email = $1::text \
                             ORDER BY k.created_at DESC, k.key_id LIMIT 10000"
                        ))
                        .await?,
                    &[&user],
                )
                .await?;
            rows.iter().map(key_record).collect()
        }
        .await;
        Ok(result?)
    }
}

const ACTIVE_STOP: &str = "\
SELECT id, session_id, stopped_at, stopped_by, reason, released_at, released_by, release_reason, \
  first_denied_at, last_denied_at, denied_count \
FROM session_stops WHERE session_id = $1::text AND released_at IS NULL";

// Stopping a stopped session keeps the stop it has.
const STOP_SESSION: &str = "\
INSERT INTO session_stops (session_id, stopped_at, stopped_by, reason) \
SELECT $1::text, $2::bigint, $3::text, $4::text \
WHERE EXISTS (SELECT 1 FROM sessions WHERE session_id = $1::text) \
ON CONFLICT (session_id) WHERE released_at IS NULL DO NOTHING";

const RELEASE_SESSION: &str = "\
UPDATE session_stops SET released_at = $2::bigint, released_by = $3::text, \
  release_reason = $4::text \
WHERE session_id = $1::text AND released_at IS NULL \
RETURNING id, session_id, stopped_at, stopped_by, reason, released_at, released_by, \
  release_reason, first_denied_at, last_denied_at, denied_count";

const DENY_SESSION: &str = "\
UPDATE session_stops SET first_denied_at = coalesce(first_denied_at, $2::bigint), \
  last_denied_at = greatest(coalesce(last_denied_at, 0), $2::bigint), \
  denied_count = denied_count + 1 \
WHERE session_id = $1::text AND released_at IS NULL";

// A review names a Call of the graph.
const ADD_REVIEW: &str = "\
INSERT INTO call_reviews (session_id, seq, status, note, actor, at) \
SELECT $1::text, $2::bigint, $3::text, $4::text, $5::text, $6::bigint \
WHERE EXISTS (SELECT 1 FROM nodes WHERE session_id = $1::text AND seq = $2::bigint \
  AND kind = 'Call') \
RETURNING id";

const SESSION_EXCEPTION: &str = "SELECT exception_id FROM sessions WHERE session_id = $1::text";

// A check-in fills what the device reports and keeps the rest; a project it reports again keeps
// when it was first reported.
const CHECKIN_CLIENT: &str = "\
INSERT INTO clients (client_id, team, hostname, os, os_user, hook_version, user_email, \
  install_scope, last_checkin_at) \
VALUES ($1::text, CASE WHEN position('/' IN $1::text) > 0 THEN split_part($1::text, '/', 1) END, \
  $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::bigint) \
ON CONFLICT (client_id) DO UPDATE SET \
  hostname = coalesce(EXCLUDED.hostname, clients.hostname), \
  os = coalesce(EXCLUDED.os, clients.os), \
  os_user = coalesce(EXCLUDED.os_user, clients.os_user), \
  hook_version = coalesce(EXCLUDED.hook_version, clients.hook_version), \
  user_email = coalesce(EXCLUDED.user_email, clients.user_email), \
  install_scope = coalesce(EXCLUDED.install_scope, clients.install_scope), \
  last_checkin_at = GREATEST(coalesce(clients.last_checkin_at, 0), EXCLUDED.last_checkin_at)";

const SEEN_PROJECTS: &str = "\
INSERT INTO client_seen_projects (client_id, project, last_used_at, first_reported_at, \
  last_reported_at) \
SELECT $1::text, p.path, p.last_used_at, $3::bigint, $3::bigint \
FROM jsonb_to_recordset($2::jsonb) AS p(path text, last_used_at bigint) \
WHERE p.path IS NOT NULL AND p.path <> '' \
ON CONFLICT (client_id, project) DO UPDATE SET \
  last_used_at = GREATEST(client_seen_projects.last_used_at, EXCLUDED.last_used_at), \
  last_reported_at = EXCLUDED.last_reported_at";

const EXCEPTION_COLUMNS: &str = "id, folder, team, client_id, actor, reason, created_at, \
removed_at, removed_by";

// The active exceptions that can cover a client's sessions: its team's, its own and everyone's.
const CLIENT_EXCEPTIONS: &str = "\
SELECT id, folder, team, client_id, actor, reason, created_at, removed_at, removed_by \
FROM exceptions WHERE removed_at IS NULL \
  AND (client_id IS NULL OR client_id = $1::text) \
  AND (team IS NULL OR team = split_part($1::text, '/', 1)) \
ORDER BY id";

// A request the gateway retried keeps its first record.
const MODEL_CALL: &str = "\
INSERT INTO model_calls (request_id, user_email, client_id, session_id, model, at) \
VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::bigint) \
ON CONFLICT (request_id) WHERE request_id IS NOT NULL DO NOTHING";

// The tokens of recorded model requests, from the gateway's request log in the same database:
// its row names our record in `attributes_json.withhuman_request`.
const MODEL_TOKENS: &str = "\
UPDATE model_calls m SET input_tokens = r.input_tokens, output_tokens = r.output_tokens, \
  model = coalesce(r.gen_ai_response_model, r.gen_ai_request_model, m.model) \
FROM request_logs r \
WHERE r.attributes_json->>'withhuman_request' = m.request_id \
  AND m.input_tokens IS NULL AND m.output_tokens IS NULL AND m.at > $1::bigint \
  AND (r.input_tokens IS NOT NULL OR r.output_tokens IS NOT NULL)";

impl PgGraphRepository {
    /// Copies the token counts of model requests recorded since `since` from the gateway's
    /// request log; none while the gateway has made no log. The number of records filled.
    pub async fn import_model_tokens(&self, since: u64) -> Result<u64, RepositoryError> {
        let since = signed(since)?;
        let result: Result<u64, PgError> = async {
            let client = self.client().await?;
            let present: bool = one(
                &client,
                "SELECT to_regclass('request_logs') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
            if !present {
                return Ok(0);
            }
            client
                .batch_execute(
                    "CREATE INDEX IF NOT EXISTS request_logs_withhuman_request \
                     ON request_logs ((attributes_json->>'withhuman_request'))",
                )
                .await?;
            run(&client, MODEL_TOKENS, &[&since]).await
        }
        .await;
        Ok(result?)
    }

    pub(crate) async fn model_call(
        &self,
        call: withhuman_contracts::inventory::ModelCall,
    ) -> Result<(), RepositoryError> {
        let at = signed(call.at)?;
        let result: Result<u64, PgError> = async {
            let client = self.client().await?;
            run(
                &client,
                MODEL_CALL,
                &[
                    &call.request_id,
                    &call.user,
                    &call.client_id,
                    &call.session_id,
                    &call.model,
                    &at,
                ],
            )
            .await
        }
        .await;
        result?;
        Ok(())
    }

    pub(crate) async fn checkin(
        &self,
        record: withhuman_contracts::inventory::ClientCheckinRecord,
    ) -> Result<(), RepositoryError> {
        let at = signed(record.checked_in_at)?;
        let c = &record.checkin;
        let text = |value: &Option<String>| {
            value
                .as_deref()
                .map(|value| withhuman_common::postgres_text(value).into_owned())
        };
        let projects = serde_json::to_value(&c.projects)
            .map_err(|error| RepositoryError::InvalidEvent(error.to_string()))?;
        let result: Result<(), PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            run(
                &tx,
                CHECKIN_CLIENT,
                &[
                    &c.client_id,
                    &text(&c.hostname),
                    &text(&c.os),
                    &text(&c.os_user),
                    &text(&c.hook_version),
                    &record.user,
                    &text(&c.scope),
                    &at,
                ],
            )
            .await?;
            run(&tx, SEEN_PROJECTS, &[&c.client_id, &projects, &at]).await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        Ok(result?)
    }

    pub(crate) async fn add_exception(
        &self,
        request: withhuman_contracts::inventory::ExceptionRequest,
        at: u64,
    ) -> Result<withhuman_contracts::inventory::Exception, RepositoryError> {
        let at = signed(at)?;
        let result: Result<Row, PgError> = async {
            let client = self.client().await?;
            one(
                &client,
                &format!(
                    "INSERT INTO exceptions (folder, team, client_id, actor, reason, created_at) \
                     VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::bigint) \
                     RETURNING {EXCEPTION_COLUMNS}"
                ),
                &[
                    &request.folder,
                    &request.team,
                    &request.client_id,
                    &request.actor,
                    &request.reason,
                    &at,
                ],
            )
            .await
        }
        .await;
        Ok(exception(&result?)?)
    }

    pub(crate) async fn remove_exception(
        &self,
        id: u64,
        actor: Option<String>,
        at: u64,
    ) -> Result<withhuman_contracts::inventory::Exception, RepositoryError> {
        let (id, at) = (signed(id)?, signed(at)?);
        let result: Result<Option<Row>, PgError> = async {
            let client = self.client().await?;
            run(
                &client,
                "UPDATE exceptions SET removed_at = $2::bigint, removed_by = $3::text \
                 WHERE id = $1::bigint AND removed_at IS NULL",
                &[&id, &at, &actor],
            )
            .await?;
            optional(
                &client,
                &format!("SELECT {EXCEPTION_COLUMNS} FROM exceptions WHERE id = $1::bigint"),
                &[&id],
            )
            .await
        }
        .await;
        Ok(exception(&result?.ok_or(RepositoryError::NotFound)?)?)
    }

    /// Every exception, or those that can cover `client_id`'s sessions (active only).
    pub(crate) async fn list_exceptions(
        &self,
        client_id: Option<&str>,
    ) -> Result<Vec<withhuman_contracts::inventory::Exception>, RepositoryError> {
        let result: Result<Vec<Row>, PgError> = async {
            let client = self.client().await?;
            Ok(match client_id {
                Some(client_id) => {
                    client
                        .query(
                            &client.prepare_cached(CLIENT_EXCEPTIONS).await?,
                            &[&client_id],
                        )
                        .await?
                }
                None => {
                    client
                        .query(
                            &client
                                .prepare_cached(&format!(
                                    "SELECT {EXCEPTION_COLUMNS} FROM exceptions ORDER BY id"
                                ))
                                .await?,
                            &[],
                        )
                        .await?
                }
            })
        }
        .await;
        result?
            .iter()
            .map(|row| exception(row).map_err(RepositoryError::from))
            .collect()
    }

    pub(crate) async fn flags(&self, session_id: &str) -> Result<SessionFlags, RepositoryError> {
        let result: Result<SessionFlags, PgError> = async {
            let client = self.client().await?;
            let stop = optional(&client, ACTIVE_STOP, &[&session_id]).await?;
            let exception = optional(&client, SESSION_EXCEPTION, &[&session_id])
                .await?
                .and_then(|row| row.get::<_, Option<i64>>(0));
            Ok(SessionFlags {
                stop: stop.as_ref().map(session_stop).transpose()?,
                exception: exception.map(crate::pg_repository::unsigned).transpose()?,
            })
        }
        .await;
        Ok(result?)
    }

    pub(crate) async fn stop(
        &self,
        session_id: &str,
        request: SessionStopRequest,
        at: u64,
    ) -> Result<SessionStop, RepositoryError> {
        let at = signed(at)?;
        let result: Result<Option<SessionStop>, PgError> = async {
            let client = self.client().await?;
            run(
                &client,
                STOP_SESSION,
                &[&session_id, &at, &request.actor, &request.reason],
            )
            .await?;
            optional(&client, ACTIVE_STOP, &[&session_id])
                .await?
                .as_ref()
                .map(session_stop)
                .transpose()
        }
        .await;
        result?.ok_or(RepositoryError::NotFound)
    }

    pub(crate) async fn release(
        &self,
        session_id: &str,
        request: SessionStopRequest,
        at: u64,
    ) -> Result<SessionStop, RepositoryError> {
        let at = signed(at)?;
        let result: Result<Option<SessionStop>, PgError> = async {
            let client = self.client().await?;
            optional(
                &client,
                RELEASE_SESSION,
                &[&session_id, &at, &request.actor, &request.reason],
            )
            .await?
            .as_ref()
            .map(session_stop)
            .transpose()
        }
        .await;
        result?.ok_or(RepositoryError::NotFound)
    }

    pub(crate) async fn deny_session(
        &self,
        session_id: &str,
        at: u64,
    ) -> Result<(), RepositoryError> {
        let at = signed(at)?;
        let result: Result<u64, PgError> = async {
            let client = self.client().await?;
            run(&client, DENY_SESSION, &[&session_id, &at]).await
        }
        .await;
        match result? {
            0 => Err(RepositoryError::NotFound),
            _ => Ok(()),
        }
    }

    pub(crate) async fn review(
        &self,
        request: ReviewRequest,
        at: u64,
    ) -> Result<Review, RepositoryError> {
        let seq = signed(request.seq)?;
        let at_signed = signed(at)?;
        let result: Result<Option<Row>, PgError> = async {
            let client = self.client().await?;
            optional(
                &client,
                ADD_REVIEW,
                &[
                    &request.session_id,
                    &seq,
                    &request.status.as_str(),
                    &request.note,
                    &request.actor,
                    &at_signed,
                ],
            )
            .await
        }
        .await;
        let row = result?.ok_or(RepositoryError::NotFound)?;
        Ok(Review {
            id: crate::pg_repository::unsigned(row.get(0))?,
            session_id: request.session_id,
            seq: request.seq,
            status: request.status,
            note: request.note,
            actor: request.actor,
            at,
        })
    }
}

fn exception(row: &Row) -> Result<withhuman_contracts::inventory::Exception, PgError> {
    Ok(withhuman_contracts::inventory::Exception {
        id: millis(row, 0)?.unwrap_or_default(),
        folder: row.get(1),
        team: row.get(2),
        client_id: row.get(3),
        actor: row.get(4),
        reason: row.get(5),
        created_at: millis(row, 6)?.unwrap_or_default(),
        removed_at: millis(row, 7)?,
        removed_by: row.get(8),
    })
}

fn session_stop(row: &Row) -> Result<SessionStop, PgError> {
    Ok(SessionStop {
        id: millis(row, 0)?.unwrap_or_default(),
        session_id: row.get(1),
        stopped_at: millis(row, 2)?.unwrap_or_default(),
        stopped_by: row.get(3),
        reason: row.get(4),
        released_at: millis(row, 5)?,
        released_by: row.get(6),
        release_reason: row.get(7),
        first_denied_at: millis(row, 8)?,
        last_denied_at: millis(row, 9)?,
        denied_count: millis(row, 10)?.unwrap_or_default(),
    })
}

fn millis(row: &Row, index: usize) -> Result<Option<u64>, PgError> {
    row.get::<_, Option<i64>>(index)
        .map(crate::pg_repository::unsigned)
        .transpose()
}

fn client_record(row: &Row) -> Result<ClientRecord, PgError> {
    Ok(ClientRecord {
        client_id: row.get(0),
        team: row.get(1),
        hostname: row.get(2),
        os: row.get(3),
        os_user: row.get(4),
        hook_version: row.get(5),
        user: row.get(6),
        registered_at: millis(row, 7)?,
        updated_at: millis(row, 8)?,
        first_seen: millis(row, 9)?,
        last_seen: millis(row, 10)?,
        projects: row.get(11),
        install_scope: row.get(12),
        last_checkin_at: millis(row, 13)?,
    })
}

fn key_record(row: &Row) -> Result<KeyRecord, PgError> {
    Ok(KeyRecord {
        key_id: row.get(0),
        user: row.get(1),
        created_at: millis(row, 2)?.unwrap_or_default(),
        created_by: row.get(3),
        note: row.get(4),
        last_used_at: millis(row, 5)?,
        revoked_at: millis(row, 6)?,
        revoked_by: row.get(7),
        revoke_reason: row.get(8),
        first_denied_at: millis(row, 9)?,
        last_denied_at: millis(row, 10)?,
        denied_count: millis(row, 11)?.unwrap_or_default(),
        user_kind: if row.get::<_, String>(12) == "service" {
            UserKind::Service
        } else {
            UserKind::Person
        },
    })
}
