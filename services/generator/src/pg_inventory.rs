//! PostgreSQL storage for the agent inventory: devices, users and their keys.

use tokio_postgres::Row;
use withhuman_contracts::inventory::{
    ClientRecord, ClientRegistrationRecord, KeyDenial, KeyRecord, KeyStatus, NewKey,
    RevokeKeyRequest, VerifyKeyRequest, VerifyKeyResponse,
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
  registered_at, updated_at) \
VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, \
  $9::bigint, $9::bigint) \
ON CONFLICT (client_id) DO UPDATE SET \
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
    '{}') \
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

const INSERT_USER: &str = "\
INSERT INTO users (email, created_at) VALUES ($1::text, $2::bigint) ON CONFLICT DO NOTHING";

const INSERT_KEY: &str = "\
INSERT INTO api_keys (key_id, user_email, hash, created_at, created_by, note) \
VALUES ($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text)";

const KEY_EVENT: &str = "\
INSERT INTO key_events (key_id, user_email, kind, actor, reason, at) \
VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::bigint)";

const KEY_COLUMNS: &str = "key_id, user_email, created_at, created_by, note, last_used_at, \
revoked_at, revoked_by, revoke_reason, first_denied_at, last_denied_at, denied_count";

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
            run(&tx, INSERT_USER, &[&key.user, &at]).await?;
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
                &format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE key_id = $1::text"),
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
                        "SELECT {KEY_COLUMNS} FROM api_keys WHERE {column} = $1::text \
                         ORDER BY created_at DESC, key_id"
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
                            "SELECT {KEY_COLUMNS} FROM api_keys \
                             WHERE $1::text IS NULL OR user_email = $1::text \
                             ORDER BY created_at DESC, key_id LIMIT 10000"
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
    })
}
