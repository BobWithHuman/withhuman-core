//! PostgreSQL storage for the agent inventory: devices, users and their keys.

use tokio_postgres::Row;
use withhuman_contracts::inventory::{
    ClientRecord, ClientRegistrationRecord, ClientState, DeletedClient, KeyDenial, KeyRecord,
    KeyStatus, NewKey, Review, ReviewRequest, RevokeKeyRequest, SessionFlags, SessionStop,
    SessionStopRequest, SetOwnerRequest, StopClientRequest, StopDenial, UserKind, VerifyKeyRequest,
    VerifyKeyResponse,
};

use crate::{
    PgGraphRepository,
    pg_repository::{PgError, one, optional, run, signed},
    repository::{KeyScope, RepositoryError},
};

// A registration fills what the setup reported and keeps the rest, the first user it was
// registered by included: another user's key does not take the device over. Hook activity
// (`first_seen`, `last_seen`) is left to the Hooks, and the owner to the security team.
const REGISTER_CLIENT: &str = "\
INSERT INTO clients (client_id, team, hostname, os, os_user, hook_version, agent, user_email, \
  registered_at, updated_at, install_scope, serial, other_serials) \
VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, \
  $9::bigint, $9::bigint, $10::text, $11::text, $12::text[]) \
ON CONFLICT (client_id) DO UPDATE SET \
  install_scope = coalesce(EXCLUDED.install_scope, clients.install_scope), \
  team = coalesce(EXCLUDED.team, clients.team), \
  hostname = coalesce(EXCLUDED.hostname, clients.hostname), \
  os = coalesce(EXCLUDED.os, clients.os), \
  os_user = coalesce(EXCLUDED.os_user, clients.os_user), \
  hook_version = coalesce(EXCLUDED.hook_version, clients.hook_version), \
  agent = coalesce(EXCLUDED.agent, clients.agent), \
  user_email = coalesce(clients.user_email, EXCLUDED.user_email), \
  serial = coalesce(EXCLUDED.serial, clients.serial), \
  other_serials = CASE WHEN cardinality(EXCLUDED.other_serials) > 0 \
    THEN EXCLUDED.other_serials ELSE clients.other_serials END, \
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
    '{}'), \
  c.serial, c.owner_email, c.owner_set_by, c.owner_set_at, \
  c.stopped_at, c.stopped_by, c.stop_reason, c.stop_denied_count, c.stop_last_denied_at, \
  c.install_scope, c.last_checkin_at \
FROM clients c LEFT JOIN client_projects p ON p.client_id = c.client_id \
WHERE $1::text IS NULL OR c.client_id = $1::text \
GROUP BY c.client_id \
ORDER BY greatest(c.last_seen, c.updated_at) DESC NULLS LAST, c.client_id \
LIMIT 10000";

const SET_OWNER: &str = "\
UPDATE clients SET owner_email = $2::text, owner_set_by = $3::text, owner_set_at = $4::bigint \
WHERE client_id = $1::text RETURNING client_id";

// A device already stopped keeps its first stop, as a revoked key keeps its revocation.
const STOP_CLIENT: &str = "\
UPDATE clients SET stopped_at = $2::bigint, stopped_by = $3::text, stop_reason = $4::text \
WHERE client_id = $1::text AND stopped_at IS NULL";

const RELEASE_CLIENT: &str = "\
UPDATE clients SET stopped_at = NULL, stopped_by = NULL, stop_reason = NULL \
WHERE client_id = $1::text";

// The sessions a device ran: those whose Hooks first carried its client ID.
const SESSIONS_OF_CLIENT: &str = "SELECT session_id FROM sessions WHERE client_id = $1::text";

/// Every table that holds a session's records by `session_id`, deleted with the session.
const SESSION_TABLES: [&str; 11] = [
    "event_commits",
    "nodes",
    "subgraphs",
    "paragraphs",
    "tokens",
    "token_mentions",
    "file_refs",
    "cause_edges",
    "pending_paragraph_enrichments",
    "pending_request_continuations",
    "session_marks",
];

const DELETE_CLIENT_PROJECTS: &str = "DELETE FROM client_projects WHERE client_id = $1::text";
const DELETE_CLIENT: &str = "DELETE FROM clients WHERE client_id = $1::text";

const CLIENT_STOPPED: &str =
    "SELECT stopped_at IS NOT NULL FROM clients WHERE client_id = $1::text";

// Counted only while the device is stopped: a refusal that raced a release is not one.
const DENY_STOPPED: &str = "\
UPDATE clients SET stop_denied_count = stop_denied_count + 1, \
  stop_last_denied_at = greatest(coalesce(stop_last_denied_at, 0), $2::bigint) \
WHERE client_id = $1::text AND stopped_at IS NOT NULL";

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
            let other_serials: Vec<String> = r
                .other_serials
                .iter()
                .map(|serial| withhuman_common::postgres_text(serial).into_owned())
                .collect();
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
                    &text(&r.serial),
                    &other_serials,
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

    /// Names the device's owner, or clears it; `NotFound` for an unknown device.
    pub(crate) async fn set_owner(
        &self,
        client_id: &str,
        request: SetOwnerRequest,
        set_at: u64,
    ) -> Result<ClientRecord, RepositoryError> {
        let at = signed(set_at)?;
        let result: Result<Option<ClientRecord>, PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            let found = optional(
                &tx,
                SET_OWNER,
                &[&client_id, &request.owner, &request.actor, &at],
            )
            .await?;
            if found.is_none() {
                return Ok(None);
            }
            let row = one(&tx, CLIENTS, &[&Some(client_id)]).await?;
            tx.commit().await?;
            client_record(&row).map(Some)
        }
        .await;
        result?.ok_or(RepositoryError::NotFound)
    }

    /// Stops the device, or releases it; `NotFound` for an unknown device. Stopping a stopped
    /// device and releasing a running one change nothing.
    pub(crate) async fn set_stopped(
        &self,
        client_id: &str,
        request: StopClientRequest,
        at: u64,
    ) -> Result<ClientRecord, RepositoryError> {
        let at = signed(at)?;
        let text = |value: &Option<String>| {
            value
                .as_deref()
                .map(|value| withhuman_common::postgres_text(value).into_owned())
        };
        let result: Result<Option<ClientRecord>, PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            if request.stopped {
                let (actor, reason) = (text(&request.actor), text(&masked(&request.reason)));
                run(&tx, STOP_CLIENT, &[&client_id, &at, &actor, &reason]).await?;
            } else {
                run(&tx, RELEASE_CLIENT, &[&client_id]).await?;
            }
            let Some(row) = optional(&tx, CLIENTS, &[&Some(client_id)]).await? else {
                return Ok(None);
            };
            tx.commit().await?;
            client_record(&row).map(Some)
        }
        .await;
        result?.ok_or(RepositoryError::NotFound)
    }

    /// Deletes the device (its row and its projects) and every session it ran, with all that
    /// was recorded of them; `NotFound` when the store holds nothing of it. The audit of keys
    /// (`key_events`) and the sources distrusted from its sessions stay. A device that sends
    /// Hooks again is recorded again.
    pub(crate) async fn remove_client(
        &self,
        client_id: &str,
    ) -> Result<DeletedClient, RepositoryError> {
        let result: Result<Option<u64>, PgError> = async {
            let mut client = self.client().await?;
            let tx = client.transaction().await?;
            let sessions: Vec<String> = tx
                .query(SESSIONS_OF_CLIENT, &[&client_id])
                .await?
                .iter()
                .map(|row| row.get(0))
                .collect();
            for table in SESSION_TABLES {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE session_id = ANY($1::text[])"),
                    &[&sessions],
                )
                .await?;
            }
            tx.execute(
                "DELETE FROM sessions WHERE session_id = ANY($1::text[])",
                &[&sessions],
            )
            .await?;
            tx.execute(DELETE_CLIENT_PROJECTS, &[&client_id]).await?;
            let removed = tx.execute(DELETE_CLIENT, &[&client_id]).await?;
            if removed == 0 && sessions.is_empty() {
                return Ok(None);
            }
            tx.commit().await?;
            Ok(Some(sessions.len() as u64))
        }
        .await;
        result?
            .map(|sessions| DeletedClient {
                client_id: client_id.to_owned(),
                sessions,
            })
            .ok_or(RepositoryError::NotFound)
    }

    /// Whether the device is stopped; a device the store does not hold is not.
    pub(crate) async fn client_stopped(
        &self,
        client_id: &str,
    ) -> Result<ClientState, RepositoryError> {
        let result: Result<Option<Row>, PgError> = async {
            let client = self.client().await?;
            optional(&client, CLIENT_STOPPED, &[&client_id]).await
        }
        .await;
        Ok(ClientState {
            stopped: result?.is_some_and(|row| row.get(0)),
        })
    }

    /// Counts a PreToolUse refused for the stopped device; `NotFound` when it is not stopped.
    pub(crate) async fn deny_stopped(
        &self,
        client_id: &str,
        denial: StopDenial,
    ) -> Result<(), RepositoryError> {
        let at = signed(denial.denied_at)?;
        let result: Result<u64, PgError> = async {
            let client = self.client().await?;
            run(&client, DENY_STOPPED, &[&client_id, &at]).await
        }
        .await;
        if result? == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
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
        let reason = masked(&request.reason);
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
                    &[&value, &at, &request.actor, &reason],
                )
                .await?;
            for row in &revoked {
                let (key_id, user): (String, String) = (row.get(0), row.get(1));
                run(
                    &tx,
                    KEY_EVENT,
                    &[&key_id, &user, &"revoked", &request.actor, &reason, &at],
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

// The session's exception while it is in force: a removed one covers nothing, sessions that
// claimed it before included.
const SESSION_EXCEPTION: &str = "\
SELECT CASE WHEN e.removed_at IS NULL THEN s.exception_id END \
FROM sessions s LEFT JOIN exceptions e ON e.id = s.exception_id \
WHERE s.session_id = $1::text";

// A check-in fills what the device reports and keeps the rest, the user it is registered to
// included; a project it reports again keeps when it was first reported.
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
  user_email = coalesce(clients.user_email, EXCLUDED.user_email), \
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

// Whom a device belongs to: the owner the security team set, else the user whose key first
// registered or used it. Another user's key cannot check in for it or read the exceptions
// covering it; the owner is changed through the admin API (`PUT .../owner`), not by a key.
const CLIENT_OWNER: &str =
    "SELECT coalesce(owner_email, user_email) FROM clients WHERE client_id = $1::text";

const EXCEPTION_COLUMNS: &str = "id, folder, team, client_id, actor, reason, created_at, \
removed_at, removed_by";

// The active exceptions that can cover a client's sessions: its team's, its own and everyone's.
const CLIENT_EXCEPTIONS: &str = "\
SELECT id, folder, team, client_id, actor, reason, created_at, removed_at, removed_by \
FROM exceptions WHERE removed_at IS NULL \
  AND (client_id IS NULL OR client_id = $1::text) \
  AND (team IS NULL OR team = split_part($1::text, '/', 1)) \
ORDER BY id";

impl PgGraphRepository {
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
            let owner = optional(&tx, &format!("{CLIENT_OWNER} FOR UPDATE"), &[&c.client_id])
                .await?
                .and_then(|row| row.get::<_, Option<String>>(0));
            if let (Some(owner), Some(user)) = (owner, record.user.as_deref()) {
                if owner != user {
                    return Err(PgError::Repository(RepositoryError::NotOwner));
                }
            }
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

    /// Every exception, or those that can cover `client_id`'s sessions (active only). A device
    /// registered to a user answers that user alone: another user's key, or none, is refused,
    /// and its hook then sends the session whole.
    pub(crate) async fn list_exceptions(
        &self,
        client_id: Option<&str>,
        user: Option<&str>,
    ) -> Result<Vec<withhuman_contracts::inventory::Exception>, RepositoryError> {
        let result: Result<Vec<Row>, PgError> = async {
            let client = self.client().await?;
            Ok(match client_id {
                Some(client_id) => {
                    let owner = optional(&client, CLIENT_OWNER, &[&client_id])
                        .await?
                        .and_then(|row| row.get::<_, Option<String>>(0));
                    if owner.is_some_and(|owner| user != Some(owner.as_str())) {
                        return Err(PgError::Repository(RepositoryError::NotOwner));
                    }
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
                &[&session_id, &at, &request.actor, &masked(&request.reason)],
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
                &[&session_id, &at, &request.actor, &masked(&request.reason)],
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
        // Stored and answered alike, so the masked note is the only one there is.
        let note = masked(&request.note);
        let result: Result<Option<Row>, PgError> = async {
            let client = self.client().await?;
            optional(
                &client,
                ADD_REVIEW,
                &[
                    &request.session_id,
                    &seq,
                    &request.status.as_str(),
                    &note,
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
            note,
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

/// A note or reason the security team typed, with any secret pasted into it masked before it is
/// stored: the viewer's read-only role reads these tables.
fn masked(text: &Option<String>) -> Option<String> {
    text.as_deref()
        .map(|text| withhuman_common::tokens::redact(text).into_owned())
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
        serial: row.get(12),
        user: row.get(6),
        owner: row.get(13),
        owner_set_by: row.get(14),
        owner_set_at: millis(row, 15)?,
        stopped_at: millis(row, 16)?,
        stopped_by: row.get(17),
        stop_reason: row.get(18),
        stop_denied_count: millis(row, 19)?.unwrap_or_default(),
        stop_last_denied_at: millis(row, 20)?,
        registered_at: millis(row, 7)?,
        updated_at: millis(row, 8)?,
        first_seen: millis(row, 9)?,
        last_seen: millis(row, 10)?,
        projects: row.get(11),
        install_scope: row.get(21),
        last_checkin_at: millis(row, 22)?,
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
