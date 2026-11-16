//! The EDR's devices in PostgreSQL: `edr_devices` mirrors the manager, and `clients` carries
//! each registered device's match (`edr_agent_id`, `edr_status`).

use std::{fmt::Display, future::Future, time::Duration};

use deadpool_postgres::Object;

use crate::{
    edr::{ClientIdentity, EdrDevice, EdrSync, EdrSyncError, match_clients},
    pg_repository::{PgError, PgGraphRepository, run, signed},
};

/// Held by the Generator that is syncing, with the schema's hash as the second key.
const SYNC_LOCK: i32 = 0x5748_4544;

const TRY_LOCK: &str = "SELECT pg_try_advisory_lock($1::int4, hashtext(current_schema()))";

const LATEST_SYNC: &str = "SELECT max(synced_at) FROM edr_devices";

const UPSERT_DEVICES: &str = "\
INSERT INTO edr_devices (agent_id, name, os, status, serial, last_seen, agent, synced_at) \
SELECT d.agent_id, d.name, d.os, d.status, d.serial, d.last_seen, d.agent, $8::bigint \
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bigint[], \
  $7::text[]) AS d(agent_id, name, os, status, serial, last_seen, agent) \
ON CONFLICT (agent_id) DO UPDATE SET \
  name = EXCLUDED.name, os = EXCLUDED.os, status = EXCLUDED.status, serial = EXCLUDED.serial, \
  last_seen = EXCLUDED.last_seen, agent = EXCLUDED.agent, synced_at = EXCLUDED.synced_at";

// A device the manager no longer lists is gone from the mirror.
const DELETE_UNLISTED: &str = "DELETE FROM edr_devices WHERE agent_id <> ALL($1::text[])";

const CLIENT_IDENTITIES: &str = "SELECT client_id, hostname, serial FROM clients";

const SET_MATCHES: &str = "\
UPDATE clients c SET edr_agent_id = m.agent_id, edr_status = m.status \
FROM unnest($1::text[], $2::text[], $3::text[]) AS m(client_id, agent_id, status) \
WHERE c.client_id = m.client_id \
  AND (c.edr_agent_id, c.edr_status) IS DISTINCT FROM (m.agent_id, m.status)";

const CLEAR_UNMATCHED: &str = "\
UPDATE clients SET edr_agent_id = NULL, edr_status = NULL \
WHERE (edr_agent_id IS NOT NULL OR edr_status IS NOT NULL) AND client_id <> ALL($1::text[])";

impl PgGraphRepository {
    /// Replaces `edr_devices` with what `fetch` returns and matches the registered clients to
    /// it, in one transaction: a reader sees the previous list or the new one, and a failed
    /// `fetch` leaves the previous one.
    ///
    /// One Generator syncs at a time. The lock is a session's advisory lock on a connection
    /// taken out of the pool, so it is released when this returns, fails or is dropped, and an
    /// idle transaction is never held open while `fetch` waits on the network. Having the lock,
    /// a sync that another Generator finished less than `fresh_within` ago is not repeated.
    pub(crate) async fn mirror_edr_devices<F, Fut, E>(
        &self,
        now: u64,
        fresh_within: Duration,
        fetch: F,
    ) -> Result<EdrSync, EdrSyncError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<Vec<EdrDevice>, E>> + Send,
        E: Display,
    {
        let store = |error: PgError| EdrSyncError::Store(error.into());
        let now = signed(now).map_err(EdrSyncError::Store)?;
        let mut connection = Object::take(self.client().await.map_err(EdrSyncError::Store)?);
        let locked: bool = connection
            .query_one(TRY_LOCK, &[&SYNC_LOCK])
            .await
            .map_err(|error| store(error.into()))?
            .get(0);
        if !locked {
            return Ok(EdrSync::Busy);
        }
        let latest: Option<i64> = connection
            .query_one(LATEST_SYNC, &[])
            .await
            .map_err(|error| store(error.into()))?
            .get(0);
        let fresh_within = i64::try_from(fresh_within.as_millis()).unwrap_or(i64::MAX);
        if latest.is_some_and(|latest| now.saturating_sub(latest) < fresh_within) {
            return Ok(EdrSync::Fresh);
        }

        let devices = fetch()
            .await
            .map_err(|error| EdrSyncError::Source(error.to_string()))?;

        let written: Result<usize, PgError> = async {
            let tx = connection.transaction().await?;
            let column = |value: fn(&EdrDevice) -> &Option<String>| -> Vec<Option<&str>> {
                devices.iter().map(|d| value(d).as_deref()).collect()
            };
            let ids: Vec<&str> = devices.iter().map(|d| d.agent_id.as_str()).collect();
            let last_seen: Vec<Option<i64>> = devices.iter().map(|d| d.last_seen).collect();
            run(
                &tx,
                UPSERT_DEVICES,
                &[
                    &ids,
                    &column(|d| &d.name),
                    &column(|d| &d.os),
                    &column(|d| &d.status),
                    &column(|d| &d.serial),
                    &last_seen,
                    &column(|d| &d.agent),
                    &now,
                ],
            )
            .await?;
            run(&tx, DELETE_UNLISTED, &[&ids]).await?;

            let clients: Vec<ClientIdentity> = tx
                .query(CLIENT_IDENTITIES, &[])
                .await?
                .iter()
                .map(|row| ClientIdentity {
                    client_id: row.get(0),
                    hostname: row.get(1),
                    serial: row.get(2),
                })
                .collect();
            let matches = match_clients(&clients, &devices);
            let matched: Vec<&str> = matches.iter().map(|m| m.client_id.as_str()).collect();
            let agents: Vec<&str> = matches.iter().map(|m| m.agent_id.as_str()).collect();
            let statuses: Vec<Option<&str>> = matches.iter().map(|m| m.status.as_deref()).collect();
            run(&tx, SET_MATCHES, &[&matched, &agents, &statuses]).await?;
            run(&tx, CLEAR_UNMATCHED, &[&matched]).await?;
            tx.commit().await?;
            Ok(matches.len())
        }
        .await;
        let matched = written.map_err(store)?;
        Ok(EdrSync::Synced {
            devices: devices.len(),
            matched,
        })
    }
}
