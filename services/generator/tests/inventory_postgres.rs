//! The agent inventory in PostgreSQL: what sessions and clients keep from the Hooks, device
//! registration, keys, and the upgrade of a database recorded before the inventory.
//! Runs against `POSTGRES_INTEGRATION_URL`, like `postgres_integration.rs`.

use std::{
    process,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tokio_postgres::{NoTls, types::ToSql};
use withhuman_generator::{GeneratorService, PgGraphRepository, app};

#[tokio::test]
async fn sessions_keep_their_client_user_mode_model_and_end() {
    let Some((db, url)) = start().await else {
        return;
    };
    let session = unique("inv-session");
    let client_id = format!("team-x/{session}");
    let event = |order: u64, observed: u64, meta: Value, payload: Value| {
        json!({"session_id": session, "order": order, "observed_at": observed,
               "client_id": client_id, "user": "ana@example.com", "meta": meta,
               "payload": payload})
    };
    post(
        &url,
        "SessionStart",
        event(
            1,
            1_000,
            json!({"model": "claude-opus-5",
        "permission_mode": "default"}),
            json!({"source": "startup"}),
        ),
    )
    .await;
    post(
        &url,
        "UserPromptSubmit",
        event(
            2,
            2_000,
            json!({"permission_mode": "default"}),
            json!({"prompt": "hi", "kind": "user", "user_docs": []}),
        ),
    )
    .await;
    let mut call = event(
        3,
        3_000,
        json!({"tool_use_id": "t1", "permission_mode": "acceptEdits"}),
        json!({"tool_name": "Read", "tool_input": {"file_path": "/r/a"}}),
    );
    call["mode"] = json!("record");
    post(&url, "PreToolUse", call).await;
    // A late, older event fills nothing the newer ones set.
    let mut late = event(
        4,
        2_500,
        json!({"tool_use_id": "t0", "permission_mode": "plan"}),
        json!({"tool_name": "Read", "tool_input": {"file_path": "/r/b"}}),
    );
    late["mode"] = json!("record");
    post(&url, "PreToolUse", late).await;
    post(
        &url,
        "SessionEnd",
        event(5, 9_000, json!({}), json!({"reason": "prompt_input_exit"})),
    )
    .await;

    let row = db
        .row(
            "SELECT jsonb_build_array(client_id, user_email, start_source, permission_mode, model, \
         last_seen_at, ended_at, end_reason) FROM sessions WHERE session_id = $1",
            &[&session],
        )
        .await;
    assert_eq!(
        row,
        json!([
            client_id,
            "ana@example.com",
            "startup",
            "acceptEdits",
            "claude-opus-5",
            9_000,
            9_000,
            "prompt_input_exit"
        ])
    );
    let calls = db.row(
        "SELECT jsonb_agg(jsonb_build_array(tool_use_id, permission_mode, model) ORDER BY \"order\") \
         FROM nodes WHERE session_id = $1 AND kind = 'Call'",
        &[&session],
    ).await;
    assert_eq!(
        calls,
        json!([
            ["t1", "acceptEdits", "claude-opus-5"],
            ["t0", "plan", "claude-opus-5"]
        ])
    );
    let client = db
        .row(
            "SELECT jsonb_build_array(team, user_email, registered_at, first_seen, last_seen) \
         FROM clients WHERE client_id = $1",
            &[&client_id],
        )
        .await;
    // Seen only through Hooks: no registration. `last_seen` moves at most every 30 s.
    assert_eq!(
        client,
        json!(["team-x", "ana@example.com", null, 1_000, 1_000])
    );

    // A resume opens the session again.
    post(
        &url,
        "SessionStart",
        event(6, 60_000, json!({}), json!({"source": "resume"})),
    )
    .await;
    let row = db
        .row(
            "SELECT jsonb_build_array(start_source, ended_at, end_reason, model) FROM sessions \
         WHERE session_id = $1",
            &[&session],
        )
        .await;
    assert_eq!(row, json!(["resume", null, null, "claude-opus-5"]));
    let last_seen = db
        .row(
            "SELECT to_jsonb(last_seen) FROM clients WHERE client_id = $1",
            &[&client_id],
        )
        .await;
    assert_eq!(last_seen, json!(60_000));

    db.remove(&session).await;
    db.exec("DELETE FROM clients WHERE client_id = $1", &[&client_id])
        .await;
}

#[tokio::test]
async fn a_session_without_a_client_id_is_kept() {
    let Some((db, url)) = start().await else {
        return;
    };
    let session = unique("inv-anonymous");
    post(
        &url,
        "SessionStart",
        json!({"session_id": session, "order": 1, "observed_at": 5,
        "meta": {}, "payload": {"source": "startup"}}),
    )
    .await;
    let row = db.row(
        "SELECT jsonb_build_array(client_id, user_email, start_source, last_seen_at) FROM sessions \
         WHERE session_id = $1",
        &[&session],
    ).await;
    assert_eq!(row, json!([null, null, "startup", 5]));
    db.remove(&session).await;
}

#[tokio::test]
async fn registers_a_device_and_its_projects() {
    let Some((db, url)) = start().await else {
        return;
    };
    let client_id = format!("team-r/{}", unique("device"));
    let registration = |project: &str, at: u64, user: Value, serial: Value| {
        json!({"client_id": client_id, "team": "team-r", "hostname": "mac-1",
               "os": "darwin 25.1", "os_user": "ana", "hook_version": "abc", "agent": "claude",
               "project": project, "serial": serial, "user": user, "registered_at": at})
    };
    let first = send(
        &url,
        "POST",
        "/v1/clients",
        Some(registration(
            "/p/one",
            100,
            json!(null),
            json!("C02TEST1234"),
        )),
    )
    .await;
    assert_eq!(first.0, 200);
    assert_eq!(first.1["registered_at"], 100);
    assert_eq!(first.1["first_seen"], Value::Null);
    assert_eq!(first.1["serial"], "C02TEST1234");
    assert_eq!(first.1["owner"], Value::Null);
    // A later setup that could not read the serial keeps the one already known.
    let (status, again) = send(
        &url,
        "POST",
        "/v1/clients",
        Some(registration(
            "/p/two",
            200,
            json!("ana@example.com"),
            json!(null),
        )),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(again["registered_at"], 100);
    assert_eq!(again["updated_at"], 200);
    assert_eq!(again["user"], "ana@example.com");
    assert_eq!(again["hostname"], "mac-1");
    assert_eq!(again["serial"], "C02TEST1234");
    assert_eq!(again["projects"], json!(["/p/two", "/p/one"]));
    let (status, all) = send(&url, "GET", "/v1/clients", None).await;
    assert_eq!(status, 200);
    assert!(
        all.as_array()
            .unwrap()
            .iter()
            .any(|client| client["client_id"] == client_id.as_str())
    );

    // The security team names the owner; the client ID travels as one path segment.
    let owner_path = format!("/v1/clients/{}/owner", client_id.replace('/', "%2F"));
    let (status, owned) = send(
        &url,
        "POST",
        &owner_path,
        Some(json!({"owner": "bo@example.com", "actor": "sec@example.com"})),
    )
    .await;
    assert_eq!(status, 200, "{owned}");
    assert_eq!(owned["client_id"], client_id.as_str());
    assert_eq!(owned["owner"], "bo@example.com");
    assert_eq!(owned["owner_set_by"], "sec@example.com");
    assert!(owned["owner_set_at"].as_u64().unwrap() > 200);
    assert_eq!(owned["user"], "ana@example.com");
    assert_eq!(owned["updated_at"], 200);
    // The viewer reads these columns by name.
    let stored = "SELECT jsonb_build_array(serial, owner_email, owner_set_by, user_email) \
                  FROM clients WHERE client_id = $1";
    assert_eq!(
        db.row(stored, &[&client_id]).await,
        json!([
            "C02TEST1234",
            "bo@example.com",
            "sec@example.com",
            "ana@example.com"
        ])
    );
    // A registration never touches the owner, and a new serial replaces the old one.
    let (status, moved) = send(
        &url,
        "POST",
        "/v1/clients",
        Some(registration(
            "/p/two",
            300,
            json!("cy@example.com"),
            json!("C02TEST5678"),
        )),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(moved["user"], "cy@example.com");
    assert_eq!(moved["serial"], "C02TEST5678");
    assert_eq!(moved["owner"], "bo@example.com");
    assert_eq!(moved["owner_set_by"], "sec@example.com");
    assert_eq!(moved["owner_set_at"], owned["owner_set_at"]);
    // The other serials a setup read are kept beside it, and one that read none keeps them.
    let others = "SELECT to_jsonb(other_serials) FROM clients WHERE client_id = $1";
    assert_eq!(db.row(others, &[&client_id]).await, json!([]));
    let mut with_others = registration("/p/two", 400, json!(null), json!("C02TEST5678"));
    with_others["other_serials"] = json!(["5CD5479KD6"]);
    let (status, _) = send(&url, "POST", "/v1/clients", Some(with_others)).await;
    assert_eq!(status, 200);
    assert_eq!(db.row(others, &[&client_id]).await, json!(["5CD5479KD6"]));
    let (status, _) = send(
        &url,
        "POST",
        "/v1/clients",
        Some(registration("/p/two", 500, json!(null), json!(null))),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(db.row(others, &[&client_id]).await, json!(["5CD5479KD6"]));

    let (status, cleared) = send(
        &url,
        "POST",
        &owner_path,
        Some(json!({"owner": null, "actor": "lead@example.com"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(cleared["owner"], Value::Null);
    assert_eq!(cleared["owner_set_by"], "lead@example.com");
    assert_eq!(
        db.row(stored, &[&client_id]).await,
        json!(["C02TEST5678", null, "lead@example.com", "cy@example.com"])
    );
    // A body that does not say the owner changes nothing; an unknown device is not made.
    let (status, _) = send(&url, "POST", &owner_path, Some(json!({"actor": "x"}))).await;
    assert!((400..500).contains(&status), "{status}");
    let (status, _) = send(
        &url,
        "POST",
        "/v1/clients/team-r%2Fno-such-device/owner",
        Some(json!({"owner": "bo@example.com"})),
    )
    .await;
    assert_eq!(status, 404);
    let unknown = db
        .row(
            "SELECT to_jsonb(count(*)) FROM clients WHERE client_id = 'team-r/no-such-device'",
            &[],
        )
        .await;
    assert_eq!(unknown, json!(0));

    db.exec(
        "DELETE FROM client_projects WHERE client_id = $1",
        &[&client_id],
    )
    .await;
    db.exec("DELETE FROM clients WHERE client_id = $1", &[&client_id])
        .await;
}

#[tokio::test]
async fn keys_are_issued_verified_revoked_and_audited() {
    let Some((db, url)) = start().await else {
        return;
    };
    let user = format!("{}@example.com", unique("user"));
    let key = |key_id: &str, hash: &str| {
        json!({"key_id": key_id, "hash": hash, "user": user, "actor": "sec@example.com",
               "note": "laptop", "created_at": 10})
    };
    let first_id = unique("k1");
    let second_id = unique("k2");
    let (status, issued) = send(
        &url,
        "POST",
        &format!("/v1/users/{user}/keys"),
        Some(key(&first_id, "hash-1")),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(issued["created_by"], "sec@example.com");
    assert!(issued.get("hash").is_none(), "a hash is never handed back");
    send(
        &url,
        "POST",
        &format!("/v1/users/{user}/keys"),
        Some(key(&second_id, "hash-2")),
    )
    .await;
    let (status, _) = send(
        &url,
        "POST",
        "/v1/users/other@example.com/keys",
        Some(key(&unique("k3"), "hash-3")),
    )
    .await;
    assert_eq!(status, 400);

    let verify =
        |key_id: &str, hash: &str, at: u64| json!({"key_id": key_id, "hash": hash, "used_at": at});
    let (_, answer) = send(
        &url,
        "POST",
        "/v1/keys/verify",
        Some(verify(&first_id, "hash-1", 100_000)),
    )
    .await;
    assert_eq!(answer, json!({"status": "active", "user": user}));
    let (_, answer) = send(
        &url,
        "POST",
        "/v1/keys/verify",
        Some(verify(&first_id, "hash-2", 100_000)),
    )
    .await;
    assert_eq!(answer, json!({"status": "unknown", "user": null}));

    let (status, revoked) = send(
        &url,
        "POST",
        &format!("/v1/keys/{first_id}/revoke"),
        Some(json!({"actor": "sec@example.com", "reason": "lost laptop"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(revoked["revoked_by"], "sec@example.com");
    assert_eq!(revoked["last_used_at"], 100_000);
    let revoked_at = revoked["revoked_at"].clone();
    // Revoking again keeps the first revocation.
    let (_, again) = send(
        &url,
        "POST",
        &format!("/v1/keys/{first_id}/revoke"),
        Some(json!({"actor": "someone@example.com"})),
    )
    .await;
    assert_eq!(
        (&again["revoked_at"], &again["revoked_by"]),
        (&revoked_at, &json!("sec@example.com"))
    );
    let (_, answer) = send(
        &url,
        "POST",
        "/v1/keys/verify",
        Some(verify(&first_id, "hash-1", 200_000)),
    )
    .await;
    assert_eq!(answer["status"], "revoked");

    for at in [300, 400] {
        let (status, _) = send(
            &url,
            "POST",
            &format!("/v1/keys/{first_id}/denials"),
            Some(json!({"session_id": "s-1", "client_id": "team/d", "denied_at": at})),
        )
        .await;
        assert_eq!(status, 204);
    }
    send(
        &url,
        "POST",
        &format!("/v1/keys/{first_id}/denials"),
        Some(json!({"session_id": "s-2", "denied_at": 500})),
    )
    .await;
    let (status, _) = send(
        &url,
        "POST",
        "/v1/keys/nope/denials",
        Some(json!({"denied_at": 1})),
    )
    .await;
    assert_eq!(status, 404);

    // The whole user: the active key goes too.
    let (status, keys) = send(
        &url,
        "POST",
        &format!("/v1/users/{user}/revoke"),
        Some(json!({"actor": "ciso@example.com", "reason": "incident"})),
    )
    .await;
    assert_eq!(status, 200);
    let keys = keys.as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|key| key["revoked_at"].is_number()));
    let (_, listed) = send(&url, "GET", &format!("/v1/users/{user}/keys"), None).await;
    let first = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key_id"] == first_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(
        (
            &first["first_denied_at"],
            &first["last_denied_at"],
            &first["denied_count"]
        ),
        (&json!(300), &json!(500), &json!(3))
    );
    assert_eq!(first["revoked_by"], "sec@example.com");
    let (status, _) = send(
        &url,
        "POST",
        "/v1/users/nobody@example.com/revoke",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 404);

    let audit = db
        .row(
            "SELECT jsonb_agg(jsonb_build_array(key_id = $2, kind, actor, reason, session_id) \
         ORDER BY id) FROM key_events WHERE user_email = $1",
            &[&user, &first_id],
        )
        .await;
    assert_eq!(
        audit,
        json!([
            [true, "issued", "sec@example.com", "laptop", null],
            [false, "issued", "sec@example.com", "laptop", null],
            [true, "revoked", "sec@example.com", "lost laptop", null],
            [true, "denied", null, null, "s-1"],
            [true, "denied", null, null, "s-2"],
            [false, "revoked", "ciso@example.com", "incident", null],
        ])
    );

    db.exec("DELETE FROM key_events WHERE user_email = $1", &[&user])
        .await;
    db.exec("DELETE FROM api_keys WHERE user_email = $1", &[&user])
        .await;
    db.exec("DELETE FROM users WHERE email = $1", &[&user])
        .await;
}

/// A database the engine wrote before the inventory gains its columns, and its sessions their
/// client, last activity and start source, when the new schema is applied.
#[tokio::test]
async fn upgrades_a_database_recorded_before_the_inventory() {
    let Ok(base) = std::env::var("POSTGRES_INTEGRATION_URL") else {
        return;
    };
    let schema = unique("upgrade").replace('-', "_");
    let admin = Db::connect(&base).await;
    admin.exec(&format!("CREATE SCHEMA {schema}"), &[]).await;
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let old = Db::connect(&url).await;
    let before = withhuman_common::POSTGRES_SCHEMA
        .split("-- Agent inventory")
        .next()
        .unwrap();
    old.0.batch_execute(before).await.unwrap();
    old.0.batch_execute(r#"
        INSERT INTO sessions (session_id, version, created_at) VALUES ('a', 2, 1), ('b', 1, 5);
        INSERT INTO event_commits (session_id, "order", version, event_name, observed_at, client_id,
          event_json, has_node) VALUES
          ('a', 1, 1, 'SessionStart', 1, 'team/dev-1',
           '{"session_id":"a","order":1,"observed_at":1,"client_id":"team/dev-1","meta":{},"payload":{"source":"resume"}}', false),
          ('a', 2, 2, 'UserPromptSubmit', 7, 'team/dev-1', '{}', true),
          ('b', 1, 1, 'UserPromptSubmit', 5, NULL, '{}', true);
    "#).await.unwrap();

    PgGraphRepository::connect(&url, 1).await.unwrap();
    // Applying it again changes nothing.
    PgGraphRepository::connect(&url, 1).await.unwrap();
    let sessions = old
        .row(
            "SELECT jsonb_agg(jsonb_build_array(session_id, client_id, start_source, last_seen_at, \
         ended_at) ORDER BY session_id) FROM sessions",
            &[],
        )
        .await;
    assert_eq!(
        sessions,
        json!([
            ["a", "team/dev-1", "resume", 7, null],
            ["b", null, null, 5, null]
        ])
    );
    let clients = old.row(
        "SELECT jsonb_agg(jsonb_build_array(client_id, team, first_seen, last_seen, registered_at)) \
         FROM clients",
        &[],
    ).await;
    assert_eq!(clients, json!([["team/dev-1", "team", 1, 7, null]]));
    let columns = old
        .row(
            "SELECT to_jsonb(count(*)) FROM information_schema.columns WHERE table_schema = $1 \
         AND table_name = 'nodes' AND column_name IN ('permission_mode', 'model')",
            &[&schema],
        )
        .await;
    assert_eq!(columns, json!(2));

    admin
        .exec(&format!("DROP SCHEMA {schema} CASCADE"), &[])
        .await;
}

/// A database that already had the inventory gains the clients' serial and owner columns and
/// keeps its devices.
#[tokio::test]
async fn upgrades_clients_recorded_before_the_serial_and_owner() {
    let Ok(base) = std::env::var("POSTGRES_INTEGRATION_URL") else {
        return;
    };
    let schema = unique("owner").replace('-', "_");
    let admin = Db::connect(&base).await;
    admin.exec(&format!("CREATE SCHEMA {schema}"), &[]).await;
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let old = Db::connect(&url).await;
    // The schema as it was: without the block that adds the columns.
    let (before, rest) = withhuman_common::POSTGRES_SCHEMA
        .split_once("  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()\n                 AND table_name = 'clients'")
        .unwrap();
    let (_, after) = rest.split_once("  END IF;\n").unwrap();
    old.0
        .batch_execute(&format!("{before}{after}"))
        .await
        .unwrap();
    let columns = "SELECT to_jsonb(count(*)) FROM information_schema.columns \
                   WHERE table_schema = $1 AND table_name = 'clients' \
                   AND column_name IN ('serial', 'owner_email', 'owner_set_by', 'owner_set_at')";
    assert_eq!(old.row(columns, &[&schema]).await, json!(0));
    old.exec(
        "INSERT INTO clients (client_id, team, hostname, user_email, registered_at, updated_at) \
         VALUES ('team/dev-1', 'team', 'mac-1', 'ana@example.com', 1, 2)",
        &[],
    )
    .await;

    PgGraphRepository::connect(&url, 1).await.unwrap();
    // Applying it again changes nothing.
    PgGraphRepository::connect(&url, 1).await.unwrap();
    assert_eq!(old.row(columns, &[&schema]).await, json!(4));
    let clients = old
        .row(
            "SELECT jsonb_agg(jsonb_build_array(client_id, hostname, user_email, updated_at, \
             serial, owner_email)) FROM clients",
            &[],
        )
        .await;
    assert_eq!(
        clients,
        json!([["team/dev-1", "mac-1", "ana@example.com", 2, null, null]])
    );

    admin
        .exec(&format!("DROP SCHEMA {schema} CASCADE"), &[])
        .await;
}

/// The security team stops a device and releases it; the Collector reads its state and counts
/// the calls it refused.
#[tokio::test]
async fn stops_and_releases_a_device_and_counts_what_it_refused() {
    let Some((db, url)) = start().await else {
        return;
    };
    let client_id = format!("team-s/{}", unique("device"));
    let encoded = client_id.replace('/', "%2F");
    let path = |end: &str| format!("/v1/clients/{encoded}/{end}");
    let stored = "SELECT jsonb_build_array(stopped_at, stopped_by, stop_reason, \
                  stop_denied_count, stop_last_denied_at) FROM clients WHERE client_id = $1";

    // A device the engine does not hold is not stopped, cannot be, and is not made by asking.
    let (status, state) = send(&url, "GET", &path("state"), None).await;
    assert_eq!((status, &state), (200, &json!({"stopped": false})));
    for stopped in [true, false] {
        let body = json!({"stopped": stopped, "actor": "sec@example.com"});
        let (status, body) = send(&url, "POST", &path("stop"), Some(body)).await;
        assert_eq!(status, 404, "{body}");
        assert_eq!(body["error"], "graph_resource_not_found");
    }
    let (status, _) = send(
        &url,
        "POST",
        &path("stop-denials"),
        Some(json!({"denied_at": 5})),
    )
    .await;
    assert_eq!(status, 404);
    let held = "SELECT to_jsonb(count(*)) FROM clients WHERE client_id = $1";
    assert_eq!(db.row(held, &[&client_id]).await, json!(0));

    let registration = json!({"client_id": client_id, "team": "team-s", "hostname": "mac-s",
        "registered_at": 100, "user": "ana@example.com"});
    let (status, registered) = send(&url, "POST", "/v1/clients", Some(registration.clone())).await;
    assert_eq!(status, 200);
    assert_eq!(registered["stopped_at"], Value::Null);
    assert_eq!(registered["stop_denied_count"], 0);
    assert_eq!(
        db.row(stored, &[&client_id]).await,
        json!([null, null, null, 0, null])
    );
    // A call refused for a device that is not stopped is not counted.
    let (status, _) = send(
        &url,
        "POST",
        &path("stop-denials"),
        Some(json!({"denied_at": 5})),
    )
    .await;
    assert_eq!(status, 404);

    let (status, stopped) = send(
        &url,
        "POST",
        &path("stop"),
        Some(json!({"stopped": true, "actor": "sec@example.com", "reason": "lost laptop"})),
    )
    .await;
    assert_eq!(status, 200, "{stopped}");
    assert_eq!(stopped["client_id"], client_id.as_str());
    let stopped_at = stopped["stopped_at"].as_u64().unwrap();
    assert!(stopped_at > 1_600_000_000_000, "{stopped}");
    assert_eq!(stopped["stopped_by"], "sec@example.com");
    assert_eq!(stopped["stop_reason"], "lost laptop");
    let (_, state) = send(&url, "GET", &path("state"), None).await;
    assert_eq!(state, json!({"stopped": true}));
    // The list of devices says so too.
    let (_, clients) = send(&url, "GET", "/v1/clients", None).await;
    let listed = clients
        .as_array()
        .unwrap()
        .iter()
        .find(|client| client["client_id"] == client_id.as_str())
        .unwrap();
    assert_eq!(listed["stopped_at"], stopped_at);

    // Stopped again, it keeps its first stop; a new setup does not release it.
    let (status, again) = send(
        &url,
        "POST",
        &path("stop"),
        Some(json!({"stopped": true, "actor": "lead@example.com", "reason": "again"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(again["stopped_at"], stopped_at);
    assert_eq!(again["stopped_by"], "sec@example.com");
    assert_eq!(again["stop_reason"], "lost laptop");
    let (_, registered) = send(&url, "POST", "/v1/clients", Some(registration)).await;
    assert_eq!(registered["stopped_at"], stopped_at);

    for at in [700_u64, 900, 800] {
        let (status, _) = send(
            &url,
            "POST",
            &path("stop-denials"),
            Some(json!({"denied_at": at})),
        )
        .await;
        assert_eq!(status, 204);
    }
    assert_eq!(
        db.row(stored, &[&client_id]).await,
        json!([stopped_at, "sec@example.com", "lost laptop", 3, 900])
    );

    // A body that does not say which changes nothing.
    let (status, _) = send(&url, "POST", &path("stop"), Some(json!({"actor": "x"}))).await;
    assert!((400..500).contains(&status), "{status}");
    let (_, state) = send(&url, "GET", &path("state"), None).await;
    assert_eq!(state, json!({"stopped": true}));

    // Released, the stop is gone and what it refused is kept; releasing again is the same.
    for _ in 0..2 {
        let (status, released) = send(
            &url,
            "POST",
            &path("stop"),
            Some(json!({"stopped": false, "actor": "lead@example.com"})),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(released["stopped_at"], Value::Null);
        assert_eq!(released["stopped_by"], Value::Null);
        assert_eq!(released["stop_reason"], Value::Null);
        assert_eq!(released["stop_denied_count"], 3);
        assert_eq!(released["stop_last_denied_at"], 900);
    }
    let (_, state) = send(&url, "GET", &path("state"), None).await;
    assert_eq!(state, json!({"stopped": false}));
    assert_eq!(
        db.row(stored, &[&client_id]).await,
        json!([null, null, null, 3, 900])
    );

    db.exec("DELETE FROM clients WHERE client_id = $1", &[&client_id])
        .await;
}

/// A database that already had devices gains the stop columns and keeps its devices running.
#[tokio::test]
async fn upgrades_clients_recorded_before_a_device_could_be_stopped() {
    let Ok(base) = std::env::var("POSTGRES_INTEGRATION_URL") else {
        return;
    };
    let schema = unique("stop").replace('-', "_");
    let admin = Db::connect(&base).await;
    admin.exec(&format!("CREATE SCHEMA {schema}"), &[]).await;
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let old = Db::connect(&url).await;
    // The schema as it was: without the block that adds the columns.
    let (before, rest) = withhuman_common::POSTGRES_SCHEMA
        .split_once("  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()\n                 AND table_name = 'clients' AND column_name = 'stopped_at')")
        .unwrap();
    let (_, after) = rest.split_once("  END IF;\n").unwrap();
    old.0
        .batch_execute(&format!("{before}{after}"))
        .await
        .unwrap();
    let columns = "SELECT to_jsonb(count(*)) FROM information_schema.columns \
                   WHERE table_schema = $1 AND table_name = 'clients' \
                   AND column_name IN ('stopped_at', 'stopped_by', 'stop_reason', \
                     'stop_denied_count', 'stop_last_denied_at')";
    assert_eq!(old.row(columns, &[&schema]).await, json!(0));
    old.exec(
        "INSERT INTO clients (client_id, team, hostname, serial, owner_email) \
         VALUES ('team/dev-1', 'team', 'mac-1', 'C02TEST1234', 'bo@example.com')",
        &[],
    )
    .await;

    PgGraphRepository::connect(&url, 1).await.unwrap();
    // Applying it again changes nothing.
    PgGraphRepository::connect(&url, 1).await.unwrap();
    assert_eq!(old.row(columns, &[&schema]).await, json!(5));
    let clients = old
        .row(
            "SELECT jsonb_agg(jsonb_build_array(client_id, hostname, serial, owner_email, \
             stopped_at, stopped_by, stop_reason, stop_denied_count, stop_last_denied_at)) \
             FROM clients",
            &[],
        )
        .await;
    assert_eq!(
        clients,
        json!([[
            "team/dev-1",
            "mac-1",
            "C02TEST1234",
            "bo@example.com",
            null,
            null,
            null,
            0,
            null
        ]])
    );

    admin
        .exec(&format!("DROP SCHEMA {schema} CASCADE"), &[])
        .await;
}

async fn start() -> Option<(Db, String)> {
    let url = std::env::var("POSTGRES_INTEGRATION_URL").ok()?;
    let repository = PgGraphRepository::connect(&url, 4).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(GeneratorService::new(repository)))
            .await
            .unwrap()
    });
    Some((Db::connect(&url).await, format!("http://{address}")))
}

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

async fn post(url: &str, event: &str, body: Value) {
    let (status, body) = send(url, "POST", &format!("/v1/events/{event}"), Some(body)).await;
    assert_eq!(status, 200, "{event}: {body}");
}

async fn send(url: &str, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut request = client.request(method.parse().unwrap(), format!("{url}{path}"));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// A device deleted takes the sessions it ran with it, every record of them, and leaves
/// another device's alone.
#[tokio::test]
async fn deletes_a_device_with_the_sessions_it_ran() {
    let Some((db, url)) = start().await else {
        return;
    };
    let gone = format!("lab/{}", unique("gone"));
    let kept = format!("lab/{}", unique("kept"));
    for client in [&gone, &kept] {
        let registration = json!({"client_id": client, "hostname": "pc", "project": "/p",
                                  "registered_at": 100});
        let (status, _) = send(&url, "POST", "/v1/clients", Some(registration)).await;
        assert_eq!(status, 200);
    }
    let sessions = [unique("s1"), unique("s2"), unique("s3")];
    for (session, client) in sessions.iter().zip([&gone, &gone, &kept]) {
        db.exec(
            "INSERT INTO sessions (session_id, client_id) VALUES ($1, $2)",
            &[session, client],
        )
        .await;
        db.exec(
            "INSERT INTO subgraphs (session_id, number) VALUES ($1, 1)",
            &[session],
        )
        .await;
        db.exec(
            "INSERT INTO session_marks (session_id, state, set_at) VALUES ($1, 'reviewing', 1)",
            &[session],
        )
        .await;
    }
    let path = |client: &str| format!("/v1/clients/{}", client.replace('/', "%2F"));
    let (status, deleted) = send(&url, "DELETE", &path(&gone), None).await;
    assert_eq!(status, 200, "{deleted}");
    assert_eq!(deleted, json!({"client_id": gone, "sessions": 2}));
    let count = |table: &str| {
        format!("SELECT to_jsonb(count(*)) FROM {table} WHERE session_id = ANY($1::text[])")
    };
    let all = sessions.to_vec();
    for table in ["sessions", "subgraphs", "session_marks"] {
        assert_eq!(db.row(&count(table), &[&all]).await, json!(1), "{table}");
    }
    let left = "SELECT to_jsonb(count(*)) FROM clients WHERE client_id = ANY($1::text[])";
    assert_eq!(
        db.row(left, &[&vec![gone.clone(), kept.clone()]]).await,
        json!(1)
    );
    let projects = "SELECT to_jsonb(count(*)) FROM client_projects WHERE client_id = $1";
    assert_eq!(db.row(projects, &[&gone]).await, json!(0));
    // Nothing left of it: not found.
    let (status, _) = send(&url, "DELETE", &path(&gone), None).await;
    assert_eq!(status, 404);
    db.remove(&sessions[2]).await;
    db.exec(
        "DELETE FROM session_marks WHERE session_id = $1",
        &[&sessions[2]],
    )
    .await;
}

#[derive(Clone)]
struct Db(Arc<tokio_postgres::Client>);

impl Db {
    async fn connect(url: &str) -> Self {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        Self(Arc::new(client))
    }

    async fn row(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Value {
        self.0.query_one(sql, params).await.unwrap().get(0)
    }

    async fn exec(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) {
        self.0.execute(sql, params).await.unwrap();
    }

    async fn remove(&self, session: &str) {
        for table in [
            "nodes",
            "event_commits",
            "subgraphs",
            "paragraphs",
            "tokens",
            "token_mentions",
            "sessions",
        ] {
            self.exec(
                &format!("DELETE FROM {table} WHERE session_id = $1"),
                &[&session],
            )
            .await;
        }
    }
}
