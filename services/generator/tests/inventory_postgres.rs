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
    let registration = |project: &str, at: u64, user: Value| {
        json!({"client_id": client_id, "team": "team-r", "hostname": "mac-1",
               "os": "darwin 25.1", "os_user": "ana", "hook_version": "abc", "agent": "claude",
               "project": project, "user": user, "registered_at": at})
    };
    let first = send(
        &url,
        "POST",
        "/v1/clients",
        Some(registration("/p/one", 100, json!(null))),
    )
    .await;
    assert_eq!(first.0, 200);
    assert_eq!(first.1["registered_at"], 100);
    assert_eq!(first.1["first_seen"], Value::Null);
    let (status, again) = send(
        &url,
        "POST",
        "/v1/clients",
        Some(registration("/p/two", 200, json!("ana@example.com"))),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(again["registered_at"], 100);
    assert_eq!(again["updated_at"], 200);
    assert_eq!(again["user"], "ana@example.com");
    assert_eq!(again["hostname"], "mac-1");
    assert_eq!(again["projects"], json!(["/p/two", "/p/one"]));
    let (status, all) = send(&url, "GET", "/v1/clients", None).await;
    assert_eq!(status, 200);
    assert!(
        all.as_array()
            .unwrap()
            .iter()
            .any(|client| client["client_id"] == client_id.as_str())
    );

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

    let stops = db
        .row(
            "SELECT jsonb_agg(jsonb_build_array(target, key_id = $2, stopped_by, first_denied_at) \
             ORDER BY stopped_at, key_id = $2 DESC) FROM stop_audit WHERE user_email = $1",
            &[&user, &first_id],
        )
        .await;
    assert_eq!(
        stops,
        json!([
            ["key", true, "sec@example.com", 300],
            ["key", false, "ciso@example.com", null]
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

#[tokio::test]
async fn sessions_are_stopped_released_and_audited() {
    let Some((db, url)) = start().await else {
        return;
    };
    let session = unique("inv-stop");
    post(
        &url,
        "SessionStart",
        json!({"session_id": session, "order": 1, "observed_at": 1,
        "user": "ana@example.com", "meta": {}, "payload": {}}),
    )
    .await;
    let (status, _) = send(&url, "POST", "/v1/sessions/nope/stop", Some(json!({}))).await;
    assert_eq!(status, 404, "only a recorded session is stopped");
    let (_, flags) = send(&url, "GET", &format!("/v1/sessions/{session}/flags"), None).await;
    assert_eq!(flags["stop"], Value::Null);

    let (status, stop) = send(
        &url,
        "POST",
        &format!("/v1/sessions/{session}/stop"),
        Some(json!({"actor": "sec@example.com", "reason": "exfiltration"})),
    )
    .await;
    assert_eq!(status, 200);
    // Stopping again keeps the first stop.
    let (_, again) = send(
        &url,
        "POST",
        &format!("/v1/sessions/{session}/stop"),
        Some(json!({"actor": "other@example.com"})),
    )
    .await;
    assert_eq!(
        (&again["id"], &again["stopped_by"]),
        (&stop["id"], &json!("sec@example.com"))
    );
    let (_, flags) = send(&url, "GET", &format!("/v1/sessions/{session}/flags"), None).await;
    assert_eq!(flags["stop"]["reason"], "exfiltration");
    for at in [500, 700] {
        let (status, _) = send(
            &url,
            "POST",
            &format!("/v1/sessions/{session}/stop/denials"),
            Some(json!({"denied_at": at})),
        )
        .await;
        assert_eq!(status, 204);
    }
    let (status, released) = send(
        &url,
        "POST",
        &format!("/v1/sessions/{session}/release"),
        Some(json!({"actor": "sec@example.com", "reason": "cleared"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        (&released["first_denied_at"], &released["denied_count"]),
        (&json!(500), &json!(2))
    );
    let (status, _) = send(
        &url,
        "POST",
        &format!("/v1/sessions/{session}/release"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 404, "nothing left to release");
    let (status, _) = send(
        &url,
        "POST",
        &format!("/v1/sessions/{session}/stop/denials"),
        Some(json!({"denied_at": 900})),
    )
    .await;
    assert_eq!(status, 404);

    let audit = db.row(
        "SELECT jsonb_agg(jsonb_build_array(target, user_email, stopped_by, reason, released_by, \
         first_denied_at, denied_count)) FROM stop_audit WHERE session_id = $1",
        &[&session],
    ).await;
    assert_eq!(
        audit,
        json!([[
            "session",
            "ana@example.com",
            "sec@example.com",
            "exfiltration",
            "sec@example.com",
            500,
            2
        ]])
    );
    db.exec(
        "DELETE FROM session_stops WHERE session_id = $1",
        &[&session],
    )
    .await;
    db.remove(&session).await;
}

#[tokio::test]
async fn reviews_name_a_call_and_keep_their_history() {
    let Some((db, url)) = start().await else {
        return;
    };
    let session = unique("inv-review");
    let mut call = json!({"session_id": session, "order": 1, "observed_at": 1,
        "meta": {"tool_use_id": "t1"}, "payload": {"tool_name": "Bash",
        "tool_input": {"command": "ls"}}, "mode": "record"});
    post(&url, "PreToolUse", call.take()).await;
    let seq = db
        .row(
            "SELECT to_jsonb(seq) FROM nodes WHERE session_id = $1 AND kind = 'Call'",
            &[&session],
        )
        .await;
    for (status, note) in [("issue", "copied .env"), ("no_issue", "false alarm")] {
        let (code, review) = send(
            &url,
            "POST",
            "/v1/reviews",
            Some(json!({"session_id": session,
            "seq": seq, "status": status, "note": note, "actor": "sec@example.com"})),
        )
        .await;
        assert_eq!((code, &review["status"]), (201, &json!(status)));
    }
    let (status, _) = send(
        &url,
        "POST",
        "/v1/reviews",
        Some(json!({"session_id": session,
        "seq": 999, "status": "issue"})),
    )
    .await;
    assert_eq!(status, 404, "only a Call is reviewed");
    let latest = db
        .row(
            "SELECT jsonb_build_array(status, note, (SELECT count(*) FROM call_reviews \
         WHERE session_id = $1)) FROM call_review_latest WHERE session_id = $1",
            &[&session],
        )
        .await;
    assert_eq!(latest, json!(["no_issue", "false alarm", 2]));
    db.exec(
        "DELETE FROM call_reviews WHERE session_id = $1",
        &[&session],
    )
    .await;
    db.remove(&session).await;
}

#[tokio::test]
async fn service_users_and_test_clients_are_told_apart() {
    let Some((db, url)) = start().await else {
        return;
    };
    let name = unique("ci");
    let key = |kind: &str, id: &str| {
        json!({"key_id": id, "hash": "h", "user": name, "kind": kind,
        "created_at": 1})
    };
    let (status, issued) = send(
        &url,
        "POST",
        &format!("/v1/users/{name}/keys"),
        Some(key("service", &unique("s1"))),
    )
    .await;
    assert_eq!((status, &issued["user_kind"]), (201, &json!("service")));
    let (status, _) = send(
        &url,
        "POST",
        &format!("/v1/users/{name}/keys"),
        Some(key("person", &unique("s2"))),
    )
    .await;
    assert_eq!(status, 400, "a user keeps the kind of their first key");

    let bench = format!("bench/{}", unique("run"));
    let device = format!("team/{}", unique("device"));
    for client in [&bench, &device] {
        post(
            &url,
            "SessionStart",
            json!({"session_id": unique("inv-test"), "order": 1,
            "observed_at": 1, "client_id": client, "meta": {}, "payload": {}}),
        )
        .await;
    }
    let test = db
        .row(
            "SELECT jsonb_agg(test ORDER BY client_id) FROM clients WHERE client_id IN ($1, $2)",
            &[&bench, &device],
        )
        .await;
    assert_eq!(test, json!([true, false]));
    db.exec("DELETE FROM key_events WHERE user_email = $1", &[&name])
        .await;
    db.exec("DELETE FROM api_keys WHERE user_email = $1", &[&name])
        .await;
    db.exec("DELETE FROM users WHERE email = $1", &[&name])
        .await;
}

#[tokio::test]
async fn a_checked_in_project_is_protected_once_hooks_ran_there() {
    let Some((db, url)) = start().await else {
        return;
    };
    let client = format!("team-c/{}", unique("device"));
    let session = unique("inv-cwd");
    post(
        &url,
        "UserPromptSubmit",
        json!({"session_id": session, "order": 1, "observed_at": 10,
        "client_id": client, "meta": {"cwd": "/work/app/src"},
        "payload": {"prompt": "hi", "kind": "user", "user_docs": []}}),
    )
    .await;
    let checkin = |at: u64, used: u64| {
        json!({"client_id": client, "hostname": "mac",
        "scope": "user", "user": "ana@example.com", "checked_in_at": at,
        "projects": [{"path": "/work/app", "last_used_at": used}, {"path": "/work/other"},
                     {"path": "/work/app-old", "last_used_at": 1}]})
    };
    let (status, _) = send(&url, "POST", "/v1/clients/checkin", Some(checkin(100, 50))).await;
    assert_eq!(status, 204);
    send(&url, "POST", "/v1/clients/checkin", Some(checkin(200, 40))).await;
    let rows = db
        .row(
            "SELECT jsonb_agg(jsonb_build_array(project, protected, last_hook_at, last_used_at, \
         first_reported_at, last_reported_at) ORDER BY project) FROM project_protection \
         WHERE client_id = $1",
            &[&client],
        )
        .await;
    // `/work/app-old` only shares a prefix with `/work/app`, so it is not protected.
    assert_eq!(
        rows,
        json!([
            ["/work/app", true, 10, 50, 100, 200],
            ["/work/app-old", false, null, 1, 100, 200],
            ["/work/other", false, null, null, 100, 200],
        ])
    );
    let device = db
        .row(
            "SELECT jsonb_build_array(last_checkin_at, install_scope, hostname, user_email) \
         FROM clients WHERE client_id = $1",
            &[&client],
        )
        .await;
    assert_eq!(device, json!([200, "user", "mac", "ana@example.com"]));
    db.exec(
        "DELETE FROM client_seen_projects WHERE client_id = $1",
        &[&client],
    )
    .await;
    db.exec("DELETE FROM client_cwds WHERE client_id = $1", &[&client])
        .await;
    db.exec("DELETE FROM clients WHERE client_id = $1", &[&client])
        .await;
    db.remove(&session).await;
}

#[tokio::test]
async fn an_exception_covers_a_session_only_where_it_applies() {
    let Some((db, url)) = start().await else {
        return;
    };
    let team = unique("t").replace('-', "");
    let client = format!("{team}/device");
    let (status, folder) = send(
        &url,
        "POST",
        "/v1/exceptions",
        Some(json!({
        "folder": "/work/secret", "team": team, "actor": "sec@example.com", "reason": "NDA"})),
    )
    .await;
    assert_eq!(status, 201);
    let id = folder["id"].as_u64().unwrap();
    let (_, other) = send(
        &url,
        "POST",
        "/v1/exceptions",
        Some(json!({"client_id": "x/y"})),
    )
    .await;
    let (_, listed) = send(
        &url,
        "GET",
        &format!("/v1/exceptions?client_id={client}"),
        None,
    )
    .await;
    let ids: Vec<u64> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_u64().unwrap())
        .collect();
    assert!(ids.contains(&id) && !ids.contains(&other["id"].as_u64().unwrap()));

    let start_at = |session: &str, cwd: &str, client: &str| {
        json!({"session_id": session,
        "order": 1, "observed_at": 1, "client_id": client, "meta": {"cwd": cwd},
        "payload": {"source": "startup", "exception": id}})
    };
    let covered = unique("inv-exc");
    let elsewhere = unique("inv-exc");
    let stranger = unique("inv-exc");
    post(
        &url,
        "SessionStart",
        start_at(&covered, "/work/secret/app", &client),
    )
    .await;
    post(
        &url,
        "SessionStart",
        start_at(&elsewhere, "/work/secretive", &client),
    )
    .await;
    post(
        &url,
        "SessionStart",
        start_at(&stranger, "/work/secret", "other-team/device"),
    )
    .await;
    for (session, expected) in [
        (&covered, json!([id, id])),
        (&elsewhere, json!([id, null])),
        (&stranger, json!([id, null])),
    ] {
        let row = db
            .row(
                "SELECT jsonb_build_array(exception_claimed, exception_id) FROM sessions \
                          WHERE session_id = $1",
                &[session],
            )
            .await;
        assert_eq!(row, expected, "{session}");
    }
    let (_, flags) = send(&url, "GET", &format!("/v1/sessions/{covered}/flags"), None).await;
    assert_eq!(flags["exception"], id);

    let (status, removed) = send(
        &url,
        "POST",
        &format!("/v1/exceptions/{id}/remove"),
        Some(json!({"actor": "sec@example.com"})),
    )
    .await;
    assert_eq!(
        (status, &removed["removed_by"]),
        (200, &json!("sec@example.com"))
    );
    let (_, listed) = send(
        &url,
        "GET",
        &format!("/v1/exceptions?client_id={client}"),
        None,
    )
    .await;
    assert!(!listed.as_array().unwrap().iter().any(|e| e["id"] == id));
    let (status, _) = send(
        &url,
        "POST",
        "/v1/exceptions/999999999/remove",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 404);
    for session in [&covered, &elsewhere, &stranger] {
        db.remove(session).await;
    }
    db.exec(
        "DELETE FROM exceptions WHERE id = ANY($1)",
        &[&vec![
            i64::try_from(id).unwrap(),
            other["id"].as_i64().unwrap(),
        ]],
    )
    .await;
}
