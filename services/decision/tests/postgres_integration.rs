use std::{
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use withhuman_contracts::decisions::{Decision, DecisionResponse};
use withhuman_decision::{
    DecisionConfig, DecisionService, MockDecisionProvider, PgDecisionRepository,
    RuntimeEnvironment, app, trace::Thresholds,
};

#[tokio::test]
async fn verifies_graph_version_and_persists_mock_verdict_over_real_http() {
    let Ok(database_url) = std::env::var("POSTGRES_INTEGRATION_URL") else {
        return;
    };
    let repository = PgDecisionRepository::connect(&database_url, 4)
        .await
        .unwrap();
    let (db, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let session_id = format!(
        "decision-it-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    db.execute(
        "INSERT INTO sessions (session_id, version) VALUES ($1, 7)",
        &[&session_id],
    )
    .await
    .unwrap();
    db.execute(r#"INSERT INTO nodes (session_id, seq, kind, event_name, "order") VALUES ($1, 7, 'Call', 'PreToolUse', 7)"#, &[&session_id]).await.unwrap();

    let config = DecisionConfig {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        environment: RuntimeEnvironment::Test,
        provider: "mock".into(),
        mock_decision: Decision::Deny,
        mock_reason: Some("Blocked by integration policy.".into()),
        mock_delay: Duration::ZERO,
        jev: None,
        thresholds: Thresholds::default(),
        trace: Default::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = app(DecisionService::new(
        repository,
        MockDecisionProvider::new(&config),
    ));
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/decide"))
        .json(&json!({
            "session_id":session_id,
            "call_seq":7,
            "graph_version":7,
            "mode":"enforce",
            "deadline_ms":1000
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response: DecisionResponse = response.json().await.unwrap();
    assert_eq!(response.decision, Decision::Deny);
    assert_eq!(response.reason, "Blocked by integration policy.");
    assert!(response.written);

    let row: Value = db.query_one("SELECT jsonb_build_array(decision, decision_version, decision_mode, NOT EXISTS (SELECT 1 FROM cause_edges e WHERE e.session_id = n.session_id AND e.call_seq = n.seq)) FROM nodes n WHERE session_id = $1 AND seq = 7", &[&session_id]).await.unwrap().get(0);
    assert_eq!(row, json!(["DENY", 7, "enforce", true]));

    let stale = reqwest::Client::new()
        .post(format!("http://{address}/v1/decide"))
        .json(&json!({
            "session_id":session_id,
            "call_seq":8,
            "graph_version":8,
            "mode":"enforce",
            "deadline_ms":1000
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), reqwest::StatusCode::NOT_FOUND);

    db.execute("DELETE FROM nodes WHERE session_id = $1", &[&session_id])
        .await
        .unwrap();
    db.execute("DELETE FROM sessions WHERE session_id = $1", &[&session_id])
        .await
        .unwrap();
}
