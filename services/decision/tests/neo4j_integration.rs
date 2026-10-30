use std::{
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use withhuman_contracts::decisions::{Decision, DecisionResponse};
use withhuman_decision::{
    DecisionConfig, DecisionService, MockDecisionProvider, Neo4jDecisionRepository,
    RuntimeEnvironment, app,
};

#[tokio::test]
async fn verifies_graph_version_and_persists_mock_verdict_over_real_http() {
    let Some(neo4j_url) = std::env::var("NEO4J_INTEGRATION_URL").ok() else {
        eprintln!("skipping Neo4j integration test; NEO4J_INTEGRATION_URL is unset");
        return;
    };
    let neo4j_user = std::env::var("NEO4J_INTEGRATION_USER").unwrap_or_else(|_| "neo4j".into());
    let neo4j_password = std::env::var("NEO4J_INTEGRATION_PASSWORD")
        .unwrap_or_else(|_| "withhuman-integration".into());
    let query = QueryClient::new(&neo4j_url, &neo4j_user, &neo4j_password);
    install_schema(&query).await;
    let session_id = format!(
        "decision-it-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    query
        .one(
            "CREATE (session:Session {session_id:$session_id,version:7}) \
             CREATE (call:Call {session_id:$session_id,seq:7}) \
             CREATE (session)-[:CONTAINS]->(call) RETURN call.seq",
            json!({"session_id":session_id}),
        )
        .await;

    let config = DecisionConfig {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        environment: RuntimeEnvironment::Test,
        provider: "mock".into(),
        mock_decision: Decision::Deny,
        mock_reason: Some("Blocked by integration policy.".into()),
        mock_delay: Duration::ZERO,
        neo4j_url,
        neo4j_user,
        neo4j_password,
        neo4j_database: "neo4j".into(),
        jev: None,
        intent_block_threshold: 0.5,
        trace: Default::default(),
    };
    let repository = Neo4jDecisionRepository::connect(&config).await.unwrap();
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

    let row = query
        .one(
            "MATCH (call:Call {session_id:$session_id,seq:7}) \
             RETURN call.decision, call.decision_version, call.decision_mode, \
                    NOT EXISTS { (call)-->() }",
            json!({"session_id":session_id}),
        )
        .await;
    assert_eq!(
        row,
        vec![json!("DENY"), json!(7), json!("enforce"), json!(true)]
    );

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

    query
        .one(
            "MATCH (node {session_id:$session_id}) DETACH DELETE node RETURN true",
            json!({"session_id":session_id}),
        )
        .await;
}

async fn install_schema(query: &QueryClient) {
    for statement in include_str!("../../../deploy/docker/neo4j/schema.cypher").split(';') {
        let statement = statement.trim();
        if !statement.is_empty() {
            query.one(statement, json!({})).await;
        }
    }
}

#[derive(Clone)]
struct QueryClient {
    endpoint: String,
    user: String,
    password: String,
    client: reqwest::Client,
}

impl QueryClient {
    fn new(base_url: &str, user: &str, password: &str) -> Self {
        Self {
            endpoint: format!("{}/db/neo4j/query/v2", base_url.trim_end_matches('/')),
            user: user.into(),
            password: password.into(),
            client: reqwest::Client::new(),
        }
    }

    async fn one(&self, statement: &str, parameters: Value) -> Vec<Value> {
        let response = self
            .client
            .post(&self.endpoint)
            .basic_auth(&self.user, Some(&self.password))
            .json(&json!({"statement":statement,"parameters":parameters}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert!(status.is_success(), "Neo4j HTTP {status}: {body}");
        assert!(
            body.get("errors").is_none_or(|errors| errors == &json!([])),
            "Neo4j query failed: {body}"
        );
        body["data"]["values"]
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }
}
