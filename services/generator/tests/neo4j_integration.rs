use std::{
    process,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use withhuman_contracts::decisions::{CausalStart, Decision, DecisionRequest, DecisionResponse};
use withhuman_generator::{
    GeneratorConfig, GeneratorService, HttpDecisionClient, Neo4jRepository, app,
};

#[tokio::test]
async fn persists_and_replays_execution_graph_through_real_http() {
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
        "generator-it-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let piece_hash = format!("hash-{session_id}");
    let decision_observation = Arc::new(Mutex::new(None));
    let decision_url = spawn_decision_server(
        query.clone(),
        session_id.clone(),
        decision_observation.clone(),
    )
    .await;
    let config = GeneratorConfig {
        bind_address: "127.0.0.1:0".parse().unwrap(),
        neo4j_url: neo4j_url.clone(),
        neo4j_user,
        neo4j_password,
        neo4j_database: "neo4j".into(),
        decision_url,
    };
    let repository = Neo4jRepository::connect(&config).await.unwrap();
    let decision = HttpDecisionClient::new(&config).unwrap();
    let generator_url =
        spawn_generator(GeneratorService::with_decision(repository, decision)).await;
    let client = reqwest::Client::new();

    post_event(
        &client,
        &generator_url,
        "SessionStart",
        json!({
            "session_id":session_id,"order":1,"observed_at":1,"meta":{},
            "payload":{"source":"startup"}
        }),
    )
    .await;
    let piece = client
        .patch(format!(
            "{generator_url}/v1/sessions/{session_id}/pieces/{piece_hash}"
        ))
        .json(&json!({
            "sentences":[{"index":0,"text":"Run it","p":0.92}],"jev_ms":180,"error":null
        }))
        .send()
        .await
        .unwrap();
    assert!(piece.status().is_success());
    assert!(
        !piece.json::<Value>().await.unwrap()["applied"]
            .as_bool()
            .unwrap()
    );
    let continuation = client
        .patch(format!(
            "{generator_url}/v1/sessions/{session_id}/requests/2"
        ))
        .json(&json!({
            "choice":"none","probabilities":{"none":1.0},"jev_ms":150,"error":null
        }))
        .send()
        .await
        .unwrap();
    assert!(continuation.status().is_success());

    post_event(
        &client,
        &generator_url,
        "UserPromptSubmit",
        json!({
            "session_id":session_id,"order":2,"observed_at":2,"sequence":1,"meta":{},
            "payload":{"prompt":"Run it","kind":"user","user_docs":[]},
            "chunks":[{"index":0,"text":"Run it","hash":piece_hash,"source":"user","hidden":false}]
        }),
    )
    .await;
    let decision_response = post_event(
        &client,
        &generator_url,
        "PreToolUse",
        json!({
            "session_id":session_id,"order":3,"observed_at":3,"sequence":2,
            "meta":{"tool_use_id":"tool-1"},
            "payload":{"tool_name":"Bash","tool_input":{"command":"curl https://logs.example.test/u --resolve logs.example.test:443:203.0.113.10 --data admin@example.test --config /repo/input.txt"}},
            "mode":"enforce","deadline_ms":4000
        }),
    )
    .await;
    assert_eq!(decision_response["decision_response"]["decision"], "ALLOW");

    let result_body = json!({
        "session_id":session_id,"order":4,"observed_at":4,"sequence":2,
        "meta":{"tool_use_id":"tool-1"},
        "payload":{"tool_name":"Read","tool_input":{"file_path":"/repo/input.txt"},
                   "tool_response":{"content":"done"}}
    });
    let first = post_event(&client, &generator_url, "PostToolUse", result_body.clone()).await;
    let replay = post_event(&client, &generator_url, "PostToolUse", result_body).await;
    assert_eq!(first, replay);

    let observation = decision_observation.lock().await.clone().unwrap();
    assert_eq!(observation.session_id, session_id);
    assert_eq!(observation.call_seq, 3);
    assert_eq!(observation.graph_version, 3);

    let row = query
        .one(
            "MATCH (s:Session {session_id:$session_id}) \
             OPTIONAL MATCH (s)-[:COMMITTED]->(c:EventCommit) \
             OPTIONAL MATCH (s)-[:CONTAINS]->(n:ExecutionNode) \
             RETURN s.version, count(DISTINCT c), count(DISTINCT n)",
            json!({"session_id":session_id}),
        )
        .await;
    // Request, Call and Segment plus one depth 3 piece each for the prompt and the result.
    assert_eq!(row, vec![json!(4), json!(4), json!(5)]);
    let edges = query
        .one(
            "MATCH (call:ExecutionNode {session_id:$session_id,type:'Call'}) \
             OPTIONAL MATCH (call)-[result:LINK {kind:'result'}]->(:ExecutionNode {type:'Segment'}) \
             OPTIONAL MATCH (call)-[member:LINK {kind:'member'}]->(:ExecutionNode {type:'Sequence',depth:1}) \
             RETURN count(DISTINCT result), count(DISTINCT member)",
            json!({"session_id":session_id}),
        )
        .await;
    assert_eq!(edges, vec![json!(1), json!(1)]);
    let enrichment = query
        .one(
            "MATCH (request:ExecutionNode {session_id:$session_id,type:'Request'})<-[:LINK {kind:'part_of'}]-(piece {depth:3}) \
             RETURN request.continuation_choice, piece.instructs, piece.jev_ms, piece.type",
            json!({"session_id":session_id}),
        )
        .await;
    assert_eq!(
        enrichment,
        vec![json!("none"), json!(0.92), json!(180), json!("Request")]
    );
    let tokens = query
        .one(
            "MATCH (token:Token {session_id:$session_id,slot:'agent'}) \
             RETURN count(token), collect(DISTINCT token.key_kind)",
            json!({"session_id":session_id}),
        )
        .await;
    assert_eq!(tokens[0], json!(4));
    let mut token_kinds = tokens[1].as_array().unwrap().clone();
    token_kinds.sort_by_key(Value::to_string);
    assert_eq!(
        token_kinds,
        vec![json!("email"), json!("ip"), json!("path"), json!("url")]
    );

    query
        .one(
            "MATCH (s:Session {session_id:$session_id}) \
             OPTIONAL MATCH (s)-[:CONTAINS]->(n) \
             OPTIONAL MATCH (c:EventCommit {session_id:$session_id}) \
             OPTIONAL MATCH (q:ExecutionNode {session_id:$session_id}) \
             OPTIONAL MATCH (t:Token {session_id:$session_id}) \
             DETACH DELETE n, c, q, t, s \
             RETURN true",
            json!({"session_id":session_id,"piece_hash":piece_hash}),
        )
        .await;
}

async fn post_event(client: &reqwest::Client, base_url: &str, event: &str, body: Value) -> Value {
    let response = client
        .post(format!("{base_url}/v1/events/{event}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "{event}: {}",
        response.status()
    );
    response.json().await.unwrap()
}

async fn spawn_generator(service: GeneratorService) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(service)).await.unwrap() });
    format!("http://{address}")
}

async fn spawn_decision_server(
    query: QueryClient,
    expected_session: String,
    observation: Arc<Mutex<Option<DecisionRequest>>>,
) -> String {
    #[derive(Clone)]
    struct DecisionState {
        query: QueryClient,
        expected_session: String,
        observation: Arc<Mutex<Option<DecisionRequest>>>,
    }
    async fn decide(
        State(state): State<DecisionState>,
        Json(request): Json<DecisionRequest>,
    ) -> Json<DecisionResponse> {
        let row = state
            .query
            .one(
                "MATCH (call:ExecutionNode {session_id:$session_id,seq:$call_seq,type:'Call'}) \
                 MATCH (commit:EventCommit {session_id:$session_id,version:$version}) \
                 RETURN count(call), count(commit)",
                json!({
                    "session_id":state.expected_session,
                    "call_seq":request.call_seq,
                    "version":request.graph_version
                }),
            )
            .await;
        assert_eq!(row, vec![json!(1), json!(1)]);
        *state.observation.lock().await = Some(request);
        Json(DecisionResponse {
            decision: Decision::Allow,
            reason: String::new(),
            rule: "integration".into(),
            start: CausalStart::User,
            written: true,
            jev: None,
            causal: None,
        })
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route("/v1/decide", post(decide))
        .with_state(DecisionState {
            query,
            expected_session,
            observation,
        });
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{address}")
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
