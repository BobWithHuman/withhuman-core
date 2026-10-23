//! Drives the real Generator and Decision HTTP apps against Neo4j, with Jev replaced by a fake
//! server that records every request and answers from a script.

#![allow(dead_code)]

use std::{
    collections::VecDeque,
    path::PathBuf,
    process,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde_json::{Value, json};
use tokio::sync::OnceCell;
use withhuman_contracts::decisions::{DecisionRequest, DecisionResponse, EnforcementMode};
use withhuman_decision::{
    DecisionConfig, DecisionService, JevDecisionProvider, Neo4jDecisionRepository,
    RuntimeEnvironment, app as decision_app,
};
use withhuman_generator::{
    GeneratorConfig, GeneratorService, Neo4jRepository, app as generator_app,
};

pub const FAKE_KEY: &str = "sk-withhuman-test-SECRET-0042";

#[derive(Clone)]
pub struct Options {
    pub seq_window: u64,
    pub prompt_window: u64,
    pub api_key: Option<String>,
    pub jev_timeout: Duration,
    pub per_call: bool,
    /// Talk to this Jev instead of the fake one.
    pub jev_url: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            seq_window: 3,
            prompt_window: 3,
            api_key: Some(FAKE_KEY.into()),
            jev_timeout: Duration::from_secs(3),
            per_call: false,
            jev_url: None,
        }
    }
}

/// What the fake Jev answers for the next request; unscripted questions get `none`.
#[derive(Debug, Clone, Default)]
pub struct Script {
    pub parent: Option<(String, f64)>,
    pub from_text: Option<(String, f64)>,
}

impl Script {
    pub fn parent(key: impl Into<String>, probability: f64) -> Self {
        Self {
            parent: Some((key.into(), probability)),
            from_text: None,
        }
    }

    pub fn with_from_text(mut self, key: impl Into<String>, probability: f64) -> Self {
        self.from_text = Some((key.into(), probability));
        self
    }
}

#[derive(Debug, Clone)]
pub struct JevCall {
    pub authorization: Option<String>,
    pub body: Value,
}

impl JevCall {
    pub fn asks(&self, question: &str) -> bool {
        self.body["questions"].get(question).is_some()
    }

    pub fn criteria(&self, question: &str) -> Vec<String> {
        let mut keys = self.body["questions"][question]["criteria"]
            .as_object()
            .map(|criteria| criteria.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        keys.sort();
        keys
    }
}

#[derive(Clone, Default)]
pub struct FakeJev {
    calls: Arc<Mutex<Vec<JevCall>>>,
    scripts: Arc<Mutex<VecDeque<Script>>>,
    delay: Arc<Mutex<Duration>>,
}

impl FakeJev {
    pub fn script(&self, script: Script) {
        self.scripts.lock().unwrap().push_back(script);
    }

    pub fn delay(&self, delay: Duration) {
        *self.delay.lock().unwrap() = delay;
    }

    pub fn calls(&self) -> Vec<JevCall> {
        self.calls.lock().unwrap().clone()
    }

    async fn spawn(&self) -> String {
        async fn answer(
            State(jev): State<FakeJev>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            jev.calls.lock().unwrap().push(JevCall {
                authorization: headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                body: body.clone(),
            });
            let script = jev.scripts.lock().unwrap().pop_front().unwrap_or_default();
            let delay = *jev.delay.lock().unwrap();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let mut answers = serde_json::Map::new();
            for (name, question) in body["questions"].as_object().cloned().unwrap_or_default() {
                let scripted = match name.as_str() {
                    "parent" => script.parent.clone(),
                    "from_text" => script.from_text.clone(),
                    _ => None,
                };
                let (choice, probability) = scripted
                    .filter(|(choice, _)| question["criteria"].get(choice).is_some())
                    .unwrap_or_else(|| ("none".into(), 0.9));
                answers.insert(
                    name,
                    json!({"choice":choice,"probabilities":{choice.clone():probability}}),
                );
            }
            Json(json!({"answers":answers}))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/v1/systemone", post(answer))
            .with_state(self.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{address}")
    }
}

/// One text piece of a tool result.
#[derive(Debug, Clone, Default)]
pub struct Piece {
    pub text: String,
    pub flagged: bool,
    pub hidden: bool,
    /// Sentence classification sent right after the result; `None` leaves it pending.
    pub instructs: Option<f64>,
}

impl Piece {
    pub fn plain(text: &str) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    pub fn instructing(text: &str) -> Self {
        Self {
            text: text.into(),
            flagged: true,
            instructs: Some(0.9),
            ..Self::default()
        }
    }

    pub fn flagged(text: &str, instructs: Option<f64>) -> Self {
        Self {
            text: text.into(),
            flagged: true,
            instructs,
            ..Self::default()
        }
    }

    pub fn hidden(text: &str) -> Self {
        Self {
            text: text.into(),
            hidden: true,
            ..Self::default()
        }
    }
}

pub struct Harness {
    pub session_id: String,
    pub query: QueryClient,
    pub jev: FakeJev,
    pub data_dir: PathBuf,
    pub config: DecisionConfig,
    generator_url: String,
    decision_url: String,
    client: reqwest::Client,
    order: AtomicU64,
    version: AtomicU64,
    hashes: AtomicU64,
}

static SCHEMA: OnceCell<()> = OnceCell::const_new();

impl Harness {
    /// `None` when `NEO4J_INTEGRATION_URL` is unset, so the test is skipped.
    pub async fn start(name: &str, options: Options) -> Option<Self> {
        let Ok(neo4j_url) = std::env::var("NEO4J_INTEGRATION_URL") else {
            eprintln!("skipping Neo4j integration test; NEO4J_INTEGRATION_URL is unset");
            return None;
        };
        let neo4j_user = std::env::var("NEO4J_INTEGRATION_USER").unwrap_or_else(|_| "neo4j".into());
        let neo4j_password = std::env::var("NEO4J_INTEGRATION_PASSWORD")
            .unwrap_or_else(|_| "withhuman-integration".into());
        let query = QueryClient::new(&neo4j_url, &neo4j_user, &neo4j_password);
        SCHEMA
            .get_or_init(|| async {
                for statement in
                    include_str!("../../../../deploy/docker/neo4j/schema.cypher").split(';')
                {
                    let statement = statement.trim();
                    if !statement.is_empty() {
                        query.rows(statement, json!({})).await;
                    }
                }
            })
            .await;

        let session_id = format!(
            "{name}-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let data_dir = std::env::temp_dir().join(format!("withhuman-{session_id}"));
        let jev = FakeJev::default();
        let jev_url = match options.jev_url.clone() {
            Some(url) => url,
            None => jev.spawn().await,
        };

        let generator_config = GeneratorConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            neo4j_url: neo4j_url.clone(),
            neo4j_user: neo4j_user.clone(),
            neo4j_password: neo4j_password.clone(),
            neo4j_database: "neo4j".into(),
            decision_url: "http://127.0.0.1:1".into(),
        };
        let generator = Neo4jRepository::connect(&generator_config).await.unwrap();
        let generator_url = serve(generator_app(GeneratorService::new(generator))).await;

        let config = DecisionConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            environment: RuntimeEnvironment::Test,
            provider: "jev".into(),
            mock_decision: withhuman_contracts::decisions::Decision::Allow,
            mock_reason: None,
            mock_delay: Duration::ZERO,
            neo4j_url,
            neo4j_user,
            neo4j_password,
            neo4j_database: "neo4j".into(),
            jev_url,
            jev_api_key: options.api_key.clone(),
            jev_model: "jev-latest".into(),
            jev_timeout: options.jev_timeout,
            parent_seq_window: options.seq_window,
            parent_prompt_window: options.prompt_window,
            parent_accept: 0.6,
            parent_max_hops: 50,
            parent_per_call: options.per_call,
            parent_body_chars: 1_500,
            sentence_from: 0.5,
            data_dir: data_dir.clone(),
        };
        let repository = Neo4jDecisionRepository::connect(&config).await.unwrap();
        let decision_url = serve(decision_app(DecisionService::new(
            repository,
            JevDecisionProvider::new(&config),
        )))
        .await;

        Some(Self {
            session_id,
            query,
            jev,
            data_dir,
            config,
            generator_url,
            decision_url,
            client: reqwest::Client::new(),
            order: AtomicU64::new(0),
            version: AtomicU64::new(0),
            hashes: AtomicU64::new(0),
        })
    }

    pub async fn post(&self, event: &str, mut body: Value) -> Value {
        let order = self.order.fetch_add(1, Ordering::SeqCst) + 1;
        body["session_id"] = json!(self.session_id);
        body["order"] = json!(order);
        body["observed_at"] = json!(order);
        if body.get("meta").is_none() {
            body["meta"] = json!({});
        }
        let response = self
            .client
            .post(format!("{}/v1/events/{event}", self.generator_url))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let response: Value = response.json().await.unwrap();
        assert!(status.is_success(), "{event}: {status} {response}");
        self.version
            .store(response["version"].as_u64().unwrap(), Ordering::SeqCst);
        response
    }

    fn node_seq(response: &Value) -> u64 {
        response["nodes"][0]["seq"].as_u64().unwrap()
    }

    pub async fn prompt(&self, sequence: u64, text: &str) -> u64 {
        let response = self
            .post(
                "UserPromptSubmit",
                json!({"sequence":sequence,"payload":{"prompt":text,"kind":"user","user_docs":[]}}),
            )
            .await;
        Self::node_seq(&response)
    }

    pub async fn instruction(&self, sequence: u64, path: &str) -> u64 {
        let response = self
            .post(
                "InstructionsLoaded",
                json!({"sequence":sequence,"payload":{"file_path":path}}),
            )
            .await;
        Self::node_seq(&response)
    }

    pub async fn message(&self, sequence: u64, text: &str) -> u64 {
        let id = format!("message-{sequence}-{}", self.order.load(Ordering::SeqCst));
        let response = self
            .post(
                "MessageDisplay",
                json!({"sequence":sequence,"payload":{"message_id":id,"text":text}}),
            )
            .await;
        Self::node_seq(&response)
    }

    /// A Bash Call; returns the Call's node seq.
    pub async fn bash(&self, sequence: u64, tool_use_id: &str, command: &str) -> u64 {
        self.call(sequence, tool_use_id, "Bash", json!({"command":command}))
            .await
    }

    pub async fn call(&self, sequence: u64, tool_use_id: &str, tool: &str, input: Value) -> u64 {
        let response = self
            .post(
                "PreToolUse",
                json!({
                    "sequence":sequence,"meta":{"tool_use_id":tool_use_id},
                    "payload":{"tool_name":tool,"tool_input":input},
                    "mode":"enforce","deadline_ms":4000
                }),
            )
            .await;
        Self::node_seq(&response)
    }

    /// A tool result split into the given pieces; returns each piece's node seq.
    pub async fn result(
        &self,
        sequence: u64,
        tool_use_id: &str,
        tool: &str,
        input: Value,
        pieces: &[Piece],
    ) -> Vec<u64> {
        let (chunks, flags) = self.chunks(pieces);
        let text = pieces
            .iter()
            .map(|piece| piece.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        let response = self
            .post(
                "PostToolUse",
                json!({
                    "sequence":sequence,"meta":{"tool_use_id":tool_use_id},
                    "payload":{"tool_name":tool,"tool_input":input,"tool_response":{"content":text}},
                    "chunks":chunks,"flags":flags
                }),
            )
            .await;
        self.classify(pieces, &chunks).await;
        piece_seqs(&response, &chunks)
    }

    pub async fn failure(
        &self,
        sequence: u64,
        tool_use_id: &str,
        tool: &str,
        input: Value,
        error: &str,
    ) -> Value {
        self.post(
            "PostToolUseFailure",
            json!({
                "sequence":sequence,"meta":{"tool_use_id":tool_use_id},
                "payload":{"tool_name":tool,"tool_input":input,"error":error}
            }),
        )
        .await
    }

    pub async fn pasted_prompt(&self, sequence: u64, pieces: &[Piece]) -> Vec<u64> {
        let (chunks, flags) = self.chunks(pieces);
        let text = pieces
            .iter()
            .map(|piece| piece.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        let response = self
            .post(
                "UserPromptSubmit",
                json!({
                    "sequence":sequence,
                    "payload":{"prompt":text,"kind":"user","user_docs":[]},
                    "chunks":chunks,"flags":flags
                }),
            )
            .await;
        self.classify(pieces, &chunks).await;
        piece_seqs(&response, &chunks)
    }

    pub async fn batch(&self, sequence: u64) {
        self.post("PostToolBatch", json!({"sequence":sequence,"payload":{}}))
            .await;
    }

    /// Sends a sentence classification for a piece, as the Collector does asynchronously.
    pub async fn classify_piece(&self, hash: &str, text: &str, probability: f64) {
        let response = self
            .client
            .patch(format!(
                "{}/v1/sessions/{}/pieces/{hash}",
                self.generator_url, self.session_id
            ))
            .json(&json!({"sentences":[{"index":0,"text":text,"p":probability}],"jev_ms":10,"error":null}))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
    }

    pub async fn decide(&self, call_seq: u64) -> DecisionResponse {
        self.decide_with_deadline(call_seq, 4_000).await
    }

    pub async fn decide_with_deadline(&self, call_seq: u64, deadline_ms: u64) -> DecisionResponse {
        let response = self
            .client
            .post(format!("{}/v1/decide", self.decision_url))
            .json(&self.decision_request(call_seq, deadline_ms))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert!(status.is_success(), "decide: {status} {body}");
        serde_json::from_value(body).unwrap()
    }

    pub fn decision_request(&self, call_seq: u64, deadline_ms: u64) -> DecisionRequest {
        DecisionRequest {
            session_id: self.session_id.clone(),
            call_seq,
            graph_version: self.version.load(Ordering::SeqCst),
            mode: EnforcementMode::Enforce,
            deadline_ms: Some(deadline_ms),
            causal_context: None,
            causal_path: None,
        }
    }

    /// The `s…`/`r…`/`i…` sequence key of a depth 1 node with this seq.
    pub async fn sequence_node(&self, sequence: u64) -> i64 {
        self.query
            .rows(
                "MATCH (s:ExecutionNode {session_id:$session_id,type:'Sequence',sequence:$sequence}) RETURN s.seq",
                json!({"session_id":self.session_id,"sequence":sequence}),
            )
            .await[0][0]
            .as_i64()
            .unwrap()
    }

    pub fn jev_record(&self) -> String {
        std::fs::read_to_string(self.data_dir.join("jev-parent.jsonl")).unwrap_or_default()
    }

    pub async fn cleanup(&self) {
        self.query
            .rows(
                "MATCH (n) WHERE n.session_id = $session_id DETACH DELETE n",
                json!({"session_id":self.session_id}),
            )
            .await;
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }

    fn chunks(&self, pieces: &[Piece]) -> (Vec<Value>, Vec<String>) {
        let mut flags = Vec::new();
        let chunks = pieces
            .iter()
            .enumerate()
            .map(|(index, piece)| {
                let hash = format!(
                    "{}-piece-{}",
                    self.session_id,
                    self.hashes.fetch_add(1, Ordering::SeqCst)
                );
                if piece.flagged {
                    flags.push(hash.clone());
                }
                json!({
                    "index":index,"text":piece.text,"hash":hash,
                    "source":"PostToolUse","hidden":piece.hidden
                })
            })
            .collect();
        (chunks, flags)
    }

    async fn classify(&self, pieces: &[Piece], chunks: &[Value]) {
        for (piece, chunk) in pieces.iter().zip(chunks) {
            if let (true, Some(probability)) = (piece.flagged, piece.instructs) {
                self.classify_piece(chunk["hash"].as_str().unwrap(), &piece.text, probability)
                    .await;
            }
        }
    }
}

fn piece_seqs(response: &Value, chunks: &[Value]) -> Vec<u64> {
    chunks
        .iter()
        .map(|chunk| {
            response["pieces"]
                .as_array()
                .unwrap()
                .iter()
                .find(|piece| piece["hash"] == chunk["hash"])
                .and_then(|piece| piece["seq"].as_u64())
                .unwrap()
        })
        .collect()
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{address}")
}

#[derive(Clone)]
pub struct QueryClient {
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

    pub async fn rows(&self, statement: &str, parameters: Value) -> Vec<Vec<Value>> {
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
        serde_json::from_value(body["data"]["values"].clone()).unwrap_or_default()
    }
}

pub fn decision_response_text(response: &DecisionResponse) -> String {
    serde_json::to_string(response).unwrap()
}
