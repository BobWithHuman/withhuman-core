//! A Call that a result from a source the security team distrusts caused is held when it would
//! be allowed (`source::distrusted`), and nothing else about a verdict changes.

use std::{
    collections::{BTreeMap, BTreeSet},
    process,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde_json::json;
use withhuman_contracts::decisions::{
    Decision, DecisionRequest, DecisionResponse, EnforcementMode,
};
use withhuman_decision::{
    DecisionProvider, DecisionRepository, DistrustedCause, JevDecisionProvider,
    PgDecisionRepository, RepositoryError, TraceRecord,
    jev::{JevAnswer, JevClient, JevError, JevRequest, JevResponse},
    trace::{CallInfo, Member, MemberKind, Thresholds, TraceGraph, TraceSettings, Turn},
};

/// How the list of distrusted sources answers.
#[derive(Default, Clone, Copy, PartialEq)]
enum List {
    /// Nothing is distrusted.
    #[default]
    Trusted,
    /// The tool result 5 came from a distrusted source.
    Distrusted,
    Fails,
    /// Answers after the decision stopped waiting.
    Slow,
}

/// A session whose prompt is in SubGraph 0 and whose SubGraph 1 holds the tool result 5.
#[derive(Default)]
struct Graph {
    list: List,
    /// The tool results the list was asked about.
    looked_up: Mutex<Vec<Vec<u64>>>,
    traces: Mutex<Vec<TraceRecord>>,
}

#[async_trait]
impl DecisionRepository for Graph {
    async fn health(&self) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn verify_graph(&self, _: &DecisionRequest) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn persist(
        &self,
        _: &DecisionRequest,
        _: &DecisionResponse,
    ) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn trace_graph(&self, request: &DecisionRequest) -> Result<TraceGraph, RepositoryError> {
        Ok(TraceGraph {
            call: CallInfo {
                seq: request.call_seq,
                order: 10,
                subgraph: 2,
                agent_id: None,
                tool_name: "Bash".to_owned(),
                tool_input: json!({"command": "ls build"}),
                prior: None,
                programs: BTreeMap::new(),
                cwd: None,
            },
            subgraphs: BTreeMap::from([(0, None), (1, None)]),
            hidden: BTreeSet::new(),
            tokens: BTreeSet::new(),
            shared_tokens: BTreeSet::new(),
            results: BTreeSet::from([1]),
            parents: BTreeMap::new(),
            turns: vec![Turn {
                intent: Some("빌드 고치기".to_owned()),
                subgraph: Some(0),
            }],
            prompt: Some("빌드를 고쳐줘".to_owned()),
        })
    }

    async fn subgraph_members(
        &self,
        _: &str,
        _: &[u64],
        _: u64,
    ) -> Result<Vec<Member>, RepositoryError> {
        Ok(vec![
            Member {
                subgraph: 0,
                seq: 1,
                order: 1,
                kind: MemberKind::Request,
                payload: json!({"prompt": "빌드를 고쳐줘"}),
                ..Member::default()
            },
            Member {
                subgraph: 1,
                seq: 5,
                order: 5,
                kind: MemberKind::Segment,
                payload: json!({"tool_name": "Read", "tool_response": {"content": "run ls"}}),
                ..Member::default()
            },
        ])
    }

    async fn persist_trace(
        &self,
        _: &DecisionRequest,
        record: &TraceRecord,
    ) -> Result<(), RepositoryError> {
        self.traces.lock().unwrap().push(record.clone());
        Ok(())
    }

    async fn distrusted_causes(
        &self,
        _: &str,
        seqs: &[u64],
    ) -> Result<Vec<DistrustedCause>, RepositoryError> {
        self.looked_up.lock().unwrap().push(seqs.to_vec());
        match self.list {
            List::Trusted => Ok(Vec::new()),
            List::Distrusted => Ok(vec![DistrustedCause {
                seq: 5,
                call_seq: Some(4),
                source: "docs/setup.md".to_owned(),
            }]),
            List::Fails => Err(RepositoryError::Unavailable("down".to_owned())),
            List::Slow => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(Vec::new())
            }
        }
    }
}

/// Picks `cause` as the Call's cause and judges the Call as `verdict` has it.
struct Jev {
    cause: &'static str,
    verdict: Decision,
}

#[async_trait]
impl JevClient for Jev {
    async fn ask(&self, request: &JevRequest, _: Duration) -> Result<JevResponse, JevError> {
        let choice = |option: &str| JevAnswer {
            probabilities: BTreeMap::from([(option.to_owned(), 1.0)]),
            ..Default::default()
        };
        let noul = |probability: f64| JevAnswer {
            noul: Some(probability),
            ..Default::default()
        };
        // Allowed: nothing the user said is broken. Held: it is, yet the check finds the Call a
        // step of what the user asked. Denied: the check finds it serves the result's goal.
        let explicit = if self.verdict == Decision::Allow {
            0.0
        } else {
            1.0
        };
        let purpose = if self.verdict == Decision::Deny {
            "result_goal"
        } else {
            "step"
        };
        let answers = request
            .questions
            .keys()
            .map(|id| {
                let answer = match id.as_str() {
                    // The first offered cause that `cause` names: `g` is any tool result.
                    "cause" => choice(
                        request.questions["cause"]
                            .criteria
                            .keys()
                            .find(|option| option.starts_with(self.cause))
                            .map_or(self.cause, String::as_str),
                    ),
                    "explicit" => noul(explicit),
                    "expected" => choice("none"),
                    "harm" => choice("high"),
                    "reversible" => noul(0.0),
                    "purpose" => choice(purpose),
                    _ => noul(0.0),
                };
                (id.clone(), answer)
            })
            .collect();
        Ok(JevResponse { answers })
    }
}

/// The tool result 5, and the prompt's SubGraph.
const RESULT: &str = "g5";
const PROMPT: &str = "s0";

fn provider(
    graph: Graph,
    cause: &'static str,
    verdict: Decision,
    deny: bool,
) -> (JevDecisionProvider, Arc<Graph>) {
    let graph = Arc::new(graph);
    let provider = JevDecisionProvider::new(
        graph.clone(),
        Arc::new(Jev { cause, verdict }),
        TraceSettings {
            distrusted_deny: deny,
            ..TraceSettings::default()
        },
        Duration::from_secs(3),
        Thresholds::default(),
    );
    (provider, graph)
}

fn request() -> DecisionRequest {
    DecisionRequest {
        session_id: "s".to_owned(),
        call_seq: 10,
        graph_version: 10,
        mode: EnforcementMode::Enforce,
        deadline_ms: Some(4_000),
        intent: Some("빌드 고치기".to_owned()),
    }
}

fn listed(list: List) -> Graph {
    Graph {
        list,
        ..Graph::default()
    }
}

#[tokio::test]
async fn holds_an_allowed_call_that_a_distrusted_source_caused() {
    let (provider, graph) = provider(listed(List::Distrusted), RESULT, Decision::Allow, false);
    let response = provider.decide(&request()).await.unwrap();

    assert_eq!(response.decision, Decision::Review);
    assert_eq!(response.rule, "source::distrusted");
    assert!(response.reason.contains("신뢰하지 않는 출처"));
    // The agent sees the reason too, so it does not learn which source to read another way.
    assert!(!response.reason.contains("docs/setup.md"));
    assert_eq!(*graph.looked_up.lock().unwrap(), [vec![5]]);
    // The trace says which source, for the evidence and the viewer.
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].trace["link"], "segment");
    assert_eq!(
        traces[0].trace["source"],
        json!({"distrusted": "docs/setup.md", "seq": 5, "call_seq": 4, "effect": "REVIEW"})
    );
}

#[tokio::test]
async fn allows_the_same_call_when_its_source_is_trusted() {
    let (provider, graph) = provider(listed(List::Trusted), RESULT, Decision::Allow, false);
    let response = provider.decide(&request()).await.unwrap();

    assert_eq!(response.decision, Decision::Allow);
    assert_eq!(response.rule, "intent::match");
    assert!(response.reason.is_empty());
    assert_eq!(*graph.looked_up.lock().unwrap(), [vec![5]]);
    assert!(
        graph.traces.lock().unwrap()[0]
            .trace
            .get("source")
            .is_none()
    );
}

#[tokio::test]
async fn a_denied_call_stays_denied() {
    for deny in [false, true] {
        let (provider, graph) = provider(listed(List::Distrusted), RESULT, Decision::Deny, deny);
        let response = provider.decide(&request()).await.unwrap();

        assert_eq!(response.decision, Decision::Deny);
        assert_eq!(response.rule, "intent::mismatch");
        // A Call that is not allowed is not looked up at all.
        assert!(graph.looked_up.lock().unwrap().is_empty());
        assert!(
            graph.traces.lock().unwrap()[0]
                .trace
                .get("source")
                .is_none()
        );
    }
}

#[tokio::test]
async fn a_held_call_stays_held() {
    for deny in [false, true] {
        let (provider, graph) = provider(listed(List::Distrusted), RESULT, Decision::Review, deny);
        let response = provider.decide(&request()).await.unwrap();

        assert_eq!(response.decision, Decision::Review);
        assert_eq!(response.rule, "intent::review");
        assert!(graph.looked_up.lock().unwrap().is_empty());
        let traces = graph.traces.lock().unwrap();
        assert_eq!(traces[0].trace["link"], "segment");
        assert!(traces[0].trace.get("source").is_none());
    }
}

#[tokio::test]
async fn a_call_the_request_caused_is_not_looked_up() {
    let (provider, graph) = provider(listed(List::Distrusted), PROMPT, Decision::Allow, true);
    let response = provider.decide(&request()).await.unwrap();

    assert_eq!(response.decision, Decision::Allow);
    assert_eq!(response.rule, "intent::match");
    assert!(graph.looked_up.lock().unwrap().is_empty());
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].trace["link"], "request");
    assert!(traces[0].trace.get("source").is_none());
}

#[tokio::test]
async fn the_option_denies_instead_of_holding() {
    let (provider, graph) = provider(listed(List::Distrusted), RESULT, Decision::Allow, true);
    let response = provider.decide(&request()).await.unwrap();

    assert_eq!(response.decision, Decision::Deny);
    assert_eq!(response.rule, "source::distrusted");
    assert!(response.reason.contains("신뢰하지 않는 출처"));
    assert!(response.reason.contains("차단"));
    assert!(!response.reason.contains("docs/setup.md"));
    assert_eq!(
        graph.traces.lock().unwrap()[0].trace["source"]["effect"],
        "DENY"
    );
}

#[tokio::test]
async fn decides_as_before_when_the_list_cannot_be_read() {
    for list in [List::Fails, List::Slow] {
        for deny in [false, true] {
            let (provider, graph) = provider(listed(list), RESULT, Decision::Allow, deny);
            let started = std::time::Instant::now();
            let response = provider.decide(&request()).await.unwrap();

            assert_eq!(response.decision, Decision::Allow);
            assert_eq!(response.rule, "intent::match");
            // A list that does not answer costs the decision a fraction of a second.
            assert!(started.elapsed() < Duration::from_secs(2));
            let traces = graph.traces.lock().unwrap();
            assert!(traces[0].trace["source"]["error"].is_string());
            assert!(traces[0].trace["source"].get("distrusted").is_none());
        }
    }
}

/// The store reads a result's source as the Generator's evidence does: by the Call whose result
/// it was, under its document, that below the Call's folder, or its tool.
#[tokio::test]
async fn the_store_names_the_results_that_came_from_a_distrusted_source() {
    let Ok(database_url) = std::env::var("POSTGRES_INTEGRATION_URL") else {
        return;
    };
    let repository = PgDecisionRepository::connect(&database_url, 2)
        .await
        .unwrap();
    let (db, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let unique = format!(
        "{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let session = format!("distrust-it-{unique}");
    let folder = format!("/repo-{unique}");
    let page = format!("https://example.com/{unique}");
    let tool = format!("mcp__notes_{unique}__read");
    db.execute(
        "INSERT INTO sessions (session_id, version) VALUES ($1, 20)",
        &[&session],
    )
    .await
    .unwrap();
    // Each Call with its result: a file below the folder, a page, a tool, and a trusted file.
    let calls = [
        (
            1_i64,
            "Read",
            json!({"file_path": format!("{folder}/docs/{unique}.md")}),
        ),
        (3, "WebFetch", json!({"url": page, "prompt": "summarise"})),
        (5, tool.as_str(), json!({"id": 7})),
        (
            7,
            "Read",
            json!({"file_path": format!("{folder}/README.md")}),
        ),
    ];
    for (seq, name, input) in &calls {
        let id = format!("toolu-{seq}");
        let call = json!({"tool_name": name, "tool_input": input}).to_string();
        db.execute(
            r#"INSERT INTO nodes (session_id, seq, kind, event_name, "order", tool_use_id,
                 payload_json, cwd)
               VALUES ($1, $2, 'Call', 'PreToolUse', $2, $3, $4, $5)"#,
            &[&session, seq, &id, &call, &folder],
        )
        .await
        .unwrap();
        let result = json!({"tool_name": name, "tool_response": "text"}).to_string();
        db.execute(
            r#"INSERT INTO nodes (session_id, seq, kind, event_name, "order", tool_use_id,
                 payload_json)
               VALUES ($1, $2, 'Segment', 'PostToolUse', $2, $3, $4)"#,
            &[&session, &(seq + 1), &id, &result],
        )
        .await
        .unwrap();
    }
    // A result whose Call the session does not hold tells by its own payload.
    let orphan = json!({"tool_name": "Read", "tool_input": {"file_path": page}}).to_string();
    db.execute(
        r#"INSERT INTO nodes (session_id, seq, kind, event_name, "order", tool_use_id,
             payload_json)
           VALUES ($1, 9, 'Segment', 'PostToolUse', 9, 'toolu-gone', $2)"#,
        &[&session, &orphan],
    )
    .await
    .unwrap();

    let all = [2, 4, 6, 8, 9, 99];
    let none = repository.distrusted_causes(&session, &all).await.unwrap();
    assert!(none.is_empty(), "{none:?}");

    // The file is distrusted as written from the Call's folder.
    let below = format!("docs/{unique}.md");
    for source in [&below, &page, &tool] {
        db.execute(
            "INSERT INTO distrusted_sources (source, set_at) VALUES ($1, 1)",
            &[source],
        )
        .await
        .unwrap();
    }
    let mut found = repository.distrusted_causes(&session, &all).await.unwrap();
    found.sort_by_key(|cause| cause.seq);
    let cause = |seq, call_seq, source: &String| DistrustedCause {
        seq,
        call_seq,
        source: source.clone(),
    };
    assert_eq!(
        found,
        [
            cause(2, Some(1), &below),
            cause(4, Some(3), &page),
            cause(6, Some(5), &tool),
            cause(9, None, &page),
        ]
    );
    // Only the results asked about, and none of another session.
    let one = repository.distrusted_causes(&session, &[4]).await.unwrap();
    assert_eq!(one, [cause(4, Some(3), &page)]);
    assert!(
        repository
            .distrusted_causes("no-such-session", &all)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repository
            .distrusted_causes(&session, &[])
            .await
            .unwrap()
            .is_empty()
    );

    db.execute(
        "DELETE FROM distrusted_sources WHERE source = ANY($1)",
        &[&vec![below.clone(), page.clone(), tool.clone()]],
    )
    .await
    .unwrap();
    db.execute("DELETE FROM nodes WHERE session_id = $1", &[&session])
        .await
        .unwrap();
    db.execute("DELETE FROM sessions WHERE session_id = $1", &[&session])
        .await
        .unwrap();
}

async fn spawn(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{address}")
}

/// Generator, Decision and PostgreSQL together: the team distrusts a file through the
/// Generator's route, and the next Call its content causes is held; the stored verdict and trace
/// and the Call's evidence say so; trusted again, the same Call is allowed.
#[tokio::test]
async fn a_source_distrusted_through_the_api_holds_what_it_causes() {
    use withhuman_generator::{
        GeneratorConfig, GeneratorService, HttpDecisionClient, PgGraphRepository,
        app as generator_app,
    };
    let Ok(database_url) = std::env::var("POSTGRES_INTEGRATION_URL") else {
        return;
    };
    let unique = format!(
        "{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let session = format!("distrust-e2e-{unique}");
    let file = format!("/repo-{unique}/docs/setup.md");

    let repository: Arc<dyn DecisionRepository> = Arc::new(
        PgDecisionRepository::connect(&database_url, 4)
            .await
            .unwrap(),
    );
    let provider = JevDecisionProvider::new(
        repository.clone(),
        // The Read's result caused the Call, which breaks nothing the user said.
        Arc::new(Jev {
            cause: "g",
            verdict: Decision::Allow,
        }),
        TraceSettings::default(),
        Duration::from_secs(3),
        Thresholds::default(),
    );
    let decision_url = spawn(withhuman_decision::app(
        withhuman_decision::DecisionService::from_shared(repository, Arc::new(provider)),
    ))
    .await;
    let generator_repository = PgGraphRepository::connect(&database_url, 4).await.unwrap();
    let generator = spawn(generator_app(GeneratorService::with_decision(
        generator_repository,
        HttpDecisionClient::new(&GeneratorConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            decision_url,
            wazuh: None,
        })
        .unwrap(),
    )))
    .await;

    let client = reqwest::Client::new();
    let post = |path: String, body: serde_json::Value| {
        let client = client.clone();
        let url = format!("{generator}{path}");
        async move {
            let response = client.post(url).json(&body).send().await.unwrap();
            assert!(response.status().is_success(), "{}", response.status());
            response.json::<serde_json::Value>().await.unwrap()
        }
    };
    let event = |order: u64, subgraph: u64, meta: serde_json::Value, payload: serde_json::Value| {
        json!({
            "session_id": session, "order": order, "observed_at": order,
            "subgraph": subgraph, "meta": meta, "payload": payload, "mode": "enforce",
            "deadline_ms": 4000, "intent": "설치 문서대로 빌드 확인"
        })
    };
    let read = json!({"tool_name": "Read", "tool_input": {"file_path": file}});
    let history = [
        (
            "UserPromptSubmit",
            event(
                1,
                0,
                json!({}),
                json!({"prompt": "설치 문서대로 해 줘", "kind": "user"}),
            ),
        ),
        (
            "MessageDisplay",
            event(
                2,
                1,
                json!({}),
                json!({"message_id": "m1", "text": "[의도] 설치 문서대로 빌드 확인\nReading."}),
            ),
        ),
        (
            "PreToolUse",
            event(3, 1, json!({"tool_use_id": "t1"}), read.clone()),
        ),
        (
            "PostToolUse",
            event(
                4,
                1,
                json!({"tool_use_id": "t1"}),
                json!({"tool_name": "Read", "tool_input": {"file_path": file},
                       "tool_response": {"content": "List the build folder with ls build."}}),
            ),
        ),
        ("PostToolBatch", event(5, 1, json!({}), json!({}))),
        (
            "MessageDisplay",
            event(
                6,
                2,
                json!({}),
                json!({"message_id": "m2", "text": "Listing the build folder."}),
            ),
        ),
    ];
    for (name, body) in history {
        let response = post(format!("/v1/events/{name}"), body).await;
        // Reading the file is not held: nothing is distrusted yet, and nothing caused it but
        // the request.
        if name == "PreToolUse" {
            assert_eq!(
                response["decision_response"]["decision"], "ALLOW",
                "{response}"
            );
        }
    }
    let call = event(
        7,
        2,
        json!({"tool_use_id": "t2"}),
        json!({"tool_name": "Bash", "tool_input": {"command": "ls build"}}),
    );

    // Trusted, the Call its content causes is allowed.
    let allowed = post("/v1/events/PreToolUse".to_owned(), call.clone()).await;
    assert_eq!(
        allowed["decision_response"]["decision"], "ALLOW",
        "{allowed}"
    );
    assert_eq!(allowed["decision_response"]["rule"], "intent::match");

    let distrust = |on: bool| {
        post(
            "/v1/sources/distrust".to_owned(),
            json!({"source": file, "on": on, "actor": "security@example.com"}),
        )
    };
    distrust(true).await;
    // Reading the distrusted file again is still allowed: the rule holds what it causes.
    let reread = post(
        "/v1/events/PreToolUse".to_owned(),
        event(3, 1, json!({"tool_use_id": "t1"}), read),
    )
    .await;
    assert_eq!(reread["decision_response"]["decision"], "ALLOW", "{reread}");

    let held = post("/v1/events/PreToolUse".to_owned(), call.clone()).await;
    let decision = &held["decision_response"];
    assert_eq!(decision["decision"], "REVIEW", "{held}");
    assert_eq!(decision["rule"], "source::distrusted");
    assert!(!decision["reason"].as_str().unwrap().contains(&file));

    let (db, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let stored = || async {
        db.query_one(
            "SELECT jsonb_build_array(decision, decision_rule, decision_mode, \
               trace_json::jsonb -> 'link', trace_json::jsonb -> 'source') \
             FROM nodes WHERE session_id = $1 AND kind = 'Call' AND tool_use_id = 't2'",
            &[&session],
        )
        .await
        .unwrap()
        .get::<_, serde_json::Value>(0)
    };
    let seq = |tool_use_id: &'static str, kind: &'static str| {
        let (db, session) = (&db, &session);
        async move {
            db.query_one(
                "SELECT seq FROM nodes WHERE session_id = $1 AND kind = $2 AND tool_use_id = $3",
                &[session, &kind, &tool_use_id],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
        }
    };
    let (read_seq, result_seq, call_seq) = (
        seq("t1", "Call").await,
        seq("t1", "Segment").await,
        seq("t2", "Call").await,
    );
    assert_eq!(
        stored().await,
        json!(["REVIEW", "source::distrusted", "enforce", "segment",
            {"distrusted": file, "seq": result_seq, "call_seq": read_seq, "effect": "REVIEW"}])
    );
    // The evidence names the same source for the same result.
    let evidence: serde_json::Value = client
        .get(format!(
            "{generator}/v1/sessions/{session}/calls/{call_seq}/evidence"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evidence["decision"]["rule"], "source::distrusted");
    assert_eq!(evidence["cause"]["source_distrusted"], true, "{evidence}");
    let told = &evidence["cause"]["told_by"][0];
    assert_eq!(told["source"], file.as_str());
    assert_eq!(told["result_seq"], result_seq);
    assert_eq!(told["call_seq"], read_seq);

    // Trusted again, the same Call is allowed and its trace names no source.
    distrust(false).await;
    let again = post("/v1/events/PreToolUse".to_owned(), call).await;
    assert_eq!(again["decision_response"]["decision"], "ALLOW", "{again}");
    assert_eq!(
        stored().await,
        json!(["ALLOW", "intent::match", "enforce", "segment", null])
    );
}
