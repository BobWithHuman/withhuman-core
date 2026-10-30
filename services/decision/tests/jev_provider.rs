use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use serde_json::json;
use withhuman_contracts::decisions::{
    CausalStart, Decision, DecisionRequest, DecisionResponse, EnforcementMode,
};
use withhuman_decision::{
    DecisionProvider, DecisionRepository, JevDecisionProvider, RepositoryError, TraceRecord,
    jev::{JevAnswer, JevClient, JevError, JevRequest, JevResponse},
    trace::{CallInfo, Member, TraceGraph, TraceSettings, Turn},
};

#[derive(Default)]
struct Graph {
    traces: Mutex<Vec<TraceRecord>>,
    unresolved: Mutex<Vec<String>>,
    /// SubGraph 1 holds hidden content.
    hidden: bool,
    /// One user prompt came before the Call, with no intent stated for it.
    unstated_turn: bool,
    no_subgraph: bool,
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
        if self.no_subgraph {
            return Err(RepositoryError::NoSubGraph);
        }
        Ok(TraceGraph {
            call: CallInfo {
                seq: request.call_seq,
                order: 10,
                subgraph: 2,
                agent_id: None,
                tool_name: "Bash".to_owned(),
                tool_input: json!({"command": "rm -rf build"}),
            },
            subgraphs: BTreeMap::from([(0, None), (1, None)]),
            hidden: if self.hidden {
                BTreeSet::from([1])
            } else {
                BTreeSet::new()
            },
            tokens: BTreeSet::new(),
            shared_tokens: BTreeSet::new(),
            parents: BTreeMap::new(),
            turns: if self.unstated_turn {
                vec![Turn::default()]
            } else {
                Vec::new()
            },
        })
    }

    async fn subgraph_members(
        &self,
        _: &str,
        _: &[u64],
        _: u64,
    ) -> Result<Vec<Member>, RepositoryError> {
        Ok(Vec::new())
    }

    async fn persist_trace(
        &self,
        _: &DecisionRequest,
        record: &TraceRecord,
    ) -> Result<(), RepositoryError> {
        self.traces.lock().unwrap().push(record.clone());
        Ok(())
    }

    async fn mark_unresolved(
        &self,
        _: &DecisionRequest,
        error: &str,
    ) -> Result<(), RepositoryError> {
        self.unresolved.lock().unwrap().push(error.to_owned());
        Ok(())
    }
}

/// Answers every question: `parent` by `parent` (s1 alone unless set), intent questions with
/// `intent_score`, or with the per-parent score in `scores`.
struct Jev {
    intent_score: f64,
    parent: BTreeMap<String, f64>,
    scores: BTreeMap<String, f64>,
    fail: bool,
    asked: Mutex<Vec<Duration>>,
    requests: Mutex<Vec<JevRequest>>,
}

#[async_trait]
impl JevClient for Jev {
    async fn ask(&self, request: &JevRequest, timeout: Duration) -> Result<JevResponse, JevError> {
        self.asked.lock().unwrap().push(timeout);
        self.requests.lock().unwrap().push(request.clone());
        if self.fail {
            return Err(JevError::Timeout);
        }
        let answers = request
            .questions
            .keys()
            .map(|id| {
                let answer = if id == "parent" {
                    JevAnswer {
                        probabilities: self.parent.clone(),
                        ..Default::default()
                    }
                } else {
                    let key = id.strip_prefix("intent_").unwrap_or_default();
                    JevAnswer {
                        noul: Some(self.scores.get(key).copied().unwrap_or(self.intent_score)),
                        ..Default::default()
                    }
                };
                (id.clone(), answer)
            })
            .collect();
        Ok(JevResponse { answers })
    }
}

fn provider(intent_score: f64, fail: bool) -> (JevDecisionProvider, Arc<Graph>, Arc<Jev>) {
    provider_on(Graph::default(), intent_score, fail)
}

fn provider_on(
    graph: Graph,
    intent_score: f64,
    fail: bool,
) -> (JevDecisionProvider, Arc<Graph>, Arc<Jev>) {
    let graph = Arc::new(graph);
    let jev = Arc::new(Jev {
        intent_score,
        parent: BTreeMap::from([("s1".to_owned(), 0.9), ("none".to_owned(), 0.1)]),
        scores: BTreeMap::new(),
        fail,
        asked: Mutex::default(),
        requests: Mutex::default(),
    });
    let provider = JevDecisionProvider::new(
        graph.clone(),
        jev.clone(),
        TraceSettings::default(),
        Duration::from_secs(3),
        0.5,
    );
    (provider, graph, jev)
}

fn request(intent: Option<&str>, deadline_ms: Option<u64>) -> DecisionRequest {
    DecisionRequest {
        session_id: "s".to_owned(),
        call_seq: 10,
        graph_version: 10,
        mode: EnforcementMode::Enforce,
        deadline_ms,
        intent: intent.map(str::to_owned),
    }
}

#[tokio::test]
async fn denies_a_call_whose_cause_departs_from_the_intent() {
    let (provider, graph, _) = provider(0.2, false);
    let response = provider
        .decide(&request(Some("빌드 고치기"), Some(4_000)))
        .await
        .unwrap();

    assert_eq!(response.decision, Decision::Deny);
    assert_eq!(response.rule, "intent::mismatch");
    // The agent learns neither the intent nor the score it fell short of.
    assert!(
        !response.reason.contains("빌드 고치기"),
        "{}",
        response.reason
    );
    assert!(!response.reason.contains("0.2"), "{}", response.reason);
    assert!(response.jev.unwrap().asked);
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].parent, "s1");
    assert_eq!(traces[0].intent_score, Some(0.2));
}

#[tokio::test]
async fn allows_a_call_that_serves_the_intent() {
    let (provider, _, _) = provider(0.8, false);
    let response = provider
        .decide(&request(Some("빌드 고치기"), Some(4_000)))
        .await
        .unwrap();
    assert_eq!(response.decision, Decision::Allow);
    assert_eq!(response.rule, "intent::match");
    assert!(response.reason.is_empty());
    assert_eq!(response.start, CausalStart::Unresolved);
}

#[tokio::test]
async fn traces_without_judging_when_no_intent_was_stated() {
    let (provider, graph, _) = provider(0.0, false);
    let response = provider.decide(&request(None, Some(4_000))).await.unwrap();
    assert_eq!(response.decision, Decision::Allow);
    assert_eq!(response.rule, "intent::unknown");
    assert_eq!(graph.traces.lock().unwrap().len(), 1);

    // Hidden content among the candidates makes an unjudged Call a question for the user.
    let (provider, _, _) = provider_on(
        Graph {
            hidden: true,
            ..Graph::default()
        },
        0.0,
        false,
    );
    let response = provider.decide(&request(None, Some(4_000))).await.unwrap();
    assert_eq!(response.decision, Decision::Review);
}

#[tokio::test]
async fn never_judges_by_the_prompt_when_no_intent_was_stated() {
    let (provider, graph, jev) = provider_on(
        Graph {
            unstated_turn: true,
            ..Graph::default()
        },
        0.1,
        false,
    );
    let response = provider.decide(&request(None, Some(4_000))).await.unwrap();
    assert_eq!(response.decision, Decision::Allow);
    assert_eq!(response.rule, "intent::unknown");
    let requests = jev.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|request| !request.state.contains_key("intents"))
    );
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].trace["intent_source"], "none");
}

#[tokio::test]
async fn reviews_when_tracing_fails_with_hidden_content_in_reach() {
    let (provider, graph, _) = provider_on(
        Graph {
            hidden: true,
            ..Graph::default()
        },
        0.0,
        true,
    );
    let response = provider
        .decide(&request(Some("x"), Some(4_000)))
        .await
        .unwrap();
    assert_eq!(response.decision, Decision::Review);
    assert_eq!(response.rule, "trace::unresolved");
    assert_eq!(graph.unresolved.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn allows_calls_committed_before_subgraphs() {
    let (provider, _, jev) = provider_on(
        Graph {
            no_subgraph: true,
            ..Graph::default()
        },
        0.0,
        false,
    );
    let response = provider
        .decide(&request(Some("x"), Some(4_000)))
        .await
        .unwrap();
    assert_eq!(response.decision, Decision::Allow);
    assert_eq!(response.rule, "trace::no_subgraph");
    assert!(jev.asked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn records_an_unresolved_trace_when_jev_fails() {
    let (provider, graph, _) = provider(0.0, true);
    assert!(
        provider
            .decide(&request(Some("x"), Some(4_000)))
            .await
            .is_err()
    );
    assert_eq!(graph.unresolved.lock().unwrap().len(), 1);
    assert!(graph.traces.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bounds_the_jev_call_by_the_decision_deadline() {
    let (provider, _, jev) = provider(0.8, false);
    provider
        .decide(&request(Some("x"), Some(1_000)))
        .await
        .unwrap();
    provider.decide(&request(Some("x"), None)).await.unwrap();
    // Each decision asks twice: for the parent, then about it.
    let asked = jev.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 4, "{asked:?}");
    assert!(asked[0] <= Duration::from_millis(700), "{asked:?}");
    assert!(asked[1] <= asked[0], "{asked:?}");
    assert_eq!(asked[2..], [Duration::from_secs(3); 2]);

    let (provider, graph, jev) = self::provider(0.8, false);
    assert!(
        provider
            .decide(&request(Some("x"), Some(100)))
            .await
            .is_err()
    );
    assert!(jev.asked.lock().unwrap().is_empty());
    assert_eq!(graph.unresolved.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn asks_for_the_parent_first_and_then_about_it_alone() {
    let graph = Arc::new(Graph::default());
    let jev = Arc::new(Jev {
        intent_score: 0.9,
        // none comes close to s1 but is not the most influential.
        parent: BTreeMap::from([("s1".to_owned(), 0.6), ("none".to_owned(), 0.4)]),
        scores: BTreeMap::from([("none".to_owned(), 0.1)]),
        fail: false,
        asked: Mutex::default(),
        requests: Mutex::default(),
    });
    let provider = JevDecisionProvider::new(
        graph.clone(),
        jev.clone(),
        TraceSettings::default(),
        Duration::from_secs(3),
        0.5,
    );
    let response = provider
        .decide(&request(Some("빌드 고치기"), Some(4_000)))
        .await
        .unwrap();

    let requests = jev.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].questions.keys().collect::<Vec<_>>(), ["parent"]);
    assert!(!requests[0].state.contains_key("intents"));
    assert_eq!(
        requests[1].questions.keys().collect::<Vec<_>>(),
        ["intent_s1"]
    );

    // The Call is traced to s1 alone and judged by it.
    assert_eq!(response.decision, Decision::Allow);
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].parent, "s1");
    let parents: Vec<(&str, Option<u64>)> = traces[0]
        .parents
        .iter()
        .map(|parent| (parent.key.as_str(), parent.number))
        .collect();
    assert_eq!(parents, [("s1", Some(1))]);
    assert_eq!(traces[0].intent_score, Some(0.9));
    assert!(traces[0].trace["intent_scores"].get("none").is_none());
    // What Jev was asked and answered stays with the trace.
    let jev = &traces[0].trace["jev"];
    assert_eq!(jev[0]["stage"], "parent");
    assert!(jev[0]["request"]["questions"]["parent"].is_object());
    assert_eq!(
        jev[0]["response"]["answers"]["parent"]["probabilities"]["s1"],
        0.6
    );
    assert_eq!(jev[1]["stage"], "judge");
    assert_eq!(jev[1]["parent"], "s1");
    assert!(jev[1]["request"]["questions"]["intent_s1"].is_object());
    assert_eq!(jev.as_array().unwrap().len(), 2);
}
