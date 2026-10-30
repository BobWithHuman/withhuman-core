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
    trace::{CallInfo, Member, TraceGraph, TraceSettings},
};

#[derive(Default)]
struct Graph {
    traces: Mutex<Vec<TraceRecord>>,
    unresolved: Mutex<Vec<String>>,
    /// Sequence 1 holds hidden content.
    hidden: bool,
    prompt: Option<&'static str>,
    unsequenced: bool,
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
        if self.unsequenced {
            return Err(RepositoryError::Unsequenced);
        }
        Ok(TraceGraph {
            call: CallInfo {
                seq: request.call_seq,
                order: 10,
                sequence: 2,
                agent_id: None,
                tool_name: "Bash".to_owned(),
                tool_input: json!({"command": "rm -rf build"}),
            },
            sequences: BTreeMap::from([(0, None), (1, None)]),
            hidden: if self.hidden {
                BTreeSet::from([1])
            } else {
                BTreeSet::new()
            },
            tokens: BTreeSet::new(),
            shared_tokens: BTreeSet::new(),
            parents: BTreeMap::new(),
            request: self.prompt.map(str::to_owned),
        })
    }

    async fn sequence_members(
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

/// Answers every question: `parent` picks s1, intent questions return `intent_score`.
struct Jev {
    intent_score: f64,
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
                        probabilities: BTreeMap::from([
                            ("s1".to_owned(), 0.9),
                            ("none".to_owned(), 0.1),
                        ]),
                        ..Default::default()
                    }
                } else {
                    JevAnswer {
                        noul: Some(self.intent_score),
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
async fn judges_by_the_prompt_when_no_intent_was_stated() {
    let (provider, graph, jev) = provider_on(
        Graph {
            prompt: Some("빌드 폴더만 정리해 줘"),
            ..Graph::default()
        },
        0.1,
        false,
    );
    let response = provider.decide(&request(None, Some(4_000))).await.unwrap();
    assert_eq!(response.decision, Decision::Deny);
    let requests = jev.requests.lock().unwrap();
    assert_eq!(requests[0].state["intent"], "빌드 폴더만 정리해 줘");
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].trace["intent_source"], "prompt");
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
async fn allows_calls_committed_before_sequences() {
    let (provider, _, jev) = provider_on(
        Graph {
            unsequenced: true,
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
    assert_eq!(response.rule, "trace::unsequenced");
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
    let asked = jev.asked.lock().unwrap().clone();
    assert!(asked[0] <= Duration::from_millis(700), "{asked:?}");
    assert_eq!(asked[1], Duration::from_secs(3));

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
