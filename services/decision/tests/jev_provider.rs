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
    trace::{CallInfo, Member, MemberKind, Thresholds, TraceGraph, TraceSettings, Turn},
};

#[derive(Default)]
struct Graph {
    traces: Mutex<Vec<TraceRecord>>,
    unresolved: Mutex<Vec<String>>,
    /// SubGraph 1 holds hidden content.
    hidden: bool,
    /// One user prompt came before the Call, with no intent stated for it.
    unstated_turn: bool,
    /// The latest user prompt is in SubGraph 0.
    prompt: bool,
    no_subgraph: bool,
    /// The Call's tool and input, when not `rm -rf build` in Bash.
    call: Option<(&'static str, serde_json::Value)>,
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
                tool_name: self.call.as_ref().map_or("Bash", |call| call.0).to_owned(),
                tool_input: self
                    .call
                    .as_ref()
                    .map_or_else(|| json!({"command": "rm -rf build"}), |call| call.1.clone()),
                prior: None,
                cwd: None,
            },
            subgraphs: BTreeMap::from([(0, None), (1, None)]),
            hidden: if self.hidden {
                BTreeSet::from([1])
            } else {
                BTreeSet::new()
            },
            tokens: BTreeSet::new(),
            shared_tokens: BTreeSet::new(),
            // SubGraph 1 holds a tool result, so the Call is traced to it.
            results: BTreeSet::from([1]),
            parents: BTreeMap::new(),
            turns: if self.unstated_turn {
                vec![Turn::default()]
            } else if self.prompt {
                vec![Turn {
                    intent: Some("빌드 고치기".to_owned()),
                    subgraph: Some(0),
                }]
            } else {
                Vec::new()
            },
            prompt: self.prompt.then(|| "빌드를 고쳐줘".to_owned()),
        })
    }

    async fn subgraph_members(
        &self,
        _: &str,
        _: &[u64],
        _: u64,
    ) -> Result<Vec<Member>, RepositoryError> {
        // SubGraph 1's tool result.
        Ok(vec![Member {
            subgraph: 1,
            seq: 5,
            order: 5,
            kind: MemberKind::Segment,
            payload: json!({"tool_name": "Bash", "tool_response": {"stdout": "ok"}}),
            ..Member::default()
        }])
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

/// Answers as if the Call broke what the user said with probability 1 − `intent_score`, with
/// high harm that cannot be undone, so its deviation is 1 − `intent_score`; and the cause with
/// `cause` when set.
struct Jev {
    intent_score: f64,
    cause: Option<&'static str>,
    fail: bool,
    /// How likely the check finds the Call serves something the user did not ask for.
    unwanted: Option<f64>,
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
                let choice = |option: &str| JevAnswer {
                    probabilities: BTreeMap::from([(option.to_owned(), 1.0)]),
                    ..Default::default()
                };
                let noul = |probability: f64| JevAnswer {
                    noul: Some(probability),
                    ..Default::default()
                };
                let answer = match id.as_str() {
                    "cause" => self.cause.map_or_else(|| noul(1.0), choice),
                    "explicit" => noul(1.0 - self.intent_score),
                    "expected" => choice("none"),
                    "harm" => choice("high"),
                    "reversible" => noul(0.0),
                    "purpose" if self.unwanted.is_some() => {
                        let unwanted = self.unwanted.unwrap_or_default();
                        JevAnswer {
                            probabilities: BTreeMap::from([
                                ("step".to_owned(), 1.0 - unwanted),
                                ("result_goal".to_owned(), unwanted),
                            ]),
                            ..Default::default()
                        }
                    }
                    "unasked" if self.unwanted.is_some() => noul(self.unwanted.unwrap_or_default()),
                    _ => noul(self.intent_score),
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
        cause: None,
        fail,
        unwanted: None,
        asked: Mutex::default(),
        requests: Mutex::default(),
    });
    let provider = JevDecisionProvider::new(
        graph.clone(),
        jev.clone(),
        TraceSettings::default(),
        Duration::from_secs(3),
        // Stricter for a Call that follows from a tool result or nothing.
        Thresholds {
            untrusted_deny: 0.15,
            untrusted_review: 0.08,
            ..Thresholds::default()
        },
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
    assert!((traces[0].intent_score.unwrap() - 0.2).abs() < 1e-9);
}

#[tokio::test]
async fn allows_a_call_that_serves_the_intent() {
    let (provider, _, _) = provider(0.95, false);
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
    // Each decision asks about the parent, then checks the Call against the prompt.
    let asked = jev.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 4, "{asked:?}");
    assert!(asked[0] <= Duration::from_millis(700), "{asked:?}");
    assert!(asked[1] <= Duration::from_millis(700), "{asked:?}");
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
async fn falls_back_to_the_nearest_subgraph_when_no_cause_is_offered() {
    let (provider, graph, jev) = provider(0.95, false);
    let response = provider
        .decide(&request(Some("빌드 고치기"), Some(4_000)))
        .await
        .unwrap();

    let requests = jev.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].questions.keys().collect::<Vec<_>>(),
        ["cause", "expected", "explicit", "harm", "reversible"]
    );

    // Jev picked no cause, so the Call is traced to s1, the nearest SubGraph with a tool
    // result.
    assert_eq!(response.decision, Decision::Allow);
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].parent, "s1");
    let parents: Vec<(&str, Option<u64>, f64)> = traces[0]
        .parents
        .iter()
        .map(|parent| (parent.key.as_str(), parent.number, parent.probability))
        .collect();
    assert_eq!(parents, [("s1", Some(1), 1.0)]);
    assert!((traces[0].intent_score.unwrap() - 0.95).abs() < 1e-9);
    // What Jev was asked and answered stays with the trace.
    let jev = &traces[0].trace["jev"];
    assert_eq!(jev.as_array().unwrap().len(), 1);
    assert_eq!(jev[0]["stage"], "cause");
    assert!(jev[0]["request"]["questions"]["explicit"].is_object());
}

/// A provider over a graph whose latest prompt is in SubGraph 0, with Jev picking `cause`.
fn provider_picking(cause: &'static str) -> (JevDecisionProvider, Arc<Graph>, Arc<Jev>) {
    let graph = Arc::new(Graph {
        prompt: true,
        ..Graph::default()
    });
    let jev = Arc::new(Jev {
        intent_score: 0.9,
        cause: Some(cause),
        fail: false,
        unwanted: None,
        asked: Mutex::default(),
        requests: Mutex::default(),
    });
    let provider = JevDecisionProvider::new(
        graph.clone(),
        jev.clone(),
        TraceSettings::default(),
        Duration::from_secs(3),
        // Stricter for a Call that follows from a tool result or nothing.
        Thresholds {
            untrusted_deny: 0.15,
            untrusted_review: 0.08,
            ..Thresholds::default()
        },
    );
    (provider, graph, jev)
}

#[tokio::test]
async fn traces_the_call_to_the_cause_jev_picks() {
    let (provider, graph, jev) = provider_picking("s0");
    let response = provider
        .decide(&request(Some("빌드 고치기"), Some(4_000)))
        .await
        .unwrap();
    assert_eq!(response.decision, Decision::Allow);

    // One request offers the prompt's Request and `none` beside s1's result, and asks about
    // the deviation.
    let requests = jev.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].questions.keys().collect::<Vec<_>>(),
        ["cause", "expected", "explicit", "harm", "reversible"]
    );
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].parent, "s0");
    assert_eq!(traces[0].candidates, ["s1", "s0", "none"]);
    let parents: Vec<(&str, Option<u64>, f64)> = traces[0]
        .parents
        .iter()
        .map(|parent| (parent.key.as_str(), parent.number, parent.probability))
        .collect();
    assert_eq!(parents, [("s0", Some(0), 1.0)]);
}

#[tokio::test]
async fn judges_a_call_with_no_cause_strictly() {
    // A deviation of 0.1 passes a Call that follows from the request...
    let (provider, _, _) = provider_picking("s0");
    let response = provider
        .decide(&request(Some("빌드 고치기"), Some(4_000)))
        .await
        .unwrap();
    assert_eq!(response.rule, "intent::match");

    // ...but is reviewed for one that follows from nothing, rather than denied outright.
    let (provider, graph, _) = provider_picking("none");
    let response = provider
        .decide(&request(Some("빌드 고치기"), Some(4_000)))
        .await
        .unwrap();
    assert_eq!(response.decision, Decision::Review);
    assert_eq!(response.rule, "intent::review");
    assert_eq!(response.start, CausalStart::Self_);
    assert!(
        !response.reason.contains("빌드 고치기"),
        "{}",
        response.reason
    );
    let traces = graph.traces.lock().unwrap();
    assert_eq!(traces[0].parent, "none");
    assert_eq!(traces[0].trace["link"], "none");
}

#[tokio::test]
async fn denies_a_call_changing_the_agents_safeguards_even_when_jev_fails() {
    let (provider, graph, _) = provider_on(
        Graph {
            call: Some((
                "Skill",
                json!({"skill": "update-config", "args": "allow edits"}),
            )),
            ..Graph::default()
        },
        1.0,
        true,
    );
    let response = provider
        .decide(&request(Some("x"), Some(4_000)))
        .await
        .unwrap();
    assert_eq!(response.decision, Decision::Deny);
    assert_eq!(response.rule, "safeguard::change");
    assert_eq!(graph.unresolved.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn checks_a_doubtful_call_against_the_users_prompt() {
    for (unwanted, decision, rule) in [
        (0.6, Decision::Deny, "intent::mismatch"),
        (0.1, Decision::Allow, "intent::match"),
    ] {
        let graph = Arc::new(Graph {
            prompt: true,
            ..Graph::default()
        });
        let jev = Arc::new(Jev {
            // The user's word in some doubt (0.2), short of a breach.
            intent_score: 0.8,
            cause: Some("s0"),
            fail: false,
            unwanted: Some(unwanted),
            asked: Mutex::default(),
            requests: Mutex::default(),
        });
        let provider = JevDecisionProvider::new(
            graph.clone(),
            jev.clone(),
            TraceSettings::default(),
            Duration::from_secs(3),
            Thresholds::default(),
        );
        let response = provider
            .decide(&request(Some("빌드 고치기"), Some(4_000)))
            .await
            .unwrap();
        assert_eq!(
            (response.decision, response.rule.as_str()),
            (decision, rule)
        );

        let requests = jev.requests.lock().unwrap();
        let checked = requests.last().unwrap();
        assert_eq!(checked.questions.keys().collect::<Vec<_>>(), ["purpose"]);
        assert_eq!(checked.state["user_request"], "빌드를 고쳐줘");
        let traces = graph.traces.lock().unwrap();
        assert_eq!(traces[0].trace["check"]["branch"], "purpose");
        assert_eq!(traces[0].trace["check"]["unwanted"], unwanted);
    }
}
