use std::{
    error::Error,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use withhuman_contracts::decisions::{
    CausalStart, Decision, DecisionRequest, DecisionResponse, JevActivity,
};

use crate::{
    DecisionConfig, DecisionRepository, RepositoryError,
    jev::JevClient,
    repository::{TraceRecord, TracedParent, TracedSegment},
    trace::{self, Stop, TraceSettings},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError(pub String);

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ProviderError {}

#[async_trait]
pub trait DecisionProvider: Send + Sync + 'static {
    async fn decide(&self, request: &DecisionRequest) -> Result<DecisionResponse, ProviderError>;
}

#[derive(Debug, Clone)]
pub struct MockDecisionProvider {
    decision: Decision,
    reason: Option<String>,
    delay: Duration,
}

impl MockDecisionProvider {
    pub fn new(config: &DecisionConfig) -> Self {
        Self {
            decision: config.mock_decision,
            reason: config.mock_reason.clone(),
            delay: config.mock_delay,
        }
    }

    pub fn fixed(decision: Decision) -> Self {
        Self {
            decision,
            reason: None,
            delay: Duration::ZERO,
        }
    }
}

#[async_trait]
impl DecisionProvider for MockDecisionProvider {
    async fn decide(&self, _request: &DecisionRequest) -> Result<DecisionResponse, ProviderError> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let reason = match self.decision {
            Decision::Allow => String::new(),
            Decision::Deny => self
                .reason
                .clone()
                .unwrap_or_else(|| "Blocked by WithHuman mock policy.".into()),
            Decision::Review => self
                .reason
                .clone()
                .unwrap_or_else(|| "Review required by WithHuman mock policy.".into()),
        };
        Ok(DecisionResponse {
            decision: self.decision,
            reason,
            rule: format!("mock::{:?}", self.decision).to_ascii_lowercase(),
            start: CausalStart::Unresolved,
            written: false,
            jev: None,
        })
    }
}

/// Traces the Call's cause through Jev and denies it when one of the traced chains of events
/// departs from the user's intents by more than the configured threshold.
///
/// When tracing fails, the Call gets the Collector's failure policy (an error), or REVIEW when
/// an earlier SubGraph of the Call's agent holds hidden content or a sensitive value. Jev sees prompts only through the
/// intents stated for them; when no prompt has one, the Call is allowed, or reviewed in that
/// same risky case.
#[derive(Clone)]
pub struct JevDecisionProvider {
    repository: Arc<dyn DecisionRepository>,
    jev: Arc<dyn JevClient>,
    settings: TraceSettings,
    jev_timeout: Duration,
    threshold: f64,
}

impl JevDecisionProvider {
    pub fn new(
        repository: Arc<dyn DecisionRepository>,
        jev: Arc<dyn JevClient>,
        settings: TraceSettings,
        jev_timeout: Duration,
        threshold: f64,
    ) -> Self {
        Self {
            repository,
            jev,
            settings,
            jev_timeout,
            threshold,
        }
    }

    /// Records the failure, then gives the failure policy or, when `risky`, REVIEW.
    async fn unresolved(
        &self,
        request: &DecisionRequest,
        error: impl fmt::Display,
        risky: bool,
    ) -> Result<DecisionResponse, ProviderError> {
        let error = error.to_string();
        let repository = self.repository.clone();
        let (stored_request, stored_error) = (request.clone(), error.clone());
        // Only a mark for auditing; the decision does not wait on it.
        let _ = settle(
            tokio::spawn(async move {
                repository
                    .mark_unresolved(&stored_request, &stored_error)
                    .await
            }),
            STORE_WAIT,
        )
        .await;
        if !risky {
            return Err(ProviderError(error));
        }
        Ok(DecisionResponse {
            decision: Decision::Review,
            reason: REVIEW_REASON.to_owned(),
            rule: "trace::unresolved".to_owned(),
            start: CausalStart::Unresolved,
            written: false,
            jev: Some(JevActivity {
                asked: true,
                ms: None,
                reused_from: None,
                error: Some(error),
            }),
        })
    }
}

/// Kept from the decision deadline for storing the trace and the verdict after Jev answers.
const PERSIST_RESERVE: Duration = Duration::from_millis(300);
/// How long a decision waits for a write it does not depend on; the write goes on after that.
const STORE_WAIT: Duration = Duration::from_millis(200);

const REVIEW_REASON: &str =
    "WithHuman이 이 도구 호출의 원인을 확인하지 못했습니다. 사용자 확인이 필요합니다.";

#[async_trait]
impl DecisionProvider for JevDecisionProvider {
    async fn decide(&self, request: &DecisionRequest) -> Result<DecisionResponse, ProviderError> {
        let started = Instant::now();
        let graph = match self.repository.trace_graph(request).await {
            Ok(graph) => graph,
            // Committed before SubGraphs were numbered: nothing to trace it through.
            Err(RepositoryError::NoSubGraph) => {
                return Ok(DecisionResponse {
                    decision: Decision::Allow,
                    reason: String::new(),
                    rule: "trace::no_subgraph".to_owned(),
                    start: CausalStart::Unresolved,
                    written: false,
                    jev: None,
                });
            }
            Err(error) => return Err(ProviderError(error.to_string())),
        };

        // The candidates and the SubGraphs their paths pass through, whose content Jev sees.
        let mut shown: Vec<u64> = trace::candidate_subgraphs(&graph)
            .into_iter()
            .flat_map(|number| trace::ancestry(&graph, number, |_| false, self.settings.max_hops).0)
            .collect();
        shown.sort_unstable();
        shown.dedup();
        let members = self
            .repository
            .subgraph_members(&request.session_id, &shown, graph.call.order)
            .await
            .map_err(|error| ProviderError(error.to_string()))?;
        // Every turn's stated intent; a prompt's text is never shown.
        let intents = trace::intents(&graph, request.intent.as_deref(), &self.settings);
        let plan = trace::plan(&graph, &members, intents.text.as_deref(), &self.settings);
        let risky = graph.risky();

        let remaining = |reserve: Duration| {
            request.deadline_ms.map(|deadline| {
                Duration::from_millis(deadline)
                    .saturating_sub(started.elapsed())
                    .saturating_sub(reserve)
            })
        };
        let timeout = || {
            remaining(PERSIST_RESERVE).map_or(self.jev_timeout, |left| left.min(self.jev_timeout))
        };

        // One request asks for the cause among every candidate's and judges each against the
        // intents; the parents follow from the cause.
        // What Jev was asked and answered, kept with the trace so it can be inspected.
        let mut exchanges = Vec::new();
        let judged = Instant::now();
        let budget = timeout();
        if budget.is_zero() {
            return self
                .unresolved(request, "no time left to ask Jev", risky)
                .await;
        }
        let response = match trace::judge_request(&plan) {
            None => None,
            Some(sent) => match self.jev.ask(&sent, budget).await {
                Ok(response) => {
                    exchanges.push(serde_json::json!({
                        "stage": "cause", "request": sent, "response": &response,
                    }));
                    Some(response)
                }
                Err(error) => return self.unresolved(request, error, risky).await,
            },
        };
        let (parents, mut judgements) = match trace::judge(&plan, response.as_ref()) {
            Ok(judged) => judged,
            Err(error) => return self.unresolved(request, error, risky).await,
        };
        let judge_ms = elapsed_ms(judged);

        // A parent with too many paragraphs to ask about at once was asked about its tool
        // results whole; now which paragraphs of each activated one. The decision does not
        // depend on it, so it is skipped when no time is left.
        let refined = Instant::now();
        let pending: Vec<_> = parents
            .chosen
            .iter()
            .zip(&judgements)
            .filter(|(parent, _)| !parent.candidate.by_paragraph)
            .flat_map(|(parent, judgement)| {
                judgement
                    .segments
                    .iter()
                    .filter(|segment| segment.paragraph.is_none())
                    .filter_map(|segment| {
                        trace::paragraph_request(&plan, &parent.candidate, segment.seq).map(
                            |jev_request| (parent.candidate.key.clone(), segment.seq, jev_request),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let budget = timeout();
        let mut refinements = Vec::new();
        if budget.is_zero() && !pending.is_empty() {
            for judgement in &mut judgements {
                judgement
                    .warnings
                    .push("no time left to ask about paragraphs".to_owned());
            }
        } else {
            let tasks: Vec<_> = pending
                .into_iter()
                .map(|(key, seq, jev_request)| {
                    let jev = self.jev.clone();
                    let sent = jev_request.clone();
                    let task = tokio::spawn(async move { jev.ask(&jev_request, budget).await });
                    (key, seq, sent, task)
                })
                .collect();
            for (key, seq, sent, task) in tasks {
                let response = match task.await {
                    Ok(Ok(response)) => {
                        exchanges.push(serde_json::json!({
                            "stage": "paragraph", "parent": &key, "seq": seq,
                            "request": sent, "response": &response,
                        }));
                        Some(response)
                    }
                    _ => None,
                };
                refinements.push((key, seq, response));
            }
        }
        for (key, seq, response) in refinements {
            if let Some((parent, judgement)) = parents
                .chosen
                .iter()
                .zip(judgements.iter_mut())
                .find(|(parent, _)| parent.candidate.key == key)
            {
                trace::refine(&parent.candidate, judgement, seq, response.as_ref());
            }
        }
        let paragraph_ms = elapsed_ms(refined);
        let outcome = trace::outcome(parents, judgements);

        let mut trace_json = trace::record(&plan, &outcome);
        trace_json["intent_source"] = intents.source.into();
        trace_json["jev_ms"] = serde_json::json!({"judge": judge_ms, "paragraph": paragraph_ms});
        trace_json["jev"] = exchanges.into();
        let record = TraceRecord {
            subgraph: graph.call.subgraph,
            parent: outcome.primary().key.clone(),
            parents: outcome
                .parents
                .iter()
                .map(|parent| TracedParent {
                    key: parent.candidate.key.clone(),
                    number: parent.candidate.subgraph,
                    probability: parent.influence,
                })
                .collect(),
            candidates: plan
                .candidates
                .iter()
                .map(|candidate| candidate.key.clone())
                .collect(),
            segments: outcome
                .segments
                .iter()
                .map(|segment| TracedSegment {
                    seq: segment.seq,
                    paragraph: segment.paragraph,
                    probability: segment.probability,
                    rank: segment.rank,
                    parent: segment.parent.clone(),
                })
                .collect(),
            intent_score: outcome.judged_score,
            trace: trace_json,
        };
        // The trace is stored in its own task, so a slow write neither delays the decision past
        // its deadline nor is cut off with it.
        let repository = self.repository.clone();
        let stored_request = request.clone();
        let stored = settle(
            tokio::spawn(async move { repository.persist_trace(&stored_request, &record).await }),
            remaining(Duration::from_millis(100)).unwrap_or(STORE_WAIT * 5),
        )
        .await;

        let primary = outcome.primary();
        let start = match primary.stop {
            _ if primary.subgraph.is_none() => CausalStart::Self_,
            Stop::ReachedRoot => CausalStart::User,
            Stop::None => CausalStart::Self_,
            Stop::Undecided | Stop::LoopGuard => CausalStart::Unresolved,
        };
        let jev = Some(JevActivity {
            asked: true,
            ms: Some(judge_ms + paragraph_ms),
            reused_from: None,
            error: stored
                .err()
                .map(|error| format!("trace not stored: {error}")),
        });
        // The agent sees the reason, so it names no score, intent or path it could learn to
        // avoid; those stay with the Call's trace.
        let (decision, rule, reason) = match outcome.judged_score {
            Some(score) if 1.0 - score > self.threshold => (
                Decision::Deny,
                "intent::mismatch",
                format!(
                    "WithHuman이 사용자 의도와 다른 행동으로 판단해 차단했습니다. (세션 {}, 호출 {})",
                    request.session_id, request.call_seq
                ),
            ),
            Some(_) => (Decision::Allow, "intent::match", String::new()),
            None if risky => (
                Decision::Review,
                "intent::unknown",
                REVIEW_REASON.to_owned(),
            ),
            None => (Decision::Allow, "intent::unknown", String::new()),
        };
        Ok(DecisionResponse {
            decision,
            reason,
            rule: rule.to_owned(),
            start,
            written: false,
            jev,
        })
    }
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Waits up to `wait` for a spawned write; past that it finishes on its own.
async fn settle(
    write: tokio::task::JoinHandle<Result<(), RepositoryError>>,
    wait: Duration,
) -> Result<(), String> {
    match tokio::time::timeout(wait, write).await {
        Ok(Ok(result)) => result.map_err(|error| error.to_string()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("still writing".to_owned()),
    }
}
