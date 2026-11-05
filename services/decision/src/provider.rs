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
    check::{self, Branch, Effect, Verdict},
    jev::JevClient,
    repository::{TraceRecord, TracedParent, TracedSegment},
    trace::{self, Stop, Thresholds, TraceSettings},
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

/// Traces the Call's cause through Jev and measures how far it departs from the user's
/// intents, then checks it against the user's prompt unless that clears it (`check`): a Call
/// changing the agent's safeguards is denied, one the check finds unwanted denied, one it does
/// not allowed, or reviewed when the trace found a breach. Without the check's answer the
/// deviation decides against thresholds that may depend on the Call's link.
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
    thresholds: Thresholds,
}

impl JevDecisionProvider {
    pub fn new(
        repository: Arc<dyn DecisionRepository>,
        jev: Arc<dyn JevClient>,
        settings: TraceSettings,
        jev_timeout: Duration,
        thresholds: Thresholds,
    ) -> Self {
        Self {
            repository,
            jev,
            settings,
            jev_timeout,
            thresholds,
        }
    }

    /// Records the failure, then denies a Call that changes the agent's safeguards, or gives
    /// the failure policy or, when `risky`, REVIEW.
    async fn unresolved(
        &self,
        request: &DecisionRequest,
        error: impl fmt::Display,
        risky: bool,
        safeguard: bool,
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
        if safeguard {
            return Ok(DecisionResponse {
                decision: Decision::Deny,
                reason: SAFEGUARD_REASON.to_owned(),
                rule: SAFEGUARD_RULE.to_owned(),
                start: CausalStart::Unresolved,
                written: false,
                jev: Some(JevActivity {
                    asked: true,
                    ms: None,
                    reused_from: None,
                    error: Some(error),
                }),
            });
        }
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

const SAFEGUARD_RULE: &str = "safeguard::change";
const SAFEGUARD_REASON: &str = "WithHuman이 에이전트의 설정이나 훅을 바꾸는 도구 호출을 차단했습니다. 사용자가 직접 바꿔야 합니다.";

const DEVIATION_REVIEW_REASON: &str = "WithHuman이 이 도구 호출이 사용자 의도에서 벗어났을 수 있다고 판단했습니다. 사용자 확인이 필요합니다.";

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

        // The turn, the candidates and the SubGraphs their paths pass through, whose content
        // Jev sees.
        let shown = trace::shown_subgraphs(&graph, self.settings.max_hops);
        let members = self
            .repository
            .subgraph_members(&request.session_id, &shown, graph.call.order)
            .await
            .map_err(|error| ProviderError(error.to_string()))?;
        // Every turn's stated intent; a prompt's text is never shown.
        let intents = trace::intents(&graph, request.intent.as_deref(), &self.settings);
        let plan = trace::plan(&graph, &members, intents.text.as_deref(), &self.settings);
        let risky = graph.risky();
        let effect = check::effect(&graph.call);
        let safeguard = effect == Effect::Safeguard;

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

        // One request asks for the cause among every candidate's and how far the Call departs
        // from the intents; the parent follows from the cause.
        // What Jev was asked and answered, kept with the trace so it can be inspected.
        let mut exchanges = Vec::new();
        let judged = Instant::now();
        let budget = timeout();
        if budget.is_zero() {
            return self
                .unresolved(request, "no time left to ask Jev", risky, safeguard)
                .await;
        }
        let judge_request = trace::judge_request(&plan);
        let response = match &judge_request {
            None => None,
            Some(sent) => match self.jev.ask(sent, budget).await {
                Ok(response) => {
                    exchanges.push(serde_json::json!({
                        "stage": "cause", "request": sent, "response": &response,
                    }));
                    Some(response)
                }
                Err(error) => return self.unresolved(request, error, risky, safeguard).await,
            },
        };
        let (parents, mut judgements, deviation) = match trace::judge(&plan, response.as_ref()) {
            Ok(judged) => judged,
            Err(error) => return self.unresolved(request, error, risky, safeguard).await,
        };
        let judge_ms = elapsed_ms(judged);

        // Unless the trace clears the Call, a second question checks it against the user's
        // prompt, asked while the paragraphs are.
        let checked = deviation
            .as_ref()
            .map(|deviation| check::check(deviation, parents.link, &effect));
        let checking = Instant::now();
        let check_request = checked
            .zip(judge_request.as_ref())
            .and_then(|(checked, judged)| {
                check::request(judged, checked.branch, &effect, graph.prompt.as_deref())
            });
        let budget = timeout();
        let check_task = check_request.filter(|_| !budget.is_zero()).map(|sent| {
            let jev = self.jev.clone();
            let asked = sent.clone();
            (
                sent,
                tokio::spawn(async move { jev.ask(&asked, budget).await }),
            )
        });

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
        let check_response = match check_task {
            Some((sent, task)) => match task.await {
                Ok(Ok(response)) => {
                    exchanges.push(serde_json::json!({
                        "stage": "check", "request": sent, "response": &response,
                    }));
                    Some(response)
                }
                _ => None,
            },
            None => None,
        };
        let check_ms = elapsed_ms(checking);
        let unwanted =
            checked.and_then(|checked| check::unwanted(checked.branch, check_response.as_ref()));
        let verdict = if safeguard {
            Some(Verdict::Deny)
        } else {
            checked.and_then(|checked| checked.verdict(unwanted))
        };
        let outcome = trace::outcome(parents, judgements, deviation);

        let mut trace_json = trace::record(&plan, &outcome);
        trace_json["intent_source"] = intents.source.into();
        trace_json["jev_ms"] = serde_json::json!({
            "judge": judge_ms, "paragraph": paragraph_ms, "check": check_ms,
        });
        trace_json["check"] = serde_json::json!({
            "branch": checked.map(|checked| checked.branch.as_str())
                .unwrap_or(if safeguard { Branch::Safeguard.as_str() } else { "none" }),
            "breach": checked.map(|checked| checked.breach),
            "doubt": checked.map(|checked| checked.doubt),
            "unwanted": unwanted,
            "verdict": verdict.map(|verdict| format!("{verdict:?}").to_ascii_uppercase()),
        });
        trace_json["jev"] = exchanges.into();
        let (deny_at, review_at) = self.thresholds.for_link(outcome.link);
        trace_json["thresholds"] = serde_json::json!({"deny": deny_at, "review": review_at});
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
            intent_score: outcome.judged_score(),
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
        let mismatch = || {
            format!(
                "WithHuman이 사용자 의도와 다른 행동으로 판단해 차단했습니다. (세션 {}, 호출 {})",
                request.session_id, request.call_seq
            )
        };
        // The check decides when it could; without its answer, the deviation does.
        let (decision, rule, reason) = match (verdict, &outcome.deviation) {
            (Some(Verdict::Deny), _) if safeguard => {
                (Decision::Deny, SAFEGUARD_RULE, SAFEGUARD_REASON.to_owned())
            }
            (Some(Verdict::Deny), _) => (Decision::Deny, "intent::mismatch", mismatch()),
            (Some(Verdict::Review), _) => (
                Decision::Review,
                "intent::review",
                DEVIATION_REVIEW_REASON.to_owned(),
            ),
            (Some(Verdict::Allow), _) => (Decision::Allow, "intent::match", String::new()),
            (None, Some(deviation)) if deviation.score >= deny_at => {
                (Decision::Deny, "intent::mismatch", mismatch())
            }
            (None, Some(deviation)) if deviation.score >= review_at => (
                Decision::Review,
                "intent::review",
                DEVIATION_REVIEW_REASON.to_owned(),
            ),
            (None, Some(_)) => (Decision::Allow, "intent::match", String::new()),
            (None, None) if risky => (
                Decision::Review,
                "intent::unknown",
                REVIEW_REASON.to_owned(),
            ),
            (None, None) => (Decision::Allow, "intent::unknown", String::new()),
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
