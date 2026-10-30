use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use withhuman_contracts::decisions::{
    CausalStart, Decision, DecisionRequest, DecisionResponse, JevActivity,
};

use withhuman_common::tokens;

use crate::{
    DecisionConfig, DecisionRepository, RepositoryError,
    jev::JevClient,
    repository::TraceRecord,
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

/// Traces the Call's cause through Jev and denies it when the traced chain of events departs
/// from the user's stated intent by more than the configured threshold.
///
/// When tracing fails, the Call gets the Collector's failure policy (an error), or REVIEW when
/// a candidate holds hidden content or a sensitive value. Without a stated intent the turn's
/// prompt stands in; with neither, the Call is allowed, or reviewed in that same risky case.
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
            // Committed before sequences were numbered: nothing to trace it through.
            Err(RepositoryError::Unsequenced) => {
                return Ok(DecisionResponse {
                    decision: Decision::Allow,
                    reason: String::new(),
                    rule: "trace::unsequenced".to_owned(),
                    start: CausalStart::Unresolved,
                    written: false,
                    jev: None,
                });
            }
            Err(error) => return Err(ProviderError(error.to_string())),
        };

        // Candidates and the sequences their paths pass through, whose content Jev sees.
        let (candidates, _) = trace::candidate_sequences(&graph, &self.settings);
        let mut shown: BTreeSet<u64> = BTreeSet::new();
        for candidate in candidates {
            let (path, _) = trace::ancestry(&graph, candidate, |_| false, self.settings.max_hops);
            shown.extend(path);
        }
        let shown: Vec<u64> = shown.into_iter().collect();
        let members = self
            .repository
            .sequence_members(&request.session_id, &shown, graph.call.order)
            .await
            .map_err(|error| ProviderError(error.to_string()))?;
        let stated = request
            .intent
            .as_deref()
            .map(str::trim)
            .filter(|intent| !intent.is_empty());
        // Without a stated intent, what the user asked for this turn stands in.
        let prompt = graph
            .request
            .as_deref()
            .map(str::trim)
            .filter(|prompt| !prompt.is_empty())
            .map(|prompt| truncate(&tokens::redact(prompt), 500));
        let (intent, intent_source) = match (stated, prompt.as_deref()) {
            (Some(intent), _) => (Some(intent), "stated"),
            (None, Some(prompt)) => (Some(prompt), "prompt"),
            (None, None) => (None, "none"),
        };
        let plan = trace::plan(&graph, &members, intent, &self.settings);
        let risky = plan.risky(&graph);

        let remaining = |reserve: Duration| {
            request.deadline_ms.map(|deadline| {
                Duration::from_millis(deadline)
                    .saturating_sub(started.elapsed())
                    .saturating_sub(reserve)
            })
        };
        let timeout =
            remaining(PERSIST_RESERVE).map_or(self.jev_timeout, |left| left.min(self.jev_timeout));
        if timeout.is_zero() {
            return self
                .unresolved(request, "no time left to ask Jev", risky)
                .await;
        }
        let asked = Instant::now();
        let answers = match self.jev.ask(&plan.request, timeout).await {
            Ok(answers) => answers,
            Err(error) => return self.unresolved(request, error, risky).await,
        };
        let jev_ms = u64::try_from(asked.elapsed().as_millis()).unwrap_or(u64::MAX);
        let outcome = match trace::interpret(&plan, &answers) {
            Ok(outcome) => outcome,
            Err(error) => return self.unresolved(request, error, risky).await,
        };

        let mut trace_json = trace::record(&plan, &outcome);
        trace_json["intent_source"] = intent_source.into();
        let record = TraceRecord {
            sequence: graph.call.sequence,
            parent: outcome.chosen.key.clone(),
            parent_number: outcome.chosen.sequence,
            parent_probability: outcome
                .influence
                .get(&outcome.chosen.key)
                .copied()
                .unwrap_or_default(),
            candidates: plan
                .candidates
                .iter()
                .map(|candidate| candidate.key.clone())
                .collect(),
            segments: outcome
                .segments
                .iter()
                .map(|segment| (segment.seq, segment.probability, segment.rank))
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

        let start = match outcome.chosen.stop {
            _ if outcome.chosen.sequence.is_none() => CausalStart::Self_,
            Stop::ReachedRoot => CausalStart::User,
            Stop::None => CausalStart::Self_,
            Stop::Undecided | Stop::LoopGuard => CausalStart::Unresolved,
        };
        let jev = Some(JevActivity {
            asked: true,
            ms: Some(jev_ms),
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

fn truncate(text: &str, chars: usize) -> String {
    match text.char_indices().nth(chars) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    }
}
