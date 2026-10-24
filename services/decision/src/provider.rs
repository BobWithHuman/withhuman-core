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

use crate::{
    DecisionConfig, DecisionRepository,
    jev::JevClient,
    repository::TraceRecord,
    trace::{self, Stop, TraceSettings},
};

/// Kept from the decision deadline for storing the trace and the verdict after Jev answers.
const PERSIST_RESERVE: Duration = Duration::from_millis(300);

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

    async fn unresolved(
        &self,
        request: &DecisionRequest,
        error: impl fmt::Display,
    ) -> ProviderError {
        let error = error.to_string();
        let _ = self.repository.mark_unresolved(request, &error).await;
        ProviderError(error)
    }
}

#[async_trait]
impl DecisionProvider for JevDecisionProvider {
    async fn decide(&self, request: &DecisionRequest) -> Result<DecisionResponse, ProviderError> {
        let started = Instant::now();
        let graph = self
            .repository
            .trace_graph(request)
            .await
            .map_err(|error| ProviderError(error.to_string()))?;

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
        let intent = request
            .intent
            .as_deref()
            .map(str::trim)
            .filter(|intent| !intent.is_empty());
        let plan = trace::plan(&graph, &members, intent, &self.settings);

        let timeout = match request.deadline_ms {
            Some(deadline) => Duration::from_millis(deadline)
                .saturating_sub(started.elapsed())
                .saturating_sub(PERSIST_RESERVE)
                .min(self.jev_timeout),
            None => self.jev_timeout,
        };
        if timeout.is_zero() {
            return Err(self.unresolved(request, "no time left to ask Jev").await);
        }
        let asked = Instant::now();
        let answers = match self.jev.ask(&plan.request, timeout).await {
            Ok(answers) => answers,
            Err(error) => return Err(self.unresolved(request, error).await),
        };
        let jev_ms = u64::try_from(asked.elapsed().as_millis()).unwrap_or(u64::MAX);
        let outcome = match trace::interpret(&plan, &answers) {
            Ok(outcome) => outcome,
            Err(error) => return Err(self.unresolved(request, error).await),
        };

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
            intent_score: outcome.intent_score,
            trace: trace::record(&plan, &outcome),
        };
        let _ = self.repository.persist_trace(request, &record).await;

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
            error: None,
        });
        let (decision, rule, reason) = match (intent, outcome.intent_score) {
            (Some(intent), Some(score)) if 1.0 - score > self.threshold => (
                Decision::Deny,
                "intent::mismatch",
                truncate(
                    &format!(
                        "사용자 의도와 다른 행동으로 판단해 차단했습니다 (일치 확률 {score:.2}, \
                         임계값 {:.2}). 의도: {intent} / 원인 경로: {}",
                        self.threshold, outcome.chosen.sentence
                    ),
                    800,
                ),
            ),
            (Some(_), Some(_)) => (Decision::Allow, "intent::match", String::new()),
            _ => (Decision::Allow, "intent::unknown", String::new()),
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

fn truncate(text: &str, chars: usize) -> String {
    match text.char_indices().nth(chars) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    }
}
