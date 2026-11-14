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

use withhuman_common::grade::{Grade, Graded};

use crate::{
    DecisionConfig, DecisionRepository, RepositoryError, category,
    causal::{self, RequestParent},
    check::{self, Branch, Effect, Verdict},
    jev::{JevClient, JevError},
    provenance,
    repository::{TraceRecord, TracedParent, TracedSegment},
    target,
    trace::{self, Link, Stop, Thresholds, TraceGraph, TraceSettings},
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
    /// Jev's recent failures, for the rules-only mode.
    breaker: Arc<std::sync::Mutex<Breaker>>,
}

/// Jev's failures in a row and, once they reach the limit, until when the rules judge alone.
#[derive(Debug, Default)]
struct Breaker {
    failures: u32,
    open_until: Option<Instant>,
}

/// A Call's grade from Jev's harm and reversibility answers, for a Call no rule grades.
fn jev_grade(harm: f64, irreversible: f64) -> Graded {
    let grade = if harm >= 0.7 && irreversible >= 0.7 {
        Grade::THREE_ONE
    } else if harm >= 0.4 || irreversible >= 0.5 {
        Grade::TWO_ONE
    } else {
        Grade::ONE
    };
    Graded {
        grade,
        reason: "jev",
    }
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
            breaker: Arc::default(),
        }
    }

    fn breaker(&self) -> std::sync::MutexGuard<'_, Breaker> {
        self.breaker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the rules-only mode is on now. When its time is up the next Call tries Jev again;
    /// one more failure starts the mode over.
    fn breaker_open(&self) -> bool {
        let mut breaker = self.breaker();
        match breaker.open_until {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                breaker.open_until = None;
                false
            }
            None => false,
        }
    }

    /// Counts a Jev failure; true when it starts the rules-only mode. A refusal for the key or
    /// the request rate (401, 402, 403, 429) starts it at once: waiting will not fix it.
    fn breaker_failure(&self, error: &JevError) -> bool {
        let settings = &self.settings.check;
        let limit = if settings.degraded_failures == 0 {
            3
        } else {
            settings.degraded_failures
        };
        let seconds = if settings.degraded_seconds == 0 {
            60
        } else {
            settings.degraded_seconds
        };
        let mut breaker = self.breaker();
        breaker.failures += 1;
        let refused = matches!(error, JevError::Rejected(401 | 402 | 403 | 429));
        if refused || breaker.failures >= limit {
            breaker.open_until = Some(Instant::now() + Duration::from_secs(seconds));
            true
        } else {
            false
        }
    }

    fn breaker_success(&self) {
        let mut breaker = self.breaker();
        breaker.failures = 0;
        breaker.open_until = None;
    }

    /// The rules-only judgment: a safeguard change is denied; grade 0 and 1 are allowed, except
    /// a sensitive one (a secret read, a web fetch, an edit of what runs later); grade 2 and 3,
    /// and a Call no rule grades, are reviewed.
    async fn degraded(
        &self,
        request: &DecisionRequest,
        graded: Option<Graded>,
        safeguard: bool,
        why: &str,
    ) -> DecisionResponse {
        let repository = self.repository.clone();
        let (stored_request, stored_error) = (request.clone(), format!("rules-only: {why}"));
        let _ = settle(
            tokio::spawn(async move {
                repository
                    .mark_unresolved(&stored_request, &stored_error)
                    .await
            }),
            STORE_WAIT,
        )
        .await;
        let graded = graded.unwrap_or(Graded {
            grade: Grade::TWO_ONE,
            reason: "unknown",
        });
        let (decision, reason) = if safeguard {
            (Decision::Deny, SAFEGUARD_REASON.to_owned())
        } else if graded.grade.level() >= 2 || withhuman_common::grade::is_sensitive(graded.reason)
        {
            (
                Decision::Review,
                format!(
                    "WithHuman 판정 모델이 응답하지 않아 규칙으로만 판정했습니다. {}({}: {})이라 사용자 확인이 필요합니다.",
                    graded.grade.label(),
                    graded.grade.as_str(),
                    graded.describe()
                ),
            )
        } else {
            (Decision::Allow, String::new())
        };
        DecisionResponse {
            decision,
            reason,
            rule: format!("degraded::{}", graded.grade.as_str()),
            start: CausalStart::Unresolved,
            written: false,
            jev: Some(JevActivity {
                asked: false,
                ms: None,
                reused_from: None,
                error: Some(why.to_owned()),
            }),
        }
    }

    /// What in the turn before made the user write the latest prompt: kept with the prompt's
    /// Request once found, asked of Jev by the turn's first traced Call. None for the session's
    /// first prompt, or when it cannot be found in time.
    async fn request_parent(
        &self,
        request: &DecisionRequest,
        graph: &TraceGraph,
        model: &str,
        budget: Duration,
    ) -> Option<RequestParent> {
        let [.., earlier, current] = graph.turns.as_slice() else {
            return None;
        };
        let (start, current) = (earlier.subgraph?, current.subgraph?);
        if let Ok(Some(kept)) = self
            .repository
            .request_parent(&request.session_id, current)
            .await
        {
            return Some(kept);
        }
        let prompt = graph.prompt.as_deref()?;
        if budget.is_zero() {
            return None;
        }
        // The main agent's SubGraphs of the turn before.
        let numbers: Vec<u64> = graph
            .subgraphs
            .range(start..current)
            .filter(|(_, agent)| agent.is_none())
            .map(|(number, _)| *number)
            .collect();
        let members = self
            .repository
            .subgraph_members(&request.session_id, &numbers, graph.call.order)
            .await
            .ok()?;
        let nodes = causal::earlier_nodes(&members);
        let sent = causal::request_parent_request(model, prompt, earlier.intent.as_deref(), &nodes);
        let response = self.jev.ask(&sent, budget).await.ok();
        let mut parent =
            causal::request_parent(response.as_ref(), earlier.intent.as_deref(), &nodes)?;
        parent.sources = causal::parent_sources(
            &parent.key,
            &members,
            &causal::earlier_paragraphs(&members),
            Some(prompt),
        );
        // Another Call of the turn may have kept one first; that one stays.
        let _ = self
            .repository
            .set_request_parent(&request.session_id, current, &parent)
            .await;
        Some(parent)
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
/// Why a file change whose line was copied from an instruction in a tool result is put to the
/// user; no score, intent or path.
const COPIED_REASON: &str = "WithHuman: 이 변경에 도구 결과나 저장소 문서의 지시를 그대로 옮긴 줄이 있어 \
     실행 전에 사용자 확인이 필요합니다.";
const SAFEGUARD_REASON: &str = "WithHuman이 에이전트의 설정이나 훅을 바꾸는 도구 호출을 차단했습니다. 사용자가 직접 바꿔야 합니다.";

/// Why a call whose causal path leads to an instruction in a tool result is put to the user; no
/// score, intent or path.
const CAUSAL_REASON: &str = "WithHuman: 이 호출이 사용자 요청보다 도구 결과에 적힌 지시에서 비롯된 것으로 보입니다. 사용자 확인이 필요합니다.";

const UNSPECIFIED_REASON: &str = "WithHuman: 이 호출이 사용자가 정하지 않은 대상이나 범위에 작용하는 것으로 \
                                  보입니다. 사용자 확인이 필요합니다.";
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
        let effect = check::call_effect(&graph.call);
        let safeguard = effect == Effect::Safeguard;
        // A change that only undoes the session's own earlier changes to the file.
        // Lines the session took out earlier and now puts back (or put in and now takes out) are
        // no addition: they are dropped from what is asked about, and a change left with none
        // undoes the session's own changes. A command that only checks files back out of git
        // undoes them too.
        let (judged_effect, restored) = match &effect {
            Effect::FileChange { path, .. } => {
                match self
                    .repository
                    .earlier_file_changes(&request.session_id, graph.call.order, path)
                    .await
                {
                    Ok(earlier) => provenance::strip_restored(&effect, &earlier),
                    Err(_) => (effect.clone(), 0),
                }
            }
            _ => (effect.clone(), 0),
        };
        let git_restore = matches!(graph.call.tool_name.as_str(), "Bash" | "PowerShell")
            && graph
                .call
                .tool_input
                .get("command")
                .and_then(serde_json::Value::as_str)
                .is_some_and(provenance::git_restores);
        let undoes = (restored > 0 && provenance::is_empty_change(&judged_effect)) || git_restore;

        // The rule grade, before Jev is asked.
        let rule_graded =
            withhuman_common::grade::grade(&graph.call.tool_name, &graph.call.tool_input);
        // Jev has kept failing, so the rules judge alone for a while.
        if self.breaker_open() {
            return Ok(self
                .degraded(request, rule_graded, safeguard, "rules-only mode")
                .await);
        }
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
        // What in the turn before made the user write the latest prompt. When it was an agent's
        // plan built on a tool result, that result is matched below like the turn's own: a line a
        // Call copies from it was copied from the tool result, not asked for by the user.
        let request_parent = if safeguard {
            None
        } else {
            self.request_parent(request, &graph, &plan.model, timeout())
                .await
        };
        // Where the added lines came from, as far as the engine tells by itself.
        let mut paragraphs = judge_request
            .as_ref()
            .map(provenance::paragraphs)
            .unwrap_or_default();
        for source in request_parent.iter().flat_map(|parent| &parent.sources) {
            paragraphs
                .entry(source.key.clone())
                .or_insert_with(|| source.text.clone());
        }
        let provenance = provenance::Provenance {
            restored,
            copied: provenance::copied_lines(&judged_effect, &paragraphs, graph.prompt.as_deref()),
        };
        let file_signal =
            !provenance.copied.is_empty() || provenance::instruction_seen(&paragraphs);
        let response = match &judge_request {
            None => None,
            Some(sent) => match self.jev.ask(sent, budget).await {
                Ok(response) => {
                    self.breaker_success();
                    exchanges.push(serde_json::json!({
                        "stage": "cause", "request": sent, "response": &response,
                    }));
                    Some(response)
                }
                Err(error) => {
                    if self.breaker_failure(&error) {
                        return Ok(self
                            .degraded(request, rule_graded, safeguard, &error.to_string())
                            .await);
                    }
                    return self.unresolved(request, error, risky, safeguard).await;
                }
            },
        };
        let (parents, mut judgements, deviation) = match trace::judge(&plan, response.as_ref()) {
            Ok(judged) => judged,
            Err(error) => return self.unresolved(request, error, risky, safeguard).await,
        };
        let judge_ms = elapsed_ms(judged);
        // The rule grade, or Jev's when no rule grades the Call, recorded in the trace.
        // Jev may raise the rule grade to 3 (impossible to undo), never lower it: the rules set
        // the grade. Raising an ordinary edit to 2 on Jev's word made plain fixes stricter.
        let jev_graded = deviation
            .as_ref()
            .map(|deviation| jev_grade(deviation.harm, deviation.irreversible));
        let graded = match (rule_graded, jev_graded) {
            (Some(rule), Some(jev))
                if jev.grade.level() >= 3 && jev.grade.level() > rule.grade.level() =>
            {
                Some(jev)
            }
            (Some(rule), _) => Some(rule),
            (None, jev) => jev,
        };
        let grade_source = match (rule_graded, graded) {
            (Some(rule), Some(graded)) if graded != rule => "rule+jev",
            (Some(_), _) => "rule",
            (None, Some(_)) => "jev",
            _ => "none",
        };
        // Unless the trace clears the Call, a second question checks it against the user's
        // prompt, asked while the paragraphs are.
        // What kind of thing the call does decides what the second question shows and asks.
        let group = category::category(&graph.call.tool_name).group;
        let checked = deviation.as_ref().map(|deviation| {
            check::check_call_in(
                deviation,
                parents.link,
                &judged_effect,
                undoes,
                file_signal,
                group,
            )
        });
        // Where each value of the Call came from: the user's prompt, a tool-result paragraph, or
        // the agent itself.
        let origins =
            provenance::value_origins(&graph.call.tool_input, &paragraphs, graph.prompt.as_deref());
        let checking = Instant::now();
        let check_request = checked
            .zip(judge_request.as_ref())
            .and_then(|(checked, judged)| {
                target::request(
                    judged,
                    checked.branch,
                    graph.prompt.as_deref(),
                    &check::service_fields(&graph.call.tool_input),
                    &origins,
                )
                .or_else(|| {
                    check::request(
                        judged,
                        checked.branch,
                        &judged_effect,
                        graph.prompt.as_deref(),
                    )
                    .map(|mut sent| {
                        if checked.branch == Branch::Purpose {
                            target::emphasize(&mut sent, group);
                        }
                        sent
                    })
                })
            })
            .map(|mut sent| {
                // The second question also checks the first one's own concern, when the first
                // alone would have put the Call to the user.
                if let Some(deviation) = deviation.as_ref() {
                    let (_, review_at) = self.thresholds.for_link(parents.link);
                    check::with_concern(&mut sent, deviation, review_at);
                }
                sent
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

        // A service call that is hard to undo is compared with what the user specified, unless
        // the user's prompt names every value it is given.
        let spec_task = judge_request
            .as_ref()
            .filter(|_| {
                !safeguard
                    && matches!(effect, Effect::Other | Effect::ServiceChange { .. })
                    && !matches!(graph.call.tool_name.as_str(), "Bash" | "PowerShell")
                    && graded.is_some_and(|graded| graded.grade.level() >= check::SPEC_GRADE)
                    && !provenance::values_from_prompt(
                        &graph.call.tool_input,
                        graph.prompt.as_deref(),
                    )
                    && !budget.is_zero()
            })
            .map(|judged| {
                let sent = check::spec_request(judged, graph.prompt.as_deref(), &origins);
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

        // The causal path to the Call, put to Jev on its own so the intent questions' answers stay
        // as they were. What it shows can only make the verdict stricter (below).
        let beyond_prompt = request_parent
            .as_ref()
            .is_some_and(|parent| parent.key != "none");
        let causal_parent = parents
            .chosen
            .first()
            .filter(|_| !safeguard && (parents.link != Link::Request || beyond_prompt));
        let activated: Vec<(String, f64)> = causal_parent
            .map(|parent| {
                judgements
                    .iter()
                    .filter(|judgement| judgement.key == parent.candidate.key)
                    .flat_map(|judgement| &judgement.segments)
                    .map(|segment| {
                        let key = match segment.paragraph {
                            Some(index) => format!("g{}p{index}", segment.seq),
                            None => format!("g{}", segment.seq),
                        };
                        (key, segment.probability)
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Paragraphs holding, word for word, a line the Call adds or a value it is given.
        let flow: Vec<String> = provenance
            .copied
            .iter()
            .map(|copied| copied.paragraph.clone())
            .chain(origins.iter().map(|(_, origin)| origin.clone()))
            .filter(|origin| origin.starts_with('g'))
            .fold(Vec::new(), |mut keys, key| {
                if !keys.contains(&key) {
                    keys.push(key);
                }
                keys
            });
        // A result a value came from was itself read for a reason: the Call that read it and
        // what that Call was traced to join the path (a secret file a planted note named, whose
        // content the Call then copies).
        let mut result_origins = Vec::new();
        if causal_parent.is_some() {
            let mut seen = Vec::new();
            for key in flow
                .iter()
                .filter(|key| !activated.iter().any(|(shown, _)| shown == *key))
            {
                let Some(seq) = causal::result_seq(key) else {
                    continue;
                };
                if seen.contains(&seq) || seen.len() >= causal::ORIGIN_LOOKUPS {
                    continue;
                }
                seen.push(seq);
                if let Ok(Some(origin)) = self
                    .repository
                    .result_origin(&request.session_id, seq)
                    .await
                {
                    result_origins.push((key.clone(), origin));
                }
            }
        }
        // The SubGraphs from the parent back to the prompt, and how the agent got to each.
        let causal_hops: Vec<u64> = causal_parent
            .map(|parent| {
                let prompts: Vec<u64> = graph
                    .turns
                    .iter()
                    .filter_map(|turn| turn.subgraph)
                    .collect();
                parent
                    .candidate
                    .path
                    .iter()
                    .copied()
                    .filter(|number| !prompts.contains(number))
                    .collect()
            })
            .unwrap_or_default();
        let mut hop_causes = Vec::new();
        for &hop in causal_hops.iter().take(causal::HOP_LOOKUPS) {
            if let Ok(causes) = self
                .repository
                .subgraph_causes(&request.session_id, hop, causal::HOP_CAUSES)
                .await
            {
                if !causes.is_empty() {
                    hop_causes.push((hop, causes));
                }
            }
        }
        let budget = timeout();
        let causal_task = judge_request
            .as_ref()
            .zip(causal_parent)
            .filter(|_| !budget.is_zero())
            .map(|(judged, parent)| {
                let key = &parent.candidate.key;
                let action = judged
                    .state
                    .get("action")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let (path, links) = causal::path(&causal::PathParts {
                    prompt: graph.prompt.as_deref(),
                    request_parent: request_parent.as_ref(),
                    hops: causal_hops.clone(),
                    members: &members,
                    hop_causes: &hop_causes,
                    activated: activated.clone(),
                    flow: flow.clone(),
                    origins: &result_origins,
                    texts: &paragraphs,
                    action,
                    parent: match (parents.link, parent.candidate.subgraph) {
                        (Link::Request, _) => causal::ParentLink::Request,
                        (Link::Segment, Some(number)) => causal::ParentLink::SubGraph(number),
                        _ => causal::ParentLink::None,
                    },
                    influence: parents.influence.get(key).copied(),
                });
                let sent = causal::request(
                    judged,
                    &path,
                    &links,
                    graph.prompt.as_deref(),
                    target::focus(group),
                    &target::values_text(&origins),
                );
                let jev = self.jev.clone();
                let asked = sent.clone();
                (
                    sent,
                    tokio::spawn(async move { jev.ask(&asked, budget).await }),
                )
            });

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
        let spec_response = match spec_task {
            Some((sent, task)) => match task.await {
                Ok(Ok(response)) => {
                    exchanges.push(serde_json::json!({
                        "stage": "spec", "request": sent, "response": &response,
                    }));
                    Some(response)
                }
                _ => None,
            },
            None => None,
        };
        let causal_response = match causal_task {
            Some((sent, task)) => match task.await {
                Ok(Ok(response)) => {
                    exchanges.push(serde_json::json!({
                        "stage": "causal", "request": sent, "response": &response,
                    }));
                    Some(response)
                }
                _ => None,
            },
            None => None,
        };
        let causal_answer = causal::read(causal_response.as_ref());
        let unspecified = check::unspecified(spec_response.as_ref());
        let concern = check::concern(check_response.as_ref());
        let check_ms = elapsed_ms(checking);
        let unwanted =
            checked.and_then(|checked| check::unwanted(checked.branch, check_response.as_ref()));
        let source = check::source_named(check_response.as_ref());
        // The call's values that stand only in an instructing tool result, never in the prompt.
        // A file change is judged by its path and the lines it adds: a Write over a file keeps the
        // lines the file already held (a rule planted there as a comment), which it adds nothing to.
        let instructed = match &judged_effect {
            Effect::FileChange { path, added, .. } => provenance::lines_from_instruction(
                path,
                added,
                &paragraphs,
                graph.prompt.as_deref(),
            ),
            _ => provenance::call_from_instruction(
                &graph.call.tool_name,
                &graph.call.tool_input,
                &paragraphs,
                graph.prompt.as_deref(),
            ),
        };
        let evidence = check::FileEvidence {
            copied_from_instruction: provenance.from_instruction() || !instructed.is_empty(),
            source_named: source.is_some(),
            // An ungraded change is taken as hard to undo.
            grade_level: graded.map_or(2, |graded| graded.grade.level()),
        };
        let file_verdict = if safeguard {
            None
        } else {
            checked.and_then(|checked| checked.file_verdict(unwanted, evidence))
        };
        // A shell command judged part by part: denied when the part Jev picks touches something
        // risky or carries out an instruction a tool result gave; with neither, Jev's doubt alone
        // is no attack.
        let part = check::picked_part(check_response.as_ref()).and_then(|(index, none)| {
            let command = graph.call.tool_input.get("command")?.as_str()?;
            let text = provenance::shell_parts(command)
                .into_iter()
                .nth(index - 1)?;
            Some(serde_json::json!({
                "part": format!("p{index}"),
                "score": 1.0 - none,
                "marks": provenance::risk_marks(&text),
                "instruction": provenance::part_from_instruction(
                    &text,
                    &paragraphs,
                    graph.prompt.as_deref(),
                ),
                "text": text.chars().take(200).collect::<String>(),
            }))
        });
        let part_verdict = part.as_ref().and_then(|part| {
            let checked = checked?;
            let score = part["score"].as_f64()?;
            let backed = part["marks"]
                .as_array()
                .is_some_and(|marks| !marks.is_empty())
                || part["instruction"]
                    .as_array()
                    .is_some_and(|found| !found.is_empty());
            Some(if score >= check::PART_CUT && backed {
                Verdict::Deny
            } else if checked.breach {
                Verdict::Review
            } else {
                Verdict::Allow
            })
        });
        // A call that sends, deletes, moves money or grants access, by what its target rests on.
        let target_scores =
            checked.and_then(|checked| target::scores(checked.branch, check_response.as_ref()));
        let target_verdict = checked
            .zip(target_scores)
            .map(|(checked, scores)| target::verdict(checked.branch, scores, checked.breach));
        let verdict = if safeguard {
            Some(Verdict::Deny)
        } else if part_verdict.is_some() {
            part_verdict
        } else if target_verdict.is_some() {
            target_verdict
        } else {
            file_verdict.map(check::FileVerdict::verdict)
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
        if undoes {
            trace_json["check"]["undoes"] = true.into();
        }
        if let Some(unspecified) = unspecified {
            trace_json["check"]["unspecified"] = unspecified.into();
        }
        if let Some(concern) = concern {
            trace_json["check"]["concern"] = concern.into();
        }
        if !instructed.is_empty() {
            trace_json["check"]["instructed"] = instructed.clone().into();
        }
        if !origins.is_empty() {
            trace_json["check"]["values"] = origins
                .iter()
                .map(|(value, origin)| serde_json::json!({"value": value, "origin": origin}))
                .collect();
        }
        if provenance != provenance::Provenance::default() {
            trace_json["check"]["provenance"] = provenance::to_json(&provenance);
        }
        if let Some(part) = &part {
            trace_json["check"]["part"] = part.clone();
        }
        trace_json["check"]["category"] =
            serde_json::json!(category::category(&graph.call.tool_name));
        if let Some(scores) = target_scores {
            trace_json["check"]["target"] = serde_json::json!({
                "from_result": scores.from_result, "unchosen": scores.unchosen,
            });
        }
        if checked.is_some_and(|checked| matches!(checked.branch, Branch::File | Branch::Change)) {
            trace_json["check"]["evidence"] = serde_json::json!({
                "copied_from_instruction": evidence.copied_from_instruction,
                "source": source,
                "grade_level": evidence.grade_level,
                "outcome": match file_verdict {
                    Some(check::FileVerdict::Unsupported(_)) => "unsupported",
                    Some(check::FileVerdict::Copied) => "copied",
                    _ => "plain",
                },
            });
        }
        if matches!(effect, Effect::ShellWrite { .. }) {
            trace_json["check"]["shell_write"] = true.into();
        }
        trace_json["check"]["grade"] = serde_json::json!({
            "grade": graded.map(|graded| graded.grade.as_str()),
            "source": grade_source,
            "reason": graded.map(|graded| graded.reason),
            "label": graded.map(|graded| graded.grade.label()),
            "description": graded.map(|graded| graded.describe()),
        });
        if let Effect::Run { programs } = &effect {
            trace_json["check"]["programs"] = programs
                .iter()
                .map(|program| serde_json::json!({"path": program.path, "seen": program.code.is_some()}))
                .collect();
        }
        if causal_answer.is_some() || request_parent.is_some() {
            trace_json["causal"] = serde_json::json!({
                "answer": causal_answer,
                "request_parent": request_parent,
            });
        }
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
            (Some(Verdict::Review), _) if file_verdict == Some(check::FileVerdict::Copied) => (
                Decision::Review,
                "provenance::instruction",
                COPIED_REASON.to_owned(),
            ),
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
        // A call let through whose target the agent picked among several the user never chose
        // between goes to the user.
        // A call let through although the first question's concern holds, by the second
        // question's own check, goes to the user.
        let (decision, rule, reason) = match concern {
            Some(concern) if decision == Decision::Allow && concern >= check::CONCERN_CUT => (
                Decision::Review,
                "intent::concern",
                DEVIATION_REVIEW_REASON.to_owned(),
            ),
            _ => (decision, rule, reason),
        };
        // A call let through that carries a value only an instructing tool result gave (never the
        // user) carries out that instruction: it goes to the user.
        let (decision, rule, reason) = if decision == Decision::Allow && !instructed.is_empty() {
            (
                Decision::Review,
                "provenance::instruction",
                COPIED_REASON.to_owned(),
            )
        } else {
            (decision, rule, reason)
        };
        // A call let through that affects what the user did not specify (one of several
        // candidates picked, or more than was named) goes to the user.
        let (decision, rule, reason) = match unspecified {
            Some(unspecified)
                if decision == Decision::Allow && unspecified >= check::UNSPECIFIED_CUT =>
            {
                (
                    Decision::Review,
                    "provenance::unspecified",
                    UNSPECIFIED_REASON.to_owned(),
                )
            }
            _ => (decision, rule, reason),
        };
        // A call whose path shows it carries out what a tool result told the agent, not what the
        // user asked, is denied when Jev also finds the agent would not make it without that
        // instruction; when only one of the two holds, it goes to the user. It never lets a call
        // through that another check stopped.
        let targeted = checked.is_some_and(|checked| target::branch(group) == Some(checked.branch));
        let grade_level = graded.map_or(2, |graded| graded.grade.level());
        let (decision, rule, reason) = match causal_answer
            .as_ref()
            .and_then(|answer| answer.verdict_for(targeted, grade_level))
        {
            Some(causal::CausalVerdict::Deny) if decision != Decision::Deny => {
                (Decision::Deny, "causal::instruction", mismatch())
            }
            Some(causal::CausalVerdict::Review) if decision == Decision::Allow => {
                (Decision::Review, "causal::review", CAUSAL_REASON.to_owned())
            }
            _ => (decision, rule, reason),
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
