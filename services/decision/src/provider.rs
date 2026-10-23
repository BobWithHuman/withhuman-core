use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use withhuman_contracts::decisions::{
    CausalCandidate, CausalChoice, CausalContext, CausalResolution, CausalStart, Decision,
    DecisionRequest, DecisionResponse, JevActivity,
};

use crate::DecisionConfig;

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
            causal: None,
        })
    }
}

#[derive(Clone)]
pub struct JevDecisionProvider {
    endpoint: String,
    api_key: Option<String>,
    model: String,
    timeout: Duration,
    accept: f64,
    per_call: bool,
    client: reqwest::Client,
    record_path: Arc<std::path::PathBuf>,
    record_lock: Arc<Mutex<()>>,
}

const PARENT_INSTRUCTIONS: &str = "`current` continues which earlier plan? Pick the closest earlier step the agent is carrying on. If both an earlier agent step (s…) and a user request (r…) fit, pick the agent step.";
const PARENT_NONE: &str = "It does not carry on any listed plan.";
const FROM_TEXT_INSTRUCTIONS: &str = "Which listed text told the agent to take `action`? Pick none if the action only follows the agent's own plan or the user's request.";
const FROM_TEXT_NONE: &str = "No listed text told the agent to do this.";

/// What one Call still has to ask Jev.
struct Questions {
    parent: bool,
    from_text: bool,
    value: Option<CausalChoice>,
}

impl JevDecisionProvider {
    pub fn new(config: &DecisionConfig) -> Self {
        if config.jev_api_key.is_some() {
            eprintln!("JEV_API_KEY=set");
        } else {
            eprintln!("warning: JEV_API_KEY=unset; causal questions will be unresolved");
        }
        Self {
            endpoint: format!("{}/v1/systemone", config.jev_url.trim_end_matches('/')),
            api_key: config.jev_api_key.clone(),
            model: config.jev_model.clone(),
            timeout: config.jev_timeout,
            accept: config.parent_accept,
            per_call: config.parent_per_call,
            client: reqwest::Client::new(),
            record_path: Arc::new(config.data_dir.join("jev-parent.jsonl")),
            record_lock: Arc::new(Mutex::new(())),
        }
    }

    fn questions(&self, context: &CausalContext) -> Questions {
        let value = context.value_match.as_ref().map(|matched| CausalChoice {
            choice: Some(format!("t{}", matched.piece_seq)),
            probability: Some(1.0),
            accepted: Some(true),
            candidates: Vec::new(),
            state: "decided".into(),
            fact: true,
            basis: Some("value".into()),
            value: Some(matched.value.clone()),
        });
        // A risk 0 Call asks nothing; a later risky Call of the same sequence asks instead.
        // TODO(parent-design): nothing computes `risk` yet, so an unset risk counts as risky.
        let risky = context.risk.is_none_or(|risk| risk > 0.0);
        let parent_open = matches!(context.parent_state.as_str(), "pending" | "unresolved");
        Questions {
            parent: risky && (parent_open || self.per_call),
            from_text: risky && value.is_none(),
            value,
        }
    }

    fn unresolved(
        &self,
        request: &DecisionRequest,
        questions: Questions,
        asked: bool,
        ms: Option<u64>,
        error: &str,
    ) -> DecisionResponse {
        let causal = request
            .causal_context
            .as_ref()
            .map(|context| CausalResolution {
                sequence: context.sequence,
                seq_window: context.seq_window,
                prompt_window: context.prompt_window,
                parent: questions
                    .parent
                    .then(|| unresolved_choice(parent_candidates(context))),
                from_text: questions.value.or_else(|| {
                    questions
                        .from_text
                        .then(|| unresolved_choice(text_candidates(context)))
                }),
            });
        causal_response(
            causal,
            JevActivity {
                asked,
                ms,
                reused_from: None,
                error: Some(error.into()),
            },
        )
    }

    fn record(&self, request: &DecisionRequest, value: Value) {
        let Some(context) = &request.causal_context else {
            return;
        };
        let _guard = self
            .record_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(parent) = self.record_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&*self.record_path)
        {
            let line = json!({
                "session_id": request.session_id,
                "sequence": context.sequence,
                "call_id": context.tool_use_id,
                "call_seq": context.call_seq,
                "seq_window": context.seq_window,
                "prompt_window": context.prompt_window,
                "parent_candidates": parent_candidates(context),
                "text_candidates": text_candidates(context),
                "result": value,
            });
            let _ = writeln!(file, "{line}");
        }
    }
}

fn parent_candidates(context: &CausalContext) -> Vec<String> {
    context
        .plans
        .iter()
        .map(|candidate| candidate.key.clone())
        .chain(["none".into()])
        .collect()
}

fn text_candidates(context: &CausalContext) -> Vec<String> {
    context
        .texts
        .iter()
        .map(|candidate| candidate.key.clone())
        .chain(["none".into()])
        .collect()
}

fn unresolved_choice(candidates: Vec<String>) -> CausalChoice {
    CausalChoice {
        choice: None,
        probability: None,
        accepted: None,
        candidates,
        state: "unresolved".into(),
        fact: false,
        basis: None,
        value: None,
    }
}

fn causal_response(causal: Option<CausalResolution>, jev: JevActivity) -> DecisionResponse {
    DecisionResponse {
        decision: Decision::Allow,
        reason: String::new(),
        rule: "jev::causal_only".into(),
        start: CausalStart::Unresolved,
        written: false,
        jev: Some(jev),
        causal,
    }
}

fn question(candidates: &[CausalCandidate], instructions: &str, none: &str) -> Value {
    let mut criteria = candidates
        .iter()
        .map(|candidate| (candidate.key.clone(), Value::Null))
        .collect::<serde_json::Map<_, _>>();
    criteria.insert("none".into(), Value::String(none.into()));
    json!({"type":"choice","instructions":instructions,"criteria":criteria})
}

fn bodies(candidates: &[CausalCandidate]) -> serde_json::Map<String, Value> {
    candidates
        .iter()
        .map(|candidate| (candidate.key.clone(), Value::String(candidate.body.clone())))
        .collect()
}

#[derive(Debug, Deserialize)]
struct JevResponse {
    answers: BTreeMap<String, JevAnswer>,
}

#[derive(Debug, Deserialize)]
struct JevAnswer {
    choice: String,
    probabilities: BTreeMap<String, f64>,
}

#[async_trait]
impl DecisionProvider for JevDecisionProvider {
    async fn decide(&self, request: &DecisionRequest) -> Result<DecisionResponse, ProviderError> {
        let Some(context) = &request.causal_context else {
            return Ok(causal_response(
                None,
                JevActivity {
                    asked: false,
                    ms: None,
                    reused_from: None,
                    error: Some("causal_context_missing".into()),
                },
            ));
        };

        let questions = self.questions(context);
        if !questions.parent && !questions.from_text {
            let causal = CausalResolution {
                sequence: context.sequence,
                seq_window: context.seq_window,
                prompt_window: context.prompt_window,
                parent: None,
                from_text: questions.value,
            };
            return Ok(causal_response(
                Some(causal),
                JevActivity {
                    asked: false,
                    ms: None,
                    reused_from: None,
                    error: None,
                },
            ));
        }
        let Some(api_key) = &self.api_key else {
            return Ok(self.unresolved(request, questions, false, None, "api_key_unset"));
        };

        // The first Call of a sequence asks parent and from_text in one request.
        let mut asked = serde_json::Map::new();
        if questions.parent {
            asked.insert(
                "parent".into(),
                question(&context.plans, PARENT_INSTRUCTIONS, PARENT_NONE),
            );
        }
        if questions.from_text {
            asked.insert(
                "from_text".into(),
                question(&context.texts, FROM_TEXT_INSTRUCTIONS, FROM_TEXT_NONE),
            );
        }
        let payload = json!({
            "model":self.model,
            "state":{
                "current":context.current,
                "action":context.action,
                "plans":bodies(&context.plans),
                "texts":bodies(&context.texts),
            },
            "questions":asked,
        });
        let started = Instant::now();
        let timeout = request
            .deadline_ms
            .map(Duration::from_millis)
            .map_or(self.timeout, |remaining| remaining.min(self.timeout));
        let result = tokio::time::timeout(timeout, async {
            let response = self
                .client
                .post(&self.endpoint)
                .bearer_auth(api_key)
                .json(&payload)
                .send()
                .await
                .map_err(|_| "jev_unavailable".to_owned())?;
            if !response.status().is_success() {
                return Err(format!("jev_http_{}", response.status().as_u16()));
            }
            response
                .json::<JevResponse>()
                .await
                .map_err(|_| "jev_invalid_response".to_owned())
        })
        .await
        .unwrap_or_else(|_| Err("jev_timeout".into()));
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let answers = match result {
            Ok(answers) => answers,
            Err(error) => {
                self.record(request, json!({"error":error,"ms":elapsed}));
                return Ok(self.unresolved(request, questions, true, Some(elapsed), &error));
            }
        };

        let choice = |name: &str, candidates: Vec<String>| -> CausalChoice {
            let Some(answer) = answers
                .answers
                .get(name)
                .filter(|answer| candidates.contains(&answer.choice))
            else {
                return unresolved_choice(candidates);
            };
            let probability = answer.probabilities.get(&answer.choice).copied();
            let state = if answer.choice == "none" {
                "none"
            } else {
                "decided"
            };
            CausalChoice {
                choice: Some(answer.choice.clone()),
                probability,
                accepted: probability.map(|probability| probability >= self.accept),
                candidates,
                state: state.into(),
                fact: false,
                basis: None,
                value: None,
            }
        };
        let parent = questions
            .parent
            .then(|| choice("parent", parent_candidates(context)));
        let from_text = questions.value.or_else(|| {
            questions
                .from_text
                .then(|| choice("from_text", text_candidates(context)))
        });
        self.record(
            request,
            json!({
                "parent":parent.as_ref().map(|choice| json!({"choice":choice.choice,"probability":choice.probability})),
                "from_text":from_text.as_ref().map(|choice| json!({"choice":choice.choice,"probability":choice.probability,"fact":choice.fact})),
                "ms":elapsed,
            }),
        );
        let causal = CausalResolution {
            sequence: context.sequence,
            seq_window: context.seq_window,
            prompt_window: context.prompt_window,
            parent,
            from_text,
        };
        Ok(causal_response(
            Some(causal),
            JevActivity {
                asked: true,
                ms: Some(elapsed),
                reused_from: None,
                error: None,
            },
        ))
    }
}
