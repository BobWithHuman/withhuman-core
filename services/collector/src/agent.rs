//! The seam every coding agent but Claude Code is added at.
//!
//! Claude Code's Hook contract ([`withhuman_contracts::hooks`]) is the engine's own form: its
//! Hooks reach `/v1/hooks/<Event>` unchanged and need no adapter. Every other agent arrives on
//! `/v1/hooks/<kind>/<event>`, where its [`Agent`] turns one Hook into the Claude Code request
//! doing the same thing, so the normalization, graph and judgment behind it are the same code
//! for every agent. The engine's rules are written against Claude Code's tools, so a tool is
//! translated to the Claude Code tool doing the same thing rather than to a name of its own.
//!
//! Everything a new agent shares with the others lives here: the route, the delivery receipts,
//! the event tagging, the intent path, the failure policy and the Hook output. What stays the
//! agent's own is the translation of its Hooks and the few answers its client reads
//! differently ([`Agent`]'s other methods).
//!
//! # Adding an agent
//!
//! 1. Write its Hook input in `withhuman_contracts` (as [`withhuman_contracts::codex`] does),
//!    with a fixture per event under `crates/contracts/tests/fixtures/<kind>/`.
//! 2. Add a module beside `codex.rs` that translates each Hook into [`Translated`], and
//!    implement [`Agent`] on a unit struct of its own.
//! 3. Name it in [`REGISTRY`]. Nothing else in the Collector changes.
//! 4. Give it a client bridge (`deploy/client/<kind>/`, on `withhuman_bridge.py`) and an entry
//!    in `deploy/client/configure.py`'s `AGENTS`.
//!
//! An event the agent has no Hook for is made by its bridge in Claude Code's own form
//! (Codex has no `MessageDisplay`, so its bridge reads the session transcript): translate it
//! straight into the matching [`Translated`] variant and keep no payload.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use withhuman_contracts::{
    decisions::EnforcementMode,
    hooks::{
        ConfigChangeRequest, HookEventName, MessageDisplayRequest, PostToolBatchRequest,
        PostToolUseFailureRequest, PostToolUseRequest, PreToolUseRequest, SessionEndRequest,
        SessionStartRequest, SubagentLifecycleRequest, UserPromptSubmitRequest,
    },
};

use crate::{
    CollectorService, NormalizedEvent,
    http::{
        HookPolicy, display_message, error, judge_call, normalize_failure, now, record_tool_result,
        send_regular, start_session, submit_prompt,
    },
};

/// The agents the Collector accepts Hooks from, by the `<kind>` of their route. Claude Code is
/// not among them: its Hooks are the form every entry here translates into.
pub static REGISTRY: &[&(dyn Agent + Sync)] = &[&crate::codex::Codex, &crate::cursor::Cursor];

/// The agent of `kind`, or none when no adapter answers for it.
pub fn find(kind: &str) -> Option<&'static (dyn Agent + Sync)> {
    REGISTRY.iter().copied().find(|agent| agent.kind() == kind)
}

/// One coding agent's Hooks, as the Collector reads them.
pub trait Agent: Send + Sync + 'static {
    /// The `<kind>` of `/v1/hooks/<kind>/<event>`, and the `agent_kind` marked on every event
    /// of this agent.
    fn kind(&self) -> &'static str;

    /// How this client's Hook answers a verdict and a failure to reach one.
    fn policy(&self) -> HookPolicy;

    /// One Hook, as the Claude Code request doing the same thing.
    fn translate(
        &self,
        event: &str,
        raw: Value,
        headers: &HeaderMap,
    ) -> Result<Incoming, Rejection>;

    /// Headers that change how a Hook is read, so a delivery receipt is bound to them too.
    fn request_headers(&self) -> &'static [&'static str] {
        &[]
    }

    /// Whether SessionStart answers with the paths the client is to watch. Only a client that
    /// reports changes to them has anything to do with the answer.
    fn watches_paths(&self) -> bool {
        false
    }

    /// Whether the client can show text of the engine's choosing in place of a streamed
    /// message, as Claude Code's MessageDisplay output does. With no such answer the intent
    /// line stays on the user's screen; the engine keeps it either way.
    fn hides_message_text(&self) -> bool {
        false
    }

    /// Whether a failed call's Hook reads output of its own. A client that reads output for
    /// finished calls only gets the turn's intent request on that event instead.
    fn reads_failure_output(&self) -> bool {
        false
    }
}

/// One Hook of an agent, ready for the engine.
pub struct Incoming {
    pub request: Translated,
    /// Recorded and judged in the background, never blocked: the call had already run when the
    /// client found it (a call the agent ran without a Hook).
    pub record: bool,
    /// The Hook as the client sent it, kept with the event under `<kind>_payload`; none for an
    /// event the bridge made itself.
    pub payload: Option<Value>,
    /// Marks on every event of this Hook, beside `agent_kind`.
    pub flags: Vec<(&'static str, Value)>,
}

impl Incoming {
    /// A Hook the engine has nothing to do with.
    pub fn nothing() -> Self {
        Self::new(Translated::Nothing)
    }

    pub fn new(request: Translated) -> Self {
        Self {
            request,
            record: false,
            payload: None,
            flags: Vec::new(),
        }
    }

    /// Keeps the Hook as the client sent it with the event.
    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn with_flag(mut self, name: &'static str, value: Value) -> Self {
        self.flags.push((name, value));
        self
    }

    /// Recorded, never blocked; see [`Incoming::record`].
    pub fn recorded(mut self) -> Self {
        self.record = true;
        self
    }
}

/// What a Hook became: the Claude Code request the engine judges.
#[derive(Debug, Clone, PartialEq)]
pub enum Translated {
    SessionStart(SessionStartRequest),
    UserPromptSubmit(UserPromptSubmitRequest),
    PreToolUse(PreToolUseRequest),
    PostToolUse(PostToolUseRequest),
    PostToolUseFailure(PostToolUseFailureRequest),
    /// A turn's end closes the open tool batch, as Claude Code's PostToolBatch does.
    PostToolBatch(PostToolBatchRequest),
    MessageDisplay(MessageDisplayRequest),
    ConfigChange(ConfigChangeRequest),
    SubagentStart(SubagentLifecycleRequest),
    SubagentStop(SubagentLifecycleRequest),
    SessionEnd(SessionEndRequest),
    /// Nothing for the engine.
    Nothing,
}

/// Why a Hook was turned away, as the client reads it.
pub struct Rejection {
    status: StatusCode,
    error: &'static str,
}

impl Rejection {
    /// This agent has no such Hook.
    pub const fn unknown_event() -> Self {
        Self::new(StatusCode::NOT_FOUND, "unknown_event")
    }

    /// The Hook is not the JSON this agent sends.
    pub const fn invalid_json() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_json")
    }

    pub const fn new(status: StatusCode, error: &'static str) -> Self {
        Self { status, error }
    }

    fn into_response(self) -> Response {
        error(self.status, self.error)
    }
}

/// Marks an agent's events: which agent they came from, the Hook as it was sent, and whatever
/// the translation could not tell for certain.
pub(crate) struct Tag<'a> {
    pub kind: &'static str,
    pub payload: Option<&'a Value>,
    pub flags: &'a [(&'static str, Value)],
}

/// Marks `event` as this agent's, keeping the Hook as the client sent it.
pub(crate) fn mark(event: &mut NormalizedEvent, tag: &Tag<'_>) {
    macro_rules! mark {
        ($envelope:expr) => {{
            let envelope = $envelope;
            envelope
                .meta
                .additional_fields
                .insert("agent_kind".to_owned(), Value::from(tag.kind));
            for (name, value) in tag.flags {
                envelope
                    .meta
                    .additional_fields
                    .insert((*name).to_owned(), value.clone());
            }
            if let Some(payload) = tag.payload {
                envelope
                    .additional_fields
                    .insert(format!("{}_payload", tag.kind), payload.clone());
            }
        }};
    }
    match event {
        NormalizedEvent::SessionStart(event) => mark!(event),
        NormalizedEvent::SessionEnd(event) => mark!(event),
        NormalizedEvent::UserPromptSubmit(event) => mark!(event),
        NormalizedEvent::PreToolUse(event) => mark!(&mut event.event),
        NormalizedEvent::PostToolUse(event) => mark!(event),
        NormalizedEvent::PostToolUseFailure(event) => mark!(event),
        NormalizedEvent::SubagentStart(event) => mark!(event),
        NormalizedEvent::SubagentStop(event) => mark!(event),
        NormalizedEvent::ConfigChange(event) => mark!(event),
        NormalizedEvent::MessageDisplay(event) => mark!(event),
        NormalizedEvent::Intent(event) => mark!(event),
        NormalizedEvent::PostToolBatch(event) => mark!(event),
        NormalizedEvent::ToolDescriptions(event) => mark!(event),
    }
}

/// One Hook of `agent`: translated, normalized, judged and answered as the client reads it.
pub(crate) async fn receive(
    service: CollectorService,
    agent: &'static (dyn Agent + Sync),
    event: &str,
    headers: HeaderMap,
    raw: Value,
) -> Response {
    let context = crate::http::trusted(&headers);
    let incoming = match agent.translate(event, raw, &headers) {
        Ok(incoming) => incoming,
        Err(rejection) => return rejection.into_response(),
    };
    let tag = Tag {
        kind: agent.kind(),
        payload: incoming.payload.as_ref(),
        flags: &incoming.flags,
    };
    let tag = Some(&tag);
    macro_rules! normalized {
        ($normalize:ident, $request:expr) => {
            match service
                .normalizer
                .$normalize(&context, $request, now())
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, tag)).await,
                Err(error) => normalize_failure(error),
            }
        };
    }
    match incoming.request {
        Translated::SessionStart(request) => {
            start_session(&service, &context, request, agent.watches_paths(), tag).await
        }
        Translated::UserPromptSubmit(request) => {
            submit_prompt(&service, &context, request, tag).await
        }
        Translated::PreToolUse(request) if incoming.record => {
            // A call the agent ran without a Hook, found later by the bridge: it already
            // happened, so it is recorded and judged in the background, never blocked.
            let deadline_ms = u64::try_from(service.config.decision_budget.as_millis()).ok();
            match service
                .normalizer
                .pre_tool_use(
                    &context,
                    request,
                    now(),
                    EnforcementMode::Record,
                    deadline_ms,
                )
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, tag)).await,
                Err(error) => normalize_failure(error),
            }
        }
        Translated::PreToolUse(request) => {
            judge_call(&service, &context, request, agent.policy(), tag).await
        }
        Translated::PostToolUse(request) => {
            record_tool_result(
                &service,
                &context,
                Ok(request),
                HookEventName::PostToolUse,
                tag,
            )
            .await
        }
        Translated::PostToolUseFailure(request) => {
            // A client that reads output for finished calls only gets the intent request on
            // that event instead; its own failure Hook has no output of its own.
            let event = match agent.reads_failure_output() {
                true => HookEventName::PostToolUseFailure,
                false => HookEventName::PostToolUse,
            };
            record_tool_result(&service, &context, Err(request), event, tag).await
        }
        Translated::MessageDisplay(request) => {
            display_message(&service, &context, request, agent.hides_message_text(), tag).await
        }
        Translated::PostToolBatch(request) => normalized!(post_tool_batch, request),
        Translated::ConfigChange(request) => normalized!(config_change, request),
        Translated::SubagentStart(request) => normalized!(subagent_start, request),
        Translated::SubagentStop(request) => normalized!(subagent_stop, request),
        Translated::SessionEnd(request) => normalized!(session_end, request),
        Translated::Nothing => StatusCode::OK.into_response(),
    }
}

pub(crate) fn tagged(mut event: NormalizedEvent, tag: Option<&Tag<'_>>) -> NormalizedEvent {
    if let Some(tag) = tag {
        mark(&mut event, tag);
    }
    event
}

/// One Hook of `agent`, with the delivery receipt its client asked for.
///
/// A client that cannot lose an event sends a durable delivery ID (`x-withhuman-event`) and
/// resends until the engine acknowledges it. Retrying the same ID retrieves the stored reply;
/// an unfinished receipt is deliberately not replayed, since normalization may already have
/// changed the session state even when no reply reached the client, and so requires a fresh
/// session. A client without the header is answered without a receipt.
pub(crate) async fn hook(
    service: CollectorService,
    agent: &'static (dyn Agent + Sync),
    event: String,
    headers: HeaderMap,
    raw: Value,
) -> Response {
    let Some(id) = crate::http::header_value(&headers, DELIVERY_HEADER) else {
        return receive(service, agent, &event, headers, raw).await;
    };
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return error(StatusCode::BAD_REQUEST, "invalid_delivery_id");
    }
    // Bind the receipt to both the event payload and the trusted client context.
    let mut bound = vec![
        Value::from(event.clone()),
        raw.clone(),
        Value::from(crate::http::header_value(
            &headers,
            crate::http::CLIENT_HEADER,
        )),
        Value::from(crate::http::header_value(
            &headers,
            crate::http::REPOSITORY_HEADER,
        )),
    ];
    bound.extend(
        agent
            .request_headers()
            .iter()
            .map(|name| Value::from(crate::http::header_value(&headers, name))),
    );
    let request = withhuman_common::chunking::sha256(&Value::Array(bound).to_string());
    let key = format!("withhuman:{}:delivery:{id}", agent.kind());
    match service.deliveries.begin(&key, &request).await {
        Ok(Some(receipt)) if receipt.request == request => {
            return match receipt.reply {
                Some(reply) => stored_reply(reply),
                None => error(StatusCode::CONFLICT, RESYNC_REQUIRED),
            };
        }
        Ok(Some(_)) => return error(StatusCode::CONFLICT, "delivery_id_conflict"),
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "delivery_store_unavailable",
            );
        }
        Ok(None) => {}
    }
    let response = receive(service.clone(), agent, &event, headers, raw).await;
    if response.status() != StatusCode::OK {
        return response;
    }
    let Ok(bytes) = axum::body::to_bytes(response.into_body(), 1024 * 1024).await else {
        return error(StatusCode::CONFLICT, RESYNC_REQUIRED);
    };
    let Ok(reply) = String::from_utf8(bytes.to_vec()) else {
        return error(StatusCode::CONFLICT, RESYNC_REQUIRED);
    };
    if service
        .deliveries
        .finish(&key, &request, reply.clone())
        .await
        .is_err()
    {
        return error(StatusCode::CONFLICT, RESYNC_REQUIRED);
    }
    stored_reply(reply)
}

/// The durable ID a client gives an event it resends until acknowledged.
const DELIVERY_HEADER: &str = "x-withhuman-event";
/// The shell a client runs commands in (`powershell`, else POSIX). Every agent whose shell
/// tool becomes Claude Code's `Bash` or `PowerShell` reports it the same way.
pub const SHELL_HEADER: &str = "x-withhuman-shell";
/// The client's own session state no longer matches the engine's: it starts a new session
/// rather than send an event twice.
pub(crate) const RESYNC_REQUIRED: &str = "resync_required";

fn stored_reply(reply: String) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        reply,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    //! What adding an agent takes, as a test: one [`Agent`] implementation, no change anywhere
    //! else. The agent here keeps the defaults of the least capable client — it cannot ask the
    //! user, hide text it shows or read a failed call's output.

    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use serde_json::json;
    use withhuman_contracts::events::{EventResponse, SessionCursor};

    use super::*;
    use crate::{CollectorConfig, FailurePolicy, GeneratorError, GeneratorTransport, ReviewPolicy};

    /// A coding agent whose Hooks name a prompt and a command, nothing else.
    struct Demo;

    impl Agent for Demo {
        fn kind(&self) -> &'static str {
            "demo"
        }

        fn policy(&self) -> HookPolicy {
            HookPolicy {
                review: ReviewPolicy::Deny,
                mcp_at_hook: true,
                failure: FailurePolicy::Closed,
                resends: false,
            }
        }

        fn translate(
            &self,
            event: &str,
            raw: Value,
            _headers: &HeaderMap,
        ) -> Result<Incoming, Rejection> {
            let session_id = raw["session"]
                .as_str()
                .ok_or_else(Rejection::invalid_json)?
                .to_owned();
            match event {
                "ask" => Ok(
                    Incoming::new(Translated::UserPromptSubmit(UserPromptSubmitRequest {
                        session_id,
                        hook_event_name: Some(HookEventName::UserPromptSubmit),
                        prompt: raw["text"].as_str().unwrap_or_default().to_owned(),
                        prompt_id: None,
                        transcript_path: None,
                        cwd: None,
                        permission_mode: None,
                    }))
                    .with_payload(raw),
                ),
                "run" => Ok(Incoming::new(Translated::PreToolUse(PreToolUseRequest {
                    session_id,
                    hook_event_name: Some(HookEventName::PreToolUse),
                    tool_name: "Bash".to_owned(),
                    tool_input: json!({"command": raw["command"].as_str().unwrap_or_default()}),
                    tool_use_id: "call-1".to_owned(),
                    cwd: None,
                    prompt_id: None,
                    agent_id: None,
                    agent_type: None,
                    permission_mode: None,
                    withhuman_programs: Vec::new(),
                }))
                .with_flag("demo_guessed", json!(true))
                .with_payload(raw)),
                _ => Err(Rejection::unknown_event()),
            }
        }
    }

    #[derive(Default)]
    struct Sent(Mutex<Vec<NormalizedEvent>>);

    #[async_trait]
    impl GeneratorTransport for Sent {
        async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
            self.0.lock().unwrap().push(event);
            Ok(EventResponse {
                nodes: Vec::new(),
                paragraphs: None,
                version: 1,
                decision_response: None,
            })
        }

        async fn session_cursor(&self, _session_id: &str) -> Result<SessionCursor, GeneratorError> {
            Ok(SessionCursor::default())
        }
    }

    fn service(generator: Arc<Sent>) -> CollectorService {
        CollectorService::new(
            CollectorConfig {
                intent_capture: false,
                ..CollectorConfig::default()
            },
            generator,
        )
    }

    /// A prompt of an agent nobody wrote engine code for reaches the engine as Claude Code's
    /// own, marked as that agent's and keeping the Hook it came from.
    #[tokio::test]
    async fn an_agent_needs_no_more_than_its_adapter() {
        let generator = Arc::new(Sent::default());
        let response = receive(
            service(generator.clone()),
            &Demo,
            "ask",
            HeaderMap::new(),
            json!({"session": "s-1", "text": "fix the build"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let events = generator.0.lock().unwrap();
        let NormalizedEvent::UserPromptSubmit(event) = &events[0] else {
            panic!("expected a prompt, got {:?}", events[0]);
        };
        assert_eq!(event.payload.prompt, "fix the build");
        assert_eq!(event.meta.additional_fields["agent_kind"], "demo");
        assert_eq!(
            event.additional_fields["demo_payload"]["text"],
            "fix the build"
        );
    }

    /// Its flags reach the engine with the event, and an event it has no Hook for is turned
    /// away by the route rather than by the agent's own code.
    #[tokio::test]
    async fn a_call_carries_the_agents_own_marks() {
        let generator = Arc::new(Sent::default());
        let service = service(generator.clone());
        let response = receive(
            service.clone(),
            &Demo,
            "run",
            HeaderMap::new(),
            json!({"session": "s-1", "command": "cargo test"}),
        )
        .await;
        // No decision came back and the agent's policy is closed, so the Call is denied: the
        // failure policy, like everything else here, is the seam's and not the agent's.
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            answer["hookSpecificOutput"]["permissionDecision"], "deny",
            "a Call nothing judged must not be allowed"
        );
        {
            let events = generator.0.lock().unwrap();
            let NormalizedEvent::PreToolUse(call) = &events[0] else {
                panic!("expected a call, got {:?}", events[0]);
            };
            assert_eq!(call.event.payload.tool_name, "Bash");
            assert_eq!(call.event.meta.additional_fields["demo_guessed"], true);
        }
        assert_eq!(
            receive(
                service,
                &Demo,
                "PreModelRequest",
                HeaderMap::new(),
                json!({"session": "s-1"}),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
}
