use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{FromRequest, Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Serialize, de::DeserializeOwned};
use utoipa::{OpenApi, ToSchema};
use withhuman_common::intent::split_intent;
use withhuman_contracts::{
    decisions::{Decision, DecisionResponse, EnforcementMode},
    events::EventResponse,
    hooks::{
        ConfigChangeRequest, HookEventName, HookSpecificResponse, MessageDisplayOutput,
        MessageDisplayRequest, PermissionDecision, PostToolBatchRequest, PostToolUseFailureRequest,
        PostToolUseOutput, PostToolUseRequest, PreToolUseOutput, PreToolUseRequest,
        SessionEndRequest, SessionStartOutput, SessionStartRequest, SubagentLifecycleRequest,
        ToolDescriptionsRequest, UserPromptSubmitOutput, UserPromptSubmitRequest,
    },
};

use crate::{
    CollectorConfig, FailurePolicy, GeneratorError, GeneratorHttpClient, GeneratorTransport,
    InMemoryVerdictStore, NormalizeError, Normalizer, RedisSessionStore, RedisVerdictStore,
    ReviewPolicy, StoreError, StoredVerdict, VerdictStore,
    agent::{self, Tag, tagged},
    devices::DeviceStops,
    inventory::{self, USER_HEADER},
    keys::KeyVerifier,
    redis_connection, triage,
};

pub(crate) const CLIENT_HEADER: &str = "x-withhuman-client";
pub(crate) const REPOSITORY_HEADER: &str = "x-withhuman-repo";
/// Display content for a flush that is all intent line: a zero-width space, since Claude Code
/// shows the original text for an empty one.
const HIDDEN_LINE: &str = "\u{200B}";
const SWAGGER_UI_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WithHuman API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>SwaggerUIBundle({url: "/api-docs/openapi.json", dom_id: "#swagger-ui"});</script>
</body>
</html>"##;

#[derive(Clone)]
pub struct CollectorService {
    pub config: CollectorConfig,
    pub normalizer: Normalizer,
    pub generator: Arc<dyn GeneratorTransport>,
    pub verdicts: Arc<dyn VerdictStore>,
    pub keys: KeyVerifier,
    pub flags: crate::flags::FlagCache,
    pub devices: DeviceStops,
    pub(crate) deliveries: Arc<crate::codex_delivery::Deliveries>,
}

impl CollectorService {
    pub fn new(config: CollectorConfig, generator: Arc<dyn GeneratorTransport>) -> Self {
        let verdicts = Arc::new(InMemoryVerdictStore::new(config.verdict_capacity));
        Self {
            keys: KeyVerifier::new(generator.clone(), config.key_cache),
            flags: crate::flags::FlagCache::new(generator.clone(), config.key_cache),
            devices: DeviceStops::new(generator.clone(), config.key_cache),
            normalizer: Normalizer::default()
                .with_history(generator.clone())
                .with_network_commands(config.network_commands.clone())
                .with_intent_capture(config.intent_capture),
            config,
            generator,
            verdicts,
            deliveries: Arc::default(),
        }
    }

    /// Uses Redis-backed state when `config.redis_url` is set, in-process state otherwise.
    pub fn from_config(
        config: CollectorConfig,
        generator: Arc<dyn GeneratorTransport>,
    ) -> Result<Self, StoreError> {
        let Some(url) = config.redis_url.clone() else {
            return Ok(Self::new(config, generator));
        };
        let connection = redis_connection(&url)?;
        Ok(Self {
            keys: KeyVerifier::new(generator.clone(), config.key_cache),
            flags: crate::flags::FlagCache::new(generator.clone(), config.key_cache),
            devices: DeviceStops::new(generator.clone(), config.key_cache),
            deliveries: Arc::new(crate::codex_delivery::Deliveries::redis(connection.clone())),
            verdicts: Arc::new(RedisVerdictStore::new(
                connection.clone(),
                config.verdict_ttl,
            )),
            normalizer: Normalizer::new(RedisSessionStore::new(connection, config.session_ttl))
                .with_history(generator.clone())
                .with_network_commands(config.network_commands.clone())
                .with_intent_capture(config.intent_capture),
            config,
            generator,
        })
    }
}

pub fn app(config: CollectorConfig) -> Router {
    let generator = Arc::new(GeneratorHttpClient::new(config.generator_url.clone()));
    app_with_transport(CollectorService::new(config, generator))
}

pub fn app_with_transport(service: CollectorService) -> Router {
    // Every Hook passes the key check first; see `inventory::authenticate`.
    let hooks = Router::new()
        .route("/v1/hooks/SessionStart", post(session_start))
        .route("/v1/hooks/SessionEnd", post(session_end))
        .route("/v1/hooks/UserPromptSubmit", post(user_prompt_submit))
        .route("/v1/hooks/PreToolUse", post(pre_tool_use))
        .route("/v1/hooks/PostToolUse", post(post_tool_use))
        .route("/v1/hooks/PostToolUseFailure", post(post_tool_use_failure))
        .route("/v1/hooks/SubagentStart", post(subagent_start))
        .route("/v1/hooks/SubagentStop", post(subagent_stop))
        .route("/v1/hooks/ConfigChange", post(config_change))
        .route("/v1/hooks/MessageDisplay", post(message_display))
        .route("/v1/hooks/PostToolBatch", post(post_tool_batch))
        .route("/v1/hooks/ToolDescriptions", post(tool_descriptions))
        .route("/v1/hooks/{agent}/{event}", post(agent_hook))
        .route_layer(axum::middleware::from_fn_with_state(
            service.clone(),
            inventory::authenticate,
        ));
    Router::new()
        .route("/healthz", get(health))
        .merge(hooks)
        .route("/v1/clients/register", post(inventory::register_client))
        .route("/v1/clients/checkin", post(inventory::checkin))
        .route("/v1/clients/exceptions", get(inventory::client_exceptions))
        .route(
            "/v1/admin/exceptions",
            post(inventory::add_exception).get(inventory::exceptions),
        )
        .route(
            "/v1/admin/exceptions/{id}/remove",
            post(inventory::remove_exception),
        )
        .route("/v1/admin/clients", get(inventory::clients))
        .route(
            "/v1/admin/clients/{client_id}",
            delete(inventory::delete_client),
        )
        .route(
            "/v1/admin/clients/{client_id}/owner",
            post(inventory::set_client_owner),
        )
        .route(
            "/v1/admin/clients/{client_id}/stop",
            post(inventory::stop_client),
        )
        .route("/v1/admin/keys", get(inventory::all_keys))
        .route(
            "/v1/admin/keys/{key_id}/revoke",
            post(inventory::revoke_key),
        )
        .route(
            "/v1/admin/users/{email}/keys",
            post(inventory::issue_key).get(inventory::user_keys),
        )
        .route(
            "/v1/admin/users/{email}/revoke",
            post(inventory::revoke_user),
        )
        .route(
            "/v1/admin/sessions/{session_id}/stop",
            post(inventory::stop_session),
        )
        .route(
            "/v1/admin/sessions/{session_id}/release",
            post(inventory::release_session),
        )
        .route("/v1/admin/reviews", post(inventory::add_review))
        .route(
            "/v1/admin/sessions/{session_id}/mark",
            post(triage::mark_session),
        )
        .route("/v1/admin/sessions/mark", post(triage::mark_sessions))
        .route("/v1/admin/sources/distrust", post(triage::distrust_source))
        .route(
            "/v1/admin/sessions/{session_id}/calls/{seq}/evidence",
            get(triage::evidence),
        )
        .route("/api-docs/openapi.json", get(openapi_document))
        .route("/swagger-ui", get(swagger_ui))
        .route("/swagger-ui/", get(swagger_ui))
        .with_state(service)
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        session_start,
        session_end,
        user_prompt_submit,
        pre_tool_use,
        post_tool_use,
        post_tool_use_failure,
        subagent_start,
        subagent_stop,
        config_change,
        message_display,
        post_tool_batch,
        tool_descriptions,
        agent_hook,
        inventory::register_client,
        inventory::checkin,
        inventory::client_exceptions,
        inventory::add_exception,
        inventory::exceptions,
        inventory::remove_exception,
        inventory::issue_key,
        inventory::user_keys,
        inventory::all_keys,
        inventory::revoke_key,
        inventory::revoke_user,
        inventory::stop_session,
        inventory::release_session,
        inventory::add_review,
        inventory::clients,
        inventory::set_client_owner,
        inventory::stop_client,
        inventory::delete_client,
        triage::mark_session,
        triage::mark_sessions,
        triage::distrust_source,
        triage::evidence
    ),
    components(schemas(
        withhuman_contracts::codex::CodexHookInput,
        withhuman_contracts::cursor::CursorHookInput,
        withhuman_contracts::hermes::HermesHookInput
    )),
    tags(
        (name = "Collector", description = "Claude Code Hook ingestion and enforcement API"),
        (name = "Inventory", description = "Device registration and per-user WithHuman keys"),
        (name = "Triage", description = "The security team's session marks, distrusted sources and Call evidence")
    )
)]
struct CollectorApiDoc;

async fn openapi_document() -> Json<utoipa::openapi::OpenApi> {
    Json(CollectorApiDoc::openapi())
}

async fn swagger_ui() -> Html<&'static str> {
    Html(SWAGGER_UI_HTML)
}

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "Collector",
    responses((status = 200, description = "Collector is ready", body = HealthResponse))
)]
// Redis is deliberately not probed: an outage would mark every replica unhealthy at once, so
// Hooks would fail at the gateway instead of getting the configured failure policy, and
// restarting replicas cannot repair Redis. Each request applies the policy on Redis errors.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "collector",
    })
}

#[utoipa::path(
    post,
    path = "/v1/hooks/SessionStart",
    tag = "Collector",
    params(
        ("X-WithHuman-Repo" = Option<String>, Header, description = "Repository identity"),
        ("X-WithHuman-Client" = Option<String>, Header, description = "Client identity")
    ),
    request_body = SessionStartRequest,
    responses(
        (status = 200, description = "Session accepted", body = HookSpecificResponse<SessionStartOutput>),
        (status = 400, description = "Invalid JSON", body = ErrorResponse),
        (status = 415, description = "Content-Type is not application/json", body = ErrorResponse),
        (status = 502, description = "Generator or session store unavailable", body = ErrorResponse)
    )
)]
async fn session_start(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<SessionStartRequest>,
) -> Response {
    start_session(&service, &trusted(&headers), request, true, None).await
}

/// A session began. With `watch_paths` the answer names the paths the client is to watch; a
/// client that reports no changes to them is answered with nothing.
pub(crate) async fn start_session(
    service: &CollectorService,
    context: &TrustedHookContext,
    request: SessionStartRequest,
    watch_paths: bool,
    tag: Option<&Tag<'_>>,
) -> Response {
    let event = match service
        .normalizer
        .session_start(context, request, now())
        .await
    {
        Ok(event) => tagged(event, tag),
        Err(error) => return normalize_failure(error),
    };
    let response = send_regular(service, event).await;
    if !watch_paths || response.status() != StatusCode::OK {
        return response;
    }
    Json(HookSpecificResponse {
        hook_specific_output: SessionStartOutput {
            hook_event_name: HookEventName::SessionStart,
            watch_paths: service.config.watch_paths.clone(),
        },
    })
    .into_response()
}

macro_rules! regular_handler {
    ($name:ident, $request:ty, $normalize:ident, $path:literal) => {
        #[utoipa::path(
            post,
            path = $path,
            tag = "Collector",
            params(
                ("X-WithHuman-Repo" = Option<String>, Header, description = "Repository identity"),
                ("X-WithHuman-Client" = Option<String>, Header, description = "Client identity")
            ),
            request_body = $request,
            responses(
                (status = 200, description = "Event accepted; response body is empty"),
                (status = 400, description = "Invalid JSON", body = ErrorResponse),
                (status = 415, description = "Content-Type is not application/json", body = ErrorResponse),
                (status = 502, description = "Generator or session store unavailable", body = ErrorResponse)
            )
        )]
        async fn $name(
            State(service): State<CollectorService>,
            headers: HeaderMap,
            StrictJson(request): StrictJson<$request>,
        ) -> Response {
            match service
                .normalizer
                .$normalize(&trusted(&headers), request, now())
                .await
            {
                Ok(event) => send_regular(&service, event).await,
                Err(error) => normalize_failure(error),
            }
        }
    };
}

macro_rules! result_handler {
    ($name:ident, $request:ty, $event:ident, $wrap:expr, $path:literal) => {
        #[utoipa::path(
            post,
            path = $path,
            tag = "Collector",
            params(
                ("X-WithHuman-Repo" = Option<String>, Header, description = "Repository identity"),
                ("X-WithHuman-Client" = Option<String>, Header, description = "Client identity")
            ),
            request_body = $request,
            responses(
                (status = 200, description = "Event accepted; empty, or the request for the turn's intent as additional context", body = HookSpecificResponse<PostToolUseOutput>),
                (status = 400, description = "Invalid JSON", body = ErrorResponse),
                (status = 415, description = "Content-Type is not application/json", body = ErrorResponse),
                (status = 502, description = "Generator or session store unavailable", body = ErrorResponse)
            )
        )]
        async fn $name(
            State(service): State<CollectorService>,
            headers: HeaderMap,
            StrictJson(request): StrictJson<$request>,
        ) -> Response {
            record_tool_result(
                &service,
                &trusted(&headers),
                $wrap(request),
                HookEventName::$event,
                None,
            )
            .await
        }
    };
}

result_handler!(
    post_tool_use,
    PostToolUseRequest,
    PostToolUse,
    Ok,
    "/v1/hooks/PostToolUse"
);
result_handler!(
    post_tool_use_failure,
    PostToolUseFailureRequest,
    PostToolUseFailure,
    Err,
    "/v1/hooks/PostToolUseFailure"
);

/// A call that finished, well or badly. The turn's intent is asked for on `event`: the Hook a
/// client reads output for, which is not always the one that reported the call.
pub(crate) async fn record_tool_result(
    service: &CollectorService,
    context: &TrustedHookContext,
    request: Result<PostToolUseRequest, PostToolUseFailureRequest>,
    event: HookEventName,
    tag: Option<&Tag<'_>>,
) -> Response {
    let (session_id, agent_id) = match &request {
        Ok(request) => (request.session_id.clone(), request.agent_id.clone()),
        Err(request) => (request.session_id.clone(), request.agent_id.clone()),
    };
    let normalized = match request {
        Ok(request) => {
            service
                .normalizer
                .post_tool_use(context, request, now())
                .await
        }
        Err(request) => {
            service
                .normalizer
                .post_tool_use_failure(context, request, now())
                .await
        }
    };
    let response = match normalized {
        Ok(normalized) => send_regular(service, tagged(normalized, tag)).await,
        Err(error) => return normalize_failure(error),
    };
    remind_of_intent(service, response, event, &session_id, agent_id.as_deref()).await
}

/// A recorded tool result of a turn that states no intent yet carries a request for it to the
/// model, once per turn. Unlike a denied Call, nothing shows on the user's screen.
pub(crate) async fn remind_of_intent(
    service: &CollectorService,
    response: Response,
    event: HookEventName,
    session_id: &str,
    agent_id: Option<&str>,
) -> Response {
    if response.status() != StatusCode::OK
        || service
            .normalizer
            .reminds_of_intent(session_id, agent_id)
            .await
            != Ok(true)
    {
        return response;
    }
    Json(HookSpecificResponse {
        hook_specific_output: PostToolUseOutput {
            hook_event_name: event,
            additional_context: crate::INTENT_REMINDER.to_owned(),
        },
    })
    .into_response()
}
regular_handler!(
    session_end,
    SessionEndRequest,
    session_end,
    "/v1/hooks/SessionEnd"
);
regular_handler!(
    config_change,
    ConfigChangeRequest,
    config_change,
    "/v1/hooks/ConfigChange"
);
regular_handler!(
    post_tool_batch,
    PostToolBatchRequest,
    post_tool_batch,
    "/v1/hooks/PostToolBatch"
);
regular_handler!(
    tool_descriptions,
    ToolDescriptionsRequest,
    tool_descriptions,
    "/v1/hooks/ToolDescriptions"
);

#[utoipa::path(
    post,
    path = "/v1/hooks/UserPromptSubmit",
    tag = "Collector",
    params(
        ("X-WithHuman-Repo" = Option<String>, Header, description = "Repository identity"),
        ("X-WithHuman-Client" = Option<String>, Header, description = "Client identity")
    ),
    request_body = UserPromptSubmitRequest,
    responses(
        (status = 200, description = "Event accepted; with intent capture on, the intent instruction as additional context", body = HookSpecificResponse<UserPromptSubmitOutput>),
        (status = 400, description = "Invalid JSON", body = ErrorResponse),
        (status = 415, description = "Content-Type is not application/json", body = ErrorResponse),
        (status = 502, description = "Generator or session store unavailable", body = ErrorResponse)
    )
)]
async fn user_prompt_submit(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<UserPromptSubmitRequest>,
) -> Response {
    submit_prompt(&service, &trusted(&headers), request, None).await
}

pub(crate) async fn submit_prompt(
    service: &CollectorService,
    context: &TrustedHookContext,
    request: UserPromptSubmitRequest,
    tag: Option<&Tag<'_>>,
) -> Response {
    let response = match service
        .normalizer
        .user_prompt_submit(context, request, now())
        .await
    {
        Ok(event) => send_regular(service, tagged(event, tag)).await,
        Err(error) => normalize_failure(error),
    };
    if response.status() != StatusCode::OK || !service.config.intent_capture {
        return response;
    }
    Json(HookSpecificResponse {
        hook_specific_output: UserPromptSubmitOutput {
            hook_event_name: HookEventName::UserPromptSubmit,
            additional_context: crate::INTENT_INSTRUCTION.to_owned(),
        },
    })
    .into_response()
}

#[utoipa::path(
    post,
    path = "/v1/hooks/SubagentStart",
    tag = "Collector",
    request_body = SubagentLifecycleRequest,
    responses((status = 200, description = "Event accepted"), (status = 400, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 502, body = ErrorResponse))
)]
async fn subagent_start(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<SubagentLifecycleRequest>,
) -> Response {
    match service
        .normalizer
        .subagent_start(&trusted(&headers), request, now())
        .await
    {
        Ok(event) => send_regular(&service, event).await,
        Err(error) => normalize_failure(error),
    }
}

#[utoipa::path(
    post,
    path = "/v1/hooks/SubagentStop",
    tag = "Collector",
    request_body = SubagentLifecycleRequest,
    responses((status = 200, description = "Event accepted"), (status = 400, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 502, body = ErrorResponse))
)]
async fn subagent_stop(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<SubagentLifecycleRequest>,
) -> Response {
    match service
        .normalizer
        .subagent_stop(&trusted(&headers), request, now())
        .await
    {
        Ok(event) => send_regular(&service, event).await,
        Err(error) => normalize_failure(error),
    }
}

#[utoipa::path(
    post,
    path = "/v1/hooks/MessageDisplay",
    tag = "Collector",
    request_body = MessageDisplayRequest,
    responses((status = 200, description = "Fragment accepted; when the first flush opens with the intent line, the flush without it as display content", body = HookSpecificResponse<MessageDisplayOutput>), (status = 400, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 500, body = ErrorResponse), (status = 502, body = ErrorResponse))
)]
async fn message_display(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<MessageDisplayRequest>,
) -> Response {
    display_message(&service, &trusted(&headers), request, true, None).await
}

/// A flush of a message the agent is showing. With `hides_text` the first flush is answered
/// with everything but the intent line, which only the engine keeps; a client that cannot
/// replace what it shows leaves the line on the user's screen.
pub(crate) async fn display_message(
    service: &CollectorService,
    context: &TrustedHookContext,
    request: MessageDisplayRequest,
    hides_text: bool,
    tag: Option<&Tag<'_>>,
) -> Response {
    // Claude Code shows the original for an empty replacement, so a flush of the intent line
    // alone is replaced by an invisible character.
    let display = (hides_text && service.config.intent_capture && request.index.unwrap_or(0) == 0)
        .then(|| split_intent(&request.delta))
        .flatten()
        .map(|line| match line.rest {
            "" => HIDDEN_LINE.to_owned(),
            rest => rest.to_owned(),
        });
    let response = match service
        .normalizer
        .message_display(context, request, now())
        .await
    {
        Ok(events) => {
            let events = events.into_iter().map(|event| tagged(event, tag)).collect();
            send_all(service, events).await
        }
        Err(error) => normalize_failure(error),
    };
    match display {
        Some(display_content) if response.status() == StatusCode::OK => {
            Json(HookSpecificResponse {
                hook_specific_output: MessageDisplayOutput {
                    hook_event_name: HookEventName::MessageDisplay,
                    display_content,
                },
            })
            .into_response()
        }
        _ => response,
    }
}

#[utoipa::path(
    post,
    path = "/v1/hooks/PreToolUse",
    tag = "Collector",
    request_body = PreToolUseRequest,
    responses(
        (status = 200, description = "Empty for ALLOW, Hook output for DENY or REVIEW", body = HookSpecificResponse<PreToolUseOutput>),
        (status = 400, body = ErrorResponse),
        (status = 415, body = ErrorResponse)
    )
)]
async fn pre_tool_use(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<PreToolUseRequest>,
) -> Response {
    judge_call(
        &service,
        &trusted(&headers),
        request,
        HookPolicy::of(&service.config),
        None,
    )
    .await
}

/// How a client's Hook answers a verdict.
#[derive(Debug, Clone, Copy)]
pub struct HookPolicy {
    /// What a REVIEW becomes: a client that cannot ask the user has to deny.
    pub review: ReviewPolicy,
    /// MCP calls are enforced by the Hook rather than by AgentGateway.
    pub mcp_at_hook: bool,
    pub failure: FailurePolicy,
    /// The client sends events with a delivery ID and resends until the engine acknowledges
    /// them. A failure then leaves the receipt unfinished, so the client starts a new session
    /// rather than risk applying an event twice, and the reason it reports is the model's to
    /// read rather than a person's.
    pub resends: bool,
}

impl HookPolicy {
    /// Claude Code's own, from the engine's configuration: it asks the user when the operator
    /// allows it, leaves MCP calls to AgentGateway and loses no event to resend.
    pub(crate) fn of(config: &CollectorConfig) -> Self {
        Self {
            review: config.review_policy,
            mcp_at_hook: config.enforce_mcp_at_hook,
            failure: config.failure_policy,
            resends: false,
        }
    }
}

pub(crate) async fn judge_call(
    service: &CollectorService,
    context: &TrustedHookContext,
    request: PreToolUseRequest,
    policy: HookPolicy,
    tag: Option<&Tag<'_>>,
) -> Response {
    // A turn whose intent has not arrived is asked for one before its first Call is judged. The
    // ask is best effort: when the session store cannot answer, the Call is judged as usual.
    if service.config.enforcement_mode == EnforcementMode::Enforce
        && service
            .normalizer
            .asks_for_intent(&request, service.config.intent_wait)
            .await
            == Ok(true)
    {
        return blocking_response(PermissionDecision::Deny, crate::INTENT_REQUIRED.to_owned());
    }
    let tool_use_id = request.tool_use_id.clone();
    let is_mcp = request.tool_name.starts_with("mcp__");
    let tool_name = request.tool_name.clone();
    let arguments = request.tool_input.clone();
    // The Call's rule grade, for when the engine gives no judgment.
    let graded = withhuman_common::grade::grade(&tool_name, &arguments);
    let deadline_ms = u64::try_from(service.config.decision_budget.as_millis()).ok();
    let event = match service
        .normalizer
        .pre_tool_use(
            context,
            request,
            now(),
            service.config.enforcement_mode,
            deadline_ms,
        )
        .await
    {
        Ok(event) => tagged(event, tag),
        Err(error) => return hook_failure(service, policy, graded, error),
    };
    let result = tokio::time::timeout(
        service.config.decision_budget,
        service.generator.send(event),
    )
    .await;
    let response = match result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => return hook_failure(service, policy, graded, error),
        Err(_) => return hook_failure(service, policy, graded, GeneratorError::Timeout),
    };
    let Some(decision) = response.decision_response else {
        return hook_failure(
            service,
            policy,
            graded,
            GeneratorError::InvalidResponse("missing decision_response".to_owned()),
        );
    };
    if decision.validate().is_err() {
        return hook_failure(
            service,
            policy,
            graded,
            GeneratorError::InvalidResponse("invalid decision semantics".to_owned()),
        );
    }
    let enforced_at_hook = !is_mcp || policy.mcp_at_hook;
    let observing = service.config.enforcement_mode != EnforcementMode::Enforce;
    let stored = service
        .verdicts
        .insert(
            tool_use_id,
            StoredVerdict::new(decision.clone(), tool_name, &arguments),
        )
        .await;
    if observing {
        // Record and shadow modes keep the verdict for analysis but never block.
        return StatusCode::OK.into_response();
    }
    if tag.is_some() && policy.failure == FailurePolicy::Closed && stored.is_err() {
        return hook_failure(service, policy, graded, "verdict store unavailable");
    }
    if !enforced_at_hook {
        // AgentGateway enforces this call and needs the stored verdict; without it the
        // extAuthz check denies, so the Hook answer follows the failure policy.
        return match stored {
            Ok(()) => StatusCode::OK.into_response(),
            Err(error) => hook_failure(service, policy, graded, error),
        };
    }
    // The verdict is in hand, so a store failure must not override it (a DENY must never turn
    // into ALLOW under the open failure policy).
    decision_response(decision, policy.review)
}

#[utoipa::path(
    post,
    path = "/v1/hooks/{agent}/{event}",
    tag = "Collector",
    params(
        ("agent" = String, Path, description = "The agent whose Hooks these are (`codex`, `cursor`, `hermes`); Claude Code has a route per event instead"),
        ("event" = String, Path, description = "The agent's Hook event, or one its bridge made in Claude Code's own form"),
        ("X-WithHuman-Repo" = Option<String>, Header, description = "Repository identity"),
        ("X-WithHuman-Client" = Option<String>, Header, description = "Client identity"),
        ("X-WithHuman-Event" = Option<String>, Header, description = "Durable delivery ID of an event the client resends until acknowledged"),
        ("X-WithHuman-Shell" = Option<String>, Header, description = "Codex: `powershell` when the client's shell is PowerShell")
    ),
    request_body = Object,
    responses(
        (status = 200, description = "Empty, or the agent's Hook output: additional context, or a deny for the call", body = HookSpecificResponse<PreToolUseOutput>),
        (status = 400, description = "Invalid JSON or Hook", body = ErrorResponse),
        (status = 404, description = "Unknown agent or event", body = ErrorResponse),
        (status = 409, description = "The client's session state no longer matches the engine's; it starts a new session", body = ErrorResponse),
        (status = 415, body = ErrorResponse),
        (status = 502, description = "Generator or session store unavailable", body = ErrorResponse)
    )
)]
/// One Hook of an agent other than Claude Code, translated to its Claude Code counterpart and
/// handled by the same code. The body is the agent's own Hook input (Codex's is shown);
/// `crate::agent` has what adding an agent takes.
async fn agent_hook(
    State(service): State<CollectorService>,
    Path((kind, event)): Path<(String, String)>,
    headers: HeaderMap,
    StrictJson(raw): StrictJson<serde_json::Value>,
) -> Response {
    let Some(agent) = agent::find(&kind) else {
        return error(StatusCode::NOT_FOUND, "unknown_agent");
    };
    agent::hook(service, agent, event, headers, raw).await
}

pub(crate) fn error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorResponse { error })).into_response()
}

fn decision_response(decision: DecisionResponse, review_policy: ReviewPolicy) -> Response {
    match decision.decision {
        Decision::Allow => StatusCode::OK.into_response(),
        Decision::Deny => blocking_response(PermissionDecision::Deny, decision.reason),
        Decision::Review => blocking_response(
            match review_policy {
                ReviewPolicy::Deny => PermissionDecision::Deny,
                ReviewPolicy::Ask => PermissionDecision::Ask,
            },
            decision.reason,
        ),
    }
}

pub(crate) fn blocking_response(
    permission_decision: PermissionDecision,
    reason: String,
) -> Response {
    Json(HookSpecificResponse {
        hook_specific_output: PreToolUseOutput {
            hook_event_name: HookEventName::PreToolUse,
            permission_decision,
            permission_decision_reason: reason,
        },
    })
    .into_response()
}

fn hook_failure(
    service: &CollectorService,
    policy: HookPolicy,
    graded: Option<withhuman_common::grade::Graded>,
    error: impl fmt::Display,
) -> Response {
    // Record and shadow modes observe only: a failure must not block either. (Record mode never
    // waits for a decision, so a missing one is expected there.)
    if service.config.enforcement_mode != EnforcementMode::Enforce {
        return StatusCode::OK.into_response();
    }
    match policy.failure {
        FailurePolicy::Open => StatusCode::OK.into_response(),
        // A person can still decide a hard or impossible to undo Call when the
        // client asks; anything else is blocked, reads included, since no judgment stands
        // behind it.
        FailurePolicy::Closed
            if !policy.resends
                && policy.review == ReviewPolicy::Ask
                && graded.is_some_and(|graded| graded.grade.level() >= 2) =>
        {
            let graded = graded.unwrap_or(withhuman_common::grade::Graded {
                grade: withhuman_common::grade::Grade::TWO_ONE,
                reason: "unknown",
            });
            blocking_response(
                PermissionDecision::Ask,
                format!(
                    "WithHuman이 이 호출을 판정하지 못했습니다({error}). {}({}: {})이라 실행 여부를 직접 확인해 주세요.",
                    graded.grade.label(),
                    graded.grade.as_str(),
                    graded.describe()
                ),
            )
        }
        FailurePolicy::Closed => {
            let mut response = blocking_response(
                PermissionDecision::Deny,
                if policy.resends {
                    "WithHuman could not check this call, so it was blocked".to_owned()
                } else {
                    error.to_string()
                },
            );
            // A normalizer or downstream error can have applied only part of the event.
            // Leave its delivery pending and make the bridge require a fresh session.
            if policy.resends {
                *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            }
            response
        }
    }
}

fn acknowledge(result: Result<EventResponse, GeneratorError>) -> Response {
    match result {
        Ok(_) => StatusCode::OK.into_response(),
        Err(error) => generator_failure(error),
    }
}

pub(crate) async fn send_regular(
    service: &CollectorService,
    event: crate::NormalizedEvent,
) -> Response {
    match tokio::time::timeout(
        service.config.decision_budget,
        service.generator.send(event),
    )
    .await
    {
        Ok(result) => acknowledge(result),
        Err(_) => generator_failure(GeneratorError::Timeout),
    }
}

/// Sends events in order, stopping at the first failure.
pub(crate) async fn send_all(
    service: &CollectorService,
    events: Vec<crate::NormalizedEvent>,
) -> Response {
    for event in events {
        let response = send_regular(service, event).await;
        if response.status() != StatusCode::OK {
            return response;
        }
    }
    StatusCode::OK.into_response()
}

/// Session store and cursor failures answer like Generator failures (502); a message that
/// cannot be assembled stays an internal error.
pub(crate) fn normalize_failure(error: NormalizeError) -> Response {
    let (status, error) = match error {
        NormalizeError::Store(_) => (StatusCode::BAD_GATEWAY, "session_store_unavailable"),
        NormalizeError::History(_) => (StatusCode::BAD_GATEWAY, "generator_unavailable"),
        NormalizeError::MissingMessageBuffer => {
            (StatusCode::INTERNAL_SERVER_ERROR, "normalization_failed")
        }
    };
    (status, Json(ErrorResponse { error })).into_response()
}

fn generator_failure(_error: GeneratorError) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse {
            error: "generator_unavailable",
        }),
    )
        .into_response()
}

pub(crate) fn trusted(headers: &HeaderMap) -> TrustedHookContext {
    TrustedHookContext::from_headers(headers)
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedHookContext {
    pub client_id: Option<String>,
    pub repository: Option<String>,
    /// The user of the Hook's verified key, as the key check set it.
    pub user: Option<String>,
}

impl TrustedHookContext {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            client_id: header_value(headers, CLIENT_HEADER),
            repository: header_value(headers, REPOSITORY_HEADER),
            user: header_value(headers, USER_HEADER),
        }
    }
}

pub(crate) fn header_value(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(crate) struct StrictJson<T>(pub(crate) T);

impl<S, T> FromRequest<S> for StrictJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = StrictJsonRejection;
    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| {
                if rejection.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                    StrictJsonRejection::UnsupportedMediaType
                } else {
                    StrictJsonRejection::InvalidJson
                }
            })
    }
}

pub(crate) enum StrictJsonRejection {
    InvalidJson,
    UnsupportedMediaType,
}

impl IntoResponse for StrictJsonRejection {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::InvalidJson => (StatusCode::BAD_REQUEST, "invalid_json"),
            Self::UnsupportedMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
        };
        (status, Json(ErrorResponse { error })).into_response()
    }
}

#[derive(Serialize, ToSchema)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: &'static str,
}
