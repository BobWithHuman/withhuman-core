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
    routing::{get, post},
};
use serde::{Serialize, de::DeserializeOwned};
use utoipa::{OpenApi, ToSchema};
use withhuman_common::intent::split_intent;
use withhuman_contracts::{
    codex::{CodexHookEvent, CodexHookInput, CodexShell},
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
    codex::{self, Translated},
    inventory::{self, USER_HEADER},
    keys::KeyVerifier,
    redis_connection,
};

pub(crate) const CLIENT_HEADER: &str = "x-withhuman-client";
const REPOSITORY_HEADER: &str = "x-withhuman-repo";
/// The shell a Codex client runs commands in (`powershell`, else POSIX).
const SHELL_HEADER: &str = "x-withhuman-shell";
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
    deliveries: Arc<crate::codex_delivery::Deliveries>,
}

impl CollectorService {
    pub fn new(config: CollectorConfig, generator: Arc<dyn GeneratorTransport>) -> Self {
        let verdicts = Arc::new(InMemoryVerdictStore::new(config.verdict_capacity));
        Self {
            keys: KeyVerifier::new(generator.clone(), config.key_cache),
            flags: crate::flags::FlagCache::new(generator.clone(), config.key_cache),
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
        .route("/v1/hooks/codex/{event}", post(codex_hook))
        .route_layer(axum::middleware::from_fn_with_state(
            service.clone(),
            inventory::authenticate,
        ));
    Router::new()
        .route("/healthz", get(health))
        .merge(hooks)
        .route("/v1/clients/register", post(inventory::register_client))
        .route("/v1/admin/clients", get(inventory::clients))
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
        codex_hook,
        inventory::register_client,
        inventory::issue_key,
        inventory::user_keys,
        inventory::all_keys,
        inventory::revoke_key,
        inventory::revoke_user,
        inventory::stop_session,
        inventory::release_session,
        inventory::add_review,
        inventory::clients
    ),
    tags(
        (name = "Collector", description = "Claude Code Hook ingestion and enforcement API"),
        (name = "Inventory", description = "Device registration and per-user WithHuman keys")
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
    let event = match service
        .normalizer
        .session_start(&trusted(&headers), request, now())
        .await
    {
        Ok(event) => event,
        Err(error) => return normalize_failure(error),
    };
    match tokio::time::timeout(
        service.config.decision_budget,
        service.generator.send(event),
    )
    .await
    {
        Ok(Ok(_)) => Json(HookSpecificResponse {
            hook_specific_output: SessionStartOutput {
                hook_event_name: HookEventName::SessionStart,
                watch_paths: service.config.watch_paths.clone(),
            },
        })
        .into_response(),
        Ok(Err(error)) => generator_failure(error),
        Err(_) => generator_failure(GeneratorError::Timeout),
    }
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
    ($name:ident, $request:ty, $normalize:ident, $event:ident, $path:literal) => {
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
            let session_id = request.session_id.clone();
            let agent_id = request.agent_id.clone();
            let response = match service
                .normalizer
                .$normalize(&trusted(&headers), request, now())
                .await
            {
                Ok(event) => send_regular(&service, event).await,
                Err(error) => return normalize_failure(error),
            };
            remind_of_intent(
                &service,
                response,
                HookEventName::$event,
                &session_id,
                agent_id.as_deref(),
            )
            .await
        }
    };
}

result_handler!(
    post_tool_use,
    PostToolUseRequest,
    post_tool_use,
    PostToolUse,
    "/v1/hooks/PostToolUse"
);
result_handler!(
    post_tool_use_failure,
    PostToolUseFailureRequest,
    post_tool_use_failure,
    PostToolUseFailure,
    "/v1/hooks/PostToolUseFailure"
);

/// A recorded tool result of a turn that states no intent yet carries a request for it to the
/// model, once per turn. Unlike a denied Call, nothing shows on the user's screen.
async fn remind_of_intent(
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

async fn submit_prompt(
    service: &CollectorService,
    context: &TrustedHookContext,
    request: UserPromptSubmitRequest,
    tag: Option<&CodexTag<'_>>,
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
    // The first flush shows everything but the intent line, which only the engine keeps. Claude
    // Code shows the original for an empty replacement, so a flush of the intent line alone is
    // replaced by an invisible character.
    let display = (service.config.intent_capture && request.index.unwrap_or(0) == 0)
        .then(|| split_intent(&request.delta))
        .flatten()
        .map(|line| match line.rest {
            "" => HIDDEN_LINE.to_owned(),
            rest => rest.to_owned(),
        });
    let response = match service
        .normalizer
        .message_display(&trusted(&headers), request, now())
        .await
    {
        Ok(events) => send_all(&service, events).await,
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
    let policy = HookPolicy {
        review: service.config.review_policy,
        mcp_at_hook: service.config.enforce_mcp_at_hook,
        failure: service.config.failure_policy,
        codex: false,
    };
    judge_call(&service, &trusted(&headers), request, policy, None).await
}

/// How a client's Hook answers a verdict.
#[derive(Debug, Clone, Copy)]
struct HookPolicy {
    review: ReviewPolicy,
    /// MCP calls are enforced by the Hook rather than by AgentGateway.
    mcp_at_hook: bool,
    failure: FailurePolicy,
    codex: bool,
}

async fn judge_call(
    service: &CollectorService,
    context: &TrustedHookContext,
    request: PreToolUseRequest,
    policy: HookPolicy,
    tag: Option<&CodexTag<'_>>,
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
        Err(error) => return hook_failure(service, policy, error),
    };
    let result = tokio::time::timeout(
        service.config.decision_budget,
        service.generator.send(event),
    )
    .await;
    let response = match result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => return hook_failure(service, policy, error),
        Err(_) => return hook_failure(service, policy, GeneratorError::Timeout),
    };
    let Some(decision) = response.decision_response else {
        return hook_failure(
            service,
            policy,
            GeneratorError::InvalidResponse("missing decision_response".to_owned()),
        );
    };
    if decision.validate().is_err() {
        return hook_failure(
            service,
            policy,
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
        return hook_failure(service, policy, "verdict store unavailable");
    }
    if !enforced_at_hook {
        // AgentGateway enforces this call and needs the stored verdict; without it the
        // extAuthz check denies, so the Hook answer follows the failure policy.
        return match stored {
            Ok(()) => StatusCode::OK.into_response(),
            Err(error) => hook_failure(service, policy, error),
        };
    }
    // The verdict is in hand, so a store failure must not override it (a DENY must never turn
    // into ALLOW under the open failure policy).
    decision_response(decision, policy.review)
}

/// Marks a Codex session's events; Claude Code's pass unchanged.
struct CodexTag<'a> {
    /// The Hook as Codex sent it; none for events the bridge made itself.
    payload: Option<&'a serde_json::Value>,
    workdir_unknown: bool,
}

fn tagged(mut event: crate::NormalizedEvent, tag: Option<&CodexTag<'_>>) -> crate::NormalizedEvent {
    if let Some(tag) = tag {
        codex::tag(&mut event, tag.payload, tag.workdir_unknown);
    }
    event
}

/// Codex has no way to ask the user, and an `ask` it receives fails the Hook and lets the call
/// run; MCP calls do not pass AgentGateway. So a REVIEW denies and the Hook enforces MCP calls.
const CODEX_POLICY: HookPolicy = HookPolicy {
    review: ReviewPolicy::Deny,
    mcp_at_hook: true,
    failure: FailurePolicy::Closed,
    codex: true,
};

#[utoipa::path(
    post,
    path = "/v1/hooks/codex/{event}",
    tag = "Collector",
    params(
        ("event" = String, Path, description = "Codex Hook event, or MessageDisplay / PostToolBatch made by the bridge"),
        ("X-WithHuman-Repo" = Option<String>, Header, description = "Repository identity"),
        ("X-WithHuman-Client" = Option<String>, Header, description = "Client identity"),
        ("X-WithHuman-Shell" = Option<String>, Header, description = "`powershell` when the client's shell is PowerShell")
    ),
    request_body = CodexHookInput,
    responses(
        (status = 200, description = "Empty, or Codex Hook output: additional context, or a deny for the call", body = HookSpecificResponse<PreToolUseOutput>),
        (status = 400, description = "Invalid JSON or Hook", body = ErrorResponse),
        (status = 404, description = "Unknown event", body = ErrorResponse),
        (status = 415, body = ErrorResponse),
        (status = 502, description = "Generator or session store unavailable", body = ErrorResponse)
    )
)]
/// A Codex Hook, translated to its Claude Code counterpart and handled by the same code.
async fn codex_hook(
    State(service): State<CollectorService>,
    Path(event): Path<String>,
    headers: HeaderMap,
    StrictJson(raw): StrictJson<serde_json::Value>,
) -> Response {
    let Some(id) = headers
        .get("x-withhuman-event")
        .and_then(|v| v.to_str().ok())
    else {
        return codex_hook_inner(service, event, headers, raw).await;
    };
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error(StatusCode::BAD_REQUEST, "invalid_delivery_id");
    }
    // Bind the receipt to both the event payload and the trusted client context.
    let request = withhuman_common::chunking::sha256(
        &serde_json::json!([
            event,
            raw,
            header_value(&headers, CLIENT_HEADER),
            header_value(&headers, REPOSITORY_HEADER),
            header_value(&headers, SHELL_HEADER)
        ])
        .to_string(),
    );
    let key = format!("withhuman:codex:delivery:{id}");
    match service.deliveries.begin(&key, &request).await {
        Ok(Some(receipt)) if receipt.request == request => {
            return match receipt.reply {
                Some(reply) => (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    reply,
                )
                    .into_response(),
                None => error(StatusCode::CONFLICT, "codex_resync_required"),
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
    let response = codex_hook_inner(service.clone(), event, headers, raw).await;
    if response.status() != StatusCode::OK {
        return response;
    }
    let Ok(bytes) = axum::body::to_bytes(response.into_body(), 1024 * 1024).await else {
        return error(StatusCode::CONFLICT, "codex_resync_required");
    };
    let Ok(reply) = String::from_utf8(bytes.to_vec()) else {
        return error(StatusCode::CONFLICT, "codex_resync_required");
    };
    if service
        .deliveries
        .finish(&key, &request, reply.clone())
        .await
        .is_err()
    {
        return error(StatusCode::CONFLICT, "codex_resync_required");
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        reply,
    )
        .into_response()
}

async fn codex_hook_inner(
    service: CollectorService,
    event: String,
    headers: HeaderMap,
    raw: serde_json::Value,
) -> Response {
    let Some(event) = CodexHookEvent::from_path(&event) else {
        return error(StatusCode::NOT_FOUND, "unknown_event");
    };
    let context = trusted(&headers);
    let made_by_bridge = CodexTag {
        payload: None,
        workdir_unknown: false,
    };
    match event {
        CodexHookEvent::MessageDisplay => {
            let Ok(request) = serde_json::from_value::<MessageDisplayRequest>(raw) else {
                return error(StatusCode::BAD_REQUEST, "invalid_json");
            };
            // Codex cannot hide text it shows, so only the events matter.
            return match service
                .normalizer
                .message_display(&context, request, now())
                .await
            {
                Ok(events) => {
                    let events = events
                        .into_iter()
                        .map(|event| tagged(event, Some(&made_by_bridge)))
                        .collect();
                    send_all(&service, events).await
                }
                Err(error) => normalize_failure(error),
            };
        }
        CodexHookEvent::PostToolBatch => {
            let Ok(request) = serde_json::from_value::<PostToolBatchRequest>(raw) else {
                return error(StatusCode::BAD_REQUEST, "invalid_json");
            };
            return match service
                .normalizer
                .post_tool_batch(&context, request, now())
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, Some(&made_by_bridge))).await,
                Err(error) => normalize_failure(error),
            };
        }
        _ => {}
    }
    let Ok(input) = serde_json::from_value::<CodexHookInput>(raw.clone()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_json");
    };
    let shell = CodexShell::from_header(header_value(&headers, SHELL_HEADER).as_deref());
    let record = input.withhuman_record;
    if record && !codex::valid_record(event, &input) {
        return error(StatusCode::BAD_REQUEST, "invalid_record_tool");
    }
    let Ok(translation) = codex::translate(event, input, shell) else {
        return error(StatusCode::BAD_REQUEST, "invalid_codex_hook");
    };
    // Program files are kept with the Call already; the copy keeps the rest as sent.
    let mut payload = raw;
    if let Some(fields) = payload.as_object_mut() {
        fields.remove("withhuman_programs");
    }
    let tag = CodexTag {
        payload: Some(&payload),
        workdir_unknown: translation.workdir_unknown,
    };
    match translation.request {
        Translated::SessionStart(request) => {
            match service
                .normalizer
                .session_start(&context, request, now())
                .await
            {
                // Watched paths are a Claude Code feature; Codex gets no output.
                Ok(event) => send_regular(&service, tagged(event, Some(&tag))).await,
                Err(error) => normalize_failure(error),
            }
        }
        Translated::UserPromptSubmit(request) => {
            submit_prompt(&service, &context, request, Some(&tag)).await
        }
        Translated::PreToolUse(request) if record => {
            // A web search Codex ran without a Hook, found later in the transcript: it already
            // happened, so it is recorded and judged in the background, never blocked.
            let deadline_ms = u64::try_from(service.config.decision_budget.as_millis()).ok();
            let event = match service
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
                Ok(event) => event,
                Err(error) => return normalize_failure(error),
            };
            send_regular(&service, tagged(event, Some(&tag))).await
        }
        Translated::PreToolUse(request) => {
            judge_call(&service, &context, request, CODEX_POLICY, Some(&tag)).await
        }
        Translated::PostToolUse(request) => {
            let (session_id, agent_id) = (request.session_id.clone(), request.agent_id.clone());
            let response = match service
                .normalizer
                .post_tool_use(&context, request, now())
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, Some(&tag))).await,
                Err(error) => return normalize_failure(error),
            };
            remind_of_intent(
                &service,
                response,
                HookEventName::PostToolUse,
                &session_id,
                agent_id.as_deref(),
            )
            .await
        }
        Translated::PostToolUseFailure(request) => {
            let (session_id, agent_id) = (request.session_id.clone(), request.agent_id.clone());
            let response = match service
                .normalizer
                .post_tool_use_failure(&context, request, now())
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, Some(&tag))).await,
                Err(error) => return normalize_failure(error),
            };
            // Codex ran a PostToolUse Hook; it reads output for that event only.
            remind_of_intent(
                &service,
                response,
                HookEventName::PostToolUse,
                &session_id,
                agent_id.as_deref(),
            )
            .await
        }
        Translated::PostToolBatch(request) => {
            match service
                .normalizer
                .post_tool_batch(&context, request, now())
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, Some(&tag))).await,
                Err(error) => normalize_failure(error),
            }
        }
        Translated::SubagentStart(request) => {
            match service
                .normalizer
                .subagent_start(&context, request, now())
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, Some(&tag))).await,
                Err(error) => normalize_failure(error),
            }
        }
        Translated::SubagentStop(request) => {
            match service
                .normalizer
                .subagent_stop(&context, request, now())
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, Some(&tag))).await,
                Err(error) => normalize_failure(error),
            }
        }
        Translated::SessionEnd(request) => {
            match service
                .normalizer
                .session_end(&context, request, now())
                .await
            {
                Ok(event) => send_regular(&service, tagged(event, Some(&tag))).await,
                Err(error) => normalize_failure(error),
            }
        }
        Translated::Nothing => StatusCode::OK.into_response(),
    }
}

fn error(status: StatusCode, error: &'static str) -> Response {
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
    error: impl fmt::Display,
) -> Response {
    // Record and shadow modes observe only: a failure must not block either. (Record mode never
    // waits for a decision, so a missing one is expected there.)
    if service.config.enforcement_mode != EnforcementMode::Enforce {
        return StatusCode::OK.into_response();
    }
    match policy.failure {
        FailurePolicy::Open => StatusCode::OK.into_response(),
        FailurePolicy::Closed => {
            let mut response = blocking_response(
                PermissionDecision::Deny,
                if policy.codex {
                    "WithHuman could not check this call, so it was blocked".to_owned()
                } else {
                    error.to_string()
                },
            );
            // A normalizer or downstream error can have applied only part of the event.
            // Leave its delivery pending and make the bridge require a fresh session.
            if policy.codex {
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

async fn send_regular(service: &CollectorService, event: crate::NormalizedEvent) -> Response {
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
async fn send_all(service: &CollectorService, events: Vec<crate::NormalizedEvent>) -> Response {
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
fn normalize_failure(error: NormalizeError) -> Response {
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

fn trusted(headers: &HeaderMap) -> TrustedHookContext {
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
