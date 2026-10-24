use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Serialize, de::DeserializeOwned};
use utoipa::{OpenApi, ToSchema};
use withhuman_common::intent::split_intent;
use withhuman_contracts::{
    decisions::{Decision, DecisionResponse},
    events::EventResponse,
    hooks::{
        ConfigChangeRequest, FileChangedRequest, HookEventName, HookSpecificResponse,
        InstructionsLoadedRequest, MessageDisplayOutput, MessageDisplayRequest, PermissionDecision,
        PostToolBatchRequest, PostToolUseFailureRequest, PostToolUseRequest, PreToolUseOutput,
        PreToolUseRequest, SessionStartOutput, SessionStartRequest, SubagentLifecycleRequest,
        ToolDescriptionsRequest, UserPromptSubmitOutput, UserPromptSubmitRequest,
    },
};

use crate::{
    CollectorConfig, FailurePolicy, GeneratorError, GeneratorHttpClient, GeneratorTransport,
    InMemoryVerdictStore, NormalizeError, Normalizer, RedisSessionStore, RedisVerdictStore,
    ReviewPolicy, StoreError, StoredVerdict, VerdictStore, redis_connection,
};

const CLIENT_HEADER: &str = "x-withhuman-client";
const REPOSITORY_HEADER: &str = "x-withhuman-repo";
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
}

impl CollectorService {
    pub fn new(config: CollectorConfig, generator: Arc<dyn GeneratorTransport>) -> Self {
        let verdicts = Arc::new(InMemoryVerdictStore::new(config.verdict_capacity));
        Self {
            config,
            normalizer: Normalizer::default().with_history(generator.clone()),
            generator,
            verdicts,
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
            verdicts: Arc::new(RedisVerdictStore::new(
                connection.clone(),
                config.verdict_ttl,
            )),
            normalizer: Normalizer::new(RedisSessionStore::new(connection, config.session_ttl))
                .with_history(generator.clone()),
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
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/hooks/SessionStart", post(session_start))
        .route("/v1/hooks/UserPromptSubmit", post(user_prompt_submit))
        .route("/v1/hooks/PreToolUse", post(pre_tool_use))
        .route("/v1/hooks/PostToolUse", post(post_tool_use))
        .route("/v1/hooks/PostToolUseFailure", post(post_tool_use_failure))
        .route("/v1/hooks/SubagentStart", post(subagent_start))
        .route("/v1/hooks/SubagentStop", post(subagent_stop))
        .route("/v1/hooks/InstructionsLoaded", post(instructions_loaded))
        .route("/v1/hooks/ConfigChange", post(config_change))
        .route("/v1/hooks/FileChanged", post(file_changed))
        .route("/v1/hooks/MessageDisplay", post(message_display))
        .route("/v1/hooks/PostToolBatch", post(post_tool_batch))
        .route("/v1/hooks/ToolDescriptions", post(tool_descriptions))
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
        user_prompt_submit,
        pre_tool_use,
        post_tool_use,
        post_tool_use_failure,
        subagent_start,
        subagent_stop,
        instructions_loaded,
        config_change,
        file_changed,
        message_display,
        post_tool_batch,
        tool_descriptions
    ),
    tags((name = "Collector", description = "Claude Code Hook ingestion and enforcement API"))
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

regular_handler!(
    post_tool_use,
    PostToolUseRequest,
    post_tool_use,
    "/v1/hooks/PostToolUse"
);
regular_handler!(
    post_tool_use_failure,
    PostToolUseFailureRequest,
    post_tool_use_failure,
    "/v1/hooks/PostToolUseFailure"
);
regular_handler!(
    instructions_loaded,
    InstructionsLoadedRequest,
    instructions_loaded,
    "/v1/hooks/InstructionsLoaded"
);
regular_handler!(
    config_change,
    ConfigChangeRequest,
    config_change,
    "/v1/hooks/ConfigChange"
);
regular_handler!(
    file_changed,
    FileChangedRequest,
    file_changed,
    "/v1/hooks/FileChanged"
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
    let response = match service
        .normalizer
        .user_prompt_submit(&trusted(&headers), request, now())
        .await
    {
        Ok(event) => send_regular(&service, event).await,
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
    // The first flush shows everything but the intent line, which only the engine keeps.
    let display = (service.config.intent_capture && request.index.unwrap_or(0) == 0)
        .then(|| split_intent(&request.delta).map(|line| line.rest.to_owned()))
        .flatten();
    let response = match service
        .normalizer
        .message_display(&trusted(&headers), request, now())
        .await
    {
        Ok(Some(event)) => send_regular(&service, event).await,
        Ok(None) => StatusCode::OK.into_response(),
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
    let tool_use_id = request.tool_use_id.clone();
    let is_mcp = request.tool_name.starts_with("mcp__");
    let tool_name = request.tool_name.clone();
    let arguments = request.tool_input.clone();
    let deadline_ms = u64::try_from(service.config.decision_budget.as_millis()).ok();
    let event = match service
        .normalizer
        .pre_tool_use(
            &trusted(&headers),
            request,
            now(),
            service.config.enforcement_mode,
            deadline_ms,
        )
        .await
    {
        Ok(event) => event,
        Err(error) => return pre_tool_failure(&service, error),
    };
    let result = tokio::time::timeout(
        service.config.decision_budget,
        service.generator.send(event),
    )
    .await;
    let response = match result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => return pre_tool_failure(&service, error),
        Err(_) => return pre_tool_failure(&service, GeneratorError::Timeout),
    };
    let Some(decision) = response.decision_response else {
        return pre_tool_failure(
            &service,
            GeneratorError::InvalidResponse("missing decision_response".to_owned()),
        );
    };
    if decision.validate().is_err() {
        return pre_tool_failure(
            &service,
            GeneratorError::InvalidResponse("invalid decision semantics".to_owned()),
        );
    }
    let enforced_at_hook = !is_mcp || service.config.enforce_mcp_at_hook;
    let stored = service
        .verdicts
        .insert(
            tool_use_id,
            StoredVerdict::new(decision.clone(), tool_name, &arguments),
        )
        .await;
    if !enforced_at_hook {
        // AgentGateway enforces this call and needs the stored verdict; without it the
        // extAuthz check denies, so the Hook answer follows the failure policy.
        return match stored {
            Ok(()) => StatusCode::OK.into_response(),
            Err(error) => pre_tool_failure(&service, error),
        };
    }
    // The verdict is in hand, so a store failure must not override it (a DENY must never turn
    // into ALLOW under the open failure policy).
    decision_response(decision, service.config.review_policy)
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

fn blocking_response(permission_decision: PermissionDecision, reason: String) -> Response {
    Json(HookSpecificResponse {
        hook_specific_output: PreToolUseOutput {
            hook_event_name: HookEventName::PreToolUse,
            permission_decision,
            permission_decision_reason: reason,
        },
    })
    .into_response()
}

fn pre_tool_failure(service: &CollectorService, error: impl fmt::Display) -> Response {
    match service.config.failure_policy {
        FailurePolicy::Open => StatusCode::OK.into_response(),
        FailurePolicy::Closed => blocking_response(PermissionDecision::Deny, error.to_string()),
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

fn now() -> u64 {
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
}

impl TrustedHookContext {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            client_id: header_value(headers, CLIENT_HEADER),
            repository: header_value(headers, REPOSITORY_HEADER),
        }
    }
}

fn header_value(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

struct StrictJson<T>(T);

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

enum StrictJsonRejection {
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
