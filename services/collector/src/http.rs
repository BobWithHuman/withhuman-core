use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Serialize, de::DeserializeOwned};
use withhuman_contracts::{
    decisions::{Decision, DecisionResponse},
    events::EventResponse,
    hooks::{
        ConfigChangeRequest, FileChangedRequest, HookEventName, HookSpecificResponse,
        InstructionsLoadedRequest, MessageDisplayRequest, PermissionDecision, PostToolBatchRequest,
        PostToolUseFailureRequest, PostToolUseRequest, PreToolUseOutput, PreToolUseRequest,
        SessionStartOutput, SessionStartRequest, SubagentLifecycleRequest, ToolDescriptionsRequest,
        UserPromptSubmitRequest,
    },
};

use crate::{
    CollectorConfig, FailurePolicy, GeneratorError, GeneratorHttpClient, GeneratorTransport,
    Normalizer, ReviewPolicy, VerdictStore,
};

const CLIENT_HEADER: &str = "x-withhuman-client";
const REPOSITORY_HEADER: &str = "x-withhuman-repo";

#[derive(Clone)]
pub struct CollectorService {
    pub config: CollectorConfig,
    pub normalizer: Normalizer,
    pub generator: Arc<dyn GeneratorTransport>,
    pub verdicts: VerdictStore,
}

impl CollectorService {
    pub fn new(config: CollectorConfig, generator: Arc<dyn GeneratorTransport>) -> Self {
        let verdicts = VerdictStore::new(config.verdict_capacity);
        Self {
            config,
            normalizer: Normalizer::default(),
            generator,
            verdicts,
        }
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
        .with_state(service)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "collector",
    })
}

async fn session_start(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<SessionStartRequest>,
) -> Response {
    let event = service
        .normalizer
        .session_start(&trusted(&headers), request, now());
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
    ($name:ident, $request:ty, $normalize:ident) => {
        async fn $name(
            State(service): State<CollectorService>,
            headers: HeaderMap,
            StrictJson(request): StrictJson<$request>,
        ) -> Response {
            let event = service
                .normalizer
                .$normalize(&trusted(&headers), request, now());
            send_regular(&service, event).await
        }
    };
}

regular_handler!(
    user_prompt_submit,
    UserPromptSubmitRequest,
    user_prompt_submit
);
regular_handler!(post_tool_use, PostToolUseRequest, post_tool_use);
regular_handler!(
    post_tool_use_failure,
    PostToolUseFailureRequest,
    post_tool_use_failure
);
regular_handler!(
    instructions_loaded,
    InstructionsLoadedRequest,
    instructions_loaded
);
regular_handler!(config_change, ConfigChangeRequest, config_change);
regular_handler!(file_changed, FileChangedRequest, file_changed);
regular_handler!(post_tool_batch, PostToolBatchRequest, post_tool_batch);
regular_handler!(
    tool_descriptions,
    ToolDescriptionsRequest,
    tool_descriptions
);

async fn subagent_start(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<SubagentLifecycleRequest>,
) -> Response {
    let event = service
        .normalizer
        .subagent_start(&trusted(&headers), request, now());
    send_regular(&service, event).await
}

async fn subagent_stop(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<SubagentLifecycleRequest>,
) -> Response {
    let event = service
        .normalizer
        .subagent_stop(&trusted(&headers), request, now());
    send_regular(&service, event).await
}

async fn message_display(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<MessageDisplayRequest>,
) -> Response {
    match service
        .normalizer
        .message_display(&trusted(&headers), request, now())
    {
        Ok(Some(event)) => send_regular(&service, event).await,
        Ok(None) => StatusCode::OK.into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "normalization_failed",
            }),
        )
            .into_response(),
    }
}

async fn pre_tool_use(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<PreToolUseRequest>,
) -> Response {
    let tool_use_id = request.tool_use_id.clone();
    let is_mcp = request.tool_name.starts_with("mcp__");
    let deadline_ms = u64::try_from(service.config.decision_budget.as_millis()).ok();
    let event = service.normalizer.pre_tool_use(
        &trusted(&headers),
        request,
        now(),
        service.config.enforcement_mode,
        deadline_ms,
    );
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
    service.verdicts.insert(tool_use_id, decision.clone());
    if is_mcp && !service.config.enforce_mcp_at_hook {
        return StatusCode::OK.into_response();
    }
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

fn pre_tool_failure(service: &CollectorService, error: GeneratorError) -> Response {
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

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}
