use std::{sync::Arc, time::Instant};

use axum::{
    Json, Router,
    extract::{FromRequest, Path, Request, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post},
};
use serde::{Serialize, de::DeserializeOwned};
use utoipa::{OpenApi, ToSchema};
use withhuman_contracts::events::{
    ConfigChangeEventRequest, FileChangedEventRequest, InstructionsLoadedEventRequest,
    MessageDisplayEventRequest, ParagraphClassificationRequest, PostToolBatchEventRequest,
    PostToolUseEventRequest, PostToolUseFailureEventRequest, PreToolUseEventRequest,
    RequestContinuationRequest, SessionStartEventRequest, SubagentStartEventRequest,
    SubagentStopEventRequest, ToolDescriptionsEventRequest, UserPromptSubmitEventRequest,
};
use withhuman_contracts::{
    decisions::{DecisionRequest, EnforcementMode},
    events::EventResponse,
};

use crate::{DecisionClient, GeneratorEvent, GraphRepository, RepositoryError};

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
pub struct GeneratorService {
    repository: Arc<dyn GraphRepository>,
    decision: Option<Arc<dyn DecisionClient>>,
}

impl GeneratorService {
    pub fn new(repository: impl GraphRepository) -> Self {
        Self {
            repository: Arc::new(repository),
            decision: None,
        }
    }

    pub fn from_shared(repository: Arc<dyn GraphRepository>) -> Self {
        Self {
            repository,
            decision: None,
        }
    }

    pub fn with_decision(repository: impl GraphRepository, decision: impl DecisionClient) -> Self {
        Self {
            repository: Arc::new(repository),
            decision: Some(Arc::new(decision)),
        }
    }

    pub fn from_shared_with_decision(
        repository: Arc<dyn GraphRepository>,
        decision: Arc<dyn DecisionClient>,
    ) -> Self {
        Self {
            repository,
            decision: Some(decision),
        }
    }
}

pub fn app(service: GeneratorService) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/events/SessionStart", post(session_start))
        .route("/v1/events/UserPromptSubmit", post(user_prompt_submit))
        .route("/v1/events/PreToolUse", post(pre_tool_use))
        .route("/v1/events/PostToolUse", post(post_tool_use))
        .route("/v1/events/PostToolUseFailure", post(post_tool_use_failure))
        .route("/v1/events/SubagentStart", post(subagent_start))
        .route("/v1/events/SubagentStop", post(subagent_stop))
        .route("/v1/events/InstructionsLoaded", post(instructions_loaded))
        .route("/v1/events/ConfigChange", post(config_change))
        .route("/v1/events/FileChanged", post(file_changed))
        .route("/v1/events/MessageDisplay", post(message_display))
        .route("/v1/events/PostToolBatch", post(post_tool_batch))
        .route("/v1/events/ToolDescriptions", post(tool_descriptions))
        .route(
            "/v1/sessions/{session_id}/paragraphs/{hash}",
            patch(classify_paragraph),
        )
        .route(
            "/v1/sessions/{session_id}/requests/{order}",
            patch(continue_request),
        )
        .route("/v1/sessions/{session_id}/cursor", get(session_cursor))
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
        tool_descriptions,
        classify_paragraph,
        continue_request,
        session_cursor
    ),
    tags((name = "Generator", description = "Normalized event persistence and graph enrichment API"))
)]
struct GeneratorApiDoc;

async fn openapi_document() -> Json<utoipa::openapi::OpenApi> {
    Json(GeneratorApiDoc::openapi())
}

async fn swagger_ui() -> Html<&'static str> {
    Html(SWAGGER_UI_HTML)
}

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "Generator",
    responses((status = 200, body = HealthResponse), (status = 503, body = ErrorResponse))
)]
async fn health(State(service): State<GeneratorService>) -> Response {
    match service.repository.health().await {
        Ok(()) => Json(HealthResponse {
            status: "ok",
            service: "generator",
        })
        .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "neo4j_unavailable",
            }),
        )
            .into_response(),
    }
}

macro_rules! event_handler {
    ($handler:ident, $request:ty, $variant:ident, $path:literal) => {
        #[utoipa::path(
            post,
            path = $path,
            tag = "Generator",
            request_body = $request,
            responses(
                (status = 200, description = "Graph mutation committed", body = EventResponse),
                (status = 400, body = ErrorResponse),
                (status = 415, body = ErrorResponse),
                (status = 500, body = ErrorResponse)
            )
        )]
        async fn $handler(
            State(service): State<GeneratorService>,
            StrictJson(request): StrictJson<$request>,
        ) -> Response {
            match service
                .repository
                .commit(GeneratorEvent::$variant(request))
                .await
            {
                Ok(response) => Json(response).into_response(),
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "graph_commit_failed",
                    }),
                )
                    .into_response(),
            }
        }
    };
}

event_handler!(
    session_start,
    SessionStartEventRequest,
    SessionStart,
    "/v1/events/SessionStart"
);
event_handler!(
    user_prompt_submit,
    UserPromptSubmitEventRequest,
    UserPromptSubmit,
    "/v1/events/UserPromptSubmit"
);
event_handler!(
    post_tool_use,
    PostToolUseEventRequest,
    PostToolUse,
    "/v1/events/PostToolUse"
);
event_handler!(
    post_tool_use_failure,
    PostToolUseFailureEventRequest,
    PostToolUseFailure,
    "/v1/events/PostToolUseFailure"
);

#[utoipa::path(
    post,
    path = "/v1/events/PreToolUse",
    tag = "Generator",
    request_body = PreToolUseEventRequest,
    responses(
        (status = 200, description = "Call persisted with an optional decision", body = EventResponse),
        (status = 400, body = ErrorResponse),
        (status = 415, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    )
)]
async fn pre_tool_use(
    State(service): State<GeneratorService>,
    StrictJson(request): StrictJson<PreToolUseEventRequest>,
) -> Response {
    let started = Instant::now();
    let session_id = request.event.session_id.clone();
    let mode = request.mode;
    let deadline_ms = request.deadline_ms;
    let mut response = match service
        .repository
        .commit(GeneratorEvent::PreToolUse(request))
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "graph_commit_failed",
                }),
            )
                .into_response();
        }
    };

    let Some(decision) = service.decision else {
        return Json(response).into_response();
    };
    let Some(call_seq) = response
        .nodes
        .iter()
        .find(|node| node.node_type == "Call")
        .map(|node| node.seq)
    else {
        return Json(response).into_response();
    };
    let remaining_ms = deadline_ms.map(|budget| {
        budget.saturating_sub(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
    });
    let decision_request = DecisionRequest {
        session_id,
        call_seq,
        graph_version: response.version,
        mode,
        deadline_ms: if mode == EnforcementMode::Record {
            None
        } else {
            remaining_ms
        },
    };

    if mode == EnforcementMode::Record {
        tokio::spawn(async move {
            let _ = decision.decide(decision_request).await;
        });
    } else if remaining_ms != Some(0) {
        response.decision_response = decision.decide(decision_request).await.ok();
    }

    Json::<EventResponse>(response).into_response()
}

#[utoipa::path(
    patch,
    path = "/v1/sessions/{session_id}/paragraphs/{hash}",
    tag = "Generator",
    params(("session_id" = String, Path), ("hash" = String, Path)),
    request_body = ParagraphClassificationRequest,
    responses(
        (status = 200, body = withhuman_contracts::events::ParagraphClassificationResponse),
        (status = 400, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 415, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    )
)]
async fn classify_paragraph(
    State(service): State<GeneratorService>,
    Path((session_id, hash)): Path<(String, String)>,
    StrictJson(request): StrictJson<ParagraphClassificationRequest>,
) -> Response {
    match service
        .repository
        .classify_paragraph(&session_id, &hash, request)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => repository_error_response(error),
    }
}

#[utoipa::path(
    patch,
    path = "/v1/sessions/{session_id}/requests/{order}",
    tag = "Generator",
    params(("session_id" = String, Path), ("order" = u64, Path)),
    request_body = RequestContinuationRequest,
    responses(
        (status = 200, body = withhuman_contracts::events::RequestContinuationResponse),
        (status = 400, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 415, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    )
)]
async fn continue_request(
    State(service): State<GeneratorService>,
    Path((session_id, order)): Path<(String, u64)>,
    StrictJson(request): StrictJson<RequestContinuationRequest>,
) -> Response {
    match service
        .repository
        .continue_request(&session_id, order, request)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => repository_error_response(error),
    }
}

#[utoipa::path(
    get,
    path = "/v1/sessions/{session_id}/cursor",
    tag = "Generator",
    params(("session_id" = String, Path)),
    responses(
        (status = 200, description = "Last committed order and agent sequences; zero for an unknown session", body = withhuman_contracts::events::SessionCursor),
        (status = 500, body = ErrorResponse)
    )
)]
async fn session_cursor(
    State(service): State<GeneratorService>,
    Path(session_id): Path<String>,
) -> Response {
    match service.repository.session_cursor(&session_id).await {
        Ok(cursor) => Json(cursor).into_response(),
        Err(error) => repository_error_response(error),
    }
}

fn repository_error_response(error: RepositoryError) -> Response {
    let (status, message) = match error {
        RepositoryError::InvalidEvent(_) => (StatusCode::BAD_REQUEST, "invalid_enrichment"),
        RepositoryError::NotFound => (StatusCode::NOT_FOUND, "graph_resource_not_found"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "graph_update_failed"),
    };
    (status, Json(ErrorResponse { error: message })).into_response()
}
event_handler!(
    subagent_start,
    SubagentStartEventRequest,
    SubagentStart,
    "/v1/events/SubagentStart"
);
event_handler!(
    subagent_stop,
    SubagentStopEventRequest,
    SubagentStop,
    "/v1/events/SubagentStop"
);
event_handler!(
    instructions_loaded,
    InstructionsLoadedEventRequest,
    InstructionsLoaded,
    "/v1/events/InstructionsLoaded"
);
event_handler!(
    config_change,
    ConfigChangeEventRequest,
    ConfigChange,
    "/v1/events/ConfigChange"
);
event_handler!(
    file_changed,
    FileChangedEventRequest,
    FileChanged,
    "/v1/events/FileChanged"
);
event_handler!(
    message_display,
    MessageDisplayEventRequest,
    MessageDisplay,
    "/v1/events/MessageDisplay"
);
event_handler!(
    post_tool_batch,
    PostToolBatchEventRequest,
    PostToolBatch,
    "/v1/events/PostToolBatch"
);
event_handler!(
    tool_descriptions,
    ToolDescriptionsEventRequest,
    ToolDescriptions,
    "/v1/events/ToolDescriptions"
);

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
