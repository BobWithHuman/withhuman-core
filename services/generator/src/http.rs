use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{FromRequest, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Serialize, de::DeserializeOwned};
use withhuman_contracts::events::{
    ConfigChangeEventRequest, FileChangedEventRequest, InstructionsLoadedEventRequest,
    MessageDisplayEventRequest, PostToolBatchEventRequest, PostToolUseEventRequest,
    PostToolUseFailureEventRequest, PreToolUseEventRequest, SessionStartEventRequest,
    SubagentStartEventRequest, SubagentStopEventRequest, ToolDescriptionsEventRequest,
    UserPromptSubmitEventRequest,
};

use crate::{GeneratorEvent, GraphRepository};

#[derive(Clone)]
pub struct GeneratorService {
    repository: Arc<dyn GraphRepository>,
}

impl GeneratorService {
    pub fn new(repository: impl GraphRepository) -> Self {
        Self {
            repository: Arc::new(repository),
        }
    }

    pub fn from_shared(repository: Arc<dyn GraphRepository>) -> Self {
        Self { repository }
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
        .with_state(service)
}

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
    ($handler:ident, $request:ty, $variant:ident) => {
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

event_handler!(session_start, SessionStartEventRequest, SessionStart);
event_handler!(
    user_prompt_submit,
    UserPromptSubmitEventRequest,
    UserPromptSubmit
);
event_handler!(pre_tool_use, PreToolUseEventRequest, PreToolUse);
event_handler!(post_tool_use, PostToolUseEventRequest, PostToolUse);
event_handler!(
    post_tool_use_failure,
    PostToolUseFailureEventRequest,
    PostToolUseFailure
);
event_handler!(subagent_start, SubagentStartEventRequest, SubagentStart);
event_handler!(subagent_stop, SubagentStopEventRequest, SubagentStop);
event_handler!(
    instructions_loaded,
    InstructionsLoadedEventRequest,
    InstructionsLoaded
);
event_handler!(config_change, ConfigChangeEventRequest, ConfigChange);
event_handler!(file_changed, FileChangedEventRequest, FileChanged);
event_handler!(message_display, MessageDisplayEventRequest, MessageDisplay);
event_handler!(post_tool_batch, PostToolBatchEventRequest, PostToolBatch);
event_handler!(
    tool_descriptions,
    ToolDescriptionsEventRequest,
    ToolDescriptions
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

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}
