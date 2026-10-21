use std::{sync::Arc, time::Instant};

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
use withhuman_contracts::{
    decisions::{DecisionRequest, EnforcementMode},
    events::EventResponse,
};

use crate::{DecisionClient, GeneratorEvent, GraphRepository};

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
event_handler!(post_tool_use, PostToolUseEventRequest, PostToolUse);
event_handler!(
    post_tool_use_failure,
    PostToolUseFailureEventRequest,
    PostToolUseFailure
);

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
