use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{FromRequest, Request, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Serialize, de::DeserializeOwned};
use utoipa::{OpenApi, ToSchema};
use withhuman_contracts::decisions::{DecisionRequest, DecisionResponse};

use crate::{DecisionProvider, DecisionRepository, RepositoryError};

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
pub struct DecisionService {
    repository: Arc<dyn DecisionRepository>,
    provider: Arc<dyn DecisionProvider>,
}

impl DecisionService {
    pub fn new(repository: impl DecisionRepository, provider: impl DecisionProvider) -> Self {
        Self {
            repository: Arc::new(repository),
            provider: Arc::new(provider),
        }
    }

    pub fn from_shared(
        repository: Arc<dyn DecisionRepository>,
        provider: Arc<dyn DecisionProvider>,
    ) -> Self {
        Self {
            repository,
            provider,
        }
    }
}

pub fn app(service: DecisionService) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/decide", post(decide))
        .route("/api-docs/openapi.json", get(openapi_document))
        .route("/swagger-ui", get(swagger_ui))
        .route("/swagger-ui/", get(swagger_ui))
        .with_state(service)
}

#[derive(OpenApi)]
#[openapi(
    paths(health, decide),
    tags((name = "Decision", description = "Graph-backed policy decision API"))
)]
struct DecisionApiDoc;

async fn openapi_document() -> Json<utoipa::openapi::OpenApi> {
    Json(DecisionApiDoc::openapi())
}

async fn swagger_ui() -> Html<&'static str> {
    Html(SWAGGER_UI_HTML)
}

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "Decision",
    responses((status = 200, body = HealthResponse), (status = 503, body = ErrorResponse))
)]
async fn health(State(service): State<DecisionService>) -> Response {
    match service.repository.health().await {
        Ok(()) => Json(HealthResponse {
            status: "ok",
            service: "decision",
        })
        .into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "neo4j_unavailable"),
    }
}

#[utoipa::path(
    post,
    path = "/v1/decide",
    tag = "Decision",
    request_body = DecisionRequest,
    responses(
        (status = 200, description = "Decision produced and persistence attempted", body = DecisionResponse),
        (status = 400, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 415, body = ErrorResponse),
        (status = 500, body = ErrorResponse),
        (status = 503, body = ErrorResponse),
        (status = 504, body = ErrorResponse)
    )
)]
async fn decide(
    State(service): State<DecisionService>,
    StrictJson(request): StrictJson<DecisionRequest>,
) -> Response {
    match service.repository.verify_graph(&request).await {
        Ok(()) => {}
        Err(RepositoryError::NotFound) => {
            return error(StatusCode::NOT_FOUND, "graph_version_or_call_not_found");
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "neo4j_unavailable"),
    }

    let provider = service.provider.decide(&request);
    let provider_result = match request.deadline_ms {
        Some(0) => return error(StatusCode::GATEWAY_TIMEOUT, "decision_deadline_exceeded"),
        Some(deadline_ms) => {
            match tokio::time::timeout(Duration::from_millis(deadline_ms), provider).await {
                Ok(result) => result,
                Err(_) => return error(StatusCode::GATEWAY_TIMEOUT, "decision_deadline_exceeded"),
            }
        }
        None => provider.await,
    };
    let mut response: DecisionResponse = match provider_result {
        Ok(response) => response,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "decision_provider_failed",
            );
        }
    };
    if response.validate().is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_provider_response",
        );
    }
    response.written = service
        .repository
        .persist(&request, &response)
        .await
        .is_ok();
    Json(response).into_response()
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorResponse { error: message })).into_response()
}

struct StrictJson<T>(T);

impl<S, T> FromRequest<S> for StrictJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| {
                let status = if rejection.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                    StatusCode::UNSUPPORTED_MEDIA_TYPE
                } else {
                    StatusCode::BAD_REQUEST
                };
                error(status, "invalid_json")
            })
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
