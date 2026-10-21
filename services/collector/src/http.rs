use axum::{
    Json, Router,
    extract::{FromRequest, Request},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

const CLIENT_HEADER: &str = "x-withhuman-client";
const REPOSITORY_HEADER: &str = "x-withhuman-repo";

pub fn app() -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/hooks/SessionStart", post(accept_hook))
        .route("/v1/hooks/UserPromptSubmit", post(accept_hook))
        .route("/v1/hooks/PreToolUse", post(accept_hook))
        .route("/v1/hooks/PostToolUse", post(accept_hook))
        .route("/v1/hooks/PostToolUseFailure", post(accept_hook))
        .route("/v1/hooks/SubagentStart", post(accept_hook))
        .route("/v1/hooks/SubagentStop", post(accept_hook))
        .route("/v1/hooks/InstructionsLoaded", post(accept_hook))
        .route("/v1/hooks/ConfigChange", post(accept_hook))
        .route("/v1/hooks/FileChanged", post(accept_hook))
        .route("/v1/hooks/MessageDisplay", post(accept_hook))
        .route("/v1/hooks/PostToolBatch", post(accept_hook))
        .route("/v1/hooks/ToolDescriptions", post(accept_hook))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: HealthStatus::Ok,
        service: "collector",
    })
}

async fn accept_hook(headers: HeaderMap, StrictJson(_payload): StrictJson<Value>) -> StatusCode {
    let _trusted_context = TrustedHookContext::from_headers(&headers);
    StatusCode::OK
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum HealthStatus {
    Ok,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct HealthResponse {
    status: HealthStatus,
    service: &'static str,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
struct ErrorResponse {
    error: &'static str,
}
