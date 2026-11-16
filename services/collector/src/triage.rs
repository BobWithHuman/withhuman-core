//! The security team's triage API (`/v1/admin/...`, with `WITHHUMAN_ADMIN_TOKEN`): marking a
//! session (reviewing, attack, benign or closed), distrusting a source, and one Call's evidence. All of it is
//! passed on to the Generator, which stores it. None of it changes how a Call is decided.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;
use withhuman_contracts::triage::{
    DistrustSourceRequest, Evidence, MarkSessionRequest, MarkSessionsRequest, MarkedSession,
    MarkedSessions, SourceTrust,
};

use crate::{
    http::{CollectorService, StrictJson},
    inventory::{error, forward, not_admin},
};

/// Longest source the team may name, in bytes: room for a long URL.
const SOURCE_LIMIT: usize = 4_096;
/// Most sessions one request may mark.
const SESSIONS_LIMIT: usize = 1_000;

#[utoipa::path(
    post,
    path = "/v1/admin/sessions/{session_id}/mark",
    tag = "Triage",
    params(
        ("session_id" = String, Path, description = "The session's ID as one path segment, percent-encoded"),
        ("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")
    ),
    request_body = MarkSessionRequest,
    responses(
        (status = 200, description = "The session with its mark, or with `mark: null` once taken off. A later mark replaces an earlier one", body = MarkedSession),
        (status = 400, description = "`state` missing, or not `reviewing`, `attack`, `benign`, `closed` or null"),
        (status = 401, description = "Admin token missing or wrong"),
        (status = 404, description = "No such session, or admin API disabled"),
        (status = 502, description = "Generator unavailable")
    )
)]
pub async fn mark_session(
    State(service): State<CollectorService>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<MarkSessionRequest>,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    forward(
        &service,
        reqwest::Method::POST,
        &["sessions", &session_id, "mark"],
        Some(json!(request)),
    )
    .await
}

#[utoipa::path(
    post,
    path = "/v1/admin/sessions/mark",
    tag = "Triage",
    params(("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    request_body = MarkSessionsRequest,
    responses(
        (status = 200, description = "One mark set on every named session the engine holds (or, with `state: null`, taken off them), together; `sessions` lists them in the order named and `unknown` the ones it does not hold, which are left alone. 200 even when all are unknown", body = MarkedSessions),
        (status = 400, description = "`session_ids` empty, over 1000 or holding an empty ID (`invalid_sessions`); `state` missing or not one of the four or null"),
        (status = 401, description = "Admin token missing or wrong"),
        (status = 404, description = "Admin API disabled"),
        (status = 502, description = "Generator unavailable")
    )
)]
pub async fn mark_sessions(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<MarkSessionsRequest>,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    let ids = &request.session_ids;
    if ids.is_empty() || ids.len() > SESSIONS_LIMIT || ids.iter().any(String::is_empty) {
        return error(StatusCode::BAD_REQUEST, "invalid_sessions");
    }
    forward(
        &service,
        reqwest::Method::POST,
        &["sessions", "mark"],
        Some(json!(request)),
    )
    .await
}

#[utoipa::path(
    post,
    path = "/v1/admin/sources/distrust",
    tag = "Triage",
    params(("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    request_body = DistrustSourceRequest,
    responses(
        (status = 200, description = "The source, distrusted (`on: true`) or trusted again (`on: false`). Either may be repeated; distrusting again keeps the latest actor, time and Call", body = SourceTrust),
        (status = 400, description = "`source` empty or longer than 4096 bytes, or the body not as documented"),
        (status = 401, description = "Admin token missing or wrong"),
        (status = 404, description = "Admin API disabled"),
        (status = 502, description = "Generator unavailable")
    )
)]
pub async fn distrust_source(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<DistrustSourceRequest>,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    // The source is compared as written, so it is stored as written too.
    if request.source.trim().is_empty() || request.source.len() > SOURCE_LIMIT {
        return error(StatusCode::BAD_REQUEST, "invalid_source");
    }
    forward(
        &service,
        reqwest::Method::POST,
        &["sources", "distrust"],
        Some(json!(request)),
    )
    .await
}

#[utoipa::path(
    get,
    path = "/v1/admin/sessions/{session_id}/calls/{seq}/evidence",
    tag = "Triage",
    params(
        ("session_id" = String, Path, description = "The session's ID as one path segment, percent-encoded"),
        ("seq" = u64, Path, description = "The Call's number in its session (`nodes.seq`)"),
        ("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")
    ),
    responses(
        (status = 200, description = "The Call's evidence: the Call, its verdict, the person's request before it, what the engine traced it to, the session's mark and whether the cause's source is distrusted. No key or key hash is in it", body = Evidence),
        (status = 401, description = "Admin token missing or wrong"),
        (status = 404, description = "No such session, no Call with this number in it, or admin API disabled"),
        (status = 502, description = "Generator unavailable")
    )
)]
pub async fn evidence(
    State(service): State<CollectorService>,
    Path((session_id, seq)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    // A number that is no Call's, and what is no number at all, are the same to the caller.
    if seq.parse::<u64>().is_err() {
        return error(StatusCode::NOT_FOUND, "graph_resource_not_found");
    }
    forward(
        &service,
        reqwest::Method::GET,
        &["sessions", &session_id, "calls", &seq, "evidence"],
        None,
    )
    .await
}
