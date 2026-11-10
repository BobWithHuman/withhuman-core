//! Who is behind a Hook, and the agent inventory's API.
//!
//! [`authenticate`] runs before every Hook: it checks the Hook's WithHuman key and, when the key
//! is valid, passes its user on in [`USER_HEADER`], which it first takes off the request so a
//! client cannot set it. A revoked key turns every PreToolUse back (the kill switch) and records
//! the denial; other Hooks of that user are still recorded. Without a valid key, Hooks are taken
//! as before unless `WITHHUMAN_REQUIRE_KEY` is on.
//!
//! A stopped session's PreToolUse is turned back the same way, and recorded with the stop.
//!
//! A PreToolUse is always turned back with a 200 deny: Claude Code lets a call run when its Hook
//! answers anything but 2xx, so a 401 would not stop it.
//!
//! The rest is the inventory API the Collector serves to devices (`/v1/clients/register`) and to
//! administrators (`/v1/admin/...`, with `WITHHUMAN_ADMIN_TOKEN`), passed on to the Generator,
//! which stores devices and keys. New keys are made here, so the Generator never sees one.

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use withhuman_common::chunking::sha256;
use withhuman_contracts::{
    hooks::PermissionDecision,
    inventory::{
        ClientRegistration, ClientRegistrationRecord, IssueKeyRequest, IssuedKey, KeyDenial,
        KeyRecord, NewKey, ReviewRequest, RevokeKeyRequest, SessionDenial, SessionStopRequest,
        UserKind,
    },
};

use crate::{
    FailurePolicy,
    http::{CLIENT_HEADER, CollectorService, StrictJson, blocking_response, header_value, now},
    keys::{self, KeyCheck},
};

/// The verified user of a Hook's key. Set by the Collector alone.
pub const USER_HEADER: &str = "x-withhuman-user";
/// Bytes of a Hook read for its session id; the Hooks' own JSON limit is lower.
const BODY_LIMIT: usize = 8 * 1024 * 1024;
/// Longest value a device may register in a field.
const FIELD_LIMIT: usize = 1_024;

pub async fn authenticate(
    State(service): State<CollectorService>,
    mut request: Request,
    next: Next,
) -> Response {
    request.headers_mut().remove(USER_HEADER);
    let path = request.uri().path();
    let call = path.ends_with("/PreToolUse");
    let codex = path.starts_with("/v1/hooks/codex/");
    let require = service.config.require_key;
    let (reason, error) = match service.keys.check(request.headers(), now()).await {
        KeyCheck::Active { user, .. } => {
            return admit(&service, request, next, Some(&user), call).await;
        }
        KeyCheck::Revoked { key_id, user } => {
            if !call {
                return admit(&service, request, next, Some(&user), call).await;
            }
            return refuse_revoked(&service, request, &key_id).await;
        }
        KeyCheck::Nothing if require => (keys::KEY_MISSING, "key_required"),
        KeyCheck::Invalid if require => (keys::KEY_INVALID, "key_invalid"),
        KeyCheck::Unchecked
            if require && service.config.failure_policy == FailurePolicy::Closed =>
        {
            (keys::KEY_UNCHECKED, "key_unchecked")
        }
        _ => return admit(&service, request, next, None, call).await,
    };
    if call {
        return blocking_response(PermissionDecision::Deny, reason.to_owned());
    }
    let status = if error == "key_unchecked" {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::UNAUTHORIZED
    };
    // A Codex bridge reports a refused Hook on stderr; give it the reason.
    let message = if codex { reason } else { error };
    (status, Json(json!({ "error": error, "message": message }))).into_response()
}

/// Passes the Hook on with its user, unless the security team stopped its session.
async fn admit(
    service: &CollectorService,
    mut request: Request,
    next: Next,
    user: Option<&str>,
    call: bool,
) -> Response {
    if let Some(value) = user.and_then(|user| HeaderValue::from_str(user).ok()) {
        request.headers_mut().insert(USER_HEADER, value);
    }
    if !call {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, BODY_LIMIT).await else {
        return error(StatusCode::BAD_REQUEST, "invalid_json");
    };
    if let Some(session_id) = session_of(&bytes) {
        if service.flags.get(&session_id).await.stop.is_some() {
            // The denial stands whether or not it could be recorded.
            let _ = service
                .generator
                .record_session_denial(&session_id, SessionDenial { denied_at: now() })
                .await;
            return blocking_response(PermissionDecision::Deny, keys::SESSION_STOPPED.to_owned());
        }
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

fn session_of(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Session {
        session_id: String,
    }
    serde_json::from_slice::<Session>(body)
        .ok()
        .map(|session| session.session_id)
}

/// The kill switch: the call is denied and the denial recorded with the key, so the audit shows
/// when the stop first took effect.
async fn refuse_revoked(service: &CollectorService, request: Request, key_id: &str) -> Response {
    let client_id = header_value(request.headers(), CLIENT_HEADER);
    let session_id = to_bytes(request.into_body(), BODY_LIMIT)
        .await
        .ok()
        .and_then(|bytes| session_of(&bytes));
    // The denial stands whether or not it could be recorded.
    let _ = service
        .generator
        .record_key_denial(
            key_id,
            KeyDenial {
                session_id,
                client_id,
                denied_at: now(),
            },
        )
        .await;
    blocking_response(PermissionDecision::Deny, keys::KEY_REVOKED.to_owned())
}

#[utoipa::path(
    post,
    path = "/v1/clients/register",
    tag = "Inventory",
    params(("Authorization" = Option<String>, Header, description = "`Bearer <WithHuman key>`")),
    request_body = ClientRegistration,
    responses(
        (status = 200, description = "Device registered or updated", body = withhuman_contracts::inventory::ClientRecord),
        (status = 400, description = "Invalid registration"),
        (status = 401, description = "Key required or not valid"),
        (status = 403, description = "Key revoked"),
        (status = 502, description = "Generator unavailable")
    )
)]
pub async fn register_client(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(registration): StrictJson<ClientRegistration>,
) -> Response {
    let fields = [
        &registration.team,
        &registration.hostname,
        &registration.os,
        &registration.os_user,
        &registration.hook_version,
        &registration.agent,
        &registration.project,
    ];
    let client_id = registration.client_id.trim();
    if client_id.is_empty()
        || client_id.len() > FIELD_LIMIT
        || fields.iter().any(|field| {
            field
                .as_ref()
                .is_some_and(|value| value.len() > FIELD_LIMIT)
        })
    {
        return error(StatusCode::BAD_REQUEST, "invalid_registration");
    }
    let user = match device_user(&service, &headers).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    let record = ClientRegistrationRecord {
        registration: ClientRegistration {
            client_id: client_id.to_owned(),
            ..registration
        },
        user,
        registered_at: now(),
    };
    forward(
        &service,
        reqwest::Method::POST,
        &["clients"],
        Some(json!(record)),
    )
    .await
}

/// The user of a device's key, by the Hooks' rules: a revoked key is refused, and a missing or
/// bad one only when keys are required.
async fn device_user(
    service: &CollectorService,
    headers: &HeaderMap,
) -> Result<Option<String>, Box<Response>> {
    match service.keys.check(headers, now()).await {
        KeyCheck::Active { user, .. } => Ok(Some(user)),
        KeyCheck::Revoked { .. } => Err(Box::new(error(StatusCode::FORBIDDEN, "key_revoked"))),
        KeyCheck::Invalid if service.config.require_key => {
            Err(Box::new(error(StatusCode::UNAUTHORIZED, "key_invalid")))
        }
        KeyCheck::Nothing if service.config.require_key => {
            Err(Box::new(error(StatusCode::UNAUTHORIZED, "key_required")))
        }
        KeyCheck::Unchecked if service.config.require_key => Err(Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "key_unchecked",
        ))),
        // Without a required key a bad one is ignored, as on the Hooks.
        _ => Ok(None),
    }
}

/// The answer to a request that is not an administrator's, who presents
/// `Authorization: Bearer <WITHHUMAN_ADMIN_TOKEN>`; none for an administrator's.
fn not_admin(service: &CollectorService, headers: &HeaderMap) -> Option<Response> {
    let Some(token) = &service.config.admin_token else {
        return Some(error(StatusCode::NOT_FOUND, "admin_api_disabled"));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();
    // Hashes compare in the same time whatever the token's length or first difference.
    (sha256(presented) != sha256(token))
        .then(|| error(StatusCode::UNAUTHORIZED, "admin_token_invalid"))
}

/// A key's user: a person's email, or a service's name (`ci-deploy`, `team.bot`).
fn key_user(name: &str, kind: UserKind) -> Option<String> {
    match kind {
        UserKind::Person => user_email(name),
        UserKind::Service => {
            let name = name.trim().to_lowercase();
            let valid = !name.is_empty()
                && name.len() <= 254
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-@".contains(&byte));
            valid.then_some(name)
        }
    }
}

fn user_email(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    let valid = email.len() <= 254
        && !email.chars().any(char::is_whitespace)
        && email
            .split_once('@')
            .is_some_and(|(name, domain)| !name.is_empty() && !domain.is_empty());
    valid.then_some(email)
}

#[utoipa::path(
    post,
    path = "/v1/admin/users/{email}/keys",
    tag = "Inventory",
    params(
        ("email" = String, Path, description = "The user the key is for"),
        ("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")
    ),
    request_body = IssueKeyRequest,
    responses(
        (status = 201, description = "The new key; shown this once only", body = IssuedKey),
        (status = 400, description = "Not an email address"),
        (status = 401, description = "Admin token missing or wrong"),
        (status = 404, description = "Admin API disabled")
    )
)]
pub async fn issue_key(
    State(service): State<CollectorService>,
    Path(email): Path<String>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<IssueKeyRequest>,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    let Some(user) = key_user(&email, request.kind) else {
        return error(StatusCode::BAD_REQUEST, "invalid_user");
    };
    let Ok((key, presented)) = keys::generate() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "key_generation_failed");
    };
    let new_key = NewKey {
        key_id: presented.key_id,
        hash: presented.hash,
        user: user.clone(),
        kind: request.kind,
        actor: request.actor,
        note: request.note,
        created_at: now(),
    };
    match service
        .generator
        .inventory(
            reqwest::Method::POST,
            &["users", &user, "keys"],
            Some(json!(new_key)),
        )
        .await
    {
        Ok((200..=299, body)) => match serde_json::from_value::<KeyRecord>(body) {
            Ok(record) => (StatusCode::CREATED, Json(IssuedKey { key, record })).into_response(),
            Err(_) => error(StatusCode::BAD_GATEWAY, "generator_unavailable"),
        },
        Ok((status, body)) => passed(status, body),
        Err(_) => error(StatusCode::BAD_GATEWAY, "generator_unavailable"),
    }
}

#[utoipa::path(
    get,
    path = "/v1/admin/users/{email}/keys",
    tag = "Inventory",
    params(("email" = String, Path), ("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    responses((status = 200, description = "The user's keys, newest first, without their secrets", body = [KeyRecord]))
)]
pub async fn user_keys(
    State(service): State<CollectorService>,
    Path(email): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    let Some(user) = user_email(&email) else {
        return error(StatusCode::BAD_REQUEST, "invalid_email");
    };
    forward(
        &service,
        reqwest::Method::GET,
        &["users", &user, "keys"],
        None,
    )
    .await
}

#[utoipa::path(
    get,
    path = "/v1/admin/keys",
    tag = "Inventory",
    params(("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    responses((status = 200, description = "Every key, newest first, without their secrets", body = [KeyRecord]))
)]
pub async fn all_keys(State(service): State<CollectorService>, headers: HeaderMap) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    forward(&service, reqwest::Method::GET, &["keys"], None).await
}

#[utoipa::path(
    post,
    path = "/v1/admin/keys/{key_id}/revoke",
    tag = "Inventory",
    params(("key_id" = String, Path), ("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    request_body = RevokeKeyRequest,
    responses(
        (status = 200, description = "The key, revoked (a key already revoked keeps its first revocation)", body = KeyRecord),
        (status = 404, description = "No such key, or admin API disabled")
    )
)]
pub async fn revoke_key(
    State(service): State<CollectorService>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<RevokeKeyRequest>,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    let response = forward(
        &service,
        reqwest::Method::POST,
        &["keys", &key_id, "revoke"],
        Some(json!(request)),
    )
    .await;
    if response.status().is_success() {
        // This replica stops the key at once; others within WITHHUMAN_KEY_CACHE_MS.
        service.keys.forget();
    }
    response
}

#[utoipa::path(
    post,
    path = "/v1/admin/users/{email}/revoke",
    tag = "Inventory",
    params(("email" = String, Path), ("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    request_body = RevokeKeyRequest,
    responses(
        (status = 200, description = "Every key of the user, now all revoked: the user's agents stop", body = [KeyRecord]),
        (status = 404, description = "The user has no key, or admin API disabled")
    )
)]
pub async fn revoke_user(
    State(service): State<CollectorService>,
    Path(email): Path<String>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<RevokeKeyRequest>,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    let Some(user) = key_user(&email, UserKind::Service) else {
        return error(StatusCode::BAD_REQUEST, "invalid_user");
    };
    let response = forward(
        &service,
        reqwest::Method::POST,
        &["users", &user, "revoke"],
        Some(json!(request)),
    )
    .await;
    if response.status().is_success() {
        service.keys.forget();
    }
    response
}

#[utoipa::path(
    get,
    path = "/v1/admin/clients",
    tag = "Inventory",
    params(("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    responses((status = 200, description = "Registered and seen devices, last seen first", body = [withhuman_contracts::inventory::ClientRecord]))
)]
pub async fn clients(State(service): State<CollectorService>, headers: HeaderMap) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    forward(&service, reqwest::Method::GET, &["clients"], None).await
}

#[utoipa::path(
    post,
    path = "/v1/admin/sessions/{session_id}/stop",
    tag = "Inventory",
    params(("session_id" = String, Path), ("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    request_body = SessionStopRequest,
    responses(
        (status = 200, description = "The session's active stop (an earlier one is kept): its PreToolUse calls are denied", body = withhuman_contracts::inventory::SessionStop),
        (status = 404, description = "No such session, or admin API disabled")
    )
)]
pub async fn stop_session(
    State(service): State<CollectorService>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<SessionStopRequest>,
) -> Response {
    session_change(&service, &headers, &session_id, "stop", request).await
}

#[utoipa::path(
    post,
    path = "/v1/admin/sessions/{session_id}/release",
    tag = "Inventory",
    params(("session_id" = String, Path), ("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    request_body = SessionStopRequest,
    responses(
        (status = 200, description = "The stop, released", body = withhuman_contracts::inventory::SessionStop),
        (status = 404, description = "The session is not stopped, or admin API disabled")
    )
)]
pub async fn release_session(
    State(service): State<CollectorService>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<SessionStopRequest>,
) -> Response {
    session_change(&service, &headers, &session_id, "release", request).await
}

async fn session_change(
    service: &CollectorService,
    headers: &HeaderMap,
    session_id: &str,
    change: &str,
    request: SessionStopRequest,
) -> Response {
    if let Some(response) = not_admin(service, headers) {
        return response;
    }
    let response = forward(
        service,
        reqwest::Method::POST,
        &["sessions", session_id, change],
        Some(json!(request)),
    )
    .await;
    if response.status().is_success() {
        service.flags.forget(session_id);
    }
    response
}

#[utoipa::path(
    post,
    path = "/v1/admin/reviews",
    tag = "Inventory",
    params(("Authorization" = String, Header, description = "`Bearer <WITHHUMAN_ADMIN_TOKEN>`")),
    request_body = ReviewRequest,
    responses(
        (status = 201, description = "The review, kept beside earlier ones of the Call", body = withhuman_contracts::inventory::Review),
        (status = 400, description = "Note too long"),
        (status = 404, description = "No Call is (session_id, seq), or admin API disabled")
    )
)]
pub async fn add_review(
    State(service): State<CollectorService>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<ReviewRequest>,
) -> Response {
    if let Some(response) = not_admin(&service, &headers) {
        return response;
    }
    if request
        .note
        .as_ref()
        .is_some_and(|note| note.len() > 10_000)
    {
        return error(StatusCode::BAD_REQUEST, "note_too_long");
    }
    forward(
        &service,
        reqwest::Method::POST,
        &["reviews"],
        Some(json!(request)),
    )
    .await
}

async fn forward(
    service: &CollectorService,
    method: reqwest::Method,
    segments: &[&str],
    body: Option<Value>,
) -> Response {
    match service.generator.inventory(method, segments, body).await {
        Ok((status, body)) => passed(status, body),
        Err(_) => error(StatusCode::BAD_GATEWAY, "generator_unavailable"),
    }
}

fn passed(status: u16, body: Value) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    if status.is_server_error() {
        return error(StatusCode::BAD_GATEWAY, "generator_unavailable");
    }
    (status, Json(body)).into_response()
}

fn error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}
