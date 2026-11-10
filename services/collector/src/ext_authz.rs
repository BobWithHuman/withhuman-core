use std::{fmt, sync::Arc};

use serde_json::Value;
use tonic::{Request, Response, Status};
use withhuman_contracts::{
    decisions::{Decision, EnforcementMode},
    ext_authz::{
        Authorization, CheckRequest, CheckResponse, JsonRpcRequest, allow_response,
        allow_with_headers, deny_response,
    },
};

use crate::{
    FailurePolicy, GeneratorTransport, VerdictStore,
    flags::FlagCache,
    http::now,
    keys::{self, KeyCheck, KeyVerifier},
};

/// The gateway marks the check of a model request with this context extension.
pub const MODEL_CONTEXT: (&str, &str) = ("withhuman", "model");
/// The headers Claude Code sends a model request with (ANTHROPIC_CUSTOM_HEADERS), apart from
/// the subscription's own Authorization.
pub const MODEL_KEY_HEADER: &str = "x-withhuman-key";
const CLIENT_HEADER: &str = "x-withhuman-client";
const USER_HEADER: &str = "x-withhuman-user";
const SESSION_HEADER: &str = "x-claude-code-session-id";
/// The id of a model request's record, which the gateway's request log keeps
/// (`attributes_json.withhuman_request`).
pub const REQUEST_HEADER: &str = "x-withhuman-request";
const MODEL_PROXY_OFF: &str = "WithHuman's model route is off (WITHHUMAN_MODEL_PROXY).";

/// What a model request is checked against: the same keys and session stops as the Hooks.
#[derive(Clone)]
pub struct ModelAccess {
    pub keys: KeyVerifier,
    pub flags: FlagCache,
    pub generator: Arc<dyn GeneratorTransport>,
    pub require_key: bool,
    pub failure: FailurePolicy,
}

const INVALID_REQUEST: &str = "Invalid MCP authorization request.";
const MISSING_VERDICT: &str = "No policy verdict exists for this MCP request.";
const REQUEST_MISMATCH: &str = "MCP request does not match the authorized tool call.";
const REVIEW_REQUIRED: &str = "MCP request requires review.";
const VERDICT_STORE_UNAVAILABLE: &str = "Policy verdict store is unavailable.";

#[derive(Clone)]
pub struct ExtAuthzService {
    verdicts: Arc<dyn VerdictStore>,
    mode: EnforcementMode,
    models: Option<ModelAccess>,
}

impl fmt::Debug for ExtAuthzService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtAuthzService")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl ExtAuthzService {
    pub fn new(verdicts: Arc<dyn VerdictStore>, mode: EnforcementMode) -> Self {
        Self {
            verdicts,
            mode,
            models: None,
        }
    }

    /// Checks model requests too (WITHHUMAN_MODEL_PROXY=on).
    pub fn with_models(mut self, access: ModelAccess) -> Self {
        self.models = Some(access);
        self
    }

    /// A model request: the user's key (`x-withhuman-key`) and the session
    /// (`x-claude-code-session-id`) are checked as the Hooks' are. A revoked key or a stopped
    /// session is denied (403) in any mode, as a missing or bad key is when keys are required.
    /// Allowed, the request goes on with the key's user in `x-withhuman-user` and without the
    /// key, and is recorded without its content.
    async fn authorize_model(&self, request: &CheckRequest) -> CheckResponse {
        let Some(access) = &self.models else {
            return deny_response(MODEL_PROXY_OFF);
        };
        let header = |name: &str| {
            http_request(request)
                .and_then(|http| http.headers.get(name))
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let mut presented = axum::http::HeaderMap::new();
        if let Some(value) = header(MODEL_KEY_HEADER)
            .and_then(|key| axum::http::HeaderValue::from_str(&format!("Bearer {key}")).ok())
        {
            presented.insert(axum::http::header::AUTHORIZATION, value);
        }
        let session_id = header(SESSION_HEADER);
        let user = match access.keys.check(&presented, now()).await {
            KeyCheck::Active { user, .. } => Some(user),
            KeyCheck::Revoked { .. } => return deny_response(keys::KEY_REVOKED),
            KeyCheck::Nothing if access.require_key => return deny_response(keys::KEY_MISSING),
            KeyCheck::Invalid if access.require_key => return deny_response(keys::KEY_INVALID),
            KeyCheck::Unchecked
                if access.require_key && access.failure == FailurePolicy::Closed =>
            {
                return deny_response(keys::KEY_UNCHECKED);
            }
            _ => None,
        };
        if let Some(session_id) = &session_id {
            if access.flags.get(session_id).await.stop.is_some() {
                let _ = access
                    .generator
                    .record_session_denial(
                        session_id,
                        withhuman_contracts::inventory::SessionDenial { denied_at: now() },
                    )
                    .await;
                return deny_response(keys::SESSION_STOPPED);
            }
        }
        let mut call = withhuman_contracts::inventory::ModelCall {
            request_id: http_request(request)
                .map(|http| http.id.clone())
                .filter(|id| !id.is_empty()),
            user: user.clone(),
            client_id: header(CLIENT_HEADER),
            session_id,
            model: requested_model(request),
            at: now(),
        };
        if call.request_id.is_none() {
            call.request_id = keys::generate().ok().map(|(_, key)| key.key_id);
        }
        let generator = access.generator.clone();
        let recorded = call.clone();
        // Recording never holds the request up.
        tokio::spawn(async move {
            let _ = generator.record_model_call(recorded).await;
        });
        // The id goes on with the request, so the gateway's request log, which has the
        // tokens, names the record it belongs to.
        let id = call.request_id.clone().unwrap_or_default();
        match &user {
            Some(user) => allow_with_headers(
                &[(USER_HEADER, user), (REQUEST_HEADER, &id)],
                &[MODEL_KEY_HEADER],
            ),
            None => allow_with_headers(&[(REQUEST_HEADER, &id)], &[MODEL_KEY_HEADER, USER_HEADER]),
        }
    }

    async fn authorize(&self, request: &CheckRequest) -> CheckResponse {
        if is_model_request(request) {
            return self.authorize_model(request).await;
        }
        if self.mode != EnforcementMode::Enforce {
            return allow_response();
        }

        let Some(body) = request_body(request) else {
            return deny_response(INVALID_REQUEST);
        };
        let Ok(rpc) = serde_json::from_slice::<JsonRpcRequest>(body) else {
            return deny_response(INVALID_REQUEST);
        };
        let call = match rpc.tool_call() {
            Ok(Some(call)) => call,
            Ok(None) => return allow_response(),
            Err(_) => return deny_response(INVALID_REQUEST),
        };
        let Some(tool_use_id) = call
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.tool_use_id.as_deref())
            .filter(|value| !value.trim().is_empty())
        else {
            return deny_response(INVALID_REQUEST);
        };
        let verdict = match self.verdicts.get(tool_use_id).await {
            Ok(Some(verdict)) => verdict,
            Ok(None) => return deny_response(MISSING_VERDICT),
            // Fail closed: an unreadable verdict is never treated as an allow.
            Err(_) => return deny_response(VERDICT_STORE_UNAVAILABLE),
        };
        let arguments = call.arguments.unwrap_or_else(empty_object);
        if mcp_tool_name(&verdict.tool_name) != call.name || !verdict.authorizes(&arguments) {
            return deny_response(REQUEST_MISMATCH);
        }

        match verdict.decision.decision {
            Decision::Allow => allow_response(),
            Decision::Deny => deny_response(verdict.decision.reason),
            Decision::Review => deny_response(if verdict.decision.reason.is_empty() {
                REVIEW_REQUIRED.to_owned()
            } else {
                verdict.decision.reason
            }),
        }
    }
}

#[tonic::async_trait]
impl Authorization for ExtAuthzService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        Ok(Response::new(self.authorize(request.get_ref()).await))
    }
}

fn http_request(
    request: &CheckRequest,
) -> Option<&withhuman_contracts::ext_authz::attribute_context::HttpRequest> {
    request.attributes.as_ref()?.request.as_ref()?.http.as_ref()
}

fn is_model_request(request: &CheckRequest) -> bool {
    request
        .attributes
        .as_ref()
        .and_then(|attributes| attributes.context_extensions.get(MODEL_CONTEXT.0))
        .is_some_and(|value| value == MODEL_CONTEXT.1)
}

/// The model the gateway read from the request, when its check carries it as metadata
/// (`withhuman.model`).
fn requested_model(request: &CheckRequest) -> Option<String> {
    use withhuman_contracts::ext_authz::MetadataValueKind as Kind;
    let fields = &request
        .attributes
        .as_ref()?
        .metadata_context
        .as_ref()?
        .filter_metadata
        .get(MODEL_CONTEXT.0)?
        .fields;
    match fields.get("model")?.kind.as_ref()? {
        Kind::StringValue(model) if !model.is_empty() => Some(model.clone()),
        _ => None,
    }
}

fn request_body(request: &CheckRequest) -> Option<&[u8]> {
    let http = request
        .attributes
        .as_ref()?
        .request
        .as_ref()?
        .http
        .as_ref()?;
    if !http.raw_body.is_empty() {
        Some(&http.raw_body)
    } else if !http.body.is_empty() {
        Some(http.body.as_bytes())
    } else {
        None
    }
}

fn mcp_tool_name(hook_name: &str) -> &str {
    hook_name
        .strip_prefix("mcp__")
        .and_then(|name| name.split_once("__"))
        .map_or(hook_name, |(_, tool)| tool)
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}
