use std::{fmt, sync::Arc};

use serde_json::Value;
use tonic::{Request, Response, Status};
use withhuman_contracts::{
    decisions::{Decision, EnforcementMode},
    ext_authz::{
        Authorization, CheckRequest, CheckResponse, JsonRpcRequest, allow_response, deny_response,
    },
};

use crate::VerdictStore;

const INVALID_REQUEST: &str = "Invalid MCP authorization request.";
const MISSING_VERDICT: &str = "No policy verdict exists for this MCP request.";
const REQUEST_MISMATCH: &str = "MCP request does not match the authorized tool call.";
const REVIEW_REQUIRED: &str = "MCP request requires review.";
const VERDICT_STORE_UNAVAILABLE: &str = "Policy verdict store is unavailable.";

#[derive(Clone)]
pub struct ExtAuthzService {
    verdicts: Arc<dyn VerdictStore>,
    mode: EnforcementMode,
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
        Self { verdicts, mode }
    }

    async fn authorize(&self, request: &CheckRequest) -> CheckResponse {
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
        if mcp_tool_name(&verdict.tool_name) != call.name || verdict.arguments != arguments {
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
