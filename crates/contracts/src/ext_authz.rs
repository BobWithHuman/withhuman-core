//! Envoy External Authorization v3 contracts used by AgentGateway.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use envoy_types::ext_authz::v3::pb::{
    Authorization, AuthorizationServer, CheckRequest, CheckResponse, DeniedHttpResponse,
    HttpResponse, HttpStatusCode, OkHttpResponse,
};
use envoy_types::ext_authz::v3::{
    CheckResponseExt as _, DeniedHttpResponseBuilder, ToHttpResponse as _,
};

pub const AUTHORIZATION_SERVICE_NAME: &str = "envoy.service.auth.v3.Authorization";
pub const CHECK_METHOD_PATH: &str = "/envoy.service.auth.v3.Authorization/Check";
pub const MCP_TOOL_CALL_METHOD: &str = "tools/call";

pub fn allow_response() -> CheckResponse {
    CheckResponse::with_status(tonic::Status::ok(""))
}

pub fn deny_response(reason: impl Into<String>) -> CheckResponse {
    let reason = reason.into();
    let mut denied = DeniedHttpResponseBuilder::new();
    denied
        .set_http_status(HttpStatusCode::Forbidden)
        .set_body(reason.clone());

    CheckResponse {
        status: CheckResponse::with_status(tonic::Status::permission_denied(reason)).status,
        http_response: Some(denied.to_http_response()),
        ..Default::default()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    #[serde(default)]
    pub jsonrpc: Option<String>,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn tool_call(&self) -> Result<Option<McpToolCallParams>, serde_json::Error> {
        if self.method != MCP_TOOL_CALL_METHOD {
            return Ok(None);
        }

        self.params.clone().map(serde_json::from_value).transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct McpToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
    #[serde(default, rename = "_meta")]
    pub metadata: Option<McpCallMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct McpCallMetadata {
    #[serde(default, rename = "claudecode/toolUseId")]
    pub tool_use_id: Option<String>,
}
