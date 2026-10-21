use withhuman_contracts::ext_authz::{
    CHECK_METHOD_PATH, CheckRequest, HttpResponse, JsonRpcRequest, allow_response, deny_response,
};

#[test]
fn exposes_envoy_v3_check_request_and_method_path() {
    let request = CheckRequest::default();

    assert!(request.attributes.is_none());
    assert_eq!(
        CHECK_METHOD_PATH,
        "/envoy.service.auth.v3.Authorization/Check"
    );
}

#[test]
fn constructs_allow_response_with_ok_status() {
    let response = allow_response();
    let status = response
        .status
        .expect("allow response should contain status");

    assert_eq!(status.code, 0);
    assert!(response.http_response.is_none());
}

#[test]
fn constructs_deny_response_with_permission_denied_and_http_403() {
    let response = deny_response("Blocked by WithHuman.");
    let status = response
        .status
        .expect("deny response should contain status");
    let denied = match response
        .http_response
        .expect("deny response should contain an HTTP response")
    {
        HttpResponse::DeniedResponse(denied) => denied,
        HttpResponse::OkResponse(_) => panic!("deny response must not contain an OK response"),
    };

    assert_eq!(status.code, 7);
    assert_eq!(status.message, "Blocked by WithHuman.");
    assert_eq!(denied.status.expect("HTTP status is required").code, 403);
    assert_eq!(denied.body, "Blocked by WithHuman.");
}

#[test]
fn extracts_mcp_tool_call_correlation_fields() {
    let request: JsonRpcRequest = serde_json::from_value(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "attach_report",
            "arguments": { "ticket_url": "https://example.test/tickets/1" },
            "_meta": { "claudecode/toolUseId": "toolu_01" }
        }
    }))
    .expect("JSON-RPC request should deserialize");
    let call = request
        .tool_call()
        .expect("tool call params should be valid")
        .expect("tools/call should produce tool call params");

    assert_eq!(call.name, "attach_report");
    assert_eq!(
        call.metadata
            .expect("metadata should exist")
            .tool_use_id
            .as_deref(),
        Some("toolu_01")
    );
}

#[test]
fn ignores_non_tool_call_json_rpc_methods() {
    let request: JsonRpcRequest = serde_json::from_value(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": "2025-06-18" }
    }))
    .expect("initialize request should deserialize");

    assert_eq!(request.tool_call().expect("method should be valid"), None);
}
