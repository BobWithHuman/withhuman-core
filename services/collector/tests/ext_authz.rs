use serde_json::{Value, json};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use withhuman_collector::{ExtAuthzService, StoredVerdict, VerdictStore};
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionResponse, EnforcementMode},
    ext_authz::{
        AttributeContext, Authorization, AuthorizationClient, AuthorizationServer, CheckRequest,
        HttpResponse, attribute_context,
    },
};

#[tokio::test]
async fn allows_only_a_matching_allow_verdict_in_enforce_mode() {
    let service = service(EnforcementMode::Enforce, Decision::Allow, "");
    let response = check(
        &service,
        tool_call("tool-1", "write_file", json!({"path":"a"})),
    )
    .await;

    assert_allowed(&response);
}

#[tokio::test]
async fn denies_policy_denials_reviews_and_missing_verdicts() {
    let denied = service(
        EnforcementMode::Enforce,
        Decision::Deny,
        "blocked by policy",
    );
    let response = check(
        &denied,
        tool_call("tool-1", "write_file", json!({"path":"a"})),
    )
    .await;
    assert_denied(&response, "blocked by policy");

    let review = service(
        EnforcementMode::Enforce,
        Decision::Review,
        "human review required",
    );
    let response = check(
        &review,
        tool_call("tool-1", "write_file", json!({"path":"a"})),
    )
    .await;
    assert_denied(&response, "human review required");

    let missing = ExtAuthzService::new(VerdictStore::new(2), EnforcementMode::Enforce);
    let response = check(
        &missing,
        tool_call("unknown", "write_file", json!({"path":"a"})),
    )
    .await;
    assert_denied(&response, "No policy verdict exists");
}

#[tokio::test]
async fn denies_changed_tool_names_arguments_and_missing_correlation() {
    let service = service(EnforcementMode::Enforce, Decision::Allow, "");

    let response = check(
        &service,
        tool_call("tool-1", "read_file", json!({"path":"a"})),
    )
    .await;
    assert_denied(&response, "does not match");

    let response = check(
        &service,
        tool_call("tool-1", "write_file", json!({"path":"b"})),
    )
    .await;
    assert_denied(&response, "does not match");

    let response = check(
        &service,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"a"}}}),
    )
    .await;
    assert_denied(&response, "Invalid MCP authorization request");
}

#[tokio::test]
async fn permits_non_tool_calls_and_non_enforcing_modes() {
    let enforce = service(EnforcementMode::Enforce, Decision::Deny, "blocked");
    let response = check(
        &enforce,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    )
    .await;
    assert_allowed(&response);

    for mode in [EnforcementMode::Record, EnforcementMode::Shadow] {
        let service = ExtAuthzService::new(VerdictStore::new(2), mode);
        let response = Authorization::check(&service, Request::new(CheckRequest::default()))
            .await
            .unwrap()
            .into_inner();
        assert_allowed(&response);
    }
}

#[tokio::test]
async fn serves_the_envoy_authorization_contract_over_grpc() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = service(EnforcementMode::Enforce, Decision::Allow, "");
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AuthorizationServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
    });

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AuthorizationClient::new(channel);
    let response = client
        .check(request(tool_call(
            "tool-1",
            "write_file",
            json!({"path":"a"}),
        )))
        .await
        .unwrap()
        .into_inner();

    assert_allowed(&response);
    server.abort();
}

fn service(mode: EnforcementMode, decision: Decision, reason: &str) -> ExtAuthzService {
    let verdicts = VerdictStore::new(2);
    verdicts.insert(
        "tool-1".to_owned(),
        StoredVerdict {
            decision: DecisionResponse {
                decision,
                reason: reason.to_owned(),
                rule: "test-rule".to_owned(),
                start: CausalStart::User,
                written: true,
                jev: None,
            },
            tool_name: "mcp__filesystem__write_file".to_owned(),
            arguments: json!({"path":"a"}),
        },
    );
    ExtAuthzService::new(verdicts, mode)
}

async fn check(
    service: &ExtAuthzService,
    body: Value,
) -> withhuman_contracts::ext_authz::CheckResponse {
    Authorization::check(service, Request::new(request(body)))
        .await
        .unwrap()
        .into_inner()
}

fn request(body: Value) -> CheckRequest {
    CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(attribute_context::Request {
                http: Some(attribute_context::HttpRequest {
                    raw_body: serde_json::to_vec(&body).unwrap(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn tool_call(tool_use_id: &str, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
            "_meta": {"claudecode/toolUseId": tool_use_id}
        }
    })
}

fn assert_allowed(response: &withhuman_contracts::ext_authz::CheckResponse) {
    assert_eq!(response.status.as_ref().unwrap().code, 0);
    assert!(response.http_response.is_none());
}

fn assert_denied(response: &withhuman_contracts::ext_authz::CheckResponse, reason: &str) {
    assert_eq!(response.status.as_ref().unwrap().code, 7);
    let Some(HttpResponse::DeniedResponse(denied)) = response.http_response.as_ref() else {
        panic!("expected denied response");
    };
    assert!(denied.body.contains(reason));
}
