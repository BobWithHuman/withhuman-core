//! The gateway's check of a model request (WITHHUMAN_MODEL_PROXY=on): the user's key and the
//! session, as for the Hooks, and a record of the request without its content.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tonic::Request;
use withhuman_collector::{
    ExtAuthzService, FailurePolicy, GeneratorError, GeneratorTransport, InMemoryVerdictStore,
    ModelAccess, NormalizedEvent, flags::FlagCache, keys,
};
use withhuman_common::chunking::sha256;
use withhuman_contracts::{
    decisions::EnforcementMode,
    events::EventResponse,
    ext_authz::{
        AttributeContext, Authorization, CheckRequest, CheckResponse, HttpResponse,
        attribute_context,
    },
    inventory::{
        KeyStatus, ModelCall, SessionDenial, SessionFlags, SessionStop, VerifyKeyRequest,
        VerifyKeyResponse,
    },
};

const ACTIVE: &str =
    "whk_00000000000000aa_1111111111111111111111111111111111111111111111111111111111111111";
const REVOKED: &str =
    "whk_00000000000000bb_2222222222222222222222222222222222222222222222222222222222222222";

#[derive(Default)]
struct Generator {
    calls: Mutex<Vec<ModelCall>>,
    denials: Mutex<Vec<String>>,
}

#[async_trait]
impl GeneratorTransport for Generator {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        unreachable!("a model request is no Hook")
    }

    async fn verify_key(
        &self,
        request: VerifyKeyRequest,
    ) -> Result<VerifyKeyResponse, GeneratorError> {
        Ok(if request.hash == sha256(ACTIVE) {
            VerifyKeyResponse {
                status: KeyStatus::Active,
                user: Some("ana@example.com".into()),
            }
        } else if request.hash == sha256(REVOKED) {
            VerifyKeyResponse {
                status: KeyStatus::Revoked,
                user: Some("bo@example.com".into()),
            }
        } else {
            VerifyKeyResponse {
                status: KeyStatus::Unknown,
                user: None,
            }
        })
    }

    async fn session_flags(&self, session_id: &str) -> Result<SessionFlags, GeneratorError> {
        Ok(SessionFlags {
            stop: (session_id == "stopped").then(|| SessionStop {
                id: 1,
                session_id: session_id.into(),
                stopped_at: 1,
                stopped_by: None,
                reason: None,
                released_at: None,
                released_by: None,
                release_reason: None,
                first_denied_at: None,
                last_denied_at: None,
                denied_count: 0,
            }),
            exception: None,
        })
    }

    async fn record_session_denial(
        &self,
        session_id: &str,
        _denial: SessionDenial,
    ) -> Result<(), GeneratorError> {
        self.denials.lock().unwrap().push(session_id.into());
        Ok(())
    }

    async fn record_model_call(&self, call: ModelCall) -> Result<(), GeneratorError> {
        self.calls.lock().unwrap().push(call);
        Ok(())
    }
}

fn service(generator: Arc<Generator>, require_key: bool) -> ExtAuthzService {
    ExtAuthzService::new(
        Arc::new(InMemoryVerdictStore::new(2)),
        EnforcementMode::Shadow,
    )
    .with_models(ModelAccess {
        keys: keys::KeyVerifier::new(generator.clone(), Duration::ZERO),
        flags: FlagCache::new(generator.clone(), Duration::ZERO),
        generator,
        require_key,
        failure: FailurePolicy::Closed,
    })
}

fn model_request(headers: &[(&str, &str)]) -> CheckRequest {
    CheckRequest {
        attributes: Some(AttributeContext {
            context_extensions: HashMap::from([("withhuman".to_owned(), "model".to_owned())]),
            request: Some(attribute_context::Request {
                http: Some(attribute_context::HttpRequest {
                    id: "req-1".into(),
                    path: "/v1/messages".into(),
                    headers: headers
                        .iter()
                        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                        .collect(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

async fn check(service: &ExtAuthzService, request: CheckRequest) -> CheckResponse {
    service
        .check(Request::new(request))
        .await
        .unwrap()
        .into_inner()
}

fn denied_with(response: &CheckResponse) -> Option<String> {
    match response.http_response.as_ref()? {
        HttpResponse::DeniedResponse(denied) => {
            assert_eq!(denied.status.as_ref().unwrap().code, 403);
            Some(denied.body.clone())
        }
        HttpResponse::OkResponse(_) => None,
    }
}

fn upstream_headers(response: &CheckResponse) -> (HashMap<String, String>, Vec<String>) {
    let Some(HttpResponse::OkResponse(ok)) = response.http_response.as_ref() else {
        panic!("not allowed: {response:?}");
    };
    (
        ok.headers
            .iter()
            .filter_map(|option| option.header.as_ref())
            .map(|header| (header.key.clone(), header.value.clone()))
            .collect(),
        ok.headers_to_remove.clone(),
    )
}

#[tokio::test]
async fn passes_a_valid_key_on_as_its_user_and_records_the_request() {
    let generator = Arc::new(Generator::default());
    let service = service(generator.clone(), true);
    let mut request = model_request(&[
        ("x-withhuman-key", ACTIVE),
        ("x-withhuman-user", "mallory@example.com"),
        ("x-withhuman-client", "team/device"),
        ("x-claude-code-session-id", "s-1"),
        ("authorization", "Bearer sk-ant-oat-subscription"),
    ]);
    request
        .attributes
        .as_mut()
        .unwrap()
        .metadata_context
        .get_or_insert_default()
        .filter_metadata
        .insert(
            "withhuman".into(),
            prost_types_struct(&[("model", "claude-opus-5")]),
        );
    let response = check(&service, request).await;
    assert_eq!(denied_with(&response), None);
    let (set, removed) = upstream_headers(&response);
    assert_eq!(set["x-withhuman-user"], "ana@example.com");
    assert_eq!(set["x-withhuman-request"], "req-1");
    assert_eq!(removed, vec!["x-withhuman-key".to_owned()]);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let calls = generator.calls.lock().unwrap();
    assert_eq!(
        calls[0],
        ModelCall {
            request_id: Some("req-1".into()),
            user: Some("ana@example.com".into()),
            client_id: Some("team/device".into()),
            session_id: Some("s-1".into()),
            model: Some("claude-opus-5".into()),
            at: calls[0].at,
        }
    );
}

#[tokio::test]
async fn denies_a_revoked_user_a_stopped_session_and_a_missing_key_in_any_mode() {
    let generator = Arc::new(Generator::default());
    let service = service(generator.clone(), true);
    let revoked = check(&service, model_request(&[("x-withhuman-key", REVOKED)])).await;
    assert_eq!(denied_with(&revoked).as_deref(), Some(keys::KEY_REVOKED));
    let stopped = check(
        &service,
        model_request(&[
            ("x-withhuman-key", ACTIVE),
            ("x-claude-code-session-id", "stopped"),
        ]),
    )
    .await;
    assert_eq!(
        denied_with(&stopped).as_deref(),
        Some(keys::SESSION_STOPPED)
    );
    assert_eq!(
        *generator.denials.lock().unwrap(),
        vec!["stopped".to_owned()]
    );
    let missing = check(&service, model_request(&[])).await;
    assert_eq!(denied_with(&missing).as_deref(), Some(keys::KEY_MISSING));
    assert!(generator.calls.lock().unwrap().is_empty());

    // Keys not required: a request without one goes on without a user, and cannot claim one.
    let open = self::service(generator.clone(), false);
    let response = check(
        &open,
        model_request(&[("x-withhuman-user", "mallory@example.com")]),
    )
    .await;
    let (set, removed) = upstream_headers(&response);
    assert!(!set.contains_key("x-withhuman-user"));
    assert!(removed.contains(&"x-withhuman-user".to_owned()));
}

#[tokio::test]
async fn the_model_route_denies_everything_while_it_is_off() {
    let service = ExtAuthzService::new(
        Arc::new(InMemoryVerdictStore::new(2)),
        EnforcementMode::Enforce,
    );
    let response = check(&service, model_request(&[("x-withhuman-key", ACTIVE)])).await;
    assert!(
        denied_with(&response)
            .unwrap()
            .contains("WITHHUMAN_MODEL_PROXY")
    );
}

fn prost_types_struct(fields: &[(&str, &str)]) -> withhuman_contracts::ext_authz::MetadataStruct {
    withhuman_contracts::ext_authz::MetadataStruct {
        fields: fields
            .iter()
            .map(|(name, value)| {
                (
                    (*name).to_owned(),
                    withhuman_contracts::ext_authz::MetadataValue {
                        kind: Some(
                            withhuman_contracts::ext_authz::MetadataValueKind::StringValue(
                                (*value).to_owned(),
                            ),
                        ),
                    },
                )
            })
            .collect(),
    }
}
