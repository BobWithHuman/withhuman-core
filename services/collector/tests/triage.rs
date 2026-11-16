//! The triage API the Collector serves to administrators: session marks, distrusted sources
//! and a Call's evidence, each passed on to the Generator.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use withhuman_collector::{
    CollectorConfig, CollectorService, GeneratorError, GeneratorTransport, NormalizedEvent,
    app_with_transport,
};
use withhuman_contracts::events::EventResponse;

const ADMIN: &str = "admin-secret";
const SESSION: &str = "0b9f6c1e-0000-4000-8000-000000000001";

/// A request the Collector passed on: method, path segments and body.
type Forwarded = (String, Vec<String>, Option<Value>);

/// A Generator that knows one session and answers as the real one does.
#[derive(Default)]
struct Generator {
    forwarded: Mutex<Vec<Forwarded>>,
    unavailable: bool,
}

#[async_trait]
impl GeneratorTransport for Generator {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        Err(GeneratorError::Rejected(500))
    }

    async fn inventory(
        &self,
        method: reqwest::Method,
        segments: &[&str],
        body: Option<Value>,
    ) -> Result<(u16, Value), GeneratorError> {
        if self.unavailable {
            return Err(GeneratorError::Unavailable("down".into()));
        }
        self.forwarded.lock().unwrap().push((
            method.to_string(),
            segments.iter().map(|s| (*s).to_owned()).collect(),
            body.clone(),
        ));
        let missing = Ok((404, json!({"error": "graph_resource_not_found"})));
        let answer = match segments {
            ["sessions", session, "mark"] if *session == SESSION || *session == "team/s 1" => {
                let body = body.unwrap();
                let mark = match &body["state"] {
                    Value::Null => Value::Null,
                    state => json!({"state": state, "set_by": body["actor"], "set_at": 7}),
                };
                json!({"session_id": session, "mark": mark})
            }
            ["sessions", _, "mark"] => return missing,
            ["sources", "distrust"] => {
                let body = body.unwrap();
                if body["on"] == true {
                    json!({"source": body["source"], "distrusted": true,
                           "set_by": body["actor"], "set_at": 7,
                           "session_id": body["session_id"], "seq": body["seq"]})
                } else {
                    json!({"source": body["source"], "distrusted": false, "set_by": null,
                           "set_at": null, "session_id": null, "seq": null})
                }
            }
            _ => return missing,
        };
        Ok((200, answer))
    }
}

#[tokio::test]
async fn administrators_mark_a_session_and_take_the_mark_off() {
    let generator = Arc::new(Generator::default());
    let path = format!("/v1/admin/sessions/{SESSION}/mark");
    let attack = json!({"state": "attack", "actor": "sec@example.com"});
    refuses_all_but_administrators(&generator, "POST", &path, Some(attack.clone())).await;

    let app = app(generator.clone(), true);
    let (status, body) = post(&app, &path, attack.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"session_id": SESSION,
               "mark": {"state": "attack", "set_by": "sec@example.com", "set_at": 7}})
    );
    // Each of the four states is passed on as named.
    for state in ["reviewing", "closed", "benign"] {
        let (status, body) = post(&app, &path, json!({"state": state})).await;
        assert_eq!(
            (status, &body["mark"]["state"]),
            (StatusCode::OK, &json!(state))
        );
    }
    let (status, body) = post(
        &app,
        &path,
        json!({"state": null, "actor": "sec@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"session_id": SESSION, "mark": null}));
    {
        let forwarded = generator.forwarded.lock().unwrap();
        assert_eq!(forwarded.len(), 5);
        for (method, segments, _) in forwarded.iter() {
            assert_eq!(method, "POST");
            assert_eq!(segments, &["sessions", SESSION, "mark"]);
        }
        assert_eq!(forwarded[0].2, Some(attack));
        assert_eq!(
            forwarded[1].2,
            Some(json!({"state": "reviewing", "actor": null}))
        );
        assert_eq!(
            forwarded[4].2,
            Some(json!({"state": null, "actor": "sec@example.com"}))
        );
    }

    // Another state, or a body that does not say the state: nothing reaches the Generator.
    for body in [
        json!({"state": "unsure"}),
        json!({"state": "ATTACK"}),
        json!({"state": true}),
        json!({"actor": "sec@example.com"}),
        json!({}),
    ] {
        let (status, answer) = post(&app, &path, body.clone()).await;
        assert_eq!(
            (status, answer["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_json")),
            "{body}"
        );
    }
    assert_eq!(generator.forwarded.lock().unwrap().len(), 5);

    // A session ID is one path segment: what is not a letter, digit, `-`, `.`, `_` or `~` in
    // it is percent-encoded, and reaches the Generator decoded.
    let (status, body) = post(
        &app,
        "/v1/admin/sessions/team%2Fs%201/mark",
        json!({"state": "attack"}),
    )
    .await;
    assert_eq!(
        (status, &body["session_id"]),
        (StatusCode::OK, &json!("team/s 1"))
    );
    let (status, _) = post(
        &app,
        "/v1/admin/sessions/team/s1/mark",
        json!({"state": "attack"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(generator.forwarded.lock().unwrap().len(), 6);

    // An unknown session is the Generator's 404.
    let (status, body) = post(
        &app,
        "/v1/admin/sessions/no-such-session/mark",
        json!({"state": "attack"}),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("graph_resource_not_found"))
    );

    let down = self::app(
        Arc::new(Generator {
            unavailable: true,
            ..Generator::default()
        }),
        true,
    );
    let (status, body) = post(&down, &path, json!({"state": "attack"})).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_GATEWAY, Some("generator_unavailable"))
    );

    let (_, document) = send(&app, "GET", "/api-docs/openapi.json", None, true).await;
    assert!(document["paths"]["/v1/admin/sessions/{session_id}/mark"]["post"].is_object());
    let schemas = &document["components"]["schemas"];
    assert_eq!(schemas["MarkSessionRequest"]["required"], json!(["state"]));
    assert_eq!(
        schemas["MarkState"]["enum"],
        json!(["reviewing", "attack", "benign", "closed"])
    );
    assert_eq!(
        schemas["MarkedSession"]["required"],
        json!(["session_id", "mark"])
    );
}

#[tokio::test]
async fn administrators_distrust_a_source_and_trust_it_again() {
    let generator = Arc::new(Generator::default());
    let path = "/v1/admin/sources/distrust";
    // The source is in the body, so a URL or a path needs no encoding.
    let source = "https://example.com/docs/a b.md?x=1&y=/z#frag";
    let on = json!({"source": source, "on": true, "actor": "sec@example.com",
                    "session_id": SESSION, "seq": 12});
    refuses_all_but_administrators(&generator, "POST", path, Some(on.clone())).await;

    let app = app(generator.clone(), true);
    let (status, body) = post(&app, path, on.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"source": source, "distrusted": true, "set_by": "sec@example.com", "set_at": 7,
               "session_id": SESSION, "seq": 12})
    );
    // The Call that showed the source is optional.
    let (status, body) = post(&app, path, json!({"source": "docs/notes.md", "on": true})).await;
    assert_eq!(
        (status, &body["distrusted"], &body["session_id"]),
        (StatusCode::OK, &json!(true), &Value::Null)
    );
    let (status, body) = post(&app, path, json!({"source": source, "on": false})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"source": source, "distrusted": false, "set_by": null, "set_at": null,
               "session_id": null, "seq": null})
    );
    {
        let forwarded = generator.forwarded.lock().unwrap();
        assert_eq!(forwarded.len(), 3);
        for (method, segments, _) in forwarded.iter() {
            assert_eq!(method, "POST");
            assert_eq!(segments, &["sources", "distrust"]);
        }
        assert_eq!(forwarded[0].2, Some(on));
        assert_eq!(
            forwarded[2].2,
            Some(
                json!({"source": source, "on": false, "actor": null, "session_id": null,
                        "seq": null})
            )
        );
    }

    // No source, too long a one, or a body that does not say `on`: nothing is passed on.
    for (body, error) in [
        (json!({"source": "", "on": true}), "invalid_source"),
        (json!({"source": "  \n", "on": false}), "invalid_source"),
        (
            json!({"source": "x".repeat(4_097), "on": true}),
            "invalid_source",
        ),
        (json!({"source": source}), "invalid_json"),
        (json!({"on": true}), "invalid_json"),
        (json!({"source": source, "on": "yes"}), "invalid_json"),
        (
            json!({"source": source, "on": true, "seq": -1}),
            "invalid_json",
        ),
    ] {
        let (status, answer) = post(&app, path, body).await;
        assert_eq!(
            (status, answer["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some(error))
        );
    }
    assert_eq!(generator.forwarded.lock().unwrap().len(), 3);
    let (status, _) = post(&app, path, json!({"source": "x".repeat(4_096), "on": true})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, document) = send(&app, "GET", "/api-docs/openapi.json", None, true).await;
    assert!(document["paths"][path]["post"].is_object());
    let schemas = &document["components"]["schemas"];
    assert_eq!(
        schemas["DistrustSourceRequest"]["required"],
        json!(["source", "on"])
    );
    assert!(schemas["SourceTrust"].is_object());
}

/// Without `WITHHUMAN_ADMIN_TOKEN` the route is not there; with it, a request without the
/// token, or with another, is refused, and none of them reaches the Generator.
async fn refuses_all_but_administrators(
    generator: &Arc<Generator>,
    method: &str,
    path: &str,
    body: Option<Value>,
) {
    let disabled = app(generator.clone(), false);
    let (status, answer) = send(&disabled, method, path, body.clone(), false).await;
    assert_eq!(
        (status, answer["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("admin_api_disabled"))
    );
    let app = app(generator.clone(), true);
    for token in [None, Some("Bearer wrong"), Some("admin-secret")] {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, token);
        }
        let request = match &body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        };
        let (status, answer) = read(app.clone().oneshot(request.unwrap()).await.unwrap()).await;
        assert_eq!(
            (status, answer["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("admin_token_invalid")),
            "{token:?}"
        );
    }
    assert!(generator.forwarded.lock().unwrap().is_empty());
}

fn app(generator: Arc<Generator>, admin: bool) -> Router {
    let config = CollectorConfig {
        intent_capture: false,
        admin_token: admin.then(|| ADMIN.to_owned()),
        ..CollectorConfig::default()
    };
    app_with_transport(CollectorService::new(config, generator))
}

/// A POST as an administrator.
async fn post(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
    send(app, "POST", path, Some(body), true).await
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    admin: bool,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if admin {
        request = request.header(header::AUTHORIZATION, format!("Bearer {ADMIN}"));
    }
    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    };
    read(app.clone().oneshot(request.unwrap()).await.unwrap()).await
}

async fn read(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}
