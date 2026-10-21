use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use tower::ServiceExt as _;
use withhuman_collector::app;

const HOOK_ROUTES: [&str; 13] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "SubagentStart",
    "SubagentStop",
    "InstructionsLoaded",
    "ConfigChange",
    "FileChanged",
    "MessageDisplay",
    "PostToolBatch",
    "ToolDescriptions",
];

#[tokio::test]
async fn exposes_every_versioned_hook_route() {
    for event in HOOK_ROUTES {
        let response = app()
            .oneshot(json_request(&format!("/v1/hooks/{event}"), "{}"))
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK, "route {event}");
    }
}

#[tokio::test]
async fn rejects_missing_json_content_type() {
    let response = app()
        .oneshot(
            Request::post("/v1/hooks/PreToolUse")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn maps_malformed_json_to_bad_request() {
    let response = app()
        .oneshot(json_request("/v1/hooks/PreToolUse", "{"))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reports_collector_health() {
    let response = app()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("health body should be readable");
    let json: Value = serde_json::from_slice(&body).expect("health body should be JSON");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "collector");
}

fn json_request(uri: &str, body: &'static str) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-withhuman-client", "team-a/laptop-3")
        .header("x-withhuman-repo", "github.com/org/repo")
        .body(Body::from(body))
        .unwrap()
}
