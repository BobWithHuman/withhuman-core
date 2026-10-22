use std::{io, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct FixtureState {
    calls: Arc<Mutex<Vec<Value>>>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let address = std::env::var("MCP_FIXTURE_ADDR").unwrap_or_else(|_| "0.0.0.0:8090".into());
    let listener = tokio::net::TcpListener::bind(address).await?;
    let state = FixtureState::default();
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/calls", get(calls))
        .route("/mcp", post(mcp))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn health() -> &'static str {
    "ok"
}

async fn calls(State(state): State<FixtureState>) -> Json<Value> {
    Json(json!({"calls": *state.calls.lock().await}))
}

async fn mcp(
    State(state): State<FixtureState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let response = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": request.pointer("/params/protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2025-03-26"),
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "withhuman-e2e-fixture", "version": "0.1.0"}
            }
        }),
        "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [{
                    "name": "write_file",
                    "description": "Records a deterministic E2E tool call.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"]
                    }
                }]
            }
        }),
        "tools/call" => {
            state.calls.lock().await.push(request.clone());
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"content": [{"type": "text", "text": "fixture call accepted"}]}
            })
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": "Method not found"}
        }),
    };

    let mut output_headers = HeaderMap::new();
    output_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if method == "initialize" && !headers.contains_key("mcp-session-id") {
        output_headers.insert(
            "mcp-session-id",
            HeaderValue::from_static("fixture-session"),
        );
    }
    (StatusCode::OK, output_headers, Json(response)).into_response()
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
