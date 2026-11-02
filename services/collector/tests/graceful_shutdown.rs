#![cfg(unix)]

use std::{
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::sync::Notify;

const WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
struct HeldEvent {
    arrived: Arc<Notify>,
    release: Arc<Notify>,
}

/// Answers an event only when told to, so the event stays in flight in the Collector.
async fn hold_event(State(held): State<HeldEvent>) -> Json<Value> {
    held.arrived.notify_one();
    held.release.notified().await;
    Json(json!({"nodes": [], "paragraphs": null, "version": 1, "decision_response": null}))
}

async fn empty_cursor() -> Json<Value> {
    Json(json!({"last_order": 0}))
}

struct Collector {
    child: Child,
    url: String,
}

impl Collector {
    fn start(generator: SocketAddr) -> Self {
        let address = free_address();
        let child = Command::new(env!("CARGO_BIN_EXE_withhuman-collector"))
            .env("COLLECTOR_ADDR", address.to_string())
            .env("COLLECTOR_EXT_AUTHZ_ADDR", free_address().to_string())
            .env("GENERATOR_URL", format!("http://{generator}"))
            .env("WITHHUMAN_DECISION_TIMEOUT_MS", "9000")
            .env_remove("REDIS_URL")
            .stdout(Stdio::null())
            .spawn()
            .expect("the Collector binary starts");
        Self {
            child,
            url: format!("http://{address}"),
        }
    }

    async fn wait_until_ready(&self, client: &reqwest::Client) {
        let deadline = Instant::now() + WAIT;
        while client
            .get(format!("{}/healthz", self.url))
            .send()
            .await
            .is_err()
        {
            assert!(Instant::now() < deadline, "the Collector did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn signal_terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(status.success());
    }

    async fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().expect("the Collector can be polled") {
                return status;
            }
            assert!(Instant::now() < deadline, "the Collector did not stop");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port exists")
}

#[tokio::test]
async fn sigterm_finishes_requests_in_flight_then_exits() {
    let held = HeldEvent::default();
    let generator = Router::new()
        .route("/v1/sessions/{session_id}/cursor", get(empty_cursor))
        .route("/v1/events/SessionStart", post(hold_event))
        .with_state(held.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fake Generator binds");
    let generator_address = listener.local_addr().expect("it has an address");
    tokio::spawn(async move { axum::serve(listener, generator).await });

    let mut collector = Collector::start(generator_address);
    let client = reqwest::Client::new();
    collector.wait_until_ready(&client).await;

    let hook = tokio::spawn(
        client
            .post(format!("{}/v1/hooks/SessionStart", collector.url))
            .json(&json!({"session_id": "s", "cwd": "/repo"}))
            .send(),
    );
    tokio::time::timeout(WAIT, held.arrived.notified())
        .await
        .expect("the event reaches the Generator");

    collector.signal_terminate();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        collector
            .child
            .try_wait()
            .expect("the Collector can be polled")
            .is_none(),
        "the Collector must wait for the request it holds"
    );

    held.release.notify_one();
    let response = hook
        .await
        .expect("the hook task finishes")
        .expect("the hook gets an answer");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(collector.wait_for_exit().await.success());
}
