use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
mod support;

use support::{context, run_scenario};
use withhuman_collector::{
    CollectorConfig, CollectorService, ExtAuthzService, GeneratorError, GeneratorTransport,
    InMemorySessionStore, MessageFragment, NormalizedEvent, Normalizer, RedisSessionStore,
    RedisVerdictStore, SessionStore, VerdictStore, app_with_transport, redis_connection,
};
use withhuman_contracts::{
    decisions::{CausalStart, Decision, DecisionResponse, EnforcementMode},
    events::{EventResponse, PostToolUseEventRequest, SessionCursor},
    ext_authz::{AttributeContext, Authorization, CheckRequest, attribute_context},
};

/// Two replicas share one Redis: the Hook reaches replica A, the extAuthz check replica B.
#[tokio::test]
async fn ext_authz_on_another_replica_finds_the_hook_verdict() {
    let Some(url) = redis_url() else {
        return;
    };
    let tool_use_id = unique("mcp-call");
    let replica_a = replica(&url, Arc::new(DecidingGenerator(Decision::Allow)));
    let replica_b = replica(&url, Arc::new(DecidingGenerator(Decision::Deny)));
    let ext_authz_b = ExtAuthzService::new(replica_b.verdicts.clone(), EnforcementMode::Enforce);

    let response = app_with_transport(replica_a)
        .oneshot(json_request(
            "/v1/hooks/PreToolUse",
            json!({
                "session_id":unique("session"),"tool_name":"mcp__filesystem__write_file",
                "tool_input":{"path":"a"},"tool_use_id":tool_use_id
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let check = Authorization::check(
        &ext_authz_b,
        tonic::Request::new(check_request(&tool_use_id, json!({"path":"a"}))),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(
        check.status.map(|status| status.code),
        Some(0),
        "expected allow"
    );
    let missing = Authorization::check(
        &ext_authz_b,
        tonic::Request::new(check_request(&unique("unknown"), json!({"path":"a"}))),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(
        missing.status.map(|status| status.code),
        Some(7),
        "expected deny"
    );
}

#[tokio::test]
async fn verdicts_expire_after_their_ttl() {
    let Some(url) = redis_url() else {
        return;
    };
    let store = RedisVerdictStore::new(redis_connection(&url).unwrap(), Duration::from_secs(1));
    let tool_use_id = unique("expiring");
    store
        .insert(
            tool_use_id.clone(),
            withhuman_collector::StoredVerdict {
                decision: decision(Decision::Allow),
                tool_name: "Read".to_owned(),
                arguments: json!({}),
            },
        )
        .await
        .unwrap();
    assert!(store.get(&tool_use_id).await.unwrap().is_some());
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert!(store.get(&tool_use_id).await.unwrap().is_none());
}

/// The Redis store must emit exactly the bytes the in-process store emits for every Hook.
#[tokio::test]
async fn redis_sessions_normalize_like_in_memory_sessions() {
    let Some(url) = redis_url() else {
        return;
    };
    let session_id = unique("equivalence");
    let in_memory = run_scenario(
        Normalizer::new(InMemorySessionStore::default()),
        &session_id,
    )
    .await;
    let redis = run_scenario(
        Normalizer::new(RedisSessionStore::new(
            redis_connection(&url).unwrap(),
            Duration::from_secs(60),
        )),
        &session_id,
    )
    .await;

    assert_eq!(in_memory.len(), 16);
    assert_eq!(in_memory, redis);
    let golden = support::GOLDEN.replace(support::GOLDEN_SESSION_ID, &session_id);
    assert_eq!(redis, golden.lines().collect::<Vec<_>>());
}

/// Events of one session processed concurrently by two replicas never share an order or an
/// agent sequence, and leave no gaps.
#[tokio::test]
async fn concurrent_events_on_two_replicas_get_unique_orders() {
    let Some(url) = redis_url() else {
        return;
    };
    let generator = Arc::new(RecordingGenerator::default());
    let apps = [
        app_with_transport(replica(&url, generator.clone())),
        app_with_transport(replica(&url, generator.clone())),
    ];
    let session_id = unique("concurrent");
    let events = 40_u64;

    let handles = (0..events)
        .map(|index| {
            let app = apps[usize::try_from(index % 2).unwrap()].clone();
            let request = json_request(
                "/v1/hooks/PreToolUse",
                json!({
                    "session_id":session_id,"tool_name":"Read","tool_input":{"n":index},
                    "tool_use_id":format!("tool-{index}"),"agent_id":"main"
                }),
            );
            tokio::spawn(async move { app.oneshot(request).await.unwrap().status() })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        assert_eq!(handle.await.unwrap(), StatusCode::OK);
    }

    let mut orders = generator.orders.lock().unwrap().clone();
    let mut sequences = generator.sequences.lock().unwrap().clone();
    orders.sort_unstable();
    sequences.sort_unstable();
    let expected = (1..=events).collect::<Vec<_>>();
    assert_eq!(orders, expected);
    assert_eq!(sequences, expected);
}

#[tokio::test]
async fn session_keys_expire_after_inactivity() {
    let Some(url) = redis_url() else {
        return;
    };
    let mut connection = redis_connection(&url).unwrap();
    let sessions = RedisSessionStore::new(connection.clone(), Duration::from_secs(30));
    let normalizer = Normalizer::new(sessions.clone());
    let session_id = unique("ttl");
    normalizer
        .pre_tool_use(
            &context(),
            serde_json::from_value(json!({
                "session_id":session_id,"tool_name":"Read","tool_input":{},"tool_use_id":"t-1"
            }))
            .unwrap(),
            1,
            EnforcementMode::Enforce,
            None,
        )
        .await
        .unwrap();
    sessions
        .append_fragment(
            &session_id,
            MessageFragment {
                message_id: "m-1".to_owned(),
                index: Some(0),
                delta: "partial".to_owned(),
            },
        )
        .await
        .unwrap();

    for key in [
        format!("withhuman:session:{{{session_id}}}"),
        format!("withhuman:session:{{{session_id}}}:tool_input:t-1"),
        format!("withhuman:session:{{{session_id}}}:fragment:m-1"),
    ] {
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!((1..=30).contains(&ttl), "{key} has TTL {ttl}");
    }
}

/// Losing a session's Redis state (expiry, flush, failover) resumes after the Generator cursor.
#[tokio::test]
async fn resumes_orders_after_redis_state_is_lost() {
    let Some(url) = redis_url() else {
        return;
    };
    let generator = Arc::new(RecordingGenerator::default());
    let app = app_with_transport(replica(&url, generator.clone()));
    let session_id = unique("resume");
    let pre_tool = |index: u64| {
        json_request(
            "/v1/hooks/PreToolUse",
            json!({
                "session_id":session_id,"tool_name":"Read","tool_input":{},
                "tool_use_id":format!("tool-{index}"),"agent_id":"main"
            }),
        )
    };
    for index in 0..3 {
        app.clone().oneshot(pre_tool(index)).await.unwrap();
    }
    let mut connection = redis_connection(&url).unwrap();
    redis::cmd("DEL")
        .arg(format!("withhuman:session:{{{session_id}}}"))
        .query_async::<()>(&mut connection)
        .await
        .unwrap();
    app.oneshot(pre_tool(3)).await.unwrap();

    let orders = generator.orders.lock().unwrap().clone();
    let sequences = generator.sequences.lock().unwrap().clone();
    assert_eq!(
        orders,
        vec![1, 2, 3, 3 + withhuman_collector::RESUME_ORDER_GAP + 1]
    );
    assert_eq!(sequences, vec![1, 2, 3, 4]);
}

/// Losing all of a session's Redis state also restores its cwd, prompt id and the input of a
/// tool result whose Hook omits it.
#[tokio::test]
async fn restores_session_context_after_redis_state_is_lost() {
    let Some(url) = redis_url() else {
        return;
    };
    let generator = Arc::new(RecordingGenerator::default());
    let app = app_with_transport(replica(&url, generator.clone()));
    let session_id = unique("context");
    for request in [
        json_request(
            "/v1/hooks/UserPromptSubmit",
            json!({"session_id":session_id,"prompt":"go","prompt_id":"p1","cwd":"/repo"}),
        ),
        json_request(
            "/v1/hooks/PreToolUse",
            json!({
                "session_id":session_id,"tool_name":"Bash","tool_input":{"command":"ls"},
                "tool_use_id":"tool-1"
            }),
        ),
    ] {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }
    let mut connection = redis_connection(&url).unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("withhuman:session:{{{session_id}}}*"))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(keys.len(), 2, "session hash and remembered tool input");
    redis::cmd("DEL")
        .arg(&keys)
        .query_async::<()>(&mut connection)
        .await
        .unwrap();

    let response = app
        .oneshot(json_request(
            "/v1/hooks/PostToolUse",
            json!({
                "session_id":session_id,"tool_name":"Bash","tool_response":"ok",
                "tool_use_id":"tool-1"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let results = generator.results.lock().unwrap();
    assert_eq!(results[0].payload.tool_input, Some(json!({"command":"ls"})));
    assert_eq!(results[0].meta.cwd.as_deref(), Some("/repo"));
    assert_eq!(results[0].meta.prompt_id.as_deref(), Some("p1"));
}

/// Replicas that meet an unknown session at the same time seed it once and share one numbering.
#[tokio::test]
async fn replicas_seed_a_resumed_session_once() {
    let Some(url) = redis_url() else {
        return;
    };
    let generator = Arc::new(RecordingGenerator::resuming_after(10));
    let apps = [
        app_with_transport(replica(&url, generator.clone())),
        app_with_transport(replica(&url, generator.clone())),
    ];
    let session_id = unique("seed-race");
    let handles = (0..20_u64)
        .map(|index| {
            let app = apps[usize::try_from(index % 2).unwrap()].clone();
            let request = json_request(
                "/v1/hooks/PreToolUse",
                json!({
                    "session_id":session_id,"tool_name":"Read","tool_input":{},
                    "tool_use_id":format!("tool-{index}"),"agent_id":"main"
                }),
            );
            tokio::spawn(async move { app.oneshot(request).await.unwrap().status() })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        assert_eq!(handle.await.unwrap(), StatusCode::OK);
    }

    let mut orders = generator.orders.lock().unwrap().clone();
    orders.sort_unstable();
    let first = 10 + withhuman_collector::RESUME_ORDER_GAP + 1;
    assert_eq!(orders, (first..first + 20).collect::<Vec<_>>());
}

/// Fragments of one message delivered out of order to different replicas assemble by index.
#[tokio::test]
async fn assembles_fragments_by_index_across_replicas() {
    let Some(url) = redis_url() else {
        return;
    };
    let generator = Arc::new(RecordingGenerator::default());
    let apps = [
        app_with_transport(replica(&url, generator.clone())),
        app_with_transport(replica(&url, generator.clone())),
    ];
    let session_id = unique("fragments");
    for (replica, index, delta, final_) in [
        (0, 2, "C", false),
        (1, 0, "A", false),
        (0, 1, "B", false),
        (1, 1, "B", false),
        (0, 3, "D", true),
    ] {
        let response = apps[replica]
            .clone()
            .oneshot(json_request(
                "/v1/hooks/MessageDisplay",
                json!({
                    "session_id":session_id,"message_id":"m-1","index":index,
                    "delta":delta,"final":final_
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    assert_eq!(generator.messages.lock().unwrap().clone(), vec!["ABCD"]);
}

/// `(order, cwd, prompt_id)` of a committed event.
type CommittedContext = (u64, Option<String>, Option<String>);

/// Records what it receives and answers cursor and tool input lookups from what it recorded,
/// like the Generator does from committed events.
#[derive(Default)]
struct RecordingGenerator {
    orders: Mutex<Vec<u64>>,
    sequences: Mutex<Vec<u64>>,
    messages: Mutex<Vec<String>>,
    contexts: Mutex<Vec<CommittedContext>>,
    inputs: Mutex<HashMap<String, Value>>,
    results: Mutex<Vec<PostToolUseEventRequest>>,
    resume_after: u64,
}

impl RecordingGenerator {
    fn resuming_after(last_order: u64) -> Self {
        Self {
            resume_after: last_order,
            ..Self::default()
        }
    }
}

#[async_trait]
impl GeneratorTransport for RecordingGenerator {
    async fn send(&self, event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        let acknowledged = EventResponse {
            nodes: Vec::new(),
            paragraphs: None,
            version: 1,
            decision_response: None,
        };
        let event = match event {
            NormalizedEvent::PreToolUse(event) => event,
            NormalizedEvent::MessageDisplay(event) => {
                self.messages.lock().unwrap().push(event.payload.text);
                return Ok(acknowledged);
            }
            NormalizedEvent::UserPromptSubmit(event) => {
                self.contexts.lock().unwrap().push((
                    event.order,
                    event.meta.cwd,
                    event.meta.prompt_id,
                ));
                return Ok(acknowledged);
            }
            NormalizedEvent::PostToolUse(event) => {
                self.results.lock().unwrap().push(event);
                return Ok(acknowledged);
            }
            other => panic!("unexpected {}", other.event_name()),
        };
        self.orders.lock().unwrap().push(event.event.order);
        self.sequences.lock().unwrap().extend(event.event.sequence);
        self.contexts.lock().unwrap().push((
            event.event.order,
            event.event.meta.cwd.clone(),
            event.event.meta.prompt_id.clone(),
        ));
        self.inputs.lock().unwrap().insert(
            event.event.meta.tool_use_id.clone().unwrap(),
            event.event.payload.tool_input.clone(),
        );
        Ok(EventResponse {
            decision_response: Some(decision(Decision::Allow)),
            ..acknowledged
        })
    }

    async fn session_cursor(&self, _session_id: &str) -> Result<SessionCursor, GeneratorError> {
        let contexts = self.contexts.lock().unwrap().clone();
        let latest = contexts.iter().max_by_key(|(order, _, _)| *order);
        let sequence = self.sequences.lock().unwrap().iter().copied().max();
        Ok(SessionCursor {
            last_order: latest.map_or(self.resume_after, |(order, _, _)| *order),
            agent_sequences: sequence
                .map(|sequence| ("main".to_owned(), sequence))
                .into_iter()
                .collect(),
            cwd: latest.and_then(|(_, cwd, _)| cwd.clone()),
            prompt_id: latest.and_then(|(_, _, prompt_id)| prompt_id.clone()),
        })
    }

    async fn tool_input(
        &self,
        _session_id: &str,
        tool_use_id: &str,
    ) -> Result<Option<Value>, GeneratorError> {
        Ok(self.inputs.lock().unwrap().get(tool_use_id).cloned())
    }
}

fn redis_url() -> Option<String> {
    let url = std::env::var("REDIS_INTEGRATION_URL").ok();
    if url.is_none() {
        eprintln!("skipping Redis integration test; REDIS_INTEGRATION_URL is unset");
    }
    url
}

fn replica(url: &str, generator: Arc<dyn GeneratorTransport>) -> CollectorService {
    let config = CollectorConfig {
        redis_url: Some(url.to_owned()),
        ..CollectorConfig::default()
    };
    CollectorService::from_config(config, generator).unwrap()
}

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

struct DecidingGenerator(Decision);

#[async_trait]
impl GeneratorTransport for DecidingGenerator {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        Ok(EventResponse {
            nodes: Vec::new(),
            paragraphs: None,
            version: 1,
            decision_response: Some(decision(self.0)),
        })
    }
}

fn decision(decision: Decision) -> DecisionResponse {
    DecisionResponse {
        decision,
        reason: String::new(),
        rule: "redis-it".to_owned(),
        start: CausalStart::User,
        written: true,
        jev: None,
    }
}

fn json_request(uri: &str, body: Value) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn check_request(tool_use_id: &str, arguments: Value) -> CheckRequest {
    let body = json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"write_file","arguments":arguments,
                  "_meta":{"claudecode/toolUseId":tool_use_id}}
    });
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
