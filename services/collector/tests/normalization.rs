mod support;

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use serde_json::json;
use withhuman_collector::{
    GeneratorError, GeneratorTransport, InMemorySessionStore, MESSAGE_INCOMPLETE_FLAG,
    NormalizeError, NormalizedEvent, Normalizer, SessionStore, TrustedHookContext,
};
use withhuman_contracts::{
    decisions::EnforcementMode,
    events::{EventResponse, SessionCursor, SidePending},
    hooks::{
        MessageDisplayRequest, PostToolUseRequest, PreToolUseRequest, SessionStartRequest,
        UserPromptSubmitRequest,
    },
};

fn context() -> TrustedHookContext {
    TrustedHookContext {
        client_id: Some("team-a/laptop-3".to_owned()),
        repository: Some("github.com/acme/service".to_owned()),
    }
}

#[tokio::test]
async fn assigns_gap_free_orders_only_when_an_event_is_emitted() {
    let normalizer = Normalizer::default();

    let start = normalizer
        .session_start(
            &context(),
            SessionStartRequest {
                session_id: "session-1".to_owned(),
                hook_event_name: None,
                transcript_path: None,
                cwd: Some("/workspace".to_owned()),
                source: Some("startup".to_owned()),
            },
            10,
        )
        .await
        .unwrap();
    let pending_fragment = normalizer
        .message_display(
            &context(),
            MessageDisplayRequest {
                session_id: "session-1".to_owned(),
                hook_event_name: None,
                message_id: "message-1".to_owned(),
                index: None,
                delta: "partial".to_owned(),
                final_: false,
                turn_id: None,
            },
            11,
        )
        .await
        .unwrap();
    let prompt = normalizer
        .user_prompt_submit(
            &context(),
            UserPromptSubmitRequest {
                session_id: "session-1".to_owned(),
                hook_event_name: None,
                prompt: "inspect the service".to_owned(),
                prompt_id: Some("prompt-1".to_owned()),
                transcript_path: None,
                cwd: None,
            },
            12,
        )
        .await
        .unwrap();

    assert_eq!(start.order(), 1);
    let NormalizedEvent::SessionStart(start) = start else {
        panic!("expected SessionStart");
    };
    assert_eq!(start.meta.cwd.as_deref(), Some("/workspace"));
    assert_eq!(start.meta.repo.as_deref(), Some("github.com/acme/service"));
    assert!(pending_fragment.is_none());
    assert_eq!(prompt.order(), 2);
}

#[tokio::test]
async fn aggregates_message_fragments_and_inherits_session_context() {
    let normalizer = Normalizer::default();
    normalizer
        .user_prompt_submit(
            &context(),
            UserPromptSubmitRequest {
                session_id: "session-1".to_owned(),
                hook_event_name: None,
                prompt: "hello".to_owned(),
                prompt_id: Some("prompt-7".to_owned()),
                transcript_path: None,
                cwd: Some("/repo".to_owned()),
            },
            1,
        )
        .await
        .unwrap();

    for (delta, final_) in [("hello ", false), ("world", true)] {
        let result = normalizer
            .message_display(
                &context(),
                MessageDisplayRequest {
                    session_id: "session-1".to_owned(),
                    hook_event_name: None,
                    message_id: "message-1".to_owned(),
                    index: None,
                    delta: delta.to_owned(),
                    final_,
                    turn_id: Some("turn-2".to_owned()),
                },
                2,
            )
            .await
            .unwrap();

        if final_ {
            let Some(NormalizedEvent::MessageDisplay(event)) = result else {
                panic!("final fragment should emit MessageDisplay");
            };
            assert_eq!(event.payload.text, "hello world");
            assert_eq!(event.meta.cwd.as_deref(), Some("/repo"));
            assert_eq!(event.meta.prompt_id.as_deref(), Some("prompt-7"));
            assert_eq!(event.meta.turn_id.as_deref(), Some("turn-2"));
        } else {
            assert!(result.is_none());
        }
    }
}

#[tokio::test]
async fn restores_tool_input_and_preserves_tool_correlation() {
    let normalizer = Normalizer::default();
    let pre = normalizer
        .pre_tool_use(
            &context(),
            PreToolUseRequest {
                session_id: "session-1".to_owned(),
                hook_event_name: None,
                tool_name: "Bash".to_owned(),
                tool_input: json!({"command": "cargo test"}),
                tool_use_id: "tool-9".to_owned(),
                cwd: Some("/repo".to_owned()),
                prompt_id: Some("prompt-1".to_owned()),
                agent_id: Some("agent-1".to_owned()),
                agent_type: Some("main".to_owned()),
            },
            100,
            EnforcementMode::Enforce,
            Some(4_000),
        )
        .await
        .unwrap();
    let post = normalizer
        .post_tool_use(
            &context(),
            PostToolUseRequest {
                session_id: "session-1".to_owned(),
                hook_event_name: None,
                tool_name: "Bash".to_owned(),
                tool_input: None,
                tool_response: json!({"exit_code": 0}),
                tool_use_id: "tool-9".to_owned(),
                cwd: None,
                prompt_id: None,
                agent_id: Some("agent-1".to_owned()),
                agent_type: Some("main".to_owned()),
            },
            101,
        )
        .await
        .unwrap();

    let NormalizedEvent::PreToolUse(pre) = pre else {
        panic!("expected PreToolUse");
    };
    let NormalizedEvent::PostToolUse(post) = post else {
        panic!("expected PostToolUse");
    };
    assert_eq!(pre.event.sequence, Some(1));
    assert_eq!(post.sequence, Some(2));
    assert_eq!(post.meta.tool_use_id.as_deref(), Some("tool-9"));
    assert_eq!(
        post.payload.tool_input,
        Some(json!({"command": "cargo test"}))
    );
}

#[tokio::test]
async fn snapshots_pending_side_analysis_references() {
    let sessions = InMemorySessionStore::default();
    sessions
        .set_side_pending(
            "session-1",
            SidePending {
                paragraphs: vec!["paragraph-hash".to_owned()],
                requests: vec![7],
            },
        )
        .await
        .unwrap();
    let normalizer = Normalizer::new(sessions);

    let event = normalizer
        .session_start(
            &context(),
            SessionStartRequest {
                session_id: "session-1".to_owned(),
                hook_event_name: None,
                transcript_path: None,
                cwd: None,
                source: None,
            },
            1,
        )
        .await
        .unwrap();

    let NormalizedEvent::SessionStart(event) = event else {
        panic!("expected SessionStart");
    };
    assert_eq!(
        event.side_pending,
        Some(SidePending {
            paragraphs: vec!["paragraph-hash".to_owned()],
            requests: vec![7],
        })
    );
}

/// Every Hook must normalize to the exact bytes the Collector produced before its session state
/// moved behind `SessionStore`, plus the `subgraph` field added since.
#[tokio::test]
async fn normalizes_the_scenario_byte_for_byte_like_the_original_collector() {
    let emitted = support::run_scenario(Normalizer::default(), support::GOLDEN_SESSION_ID).await;

    assert_eq!(emitted, support::GOLDEN.lines().collect::<Vec<_>>());
}

/// After a restart or lost state the Collector continues after the Generator's committed cursor
/// instead of reusing orders, and every agent continues its sequence.
#[tokio::test]
async fn resumes_numbering_after_the_generator_cursor() {
    let history = Arc::new(History(Ok(SessionCursor {
        last_order: 41,
        agent_sequences: BTreeMap::from([("agent-1".to_owned(), 7)]),
        ..Default::default()
    })));
    let normalizer = Normalizer::default().with_history(history);

    let first = normalizer
        .pre_tool_use(
            &context(),
            serde_json::from_value(json!({
                "session_id":"session-1","tool_name":"Read","tool_input":{},
                "tool_use_id":"tool-1","agent_id":"agent-1"
            }))
            .unwrap(),
            1,
            EnforcementMode::Enforce,
            None,
        )
        .await
        .unwrap();
    let second = normalizer
        .post_tool_batch(
            &context(),
            serde_json::from_value(json!({"session_id":"session-1"})).unwrap(),
            2,
        )
        .await
        .unwrap();

    let NormalizedEvent::PreToolUse(first) = first else {
        panic!("expected PreToolUse");
    };
    assert_eq!(
        first.event.order,
        41 + withhuman_collector::RESUME_ORDER_GAP + 1
    );
    assert_eq!(first.event.sequence, Some(8));
    assert_eq!(second.order(), first.event.order + 1);
}

/// A lost session resumes inside its committed open SubGraph: the waiting call's result joins it,
/// the next call too, and the intent a fragment stated before the seed is kept.
#[tokio::test]
async fn resumes_inside_the_committed_open_subgraph() {
    let normalizer =
        Normalizer::default().with_history(Arc::new(support::Committed(support::resume_cursor())));
    let emitted = support::run_steps(normalizer, "session-1", support::RESUME_SCENARIO).await;
    let observed: Vec<(u64, Option<String>)> = emitted
        .iter()
        .map(|event| {
            let event: serde_json::Value = serde_json::from_str(event).unwrap();
            (
                event["subgraph"].as_u64().unwrap(),
                event["intent"].as_str().map(str::to_owned),
            )
        })
        .collect();
    let intent = Some("새 의도".to_owned());
    assert_eq!(
        observed,
        [(3, None), (3, intent.clone()), (4, None), (4, intent)]
    );
}

/// A session committed before SubGraphs were numbered continues after SubGraph 0, which
/// belongs to a session's first prompt.
#[tokio::test]
async fn numbers_a_session_without_subgraphs_after_subgraph_zero() {
    let normalizer =
        Normalizer::default().with_history(Arc::new(support::Committed(SessionCursor {
            last_order: 12,
            ..Default::default()
        })));
    let emitted = support::run_steps(
        normalizer,
        "session-1",
        r#"[["MessageDisplay", {"message_id": "m1", "delta": "hi", "final": true}],
            ["UserPromptSubmit", {"prompt": "next"}]]"#,
    )
    .await;
    let subgraphs: Vec<u64> = emitted
        .iter()
        .map(|event| {
            serde_json::from_str::<serde_json::Value>(event).unwrap()["subgraph"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(subgraphs, [1, 2]);
}

#[tokio::test]
async fn reports_an_unreadable_generator_cursor() {
    let history = Arc::new(History(Err(GeneratorError::Unavailable("down".to_owned()))));
    let normalizer = Normalizer::default().with_history(history);

    let result = normalizer
        .post_tool_batch(
            &context(),
            serde_json::from_value(json!({"session_id":"session-1"})).unwrap(),
            1,
        )
        .await;

    assert!(matches!(result, Err(NormalizeError::History(_))));
}

/// The cwd, prompt id and remembered tool inputs of a session the Collector lost come back from
/// the Generator instead of going missing until a later Hook resends them.
#[tokio::test]
async fn restores_lost_session_context_from_the_generator() {
    let history = Arc::new(History(Ok(SessionCursor {
        last_order: 9,
        cwd: Some("/repo".to_owned()),
        prompt_id: Some("prompt-3".to_owned()),
        ..Default::default()
    })));
    let normalizer = Normalizer::default().with_history(history);

    let post = normalizer
        .post_tool_use(
            &context(),
            serde_json::from_value(json!({
                "session_id":"session-1","tool_name":"Bash","tool_response":"ok",
                "tool_use_id":"tool-9"
            }))
            .unwrap(),
            1,
        )
        .await
        .unwrap();

    let NormalizedEvent::PostToolUse(post) = post else {
        panic!("expected PostToolUse");
    };
    assert_eq!(post.meta.cwd.as_deref(), Some("/repo"));
    assert_eq!(post.meta.prompt_id.as_deref(), Some("prompt-3"));
    assert_eq!(post.payload.tool_input, Some(json!({"restored": "tool-9"})));
}

/// Fragments join by their flush index, so retried and reordered deliveries still yield the
/// streamed text; a missing index is flagged instead of silently dropped.
#[tokio::test]
async fn assembles_message_fragments_by_index() {
    let assembled = assemble(
        Normalizer::default(),
        &[
            (1, "B", false),
            (0, "A", false),
            (1, "B", false),
            (2, "C", true),
        ],
    )
    .await;
    assert_eq!(assembled.payload.text, "ABC");
    assert_eq!(assembled.flags, None);

    let gapped = assemble(Normalizer::default(), &[(0, "A", false), (2, "C", true)]).await;
    assert_eq!(gapped.payload.text, "AC");
    assert_eq!(gapped.flags, Some(vec![MESSAGE_INCOMPLETE_FLAG.to_owned()]));
}

async fn assemble(
    normalizer: Normalizer,
    fragments: &[(u64, &str, bool)],
) -> withhuman_contracts::events::MessageDisplayEventRequest {
    let mut emitted = None;
    for (index, delta, final_) in fragments {
        emitted = normalizer
            .message_display(
                &context(),
                MessageDisplayRequest {
                    session_id: "session-1".to_owned(),
                    hook_event_name: None,
                    message_id: "message-1".to_owned(),
                    index: Some(*index),
                    delta: (*delta).to_owned(),
                    final_: *final_,
                    turn_id: None,
                },
                1,
            )
            .await
            .unwrap();
    }
    let Some(NormalizedEvent::MessageDisplay(event)) = emitted else {
        panic!("final fragment should emit MessageDisplay");
    };
    event
}

struct History(Result<SessionCursor, GeneratorError>);

#[async_trait]
impl GeneratorTransport for History {
    async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
        unreachable!("normalization never sends events")
    }

    async fn session_cursor(&self, _session_id: &str) -> Result<SessionCursor, GeneratorError> {
        self.0.clone()
    }

    async fn tool_input(
        &self,
        _session_id: &str,
        tool_use_id: &str,
    ) -> Result<Option<serde_json::Value>, GeneratorError> {
        Ok(Some(json!({"restored": tool_use_id})))
    }
}

/// Session-wide SubGraphs follow the conversation: SubGraph 0 holds the first prompt and what
/// came before the first message; each message opens a SubGraph its calls and results join
/// (also when the message arrives after its first call); a later prompt stands alone. A config
/// change joins the SubGraph that is open.
#[tokio::test]
async fn numbers_session_wide_subgraphs_and_carries_the_stated_intent() {
    let emitted = support::run_steps(
        Normalizer::default(),
        "session-1",
        support::SUBGRAPH_SCENARIO,
    )
    .await;
    let observed: Vec<(String, u64, Option<String>)> = emitted
        .iter()
        .map(|event| {
            let event: serde_json::Value = serde_json::from_str(event).unwrap();
            let hook = match event["payload"].as_object().unwrap() {
                payload if payload.contains_key("prompt") => "Request",
                payload if payload.contains_key("agent_id") => "Subagent",
                payload if payload.contains_key("text") => "Message",
                payload if payload.contains_key("source") => "ConfigChange",
                payload if payload.contains_key("tool_response") => "Result",
                payload if payload.contains_key("tool_input") => "Call",
                _ => "Batch",
            };
            (
                hook.to_owned(),
                event["subgraph"].as_u64().unwrap(),
                event["intent"].as_str().map(str::to_owned),
            )
        })
        .collect();
    let intent = Some("로그인 버그 수정 (확신도: 높음)".to_owned());
    let deploy = Some("배포 (확신도: 중간)".to_owned());
    let expected: Vec<(String, u64, Option<String>)> = [
        ("ConfigChange", 0, None),
        ("Request", 0, None),
        ("Message", 1, None),
        ("Call", 1, intent.clone()),
        ("Call", 1, intent.clone()),
        ("Result", 1, None),
        ("Result", 1, None),
        ("Batch", 1, None),
        ("Call", 2, intent.clone()),
        ("Message", 2, None),
        ("Result", 2, None),
        ("Batch", 2, None),
        ("Call", 3, intent),
        ("Result", 3, None),
        ("Batch", 3, None),
        ("Request", 4, None),
        ("Call", 5, None),
        ("ConfigChange", 5, None),
        // A subagent's calls get SubGraphs of their own; the main agent's SubGraph stays open.
        ("Subagent", 5, None),
        ("Message", 5, None),
        ("Call", 6, deploy.clone()),
        ("Call", 5, deploy.clone()),
        // A repeated message keeps its SubGraph; a later intent line does not replace the
        // turn's first.
        ("Message", 5, None),
        ("Message", 7, None),
        ("Result", 6, None),
        ("Batch", 6, None),
        ("Result", 5, None),
        // A batch closes the SubGraph of its calls only.
        ("Batch", 5, None),
        ("Call", 7, deploy.clone()),
        // Naming only batched calls, a late repeat closes nothing.
        ("Batch", 7, None),
        ("Result", 7, None),
        ("Batch", 7, None),
    ]
    .into_iter()
    .map(|(hook, subgraph, intent)| (hook.to_owned(), subgraph, intent))
    .collect();
    assert_eq!(observed, expected);
}
