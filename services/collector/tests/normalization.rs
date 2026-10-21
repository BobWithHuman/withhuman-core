use serde_json::json;
use withhuman_collector::{NormalizedEvent, Normalizer, SessionStore, TrustedHookContext};
use withhuman_contracts::{
    decisions::EnforcementMode,
    events::SidePending,
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

#[test]
fn assigns_gap_free_orders_only_when_an_event_is_emitted() {
    let normalizer = Normalizer::default();

    let start = normalizer.session_start(
        &context(),
        SessionStartRequest {
            session_id: "session-1".to_owned(),
            hook_event_name: None,
            transcript_path: None,
            cwd: Some("/workspace".to_owned()),
            source: Some("startup".to_owned()),
        },
        10,
    );
    let pending_fragment = normalizer
        .message_display(
            &context(),
            MessageDisplayRequest {
                session_id: "session-1".to_owned(),
                hook_event_name: None,
                message_id: "message-1".to_owned(),
                delta: "partial".to_owned(),
                final_: false,
                turn_id: None,
            },
            11,
        )
        .unwrap();
    let prompt = normalizer.user_prompt_submit(
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
    );

    assert_eq!(start.order(), 1);
    assert!(pending_fragment.is_none());
    assert_eq!(prompt.order(), 2);
}

#[test]
fn aggregates_message_fragments_and_inherits_session_context() {
    let normalizer = Normalizer::default();
    normalizer.user_prompt_submit(
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
    );

    for (delta, final_) in [("hello ", false), ("world", true)] {
        let result = normalizer
            .message_display(
                &context(),
                MessageDisplayRequest {
                    session_id: "session-1".to_owned(),
                    hook_event_name: None,
                    message_id: "message-1".to_owned(),
                    delta: delta.to_owned(),
                    final_,
                    turn_id: Some("turn-2".to_owned()),
                },
                2,
            )
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

#[test]
fn restores_tool_input_and_preserves_tool_correlation() {
    let normalizer = Normalizer::default();
    let pre = normalizer.pre_tool_use(
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
    );
    let post = normalizer.post_tool_use(
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
    );

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

#[test]
fn snapshots_pending_side_analysis_references() {
    let sessions = SessionStore::default();
    sessions.set_side_pending(
        "session-1",
        SidePending {
            paragraphs: vec!["paragraph-hash".to_owned()],
            requests: vec![7],
        },
    );
    let normalizer = Normalizer::new(sessions);

    let event = normalizer.session_start(
        &context(),
        SessionStartRequest {
            session_id: "session-1".to_owned(),
            hook_event_name: None,
            transcript_path: None,
            cwd: None,
            source: None,
        },
        1,
    );

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
