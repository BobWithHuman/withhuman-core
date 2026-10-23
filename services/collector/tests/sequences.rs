use serde_json::json;
use withhuman_collector::{NormalizedEvent, Normalizer, TrustedHookContext};
use withhuman_contracts::{
    decisions::EnforcementMode,
    hooks::{
        InstructionsLoadedRequest, MessageDisplayRequest, PostToolBatchRequest, PreToolUseRequest,
        UserPromptSubmitRequest,
    },
};

const SESSION: &str = "session-seq";

fn context() -> TrustedHookContext {
    TrustedHookContext {
        client_id: None,
        repository: None,
    }
}

fn sequence(event: &NormalizedEvent) -> Option<u64> {
    match event {
        NormalizedEvent::UserPromptSubmit(event) => event.sequence,
        NormalizedEvent::PreToolUse(event) => event.event.sequence,
        NormalizedEvent::InstructionsLoaded(event) => event.sequence,
        NormalizedEvent::MessageDisplay(event) => event.sequence,
        NormalizedEvent::PostToolBatch(event) => event.sequence,
        _ => None,
    }
}

fn request(normalizer: &Normalizer, prompt: &str) -> Option<u64> {
    sequence(&normalizer.user_prompt_submit(
        &context(),
        UserPromptSubmitRequest {
            session_id: SESSION.into(),
            hook_event_name: None,
            prompt: prompt.into(),
            prompt_id: None,
            transcript_path: None,
            cwd: None,
        },
        1,
    ))
}

fn message(normalizer: &Normalizer, id: &str, text: &str) -> Option<u64> {
    let event = normalizer
        .message_display(
            &context(),
            MessageDisplayRequest {
                session_id: SESSION.into(),
                hook_event_name: None,
                message_id: id.into(),
                delta: text.into(),
                final_: true,
                turn_id: None,
            },
            1,
        )
        .unwrap()
        .unwrap();
    sequence(&event)
}

fn call(normalizer: &Normalizer, tool_use_id: &str, command: &str) -> Option<u64> {
    sequence(&normalizer.pre_tool_use(
        &context(),
        PreToolUseRequest {
            session_id: SESSION.into(),
            hook_event_name: None,
            tool_name: "Bash".into(),
            tool_input: json!({"command":command}),
            tool_use_id: tool_use_id.into(),
            cwd: None,
            prompt_id: None,
            agent_id: None,
            agent_type: None,
        },
        1,
        EnforcementMode::Enforce,
        Some(4_000),
    ))
}

fn batch(normalizer: &Normalizer) {
    normalizer.post_tool_batch(
        &context(),
        PostToolBatchRequest {
            session_id: SESSION.into(),
            hook_event_name: None,
        },
        1,
    );
}

fn instruction(normalizer: &Normalizer, path: &str) -> Option<u64> {
    sequence(&normalizer.instructions_loaded(
        &context(),
        InstructionsLoadedRequest {
            session_id: SESSION.into(),
            hook_event_name: None,
            file_path: path.into(),
            memory_type: None,
            load_reason: None,
            trigger_file_path: None,
            parent_file_path: None,
        },
        1,
    ))
}

#[test]
fn numbers_sequences_across_requests_messages_and_batches() {
    let normalizer = Normalizer::default();

    assert_eq!(request(&normalizer, "first"), Some(0));
    assert_eq!(message(&normalizer, "m1", "Reading."), Some(1));
    assert_eq!(call(&normalizer, "c1", "cat README.md"), Some(1));
    batch(&normalizer);
    assert_eq!(message(&normalizer, "m2", "Installing."), Some(2));
    assert_eq!(call(&normalizer, "c2", "npm install"), Some(2));
    batch(&normalizer);
    assert_eq!(request(&normalizer, "second"), Some(3));
    assert_eq!(message(&normalizer, "m3", "Testing."), Some(4));
    assert_eq!(call(&normalizer, "c3", "npm test"), Some(4));
}

#[test]
fn puts_instructions_loaded_before_the_first_message_into_sequence_zero() {
    let normalizer = Normalizer::default();

    assert_eq!(instruction(&normalizer, "/repo/CLAUDE.md"), Some(0));
    assert_eq!(request(&normalizer, "first"), Some(0));
    assert_eq!(instruction(&normalizer, "/repo/docs/CLAUDE.md"), Some(0));
    assert_eq!(message(&normalizer, "m1", "Reading."), Some(1));
    assert_eq!(instruction(&normalizer, "/repo/src/CLAUDE.md"), Some(1));
}

#[test]
fn groups_calls_without_a_message_into_one_sequence_until_the_batch_ends() {
    let normalizer = Normalizer::default();

    assert_eq!(request(&normalizer, "first"), Some(0));
    assert_eq!(call(&normalizer, "c1", "make bootstrap"), Some(1));
    assert_eq!(call(&normalizer, "c2", "cat README.md"), Some(1));
    batch(&normalizer);
    assert_eq!(call(&normalizer, "c3", "npm test"), Some(2));
}
