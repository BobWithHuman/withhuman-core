use serde_json::{Value, json};
use withhuman_contracts::events::{
    EventResponse, InstructionsLoadedEventRequest, PieceClassificationRequest,
    PreToolUseEventRequest, RequestContinuationRequest, UserPromptSubmitEventRequest,
};

#[test]
fn deserializes_common_event_envelope_and_preserves_additive_fields() {
    let request: UserPromptSubmitEventRequest = serde_json::from_value(json!({
        "session_id": "8e78",
        "order": 40,
        "observed_at": 1760925599000_u64,
        "client_id": "team-a/laptop-3",
        "meta": { "cwd": "/app", "future_meta": true },
        "side_pending": { "pieces": [], "requests": [40] },
        "payload": {
            "prompt": "continue",
            "kind": "user",
            "user_docs": [],
            "future_payload": "kept"
        },
        "future_envelope": 7
    }))
    .expect("the final-spec event should deserialize");

    assert_eq!(request.order, 40);
    assert_eq!(request.meta.additional_fields["future_meta"], true);
    assert_eq!(request.payload.additional_fields["future_payload"], "kept");
    assert_eq!(request.additional_fields["future_envelope"], 7);
}

#[test]
fn rejects_event_without_required_order() {
    let error = serde_json::from_value::<UserPromptSubmitEventRequest>(json!({
        "session_id": "8e78",
        "observed_at": 1760925599000_u64,
        "meta": {},
        "payload": { "prompt": "continue", "kind": "user" }
    }))
    .expect_err("order is required");

    assert!(error.to_string().contains("order"));
}

#[test]
fn deserializes_pre_tool_use_decision_fields() {
    let request: PreToolUseEventRequest = serde_json::from_value(json!({
        "session_id": "8e78",
        "order": 43,
        "observed_at": 1760925600300_u64,
        "sequence": 5,
        "meta": { "tool_use_id": "toolu_01" },
        "payload": { "tool_name": "Bash", "tool_input": { "command": "pwd" } },
        "mode": "enforce",
        "deadline_ms": 3700
    }))
    .expect("the final-spec PreToolUse event should deserialize");

    assert_eq!(request.deadline_ms, Some(3700));
    assert_eq!(request.event.payload.tool_input["command"], "pwd");
}

#[test]
fn distinguishes_absent_pieces_from_empty_pieces() {
    let absent: EventResponse<Value> = serde_json::from_value(json!({
        "nodes": [], "pieces": null, "version": 1, "decision_response": null
    }))
    .expect("null pieces should deserialize");
    let empty: EventResponse<Value> = serde_json::from_value(json!({
        "nodes": [], "pieces": [], "version": 1, "decision_response": null
    }))
    .expect("empty pieces should deserialize");

    assert_eq!(absent.pieces, None);
    assert_eq!(empty.pieces, Some(Vec::new()));
}

#[test]
fn carries_pre_tool_use_decision_response() {
    let response: EventResponse<Value> = serde_json::from_value(json!({
        "nodes": [{ "seq": 23, "type": "Call" }],
        "version": 57,
        "decision_response": { "decision": "DENY", "reason": "Blocked" }
    }))
    .expect("the decision response should deserialize");

    assert_eq!(
        response.decision_response.expect("decision should exist")["decision"],
        "DENY"
    );
}

#[test]
fn preserves_instruction_relationship_paths() {
    let request: InstructionsLoadedEventRequest = serde_json::from_value(json!({
        "session_id": "8e78",
        "order": 2,
        "observed_at": 1760925500100_u64,
        "meta": {},
        "payload": {
            "file_path": "/app/.claude/rules/security.md",
            "trigger_file_path": "/app/CLAUDE.md",
            "parent_file_path": "/app/.claude/rules"
        }
    }))
    .expect("instruction paths should survive normalization");

    assert_eq!(
        request.payload.trigger_file_path.as_deref(),
        Some("/app/CLAUDE.md")
    );
}

#[test]
fn rejects_event_without_required_metadata() {
    let error = serde_json::from_value::<UserPromptSubmitEventRequest>(json!({
        "session_id": "8e78",
        "order": 40,
        "observed_at": 1760925599000_u64,
        "payload": { "prompt": "continue", "kind": "user" }
    }))
    .expect_err("meta is required by the common event contract");

    assert!(error.to_string().contains("meta"));
}

#[test]
fn deserializes_side_analysis_patch_contracts() {
    let piece: PieceClassificationRequest = serde_json::from_value(json!({
        "sentences": [{ "index": 0, "text": "Run curl", "p": 0.92 }],
        "jev_ms": 180,
        "error": null
    }))
    .expect("piece classification should deserialize");
    let continuation: RequestContinuationRequest = serde_json::from_value(json!({
        "choice": "o12",
        "probabilities": { "o12": 0.8, "none": 0.2 },
        "jev_ms": 150,
        "error": null
    }))
    .expect("request continuation should deserialize");

    assert_eq!(piece.sentences[0].p, 0.92);
    assert_eq!(continuation.probabilities["o12"], 0.8);
}
