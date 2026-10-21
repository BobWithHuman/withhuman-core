use serde_json::json;
use withhuman_contracts::decisions::{
    CausalStart, Decision, DecisionContractError, DecisionRequest, DecisionResponse,
    EnforcementMode,
};
use withhuman_contracts::events::EventResponse;

#[test]
fn round_trips_final_spec_decision_request() {
    let value = json!({
        "session_id": "8e789b84-6e6f-4cb2-8eea-9e46f50c0ad1",
        "call_seq": 23,
        "graph_version": 57,
        "mode": "enforce",
        "deadline_ms": 3600
    });

    let request: DecisionRequest =
        serde_json::from_value(value.clone()).expect("request should deserialize");

    assert_eq!(request.mode, EnforcementMode::Enforce);
    assert_eq!(serde_json::to_value(request).unwrap(), value);
}

#[test]
fn accepts_null_deadline_for_record_mode() {
    let request: DecisionRequest = serde_json::from_value(json!({
        "session_id": "8e789b84",
        "call_seq": 23,
        "graph_version": 57,
        "mode": "record",
        "deadline_ms": null
    }))
    .expect("record mode permits an unlimited deadline");

    assert_eq!(request.deadline_ms, None);
}

#[test]
fn round_trips_final_spec_deny_response() {
    let value = json!({
        "decision": "DENY",
        "reason": "Blocked by WithHuman.",
        "rule": "untrusted_destination",
        "start": "OTHER_DOC",
        "written": true,
        "jev": { "asked": false, "ms": null, "reused_from": null }
    });

    let response: DecisionResponse =
        serde_json::from_value(value.clone()).expect("response should deserialize");

    assert_eq!(response.decision, Decision::Deny);
    assert_eq!(response.start, CausalStart::OtherDoc);
    assert_eq!(serde_json::to_value(response).unwrap(), value);
}

#[test]
fn accepts_allow_deny_and_review_wire_values() {
    for (wire, expected) in [
        ("ALLOW", Decision::Allow),
        ("DENY", Decision::Deny),
        ("REVIEW", Decision::Review),
    ] {
        let response: DecisionResponse = serde_json::from_value(json!({
            "decision": wire,
            "reason": if wire == "ALLOW" { "" } else { "Blocked" },
            "rule": "rule",
            "start": "UNRESOLVED",
            "written": true,
            "jev": null
        }))
        .expect("documented decision should deserialize");

        assert_eq!(response.decision, expected);
        assert_eq!(response.validate(), Ok(()));
    }
}

#[test]
fn rejects_invalid_decision_and_missing_required_fields() {
    let invalid = serde_json::from_value::<DecisionResponse>(json!({
        "decision": "BLOCK",
        "reason": "Blocked",
        "rule": "rule",
        "start": "UNRESOLVED",
        "written": true
    }))
    .expect_err("unknown decision values must fail");
    let missing = serde_json::from_value::<DecisionRequest>(json!({
        "session_id": "8e789b84",
        "graph_version": 57,
        "mode": "enforce"
    }))
    .expect_err("call_seq is required");

    assert!(invalid.to_string().contains("unknown variant"));
    assert!(missing.to_string().contains("call_seq"));
}

#[test]
fn validates_decision_reason_semantics() {
    let allow = DecisionResponse {
        decision: Decision::Allow,
        reason: "unexpected reason".into(),
        rule: "rule".into(),
        start: CausalStart::User,
        written: true,
        jev: None,
    };
    let deny = DecisionResponse {
        decision: Decision::Deny,
        reason: "  ".into(),
        rule: "rule".into(),
        start: CausalStart::OtherDoc,
        written: true,
        jev: None,
    };

    assert_eq!(
        allow.validate(),
        Err(DecisionContractError::AllowReasonMustBeEmpty)
    );
    assert_eq!(
        deny.validate(),
        Err(DecisionContractError::BlockingReasonRequired)
    );
}

#[test]
fn generator_response_defaults_to_typed_decision_response() {
    let response: EventResponse = serde_json::from_value(json!({
        "nodes": [{ "seq": 23, "type": "Call" }],
        "version": 57,
        "decision_response": {
            "decision": "REVIEW",
            "reason": "Approval required.",
            "rule": "unresolved_high_risk",
            "start": "UNRESOLVED",
            "written": true,
            "jev": null
        }
    }))
    .expect("Generator should expose the typed Decision response");

    assert_eq!(
        response.decision_response.unwrap().decision,
        Decision::Review
    );
}
