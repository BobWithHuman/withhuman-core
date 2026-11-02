use serde::de::DeserializeOwned;
use serde_json::Value;
use withhuman_contracts::{
    decisions::{DecisionRequest, DecisionResponse},
    events::{EventResponse, PreToolUseEventRequest, UserPromptSubmitEventRequest},
    hooks::{
        ConfigChangeRequest, HookSpecificResponse, MessageDisplayOutput, MessageDisplayRequest,
        PostToolBatchRequest, PostToolUseFailureRequest, PostToolUseRequest, PreToolUseOutput,
        PreToolUseRequest, SessionStartOutput, SessionStartRequest, SubagentLifecycleRequest,
        ToolDescriptionsRequest, UserPromptSubmitOutput, UserPromptSubmitRequest,
    },
};

fn fixture(contents: &str) -> Value {
    serde_json::from_str(contents).expect("fixture must contain valid JSON")
}

fn contract<T: DeserializeOwned>(fixtures: &Value, name: &str) -> T {
    serde_json::from_value(fixtures[name].clone())
        .unwrap_or_else(|error| panic!("fixture {name} must match its contract: {error}"))
}

#[test]
fn all_supported_hook_request_fixtures_match_contracts() {
    let fixtures = fixture(include_str!("fixtures/hooks/requests.json"));

    let _: SessionStartRequest = contract(&fixtures, "session_start");
    let _: UserPromptSubmitRequest = contract(&fixtures, "user_prompt_submit");
    let _: PreToolUseRequest = contract(&fixtures, "pre_tool_use");
    let _: PostToolUseRequest = contract(&fixtures, "post_tool_use");
    let _: PostToolUseFailureRequest = contract(&fixtures, "post_tool_use_failure");
    let _: SubagentLifecycleRequest = contract(&fixtures, "subagent_start");
    let _: SubagentLifecycleRequest = contract(&fixtures, "subagent_stop");
    let _: ConfigChangeRequest = contract(&fixtures, "config_change");
    let _: MessageDisplayRequest = contract(&fixtures, "message_display");
    let _: PostToolBatchRequest = contract(&fixtures, "post_tool_batch");
    let _: ToolDescriptionsRequest = contract(&fixtures, "tool_descriptions");
}

#[test]
fn hook_response_fixtures_round_trip_without_wire_name_changes() {
    let fixtures = fixture(include_str!("fixtures/hooks/responses.json"));

    for (name, value) in fixtures.as_object().expect("fixture must be an object") {
        let serialized = match name.as_str() {
            "session_start" => round_trip::<SessionStartOutput>(value),
            "user_prompt_submit" => round_trip::<UserPromptSubmitOutput>(value),
            "message_display" => round_trip::<MessageDisplayOutput>(value),
            _ => round_trip::<PreToolUseOutput>(value),
        };

        assert_eq!(&serialized, value, "wire contract changed for {name}");
    }
}

#[test]
fn normalized_event_fixtures_match_contracts() {
    let fixtures = fixture(include_str!("fixtures/events/contracts.json"));

    let prompt: UserPromptSubmitEventRequest = contract(&fixtures, "user_prompt_submit");
    let _: PreToolUseEventRequest = contract(&fixtures, "pre_tool_use");
    let absent: EventResponse = contract(&fixtures, "response_without_paragraphs");
    let empty: EventResponse = contract(&fixtures, "response_with_empty_paragraphs");

    assert_eq!(
        prompt.payload.additional_fields["future_payload_field"],
        "preserved"
    );
    assert!(absent.paragraphs.is_none());
    assert_eq!(empty.paragraphs, Some(Vec::new()));
}

#[test]
fn decision_fixtures_round_trip_and_validate() {
    let fixtures = fixture(include_str!("fixtures/decisions/contracts.json"));
    let request: DecisionRequest = contract(&fixtures, "request");
    assert_eq!(
        serde_json::to_value(request).expect("request must serialize"),
        fixtures["request"]
    );

    for value in fixtures["responses"]
        .as_array()
        .expect("responses must be an array")
    {
        let response: DecisionResponse =
            serde_json::from_value(value.clone()).expect("decision must deserialize");
        response
            .validate()
            .expect("decision must be semantically valid");
        assert_eq!(
            serde_json::to_value(response).expect("decision must serialize"),
            *value
        );
    }
}

#[test]
fn required_field_regressions_are_rejected() {
    let hooks = fixture(include_str!("fixtures/hooks/requests.json"));
    let mut request = hooks["pre_tool_use"].clone();
    request
        .as_object_mut()
        .expect("request must be an object")
        .remove("tool_use_id");

    let error = serde_json::from_value::<PreToolUseRequest>(request)
        .expect_err("missing required fields must fail");
    assert!(error.to_string().contains("tool_use_id"));
}

fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned>(
    value: &serde_json::Value,
) -> serde_json::Value {
    let response: HookSpecificResponse<T> =
        serde_json::from_value(value.clone()).expect("response must deserialize");
    serde_json::to_value(response).expect("response must serialize")
}
