use serde::de::DeserializeOwned;
use serde_json::Value;
use withhuman_contracts::{
    decisions::{DecisionRequest, DecisionResponse},
    events::{EventResponse, PreToolUseEventRequest, UserPromptSubmitEventRequest},
    hooks::{
        ConfigChangeRequest, FileChangedRequest, HookSpecificResponse, InstructionsLoadedRequest,
        MessageDisplayRequest, PostToolBatchRequest, PostToolUseFailureRequest, PostToolUseRequest,
        PreToolUseOutput, PreToolUseRequest, SessionStartOutput, SessionStartRequest,
        SubagentLifecycleRequest, ToolDescriptionsRequest, UserPromptSubmitRequest,
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
    let _: InstructionsLoadedRequest = contract(&fixtures, "instructions_loaded");
    let _: ConfigChangeRequest = contract(&fixtures, "config_change");
    let _: FileChangedRequest = contract(&fixtures, "file_changed");
    let _: MessageDisplayRequest = contract(&fixtures, "message_display");
    let _: PostToolBatchRequest = contract(&fixtures, "post_tool_batch");
    let _: ToolDescriptionsRequest = contract(&fixtures, "tool_descriptions");
}

#[test]
fn hook_response_fixtures_round_trip_without_wire_name_changes() {
    let fixtures = fixture(include_str!("fixtures/hooks/responses.json"));

    for (name, value) in fixtures.as_object().expect("fixture must be an object") {
        let serialized = if name == "session_start" {
            let response: HookSpecificResponse<SessionStartOutput> =
                serde_json::from_value(value.clone()).expect("session response must deserialize");
            serde_json::to_value(response).expect("session response must serialize")
        } else {
            let response: HookSpecificResponse<PreToolUseOutput> =
                serde_json::from_value(value.clone()).expect("tool response must deserialize");
            serde_json::to_value(response).expect("tool response must serialize")
        };

        assert_eq!(&serialized, value, "wire contract changed for {name}");
    }
}

#[test]
fn normalized_event_fixtures_match_contracts() {
    let fixtures = fixture(include_str!("fixtures/events/contracts.json"));

    let prompt: UserPromptSubmitEventRequest = contract(&fixtures, "user_prompt_submit");
    let _: PreToolUseEventRequest = contract(&fixtures, "pre_tool_use");
    let absent: EventResponse = contract(&fixtures, "response_without_pieces");
    let empty: EventResponse = contract(&fixtures, "response_with_empty_pieces");

    assert_eq!(
        prompt.payload.additional_fields["future_payload_field"],
        "preserved"
    );
    assert!(absent.pieces.is_none());
    assert_eq!(empty.pieces, Some(Vec::new()));
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
