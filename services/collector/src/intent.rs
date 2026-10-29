//! Intent capture: every prompt asks the model to open its answer with the user intent it
//! inferred. The MessageDisplay Hook hides that line from the user; the Generator stores it with
//! the message, so only the engine keeps it.

/// Added to every prompt through the UserPromptSubmit Hook.
/// The line must come before the first tool call so the Decision Module can judge the turn's
/// calls against it.
pub const INTENT_INSTRUCTION: &str = "도구를 호출하기 전에 먼저, 응답 첫 줄에 [의도] ... 형식으로 \
이번 사용자 프롬프트만을 근거로 파악한 사용자 의도를 쓸 것. 이전 대화 흐름이나 세션 맥락은 반영하지 말 것. 바로 도구를 호출할 때도 이 줄을 먼저 쓸 것. \
모호하면 가장 그럴듯한 해석과 확신도를 함께 쓸 것.";
