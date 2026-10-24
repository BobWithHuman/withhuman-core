//! Intent capture: every prompt asks the model to open its answer with the user intent it
//! inferred. The MessageDisplay Hook hides that line from the user; the Generator stores it with
//! the message, so only the engine keeps it.

/// Added to every prompt through the UserPromptSubmit Hook.
pub const INTENT_INSTRUCTION: &str = "응답 첫 줄에 [의도] ... 형식으로, 현재 세션의 대화 흐름을 바탕으로 \
파악한 사용자 의도를 쓸 것. 모호하면 가장 그럴듯한 해석과 확신도를 함께 쓸 것.";
