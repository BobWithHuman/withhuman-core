//! Intent capture: every prompt asks the model to open its answer with the user intent it
//! inferred. The MessageDisplay Hook hides that line from the user and sends it as an Intent event
//! in the SubGraph of the prompt, apart from the message, so only the engine keeps it.

/// Added to every prompt through the UserPromptSubmit Hook. The model reads the prompt in the
/// light of the whole session, so a prompt that points back at earlier turns ("do 1 and 2")
/// gets a clear intent.
/// The line must come before the first tool call so the Decision Module can judge the turn's
/// calls against it.
pub const INTENT_INSTRUCTION: &str = "도구를 호출하기 전에 먼저, 응답 첫 줄에 [의도] ... 형식으로 \
이번 사용자 프롬프트로 사용자가 원하는 것을 쓸 것. 프롬프트가 앞선 대화를 가리키면 세션 전체 맥락을 근거로 파악할 것. \
바로 도구를 호출할 때도 이 줄을 먼저 쓸 것. 모호하면 가장 그럴듯한 해석과 확신도를 함께 쓸 것.";

/// Why the first Call of a turn that stated no intent is turned back. The agent writes the line
/// and calls the tool again.
pub const INTENT_REQUIRED: &str = "이번 프롬프트에 대한 [의도] 줄이 아직 없습니다. 응답 첫 줄에 \
[의도] ... 형식으로 세션 전체 맥락을 근거로 사용자가 원하는 것을 쓴 다음, 같은 도구 호출을 다시 할 것.";
