//! Intent capture: every prompt asks the model to open its answer with the user intent it
//! inferred. The MessageDisplay Hook hides that line from the user and sends it as an Intent event
//! in the SubGraph of the prompt, apart from the message, so only the engine keeps it.

/// Added to every prompt through the UserPromptSubmit Hook. The model reads the prompt in the
/// light of the whole session, so a prompt that points back at earlier turns ("do 1 and 2")
/// gets a clear intent, and states the user's goal rather than its own next step: Calls are
/// judged against the line, and a narrow step would turn ordinary work away.
/// The line must come before the first tool call so the Decision Module can judge the turn's
/// calls against it.
pub const INTENT_INSTRUCTION: &str = "도구를 호출하기 전에 먼저, 응답 첫 줄에 [의도] ... 형식으로 \
사용자가 이번 프롬프트로 최종적으로 원하는 것을 사용자 입장에서 쓸 것. 네가 할 일이나 계획이 아니라 사용자의 목표를 쓸 것 \
(좋은 예: \"[의도] 크롬 확장 프로그램을 무료+프리미엄 모델로 바꿔 판매하고 싶음\", \
나쁜 예: \"[의도] 먼저 결제 대행사를 조사하겠습니다\"). \
프롬프트가 앞선 대화를 가리키면(\"응\", \"계속해\" 등) 세션 전체 맥락을 근거로 파악하고, 짧은 프롬프트도 예외 없이 매번 쓸 것. \
바로 도구를 호출할 때도 이 줄을 먼저 쓸 것. 모호하면 가장 그럴듯한 해석과 확신도를 함께 쓸 것.";

/// Why the first Call of a turn that stated no intent is turned back. The agent writes the line
/// and calls the tool again.
pub const INTENT_REQUIRED: &str = "이번 프롬프트에 대한 [의도] 줄이 아직 없습니다. 응답 첫 줄에 \
[의도] ... 형식으로 세션 전체 맥락을 근거로 사용자가 최종적으로 원하는 것을 사용자 입장에서 쓴 다음, \
같은 도구 호출을 다시 할 것.";

/// Added to a tool result while the turn still states no intent, so the model opens its next
/// reply with the line. Hook context reaches the model only, unlike a denied Call's reason.
pub const INTENT_REMINDER: &str = "이번 프롬프트에 대한 [의도] 줄이 아직 없습니다. 다음 응답 첫 줄에 \
[의도] ... 형식으로 세션 전체 맥락을 근거로 사용자가 최종적으로 원하는 것을 사용자 입장에서 쓸 것.";
