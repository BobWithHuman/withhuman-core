//! Intent echo: every prompt asks the model to open its answer with the user intent it inferred,
//! and the MessageDisplay Hook shows that line highlighted, so the user sees at a glance how the
//! request was understood.

/// Added to every prompt through the UserPromptSubmit Hook.
pub const INTENT_INSTRUCTION: &str = "응답 첫 줄에 [의도] ... 형식으로, 현재 세션의 대화 흐름을 바탕으로 \
파악한 사용자 의도를 쓸 것. 모호하면 가장 그럴듯한 해석과 확신도를 함께 쓸 것.";

const MARKER: &str = "[의도]";

/// The first flush of a message with its leading `[의도] ...` line shown as
/// `**[파악한 의도] → ...**`, or `None` when the delta does not open with that line.
pub fn highlight_intent(delta: &str) -> Option<String> {
    // The line ending, `\r\n` included, stays with the rest of the delta.
    let line_end = delta.find('\n').map_or(delta.len(), |end| {
        if delta[..end].ends_with('\r') {
            end - 1
        } else {
            end
        }
    });
    let (line, rest) = delta.split_at(line_end);
    let line = line.trim();
    let intent = line
        .strip_prefix("**")
        .unwrap_or(line)
        .strip_prefix(MARKER)?
        .trim_start_matches("**")
        .trim_start()
        .trim_start_matches([':', '：'])
        .trim_end_matches("**")
        .trim();
    (!intent.is_empty()).then(|| format!("**[파악한 의도] → {intent}**{rest}"))
}
