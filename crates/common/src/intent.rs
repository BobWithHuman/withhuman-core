//! The `[의도] ...` line the Collector asks the model to open every reply with: the user intent
//! it inferred from the prompt. The Collector hides the line on screen and records it as the
//! prompt's Intent node, apart from the message.

const MARKER: &str = "[의도]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentLine<'a> {
    /// The stated intent, without the marker.
    pub intent: &'a str,
    /// Everything after the intent line and its line ending.
    pub rest: &'a str,
}

/// Splits a leading `[의도] ...` line off `text`. The marker may be bold and followed by a colon.
pub fn split_intent(text: &str) -> Option<IntentLine<'_>> {
    let newline = text.find('\n');
    let line = &text[..newline.unwrap_or(text.len())];
    let line = line.trim_end_matches('\r').trim();
    let intent = line
        .strip_prefix("**")
        .unwrap_or(line)
        .strip_prefix(MARKER)?
        .trim_start_matches("**")
        .trim_start()
        .trim_start_matches([':', '：'])
        .trim_end_matches("**")
        .trim();
    (!intent.is_empty()).then(|| IntentLine {
        intent,
        rest: newline.map_or("", |newline| &text[newline + 1..]),
    })
}
