use std::{collections::BTreeSet, fmt::Write as _};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use withhuman_common::tokens;
use withhuman_contracts::events::{
    ConfigChangeEventRequest, FileChangedEventRequest, InstructionsLoadedEventRequest,
    MessageDisplayEventRequest, PostToolBatchEventRequest, PostToolUseEventRequest,
    PostToolUseFailureEventRequest, PreToolUseEventRequest, SessionStartEventRequest,
    SubagentStartEventRequest, SubagentStopEventRequest, ToolDescriptionsEventRequest,
    UserPromptSubmitEventRequest,
};

use crate::RepositoryError;

#[derive(Debug, Clone, PartialEq)]
pub enum GeneratorEvent {
    SessionStart(SessionStartEventRequest),
    UserPromptSubmit(UserPromptSubmitEventRequest),
    PreToolUse(PreToolUseEventRequest),
    PostToolUse(PostToolUseEventRequest),
    PostToolUseFailure(PostToolUseFailureEventRequest),
    SubagentStart(SubagentStartEventRequest),
    SubagentStop(SubagentStopEventRequest),
    InstructionsLoaded(InstructionsLoadedEventRequest),
    ConfigChange(ConfigChangeEventRequest),
    FileChanged(FileChangedEventRequest),
    MessageDisplay(MessageDisplayEventRequest),
    PostToolBatch(PostToolBatchEventRequest),
    ToolDescriptions(ToolDescriptionsEventRequest),
}

impl GeneratorEvent {
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::SessionStart(_) => "SessionStart",
            Self::UserPromptSubmit(_) => "UserPromptSubmit",
            Self::PreToolUse(_) => "PreToolUse",
            Self::PostToolUse(_) => "PostToolUse",
            Self::PostToolUseFailure(_) => "PostToolUseFailure",
            Self::SubagentStart(_) => "SubagentStart",
            Self::SubagentStop(_) => "SubagentStop",
            Self::InstructionsLoaded(_) => "InstructionsLoaded",
            Self::ConfigChange(_) => "ConfigChange",
            Self::FileChanged(_) => "FileChanged",
            Self::MessageDisplay(_) => "MessageDisplay",
            Self::PostToolBatch(_) => "PostToolBatch",
            Self::ToolDescriptions(_) => "ToolDescriptions",
        }
    }

    pub fn session_id(&self) -> &str {
        match self {
            Self::SessionStart(event) => &event.session_id,
            Self::UserPromptSubmit(event) => &event.session_id,
            Self::PreToolUse(event) => &event.event.session_id,
            Self::PostToolUse(event) => &event.session_id,
            Self::PostToolUseFailure(event) => &event.session_id,
            Self::SubagentStart(event) => &event.session_id,
            Self::SubagentStop(event) => &event.session_id,
            Self::InstructionsLoaded(event) => &event.session_id,
            Self::ConfigChange(event) => &event.session_id,
            Self::FileChanged(event) => &event.session_id,
            Self::MessageDisplay(event) => &event.session_id,
            Self::PostToolBatch(event) => &event.session_id,
            Self::ToolDescriptions(event) => &event.session_id,
        }
    }

    pub fn order(&self) -> u64 {
        match self {
            Self::SessionStart(event) => event.order,
            Self::UserPromptSubmit(event) => event.order,
            Self::PreToolUse(event) => event.event.order,
            Self::PostToolUse(event) => event.order,
            Self::PostToolUseFailure(event) => event.order,
            Self::SubagentStart(event) => event.order,
            Self::SubagentStop(event) => event.order,
            Self::InstructionsLoaded(event) => event.order,
            Self::ConfigChange(event) => event.order,
            Self::FileChanged(event) => event.order,
            Self::MessageDisplay(event) => event.order,
            Self::PostToolBatch(event) => event.order,
            Self::ToolDescriptions(event) => event.order,
        }
    }

    pub(crate) fn into_mutation(self) -> Result<GraphMutation, RepositoryError> {
        match self {
            Self::SessionStart(event) => {
                mutation("SessionStart", None, None, None, event, |event| event)
            }
            Self::UserPromptSubmit(event) => {
                let text = Some(event.payload.prompt.clone());
                mutation(
                    "UserPromptSubmit",
                    Some("Request"),
                    text,
                    None,
                    event,
                    |event| event,
                )
            }
            Self::PreToolUse(event) => {
                let action = call_summary(
                    &event.event.payload.tool_name,
                    &event.event.payload.tool_input,
                );
                let file_path = input_file_path(Some(&event.event.payload.tool_input));
                mutation(
                    "PreToolUse",
                    Some("Call"),
                    Some(action),
                    file_path,
                    event,
                    |event| &event.event,
                )
            }
            Self::PostToolUse(event) => {
                let text = text_content(&event.payload.tool_response);
                let file_path = input_file_path(event.payload.tool_input.as_ref());
                mutation(
                    "PostToolUse",
                    Some("Segment"),
                    text,
                    file_path,
                    event,
                    |event| event,
                )
            }
            Self::PostToolUseFailure(event) => {
                let file_path = input_file_path(event.payload.tool_input.as_ref());
                mutation(
                    "PostToolUseFailure",
                    Some("Error"),
                    Some(event.payload.error.clone()),
                    file_path,
                    event,
                    |event| event,
                )
            }
            Self::SubagentStart(event) => mutation(
                "SubagentStart",
                Some("SubagentStart"),
                None,
                None,
                event,
                |event| event,
            ),
            Self::SubagentStop(event) => mutation(
                "SubagentStop",
                Some("SubagentStop"),
                None,
                None,
                event,
                |event| event,
            ),
            Self::InstructionsLoaded(event) => {
                let file_path = Some(event.payload.file_path.clone());
                // TODO(parent-design): the Hook contract carries no instruction text yet; a
                // `content` field is used when a client sends one.
                let body = match event
                    .payload
                    .additional_fields
                    .get("content")
                    .and_then(Value::as_str)
                {
                    Some(content) => format!("{}\n{content}", event.payload.file_path),
                    None => event.payload.file_path.clone(),
                };
                mutation(
                    "InstructionsLoaded",
                    Some("Instruction"),
                    Some(body),
                    file_path,
                    event,
                    |event| event,
                )
            }
            Self::ConfigChange(event) => {
                let file_path = Some(event.payload.file_path.clone());
                mutation(
                    "ConfigChange",
                    Some("ConfigChange"),
                    None,
                    file_path,
                    event,
                    |event| event,
                )
            }
            Self::FileChanged(event) => {
                let file_path = Some(event.payload.file_path.clone());
                mutation(
                    "FileChanged",
                    Some("FileChanged"),
                    None,
                    file_path,
                    event,
                    |event| event,
                )
            }
            Self::MessageDisplay(event) => {
                let text = Some(event.payload.text.clone());
                mutation(
                    "MessageDisplay",
                    Some("Message"),
                    text,
                    None,
                    event,
                    |event| event,
                )
            }
            Self::PostToolBatch(event) => mutation(
                "PostToolBatch",
                Some("ToolBatch"),
                None,
                None,
                event,
                |event| event,
            ),
            Self::ToolDescriptions(event) => mutation(
                "ToolDescriptions",
                Some("ToolDescriptions"),
                None,
                None,
                event,
                |event| event,
            ),
        }
    }
}

pub(crate) struct GraphMutation {
    pub(crate) event_name: &'static str,
    pub(crate) node_type: Option<&'static str>,
    pub(crate) session_id: String,
    pub(crate) order: i64,
    pub(crate) observed_at: i64,
    pub(crate) client_id: Option<String>,
    pub(crate) sequence: Option<i64>,
    pub(crate) prompt_id: Option<String>,
    pub(crate) agent_id: Option<String>,
    pub(crate) agent_type: Option<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) tool_use_id: Option<String>,
    pub(crate) turn_id: Option<String>,
    pub(crate) repository: Option<String>,
    pub(crate) event_json: String,
    pub(crate) payload_json: String,
    pub(crate) file_path: Option<String>,
    pub(crate) tool_name: Option<String>,
    pub(crate) body: Option<String>,
    pub(crate) pieces: Vec<PieceMutation>,
    pub(crate) tokens: Vec<TokenMutation>,
}

#[derive(Serialize)]
pub(crate) struct PieceMutation {
    pub(crate) index: i64,
    pub(crate) text: String,
    pub(crate) hash: String,
    pub(crate) source: String,
    pub(crate) hidden: bool,
    pub(crate) from_user_doc: Option<bool>,
    pub(crate) flagged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct TokenMutation {
    pub(crate) key_kind: String,
    pub(crate) key: String,
    pub(crate) slot: String,
    pub(crate) decoded: String,
    /// `percent` or `base64` when the value was only visible after decoding.
    pub(crate) encoding: Option<String>,
    /// Set when the value was read from a depth 3 piece, so the Token Index points at it.
    pub(crate) piece_hash: Option<String>,
}

fn mutation<T, E>(
    event_name: &'static str,
    node_type: Option<&'static str>,
    text: Option<String>,
    file_path: Option<String>,
    event: T,
    envelope: impl FnOnce(&T) -> &withhuman_contracts::events::EventRequest<E>,
) -> Result<GraphMutation, RepositoryError>
where
    T: Serialize,
    E: Serialize,
{
    let event_json = serde_json::to_string(&event)
        .map_err(|error| RepositoryError::InvalidEvent(error.to_string()))?;
    let envelope = envelope(&event);
    let payload_json = serde_json::to_string(&envelope.payload)
        .map_err(|error| RepositoryError::InvalidEvent(error.to_string()))?;
    let tool_name = tool_name(event_name, &payload_json);
    let body = text.clone();
    let pieces = match &envelope.chunks {
        Some(chunks) => chunks
            .iter()
            .map(|chunk| {
                Ok(PieceMutation {
                    index: signed(chunk.index, "chunk.index")?,
                    text: chunk.text.clone(),
                    hash: chunk.hash.clone(),
                    source: chunk.source.clone(),
                    hidden: chunk.hidden,
                    from_user_doc: chunk.from_user_doc,
                    flagged: envelope
                        .flags
                        .as_ref()
                        .is_some_and(|flags| flags.iter().any(|flag| flag == &chunk.hash)),
                })
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?,
        // A Call summary and an Instruction body describe the node; they are not text read
        // by the agent, so they are not split into pieces.
        None if matches!(event_name, "PreToolUse" | "InstructionsLoaded") => Vec::new(),
        None => text
            .as_deref()
            .map(|text| chunk_text(text, event_name))
            .unwrap_or_default(),
    };

    // Token Index slots: who put the value into the session.
    let mut tokens = BTreeSet::new();
    let observed = is_listing(event_name, &payload_json);
    match event_name {
        // The prompt and the agent's message are indexed through their pieces.
        "UserPromptSubmit" | "MessageDisplay" => {}
        "PreToolUse" => {
            if let Some(input) = payload_field(&payload_json, "tool_input") {
                index_tokens(&input, "agent", None, &mut tokens);
            }
        }
        // Results are indexed through their pieces; the arguments repeated in the payload
        // were indexed on the Call.
        "PostToolUse" | "PostToolUseFailure" => {
            if pieces.is_empty() {
                let field = if event_name == "PostToolUse" {
                    "tool_response"
                } else {
                    "error"
                };
                if let Some(response) = payload_field(&payload_json, field) {
                    index_tokens(&response, result_slot(observed), None, &mut tokens);
                }
            }
        }
        _ => index_tokens(&payload_json, "external", None, &mut tokens),
    }
    for piece in &pieces {
        let slot = if piece.from_user_doc == Some(true) {
            "user"
        } else {
            match piece.source.as_str() {
                "user" | "UserPromptSubmit" => "user",
                "MessageDisplay" => "agent",
                _ => result_slot(observed),
            }
        };
        index_tokens(&piece.text, slot, Some(&piece.hash), &mut tokens);
    }

    Ok(GraphMutation {
        event_name,
        node_type,
        session_id: envelope.session_id.clone(),
        order: signed(envelope.order, "order")?,
        observed_at: signed(envelope.observed_at, "observed_at")?,
        client_id: envelope.client_id.clone(),
        sequence: envelope
            .sequence
            .map(|value| signed(value, "sequence"))
            .transpose()?,
        prompt_id: envelope.meta.prompt_id.clone(),
        agent_id: envelope.meta.agent_id.clone(),
        agent_type: envelope.meta.agent_type.clone(),
        cwd: envelope.meta.cwd.clone(),
        tool_use_id: envelope.meta.tool_use_id.clone(),
        turn_id: envelope.meta.turn_id.clone(),
        repository: envelope.meta.repo.clone(),
        event_json,
        payload_json,
        file_path,
        tool_name,
        body,
        pieces,
        tokens: tokens.into_iter().collect(),
    })
}

fn index_tokens(
    text: &str,
    slot: &str,
    piece_hash: Option<&str>,
    tokens: &mut BTreeSet<TokenMutation>,
) {
    for value in tokens::extract(text) {
        tokens.insert(TokenMutation {
            key_kind: value.kind.to_owned(),
            decoded: value.key.clone(),
            key: value.key,
            slot: slot.to_owned(),
            encoding: value.encoding.map(str::to_owned),
            piece_hash: piece_hash.map(str::to_owned),
        });
    }
}

/// A listing (`ls`, `find`, Glob …) shows names that exist; it does not tell the agent to use
/// them, so its values go to the `observed` slot instead of `external`.
fn result_slot(observed: bool) -> &'static str {
    if observed { "observed" } else { "external" }
}

fn is_listing(event_name: &str, payload_json: &str) -> bool {
    if !matches!(event_name, "PostToolUse" | "PostToolUseFailure") {
        return false;
    }
    let Ok(payload) = serde_json::from_str::<Value>(payload_json) else {
        return false;
    };
    let tool = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if tokens::LISTING_TOOLS.contains(&tool) {
        return true;
    }
    tool == "Bash"
        && payload
            .pointer("/tool_input/command")
            .and_then(Value::as_str)
            .is_some_and(tokens::is_listing_command)
}

/// A payload field as text: strings as they are, anything else as JSON.
fn payload_field(payload_json: &str, field: &str) -> Option<String> {
    let payload = serde_json::from_str::<Value>(payload_json).ok()?;
    match payload.get(field)? {
        Value::String(text) => Some(text.clone()),
        Value::Null => None,
        value => Some(value.to_string()),
    }
}

/// Text of a tool response: a string, `{"content": "…"}`, or MCP text blocks
/// (`[{"type": "text", "text": "…"}]`, also under `content`).
fn text_content(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_owned());
    }
    if let Some(blocks) = value.as_array() {
        let texts = blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>();
        return (!texts.is_empty()).then(|| texts.join("\n\n"));
    }
    value.get("content").and_then(text_content)
}

fn chunk_text(text: &str, source: &str) -> Vec<PieceMutation> {
    text.split("\n\n")
        .map(str::trim)
        .filter(|piece| !piece.is_empty())
        .enumerate()
        .map(|(index, text)| PieceMutation {
            index: i64::try_from(index).unwrap_or(i64::MAX),
            text: text.to_owned(),
            hash: sha256(text),
            source: source.to_owned(),
            hidden: false,
            from_user_doc: Some(false),
            flagged: false,
        })
        .collect()
}

fn tool_name(event_name: &str, payload_json: &str) -> Option<String> {
    matches!(
        event_name,
        "PreToolUse" | "PostToolUse" | "PostToolUseFailure"
    )
    .then(|| serde_json::from_str::<Value>(payload_json).ok())
    .flatten()
    .and_then(|payload| {
        payload
            .get("tool_name")
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
}

fn input_file_path(input: Option<&Value>) -> Option<String> {
    input
        .and_then(|input| input.get("file_path").or_else(|| input.get("path")))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn call_summary(tool_name: &str, input: &Value) -> String {
    let main = input
        .get("command")
        .or_else(|| input.get("file_path"))
        .or_else(|| input.get("path"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| input.to_string());
    format!("{tool_name}: {main}")
}

fn sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}

fn signed(value: u64, field: &str) -> Result<i64, RepositoryError> {
    i64::try_from(value)
        .map_err(|_| RepositoryError::InvalidEvent(format!("{field} exceeds Neo4j integer range")))
}
