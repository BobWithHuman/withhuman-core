use std::{borrow::Cow, collections::BTreeSet};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use withhuman_common::{
    chunking::{self, Profile},
    tokens,
};
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

    /// Rebuilds an event from the JSON stored on its `EventCommit`.
    pub fn from_json(event_name: &str, event_json: &str) -> Result<Self, RepositoryError> {
        fn parse<T: DeserializeOwned>(event_json: &str) -> Result<T, RepositoryError> {
            serde_json::from_str(event_json)
                .map_err(|error| RepositoryError::InvalidEvent(error.to_string()))
        }

        Ok(match event_name {
            "SessionStart" => Self::SessionStart(parse(event_json)?),
            "UserPromptSubmit" => Self::UserPromptSubmit(parse(event_json)?),
            "PreToolUse" => Self::PreToolUse(parse(event_json)?),
            "PostToolUse" => Self::PostToolUse(parse(event_json)?),
            "PostToolUseFailure" => Self::PostToolUseFailure(parse(event_json)?),
            "SubagentStart" => Self::SubagentStart(parse(event_json)?),
            "SubagentStop" => Self::SubagentStop(parse(event_json)?),
            "InstructionsLoaded" => Self::InstructionsLoaded(parse(event_json)?),
            "ConfigChange" => Self::ConfigChange(parse(event_json)?),
            "FileChanged" => Self::FileChanged(parse(event_json)?),
            "MessageDisplay" => Self::MessageDisplay(parse(event_json)?),
            "PostToolBatch" => Self::PostToolBatch(parse(event_json)?),
            "ToolDescriptions" => Self::ToolDescriptions(parse(event_json)?),
            other => {
                return Err(RepositoryError::InvalidEvent(format!(
                    "unknown event {other}"
                )));
            }
        })
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
                mutation("PreToolUse", Some("Call"), None, None, event, |event| {
                    &event.event
                })
            }
            Self::PostToolUse(event) => {
                let text = text_content(&event.payload.tool_response);
                mutation(
                    "PostToolUse",
                    Some("Sequence"),
                    text,
                    None,
                    event,
                    |event| event,
                )
            }
            Self::PostToolUseFailure(event) => mutation(
                "PostToolUseFailure",
                Some("Error"),
                None,
                None,
                event,
                |event| event,
            ),
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
                mutation(
                    "InstructionsLoaded",
                    Some("Instructions"),
                    None,
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
    pub(crate) paragraphs: Vec<ParagraphMutation>,
    pub(crate) tokens: Vec<TokenMutation>,
}

#[derive(Serialize)]
pub(crate) struct ParagraphMutation {
    pub(crate) index: i64,
    pub(crate) text: String,
    pub(crate) hash: String,
    pub(crate) source: String,
    pub(crate) hidden: bool,
    pub(crate) from_user_doc: Option<bool>,
    pub(crate) long_paragraph: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct TokenMutation {
    pub(crate) key_kind: String,
    pub(crate) key: String,
    pub(crate) slot: String,
    pub(crate) decoded: String,
    /// Detector category (`address`, `credential`, `pii`, `financial`, `device`).
    pub(crate) category: String,
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
    // Tokens come from the original values so sensitive ones are keyed by their real hash;
    // everything stored (event, payload, paragraphs) is redacted.
    let event_json = redacted_json(&event)?;
    let envelope = envelope(&event);
    let original_payload_json = serde_json::to_string(&envelope.payload)
        .map_err(|error| RepositoryError::InvalidEvent(error.to_string()))?;
    let payload_json = redacted_json(&envelope.payload)?;
    let paragraphs = match &envelope.chunks {
        Some(chunks) => chunks
            .iter()
            .map(|chunk| {
                Ok(ParagraphMutation {
                    index: signed(chunk.index, "chunk.index")?,
                    text: tokens::redact(&chunk.text).into_owned(),
                    hash: chunk.hash.clone(),
                    source: chunk.source.clone(),
                    hidden: chunk.hidden,
                    from_user_doc: chunk.from_user_doc,
                    long_paragraph: false,
                })
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?,
        None => text
            .as_deref()
            .map(|text| chunk_text(&tokens::redact(text), event_name))
            .unwrap_or_default(),
    };

    let mut tokens = BTreeSet::new();
    let payload_slot = match event_name {
        "PreToolUse" | "MessageDisplay" => "agent",
        "UserPromptSubmit" => "user",
        _ => "external",
    };
    extract_tokens(&original_payload_json, payload_slot, &mut tokens);
    match &envelope.chunks {
        Some(chunks) => {
            for chunk in chunks {
                extract_tokens(&chunk.text, paragraph_slot(&chunk.source), &mut tokens);
            }
        }
        None => {
            if let Some(text) = &text {
                extract_tokens(text, paragraph_slot(event_name), &mut tokens);
            }
        }
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
        paragraphs,
        tokens: tokens.into_iter().collect(),
    })
}

fn paragraph_slot(source: &str) -> &'static str {
    match source {
        "user" | "UserPromptSubmit" => "user",
        "MessageDisplay" => "agent",
        _ => "external",
    }
}

/// `value` as JSON with sensitive strings masked. It is re-serialized only when something was
/// masked, so events without secrets keep their exact bytes.
fn redacted_json<T: Serialize>(value: &T) -> Result<String, RepositoryError> {
    let invalid = |error: serde_json::Error| RepositoryError::InvalidEvent(error.to_string());
    let mut tree = serde_json::to_value(value).map_err(invalid)?;
    if redact_json(&mut tree) {
        serde_json::to_string(&tree).map_err(invalid)
    } else {
        serde_json::to_string(value).map_err(invalid)
    }
}

/// Masks sensitive values in every string and every field named as a secret; reports whether
/// anything changed.
fn redact_json(value: &mut Value) -> bool {
    match value {
        Value::String(text) => match tokens::redact(text) {
            Cow::Owned(redacted) => {
                *text = redacted;
                true
            }
            Cow::Borrowed(_) => false,
        },
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |changed, item| redact_json(item) | changed),
        Value::Object(fields) => fields.iter_mut().fold(false, |changed, (name, item)| {
            if let Value::String(text) = item {
                if let Some(masked) = tokens::redact_field(name, text) {
                    *text = masked;
                    return true;
                }
            }
            redact_json(item) | changed
        }),
        _ => false,
    }
}

fn extract_tokens(value: &str, slot: &str, tokens: &mut BTreeSet<TokenMutation>) {
    for token in tokens::extract_tokens(value) {
        tokens.insert(TokenMutation {
            key_kind: token.kind.to_owned(),
            key: token.key,
            slot: slot.to_owned(),
            decoded: token.decoded,
            category: token.category.as_str().to_owned(),
        });
    }
}

fn text_content(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned).or_else(|| {
        value
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
}

fn chunk_text(text: &str, source: &str) -> Vec<ParagraphMutation> {
    let profile = match source {
        "PostToolUse" => Profile::ToolOutput,
        _ => Profile::Prose,
    };
    chunking::chunk_text(text, profile)
        .into_iter()
        .map(|chunk| ParagraphMutation {
            index: i64::try_from(chunk.index).unwrap_or(i64::MAX),
            text: chunk.text,
            hash: chunk.hash,
            source: source.to_owned(),
            hidden: false,
            from_user_doc: Some(false),
            long_paragraph: chunk.long_paragraph,
        })
        .collect()
}

fn signed(value: u64, field: &str) -> Result<i64, RepositoryError> {
    i64::try_from(value)
        .map_err(|_| RepositoryError::InvalidEvent(format!("{field} exceeds Neo4j integer range")))
}
