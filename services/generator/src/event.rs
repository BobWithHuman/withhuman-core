use std::{collections::BTreeSet, fmt::Write as _, net::IpAddr, sync::LazyLock};

use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct TokenMutation {
    pub(crate) key_kind: String,
    pub(crate) key: String,
    pub(crate) slot: String,
    pub(crate) decoded: String,
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
    let paragraphs = match &envelope.chunks {
        Some(chunks) => chunks
            .iter()
            .map(|chunk| {
                Ok(ParagraphMutation {
                    index: signed(chunk.index, "chunk.index")?,
                    text: chunk.text.clone(),
                    hash: chunk.hash.clone(),
                    source: chunk.source.clone(),
                    hidden: chunk.hidden,
                    from_user_doc: chunk.from_user_doc,
                })
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?,
        None => text
            .as_deref()
            .map(|text| chunk_text(text, event_name))
            .unwrap_or_default(),
    };

    let mut tokens = BTreeSet::new();
    let payload_slot = match event_name {
        "PreToolUse" | "MessageDisplay" => "agent",
        "UserPromptSubmit" => "user",
        _ => "external",
    };
    extract_tokens(&payload_json, payload_slot, &mut tokens);
    for paragraph in &paragraphs {
        let slot = match paragraph.source.as_str() {
            "user" | "UserPromptSubmit" => "user",
            "MessageDisplay" => "agent",
            _ => "external",
        };
        extract_tokens(&paragraph.text, slot, &mut tokens);
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

fn extract_tokens(value: &str, slot: &str, tokens: &mut BTreeSet<TokenMutation>) {
    static URL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"https?://[^\s\"'<>\\]+"#).unwrap());
    static EMAIL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap());
    static IP: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap());
    static PATH: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?:^|[\s\"'=])((?:/|\./|\.\./)[A-Za-z0-9._~/-]+)"#).unwrap()
    });

    for found in URL.find_iter(value) {
        insert_token(tokens, "url", found.as_str(), slot);
    }
    for found in EMAIL.find_iter(value) {
        insert_token(tokens, "email", found.as_str(), slot);
    }
    for found in IP.find_iter(value) {
        if found.as_str().parse::<IpAddr>().is_ok() {
            insert_token(tokens, "ip", found.as_str(), slot);
        }
    }
    for captures in PATH.captures_iter(value) {
        if let Some(found) = captures.get(1) {
            insert_token(tokens, "path", found.as_str(), slot);
        }
    }
}

fn insert_token(tokens: &mut BTreeSet<TokenMutation>, kind: &str, value: &str, slot: &str) {
    let decoded = value.trim_end_matches([',', '.', ')', ']', '}']);
    tokens.insert(TokenMutation {
        key_kind: kind.to_owned(),
        key: decoded.to_owned(),
        slot: slot.to_owned(),
        decoded: decoded.to_owned(),
    });
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
    text.split("\n\n")
        .map(str::trim)
        .filter(|paragraph| !paragraph.is_empty())
        .enumerate()
        .map(|(index, text)| ParagraphMutation {
            index: i64::try_from(index).unwrap_or(i64::MAX),
            text: text.to_owned(),
            hash: sha256(text),
            source: source.to_owned(),
            hidden: false,
            from_user_doc: Some(false),
        })
        .collect()
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
