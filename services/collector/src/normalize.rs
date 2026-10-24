use std::{error::Error, fmt, sync::Arc};

use serde_json::Value;
use withhuman_common::{
    origin::{self, Origin, OriginContext},
    tokens,
};

use withhuman_contracts::{
    events::{
        ConfigChangeEventRequest, ConfigChangePayload, ContentOrigin, EventMetadata, EventRequest,
        FileChangedEventRequest, FileChangedPayload, InstructionsLoadedEventRequest,
        InstructionsLoadedPayload, MessageDisplayEventRequest, MessageDisplayPayload,
        PostToolBatchEventRequest, PostToolBatchPayload, PostToolUseEventRequest,
        PostToolUseFailureEventRequest, PostToolUseFailurePayload, PostToolUsePayload,
        PreToolUseEventRequest, PreToolUsePayload, SessionCursor, SessionStartEventRequest,
        SessionStartPayload, SubagentStartEventRequest, SubagentStartPayload,
        SubagentStopEventRequest, SubagentStopPayload, ToolDescription,
        ToolDescriptionsEventRequest, ToolDescriptionsPayload, UserPromptSubmitEventRequest,
        UserPromptSubmitPayload,
    },
    hooks::{
        ConfigChangeRequest, FileChangedRequest, InstructionsLoadedRequest, MessageDisplayRequest,
        PostToolBatchRequest, PostToolUseFailureRequest, PostToolUseRequest, PreToolUseRequest,
        SessionStartRequest, SubagentLifecycleRequest, ToolDescriptionsRequest,
        UserPromptSubmitRequest,
    },
};

use crate::{
    GeneratorError, GeneratorTransport, InMemorySessionStore, MessageFragment, SessionSnapshot,
    SessionStore, SessionUpdate, StoreError, TrustedHookContext,
};

/// Orders skipped when a session resumes without Collector state, so events that were still on
/// their way to the Generator when the state was lost keep orders nobody reuses. The Generator
/// links events by order, so the gap leaves the graph intact.
pub const RESUME_ORDER_GAP: u64 = 100;

/// Set on a MessageDisplay event whose fragments had a missing index below the final one.
pub const MESSAGE_INCOMPLETE_FLAG: &str = "message_incomplete";

#[derive(Debug, Clone, PartialEq)]
pub enum NormalizedEvent {
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

impl NormalizedEvent {
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
}

#[derive(Clone)]
pub struct Normalizer {
    sessions: Arc<dyn SessionStore>,
    history: Option<Arc<dyn GeneratorTransport>>,
    /// Commands, besides the built-in list, whose output comes from the network.
    network_commands: Arc<[String]>,
}

impl Default for Normalizer {
    fn default() -> Self {
        Self::new(InMemorySessionStore::default())
    }
}

impl fmt::Debug for Normalizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Normalizer").finish_non_exhaustive()
    }
}

impl Normalizer {
    pub fn new(sessions: impl SessionStore + 'static) -> Self {
        Self {
            sessions: Arc::new(sessions),
            history: None,
            network_commands: Arc::from([]),
        }
    }

    /// Treats the output of these commands as fetched from the network.
    pub fn with_network_commands(mut self, commands: Vec<String>) -> Self {
        self.network_commands = commands.into();
        self
    }

    /// Resumes sessions the store does not know from the Generator's committed cursor. Without
    /// history such sessions start at order 1.
    pub fn with_history(mut self, history: Arc<dyn GeneratorTransport>) -> Self {
        self.history = Some(history);
        self
    }

    pub fn sessions(&self) -> &dyn SessionStore {
        self.sessions.as_ref()
    }

    async fn apply(
        &self,
        session_id: &str,
        update: SessionUpdate,
    ) -> Result<SessionSnapshot, NormalizeError> {
        match self.sessions.apply_event(session_id, update.clone()).await {
            Err(StoreError::UnknownSession) => {}
            result => return result.map_err(NormalizeError::Store),
        }
        let cursor = match &self.history {
            Some(history) => history
                .session_cursor(session_id)
                .await
                .map_err(NormalizeError::History)?,
            None => Default::default(),
        };
        let last_order = match cursor.last_order {
            0 => 0,
            committed => committed + RESUME_ORDER_GAP,
        };
        self.sessions
            .seed(
                session_id,
                &SessionCursor {
                    last_order,
                    ..cursor
                },
            )
            .await
            .map_err(NormalizeError::Store)?;
        self.sessions
            .apply_event(session_id, update)
            .await
            .map_err(NormalizeError::Store)
    }

    /// The input of a tool result whose Hook omits it: the one remembered at PreToolUse, or, when
    /// the Collector lost it, the committed PreToolUse call's.
    async fn tool_input(
        &self,
        session_id: &str,
        tool_use_id: &str,
        sent: Option<Value>,
        remembered: Option<Value>,
    ) -> Result<Option<Value>, NormalizeError> {
        if let Some(input) = sent.or(remembered) {
            return Ok(Some(input));
        }
        match &self.history {
            Some(history) => history
                .tool_input(session_id, tool_use_id)
                .await
                .map_err(NormalizeError::History),
            None => Ok(None),
        }
    }

    pub async fn session_start(
        &self,
        context: &TrustedHookContext,
        request: SessionStartRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(
                &request.session_id,
                SessionUpdate {
                    cwd: request.cwd,
                    ..Default::default()
                },
            )
            .await?;
        let meta = metadata(&state, context, None, None, None, None);
        let envelope = envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            SessionStartPayload {
                source: request.source,
                ..Default::default()
            },
        );
        Ok(NormalizedEvent::SessionStart(envelope))
    }

    pub async fn user_prompt_submit(
        &self,
        context: &TrustedHookContext,
        request: UserPromptSubmitRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(
                &request.session_id,
                SessionUpdate {
                    cwd: request.cwd,
                    prompt_id: request.prompt_id,
                    ..Default::default()
                },
            )
            .await?;
        let meta = metadata(&state, context, None, None, None, None);
        Ok(NormalizedEvent::UserPromptSubmit(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            UserPromptSubmitPayload {
                prompt: request.prompt,
                kind: "user".to_owned(),
                user_docs: Vec::new(),
                additional_fields: Default::default(),
            },
        )))
    }

    pub async fn pre_tool_use(
        &self,
        context: &TrustedHookContext,
        request: PreToolUseRequest,
        observed_at: u64,
        mode: withhuman_contracts::events::EnforcementMode,
        deadline_ms: Option<u64>,
    ) -> Result<NormalizedEvent, NormalizeError> {
        // Where a command saves downloads, so later reads of those files count as external.
        let record_downloads = match request.tool_name.as_str() {
            "Bash" | "PowerShell" => request
                .tool_input
                .get("command")
                .and_then(Value::as_str)
                .map(|command| origin::downloaded_paths(command, request.cwd.as_deref()))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let state = self
            .apply(
                &request.session_id,
                SessionUpdate {
                    cwd: request.cwd,
                    prompt_id: request.prompt_id,
                    store_tool_input: Some((
                        request.tool_use_id.clone(),
                        redacted(&request.tool_input),
                    )),
                    agent_id: request.agent_id.clone(),
                    record_downloads,
                    ..Default::default()
                },
            )
            .await?;
        let meta = metadata(
            &state,
            context,
            Some(request.tool_use_id),
            request.agent_id,
            request.agent_type,
            None,
        );
        Ok(NormalizedEvent::PreToolUse(PreToolUseEventRequest {
            event: envelope(
                &state,
                context,
                request.session_id,
                observed_at,
                state.agent_sequence,
                meta,
                PreToolUsePayload {
                    tool_name: request.tool_name,
                    tool_input: request.tool_input,
                    additional_fields: Default::default(),
                },
            ),
            mode,
            deadline_ms,
        }))
    }

    pub async fn post_tool_use(
        &self,
        context: &TrustedHookContext,
        request: PostToolUseRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(
                &request.session_id,
                SessionUpdate {
                    cwd: request.cwd,
                    prompt_id: request.prompt_id,
                    take_tool_input: Some(request.tool_use_id.clone()),
                    agent_id: request.agent_id.clone(),
                    ..Default::default()
                },
            )
            .await?;
        let tool_input = self
            .tool_input(
                &request.session_id,
                &request.tool_use_id,
                request.tool_input,
                state.tool_input.clone(),
            )
            .await?;
        let mut meta = metadata(
            &state,
            context,
            Some(request.tool_use_id),
            request.agent_id,
            request.agent_type,
            None,
        );
        let content_origin = origin::tool_origin(
            &request.tool_name,
            tool_input.as_ref(),
            origin::tool_output(&request.tool_response).as_deref(),
            &OriginContext {
                cwd: state.cwd.as_deref(),
                network_commands: &self.network_commands,
                downloaded_paths: &state.downloads,
            },
        );
        if content_origin == Origin::External {
            meta.content_origin = Some(ContentOrigin::External);
        }
        Ok(NormalizedEvent::PostToolUse(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            state.agent_sequence,
            meta,
            PostToolUsePayload {
                tool_name: request.tool_name,
                tool_input,
                tool_response: request.tool_response,
                additional_fields: Default::default(),
            },
        )))
    }

    pub async fn post_tool_use_failure(
        &self,
        context: &TrustedHookContext,
        request: PostToolUseFailureRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(
                &request.session_id,
                SessionUpdate {
                    cwd: request.cwd,
                    prompt_id: request.prompt_id,
                    take_tool_input: Some(request.tool_use_id.clone()),
                    agent_id: request.agent_id.clone(),
                    ..Default::default()
                },
            )
            .await?;
        let tool_input = self
            .tool_input(
                &request.session_id,
                &request.tool_use_id,
                request.tool_input,
                state.tool_input.clone(),
            )
            .await?;
        let meta = metadata(
            &state,
            context,
            Some(request.tool_use_id),
            request.agent_id,
            request.agent_type,
            None,
        );
        Ok(NormalizedEvent::PostToolUseFailure(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            state.agent_sequence,
            meta,
            PostToolUseFailurePayload {
                tool_name: request.tool_name,
                tool_input,
                error: request.error,
                additional_fields: Default::default(),
            },
        )))
    }

    pub async fn subagent_start(
        &self,
        context: &TrustedHookContext,
        request: SubagentLifecycleRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(
                &request.session_id,
                SessionUpdate {
                    agent_id: Some(request.agent_id.clone()),
                    ..Default::default()
                },
            )
            .await?;
        let meta = metadata(
            &state,
            context,
            None,
            Some(request.agent_id.clone()),
            request.agent_type.clone(),
            None,
        );
        Ok(NormalizedEvent::SubagentStart(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            state.agent_sequence,
            meta,
            SubagentStartPayload {
                agent_id: request.agent_id,
                agent_type: request.agent_type,
                additional_fields: Default::default(),
            },
        )))
    }

    pub async fn subagent_stop(
        &self,
        context: &TrustedHookContext,
        request: SubagentLifecycleRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(
                &request.session_id,
                SessionUpdate {
                    agent_id: Some(request.agent_id.clone()),
                    ..Default::default()
                },
            )
            .await?;
        let meta = metadata(
            &state,
            context,
            None,
            Some(request.agent_id.clone()),
            request.agent_type,
            None,
        );
        Ok(NormalizedEvent::SubagentStop(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            state.agent_sequence,
            meta,
            SubagentStopPayload {
                agent_id: request.agent_id,
                additional_fields: Default::default(),
            },
        )))
    }

    pub async fn instructions_loaded(
        &self,
        context: &TrustedHookContext,
        request: InstructionsLoadedRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(&request.session_id, SessionUpdate::default())
            .await?;
        let meta = metadata(&state, context, None, None, None, None);
        Ok(NormalizedEvent::InstructionsLoaded(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            InstructionsLoadedPayload {
                file_path: request.file_path,
                memory_type: request.memory_type,
                load_reason: request.load_reason,
                trigger_file_path: request.trigger_file_path,
                parent_file_path: request.parent_file_path,
                additional_fields: Default::default(),
            },
        )))
    }

    pub async fn config_change(
        &self,
        context: &TrustedHookContext,
        request: ConfigChangeRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(&request.session_id, SessionUpdate::default())
            .await?;
        let meta = metadata(&state, context, None, None, None, None);
        Ok(NormalizedEvent::ConfigChange(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            ConfigChangePayload {
                file_path: request.file_path,
                source: request.source,
                additional_fields: Default::default(),
            },
        )))
    }

    pub async fn file_changed(
        &self,
        context: &TrustedHookContext,
        request: FileChangedRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(&request.session_id, SessionUpdate::default())
            .await?;
        let meta = metadata(&state, context, None, None, None, None);
        let mut additional_fields = withhuman_contracts::events::AdditionalFields::new();
        if let Some(event) = request.event {
            additional_fields.insert("event".to_owned(), event.into());
        }
        Ok(NormalizedEvent::FileChanged(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            FileChangedPayload {
                file_path: request.file_path,
                additional_fields,
            },
        )))
    }

    pub async fn message_display(
        &self,
        context: &TrustedHookContext,
        request: MessageDisplayRequest,
        observed_at: u64,
    ) -> Result<Option<NormalizedEvent>, NormalizeError> {
        // Buffered fragments wait in shared state, so they are kept redacted.
        let fragment = MessageFragment {
            message_id: request.message_id.clone(),
            index: request.index,
            delta: tokens::redact(&request.delta).into_owned(),
        };
        if !request.final_ {
            self.sessions
                .append_fragment(&request.session_id, fragment)
                .await
                .map_err(NormalizeError::Store)?;
            return Ok(None);
        }
        let state = self
            .apply(
                &request.session_id,
                SessionUpdate {
                    finish_message: Some(fragment),
                    ..Default::default()
                },
            )
            .await?;
        let text = state
            .message
            .clone()
            .ok_or(NormalizeError::MissingMessageBuffer)?;
        let meta = metadata(&state, context, None, None, None, request.turn_id);
        let mut event = envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            MessageDisplayPayload {
                message_id: request.message_id,
                text,
                additional_fields: Default::default(),
            },
        );
        if state.message_incomplete {
            event.flags = Some(vec![MESSAGE_INCOMPLETE_FLAG.to_owned()]);
        }
        Ok(Some(NormalizedEvent::MessageDisplay(event)))
    }

    pub async fn post_tool_batch(
        &self,
        context: &TrustedHookContext,
        request: PostToolBatchRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(&request.session_id, SessionUpdate::default())
            .await?;
        let meta = metadata(&state, context, None, None, None, None);
        Ok(NormalizedEvent::PostToolBatch(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            PostToolBatchPayload::default(),
        )))
    }

    pub async fn tool_descriptions(
        &self,
        context: &TrustedHookContext,
        request: ToolDescriptionsRequest,
        observed_at: u64,
    ) -> Result<NormalizedEvent, NormalizeError> {
        let state = self
            .apply(&request.session_id, SessionUpdate::default())
            .await?;
        let meta = metadata(&state, context, None, None, None, None);
        Ok(NormalizedEvent::ToolDescriptions(envelope(
            &state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            ToolDescriptionsPayload {
                tools: request
                    .tools
                    .into_iter()
                    .map(|tool| ToolDescription {
                        name: tool.name,
                        description: tool.description,
                    })
                    .collect(),
                additional_fields: Default::default(),
            },
        )))
    }
}

/// A copy of `value` with sensitive values masked, for state the Collector keeps between Hooks.
fn redacted(value: &Value) -> Value {
    let mut value = value.clone();
    tokens::redact_json(&mut value);
    value
}

fn envelope<T>(
    state: &SessionSnapshot,
    context: &TrustedHookContext,
    session_id: String,
    observed_at: u64,
    sequence: Option<u64>,
    meta: EventMetadata,
    payload: T,
) -> EventRequest<T> {
    EventRequest {
        session_id,
        order: state.order,
        observed_at,
        client_id: context.client_id.clone(),
        sequence,
        meta,
        side_pending: Some(state.side_pending.clone()),
        payload,
        chunks: None,
        flags: None,
        additional_fields: Default::default(),
    }
}

fn metadata(
    state: &SessionSnapshot,
    context: &TrustedHookContext,
    tool_use_id: Option<String>,
    agent_id: Option<String>,
    agent_type: Option<String>,
    turn_id: Option<String>,
) -> EventMetadata {
    EventMetadata {
        prompt_id: state.prompt_id.clone(),
        agent_id,
        agent_type,
        cwd: state.cwd.clone(),
        tool_use_id,
        turn_id,
        repo: context.repository.clone(),
        content_origin: None,
        additional_fields: Default::default(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    MissingMessageBuffer,
    Store(StoreError),
    /// The Generator cursor needed to resume the session could not be read.
    History(GeneratorError),
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMessageBuffer => {
                formatter.write_str("completed message has no aggregation buffer")
            }
            Self::Store(error) => error.fmt(formatter),
            Self::History(error) => error.fmt(formatter),
        }
    }
}

impl Error for NormalizeError {}
