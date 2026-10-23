use std::{error::Error, fmt};

use withhuman_contracts::{
    events::{
        ConfigChangeEventRequest, ConfigChangePayload, EventMetadata, EventRequest,
        FileChangedEventRequest, FileChangedPayload, InstructionsLoadedEventRequest,
        InstructionsLoadedPayload, MessageDisplayEventRequest, MessageDisplayPayload,
        PostToolBatchEventRequest, PostToolBatchPayload, PostToolUseEventRequest,
        PostToolUseFailureEventRequest, PostToolUseFailurePayload, PostToolUsePayload,
        PreToolUseEventRequest, PreToolUsePayload, SessionStartEventRequest, SessionStartPayload,
        SubagentStartEventRequest, SubagentStartPayload, SubagentStopEventRequest,
        SubagentStopPayload, ToolDescription, ToolDescriptionsEventRequest,
        ToolDescriptionsPayload, UserPromptSubmitEventRequest, UserPromptSubmitPayload,
    },
    hooks::{
        ConfigChangeRequest, FileChangedRequest, InstructionsLoadedRequest, MessageDisplayRequest,
        PostToolBatchRequest, PostToolUseFailureRequest, PostToolUseRequest, PreToolUseRequest,
        SessionStartRequest, SubagentLifecycleRequest, ToolDescriptionsRequest,
        UserPromptSubmitRequest,
    },
};

use crate::{SessionStore, TrustedHookContext, state::SessionState};

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

#[derive(Debug, Clone, Default)]
pub struct Normalizer {
    sessions: SessionStore,
}

impl Normalizer {
    pub fn new(sessions: SessionStore) -> Self {
        Self { sessions }
    }

    pub fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    pub fn session_start(
        &self,
        context: &TrustedHookContext,
        request: SessionStartRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        update_context(state, request.cwd, None);
        let meta = metadata(state, context, None, None, None, None);
        let envelope = envelope(
            state,
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
        NormalizedEvent::SessionStart(envelope)
    }

    pub fn user_prompt_submit(
        &self,
        context: &TrustedHookContext,
        request: UserPromptSubmitRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        update_context(state, request.cwd, request.prompt_id);
        let meta = metadata(state, context, None, None, None, None);
        NormalizedEvent::UserPromptSubmit(envelope(
            state,
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
        ))
    }

    pub fn pre_tool_use(
        &self,
        context: &TrustedHookContext,
        request: PreToolUseRequest,
        observed_at: u64,
        mode: withhuman_contracts::events::EnforcementMode,
        deadline_ms: Option<u64>,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        update_context(state, request.cwd, request.prompt_id);
        state
            .tool_inputs
            .insert(request.tool_use_id.clone(), request.tool_input.clone());
        let sequence = state.next_agent_sequence(request.agent_id.as_deref());
        let meta = metadata(
            state,
            context,
            Some(request.tool_use_id),
            request.agent_id,
            request.agent_type,
            None,
        );
        NormalizedEvent::PreToolUse(PreToolUseEventRequest {
            event: envelope(
                state,
                context,
                request.session_id,
                observed_at,
                sequence,
                meta,
                PreToolUsePayload {
                    tool_name: request.tool_name,
                    tool_input: request.tool_input,
                    additional_fields: Default::default(),
                },
            ),
            mode,
            deadline_ms,
        })
    }

    pub fn post_tool_use(
        &self,
        context: &TrustedHookContext,
        request: PostToolUseRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        update_context(state, request.cwd, request.prompt_id);
        let cached_tool_input = state.tool_inputs.remove(&request.tool_use_id);
        let tool_input = request.tool_input.or(cached_tool_input);
        let sequence = state.next_agent_sequence(request.agent_id.as_deref());
        let meta = metadata(
            state,
            context,
            Some(request.tool_use_id),
            request.agent_id,
            request.agent_type,
            None,
        );
        NormalizedEvent::PostToolUse(envelope(
            state,
            context,
            request.session_id,
            observed_at,
            sequence,
            meta,
            PostToolUsePayload {
                tool_name: request.tool_name,
                tool_input,
                tool_response: request.tool_response,
                additional_fields: Default::default(),
            },
        ))
    }

    pub fn post_tool_use_failure(
        &self,
        context: &TrustedHookContext,
        request: PostToolUseFailureRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        update_context(state, request.cwd, request.prompt_id);
        let cached_tool_input = state.tool_inputs.remove(&request.tool_use_id);
        let tool_input = request.tool_input.or(cached_tool_input);
        let sequence = state.next_agent_sequence(request.agent_id.as_deref());
        let meta = metadata(
            state,
            context,
            Some(request.tool_use_id),
            request.agent_id,
            request.agent_type,
            None,
        );
        NormalizedEvent::PostToolUseFailure(envelope(
            state,
            context,
            request.session_id,
            observed_at,
            sequence,
            meta,
            PostToolUseFailurePayload {
                tool_name: request.tool_name,
                tool_input,
                error: request.error,
                additional_fields: Default::default(),
            },
        ))
    }

    pub fn subagent_start(
        &self,
        context: &TrustedHookContext,
        request: SubagentLifecycleRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        let sequence = state.next_agent_sequence(Some(&request.agent_id));
        let meta = metadata(
            state,
            context,
            None,
            Some(request.agent_id.clone()),
            request.agent_type.clone(),
            None,
        );
        NormalizedEvent::SubagentStart(envelope(
            state,
            context,
            request.session_id,
            observed_at,
            sequence,
            meta,
            SubagentStartPayload {
                agent_id: request.agent_id,
                agent_type: request.agent_type,
                additional_fields: Default::default(),
            },
        ))
    }

    pub fn subagent_stop(
        &self,
        context: &TrustedHookContext,
        request: SubagentLifecycleRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        let sequence = state.next_agent_sequence(Some(&request.agent_id));
        let meta = metadata(
            state,
            context,
            None,
            Some(request.agent_id.clone()),
            request.agent_type,
            None,
        );
        NormalizedEvent::SubagentStop(envelope(
            state,
            context,
            request.session_id,
            observed_at,
            sequence,
            meta,
            SubagentStopPayload {
                agent_id: request.agent_id,
                additional_fields: Default::default(),
            },
        ))
    }

    pub fn instructions_loaded(
        &self,
        context: &TrustedHookContext,
        request: InstructionsLoadedRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        let meta = metadata(state, context, None, None, None, None);
        NormalizedEvent::InstructionsLoaded(envelope(
            state,
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
        ))
    }

    pub fn config_change(
        &self,
        context: &TrustedHookContext,
        request: ConfigChangeRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        let meta = metadata(state, context, None, None, None, None);
        NormalizedEvent::ConfigChange(envelope(
            state,
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
        ))
    }

    pub fn file_changed(
        &self,
        context: &TrustedHookContext,
        request: FileChangedRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        let meta = metadata(state, context, None, None, None, None);
        let mut additional_fields = withhuman_contracts::events::AdditionalFields::new();
        if let Some(event) = request.event {
            additional_fields.insert("event".to_owned(), event.into());
        }
        NormalizedEvent::FileChanged(envelope(
            state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            FileChangedPayload {
                file_path: request.file_path,
                additional_fields,
            },
        ))
    }

    pub fn message_display(
        &self,
        context: &TrustedHookContext,
        request: MessageDisplayRequest,
        observed_at: u64,
    ) -> Result<Option<NormalizedEvent>, NormalizeError> {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        let buffer = state
            .message_fragments
            .entry(request.message_id.clone())
            .or_default();
        buffer.push_str(&request.delta);
        if !request.final_ {
            return Ok(None);
        }
        let text = state
            .message_fragments
            .remove(&request.message_id)
            .ok_or(NormalizeError::MissingMessageBuffer)?;
        let meta = metadata(state, context, None, None, None, request.turn_id);
        Ok(Some(NormalizedEvent::MessageDisplay(envelope(
            state,
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
        ))))
    }

    pub fn post_tool_batch(
        &self,
        context: &TrustedHookContext,
        request: PostToolBatchRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        let meta = metadata(state, context, None, None, None, None);
        NormalizedEvent::PostToolBatch(envelope(
            state,
            context,
            request.session_id,
            observed_at,
            None,
            meta,
            PostToolBatchPayload::default(),
        ))
    }

    pub fn tool_descriptions(
        &self,
        context: &TrustedHookContext,
        request: ToolDescriptionsRequest,
        observed_at: u64,
    ) -> NormalizedEvent {
        let mut sessions = self.sessions.lock();
        let state = sessions.entry(request.session_id.clone()).or_default();
        let meta = metadata(state, context, None, None, None, None);
        NormalizedEvent::ToolDescriptions(envelope(
            state,
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
        ))
    }
}

fn envelope<T>(
    state: &mut SessionState,
    context: &TrustedHookContext,
    session_id: String,
    observed_at: u64,
    sequence: Option<u64>,
    meta: EventMetadata,
    payload: T,
) -> EventRequest<T> {
    EventRequest {
        session_id,
        order: state.reserve_order(),
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
    state: &SessionState,
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
        additional_fields: Default::default(),
    }
}

fn update_context(state: &mut SessionState, cwd: Option<String>, prompt_id: Option<String>) {
    if cwd.is_some() {
        state.cwd = cwd;
    }
    if prompt_id.is_some() {
        state.prompt_id = prompt_id;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizeError {
    MissingMessageBuffer,
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("completed message has no aggregation buffer")
    }
}

impl Error for NormalizeError {}
