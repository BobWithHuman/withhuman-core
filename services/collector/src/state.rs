use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use serde_json::Value;
use withhuman_contracts::events::SidePending;

#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
}

impl SessionStore {
    pub(crate) fn lock(&self) -> MutexGuard<'_, HashMap<String, SessionState>> {
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub fn set_side_pending(&self, session_id: &str, pending: SidePending) {
        self.lock()
            .entry(session_id.to_owned())
            .or_default()
            .side_pending = pending;
    }
}

#[derive(Debug, Default)]
pub(crate) struct SessionState {
    next_order: u64,
    pub(crate) cwd: Option<String>,
    pub(crate) prompt_id: Option<String>,
    pub(crate) message_fragments: HashMap<String, String>,
    pub(crate) tool_inputs: HashMap<String, Value>,
    agent_sequences: HashMap<String, u64>,
    pub(crate) side_pending: SidePending,
}

impl SessionState {
    pub(crate) fn reserve_order(&mut self) -> u64 {
        self.next_order += 1;
        self.next_order
    }

    pub(crate) fn next_agent_sequence(&mut self, agent_id: Option<&str>) -> Option<u64> {
        agent_id.map(|agent_id| {
            let sequence = self.agent_sequences.entry(agent_id.to_owned()).or_default();
            *sequence += 1;
            *sequence
        })
    }
}
