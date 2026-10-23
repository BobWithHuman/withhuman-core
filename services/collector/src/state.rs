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
    pub(crate) tool_sequences: HashMap<String, u64>,
    next_sequence: u64,
    current_sequence: Option<u64>,
    first_request_seen: bool,
    first_message_seen: bool,
    initial_sequence_open: bool,
    pub(crate) side_pending: SidePending,
}

impl SessionState {
    pub(crate) fn reserve_order(&mut self) -> u64 {
        self.next_order += 1;
        self.next_order
    }

    /// A Request gets a sequence of its own. The first Request shares sequence 0 with the
    /// Instructions loaded before the first Message.
    pub(crate) fn request_sequence(&mut self) -> u64 {
        let sequence = if !self.first_request_seen && !self.first_message_seen {
            self.initial_sequence()
        } else {
            self.new_sequence()
        };
        self.first_request_seen = true;
        self.current_sequence = None;
        sequence
    }

    pub(crate) fn instruction_sequence(&mut self) -> u64 {
        if !self.first_message_seen {
            self.initial_sequence()
        } else if let Some(sequence) = self.current_sequence {
            sequence
        } else {
            // TODO(parent-design): an Instruction loaded while no work sequence is open (for
            // example right after a later Request) gets a sequence number of its own.
            self.new_sequence()
        }
    }

    pub(crate) fn open_message_sequence(&mut self) -> u64 {
        self.first_message_seen = true;
        let sequence = self.new_sequence();
        self.current_sequence = Some(sequence);
        sequence
    }

    pub(crate) fn active_or_new_sequence(&mut self) -> u64 {
        if let Some(sequence) = self.current_sequence {
            sequence
        } else {
            let sequence = self.new_sequence();
            self.current_sequence = Some(sequence);
            sequence
        }
    }

    pub(crate) fn current_sequence(&self) -> Option<u64> {
        self.current_sequence
    }

    pub(crate) fn close_sequence(&mut self) -> Option<u64> {
        self.current_sequence.take()
    }

    fn initial_sequence(&mut self) -> u64 {
        if self.next_sequence == 0 {
            self.next_sequence = 1;
            self.initial_sequence_open = true;
        }
        if self.initial_sequence_open {
            0
        } else {
            self.new_sequence()
        }
    }

    fn new_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        sequence
    }
}
