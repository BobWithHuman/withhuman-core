use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use serde_json::Value;
use withhuman_contracts::decisions::DecisionResponse;

#[derive(Debug, Clone, PartialEq)]
pub struct StoredVerdict {
    pub decision: DecisionResponse,
    pub tool_name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone)]
pub struct VerdictStore {
    capacity: usize,
    inner: Arc<Mutex<Verdicts>>,
}

#[derive(Debug, Default)]
struct Verdicts {
    values: HashMap<String, StoredVerdict>,
    insertion_order: VecDeque<String>,
}

impl VerdictStore {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "verdict capacity must be positive");
        Self {
            capacity,
            inner: Arc::default(),
        }
    }

    pub fn insert(&self, tool_use_id: String, verdict: StoredVerdict) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if !inner.values.contains_key(&tool_use_id) {
            inner.insertion_order.push_back(tool_use_id.clone());
        }
        inner.values.insert(tool_use_id, verdict);
        while inner.values.len() > self.capacity {
            if let Some(expired) = inner.insertion_order.pop_front() {
                inner.values.remove(&expired);
            }
        }
    }

    pub fn get(&self, tool_use_id: &str) -> Option<StoredVerdict> {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values
            .get(tool_use_id)
            .cloned()
    }
}
