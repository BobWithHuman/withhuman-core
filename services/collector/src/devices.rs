//! Stopped devices: the security team stops one client ID and the Collector refuses every
//! PreToolUse that carries it until the team releases it.
//!
//! The Generator stores the stop. The Collector asks it whether a PreToolUse's device is
//! stopped and keeps each answer as long as a key's (`WITHHUMAN_KEY_CACHE_MS`), so a stop or a
//! release reaches every replica within that time and a busy device costs one question per
//! period, not one per Hook. The key check cannot carry the answer: a key is cached by its hash
//! and may be used on several devices, and a Hook without a key has a device too.
//!
//! The limit: the client ID is the `x-withhuman-client` header the device's own Hooks send. A
//! device that sends another ID, or none, is not stopped, and `WITHHUMAN_REQUIRE_KEY` does not
//! change that, since the key names a person and not a machine. This stops a device that keeps
//! running its installed Hooks; to stop a person whatever they run, revoke their keys.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::GeneratorTransport;

/// Cached answers kept at most; the cache starts over beyond this.
const CACHE_ENTRIES: usize = 10_000;

/// Why a PreToolUse was turned back because of its device. Shown to the user and the agent.
pub const DEVICE_STOPPED: &str = "보안팀이 이 기기의 에이전트 사용을 멈췄습니다. \
도구 호출이 모두 막혀 있으니 작업을 멈추고, 필요하면 보안팀에 문의하세요.";

#[derive(Clone)]
pub struct DeviceStops {
    generator: Arc<dyn GeneratorTransport>,
    ttl: Duration,
    /// By client ID: when the Generator answered, and whether the device was stopped.
    cache: Arc<Mutex<HashMap<String, (Instant, bool)>>>,
}

impl DeviceStops {
    pub fn new(generator: Arc<dyn GeneratorTransport>, ttl: Duration) -> Self {
        Self {
            generator,
            ttl,
            cache: Arc::default(),
        }
    }

    /// Whether the device is stopped. When the Generator cannot answer, the last answer it gave
    /// stands, so a stopped device stays stopped through an outage; a device it never answered
    /// for is taken as running, and its call goes on to be decided like any other.
    pub async fn stopped(&self, client_id: &str) -> bool {
        let known = self.known(client_id);
        match known {
            Some((at, stopped)) if at.elapsed() < self.ttl => return stopped,
            _ => {}
        }
        match self.generator.client_state(client_id).await {
            Ok(state) => {
                if let Ok(mut cache) = self.cache.lock() {
                    if cache.len() >= CACHE_ENTRIES {
                        cache.clear();
                    }
                    cache.insert(client_id.to_owned(), (Instant::now(), state.stopped));
                }
                state.stopped
            }
            Err(_) => known.is_some_and(|(_, stopped)| stopped),
        }
    }

    /// Forgets every answer, so a stop or a release made here applies at once.
    pub fn forget(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    fn known(&self, client_id: &str) -> Option<(Instant, bool)> {
        self.cache.lock().ok()?.get(client_id).copied()
    }
}
