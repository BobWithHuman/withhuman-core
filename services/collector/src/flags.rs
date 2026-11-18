//! What the security team decided about a session: whether it is stopped. The Collector asks the
//! Generator and keeps the answer a short while (`WITHHUMAN_KEY_CACHE_MS`), as it does for keys;
//! a change made through this Collector applies at once.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use withhuman_contracts::inventory::SessionFlags;

use crate::GeneratorTransport;

/// Cached sessions kept at most; the cache starts over beyond this.
const CACHE_ENTRIES: usize = 10_000;

#[derive(Clone)]
pub struct FlagCache {
    generator: Arc<dyn GeneratorTransport>,
    ttl: Duration,
    cache: Arc<Mutex<HashMap<String, (Instant, SessionFlags)>>>,
}

impl FlagCache {
    pub fn new(generator: Arc<dyn GeneratorTransport>, ttl: Duration) -> Self {
        Self {
            generator,
            ttl,
            cache: Arc::default(),
        }
    }

    /// The session's flags; none when the Generator cannot say. A call the Generator cannot
    /// reach is not judged either, so it fails by the failure policy there.
    pub async fn get(&self, session_id: &str) -> SessionFlags {
        if let Some(flags) = self.cache.lock().ok().and_then(|cache| {
            cache
                .get(session_id)
                .filter(|(at, _)| at.elapsed() < self.ttl)
                .map(|(_, flags)| flags.clone())
        }) {
            return flags;
        }
        let Ok(flags) = self.generator.session_flags(session_id).await else {
            return SessionFlags::default();
        };
        if !self.ttl.is_zero() {
            if let Ok(mut cache) = self.cache.lock() {
                if cache.len() >= CACHE_ENTRIES {
                    cache.clear();
                }
                cache.insert(session_id.to_owned(), (Instant::now(), flags.clone()));
            }
        }
        flags
    }

    pub fn forget(&self, session_id: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(session_id);
        }
    }
}
