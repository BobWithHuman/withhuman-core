//! What the security team decided about a session: whether it is stopped. The Collector asks the
//! Generator and keeps the answer a short while (`WITHHUMAN_KEY_CACHE_MS`), as it does for keys;
//! a change made through this Collector applies at once.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use withhuman_contracts::inventory::SessionFlags;

use crate::{GeneratorError, GeneratorTransport};

/// Cached sessions kept at most; the cache starts over beyond this.
const CACHE_ENTRIES: usize = 10_000;

#[derive(Clone)]
pub struct FlagCache {
    generator: Arc<dyn GeneratorTransport>,
    ttl: Duration,
    cache: Arc<Mutex<HashMap<String, (Instant, SessionFlags)>>>,
    /// Moved on by every change made here, so a lookup that began before it is not cached.
    generation: Arc<AtomicU64>,
}

impl FlagCache {
    pub fn new(generator: Arc<dyn GeneratorTransport>, ttl: Duration) -> Self {
        Self {
            generator,
            ttl,
            cache: Arc::default(),
            generation: Arc::default(),
        }
    }

    /// The session's flags, or the error when the Generator cannot say. A failed lookup is
    /// never taken for "not stopped": the caller applies its failure policy.
    pub async fn get(&self, session_id: &str) -> Result<SessionFlags, GeneratorError> {
        if let Some(flags) = self.cache.lock().ok().and_then(|cache| {
            cache
                .get(session_id)
                .filter(|(at, _)| at.elapsed() < self.ttl)
                .map(|(_, flags)| flags.clone())
        }) {
            return Ok(flags);
        }
        let generation = self.generation.load(Ordering::SeqCst);
        let flags = self.generator.session_flags(session_id).await?;
        if !self.ttl.is_zero() {
            if let Ok(mut cache) = self.cache.lock() {
                // A stop (or another change) made while the lookup ran may not be in its answer:
                // that answer is used once, not kept.
                if self.generation.load(Ordering::SeqCst) == generation {
                    if cache.len() >= CACHE_ENTRIES {
                        cache.clear();
                    }
                    cache.insert(session_id.to_owned(), (Instant::now(), flags.clone()));
                }
            }
        }
        Ok(flags)
    }

    /// Drops what is kept of the session after a change to it.
    pub fn forget(&self, session_id: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            self.generation.fetch_add(1, Ordering::SeqCst);
            cache.remove(session_id);
        }
    }

    /// Drops every session kept, after a change that can reach any of them.
    pub fn forget_all(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            self.generation.fetch_add(1, Ordering::SeqCst);
            cache.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::sync::Notify;
    use withhuman_contracts::{
        events::{EventResponse, SessionCursor},
        inventory::{SessionFlags, SessionStop},
    };

    use super::*;
    use crate::NormalizedEvent;

    /// A Generator whose first answer waits until it is let go, and says "not stopped"; after
    /// that the session is stopped.
    #[derive(Default)]
    struct Slow {
        go: Notify,
        asked: Mutex<usize>,
    }

    #[async_trait]
    impl GeneratorTransport for Slow {
        async fn session_flags(&self, session_id: &str) -> Result<SessionFlags, GeneratorError> {
            let first = {
                let mut asked = self.asked.lock().unwrap();
                *asked += 1;
                *asked == 1
            };
            if first {
                self.go.notified().await;
                return Ok(SessionFlags::default());
            }
            Ok(SessionFlags {
                stop: Some(SessionStop {
                    id: 1,
                    session_id: session_id.to_owned(),
                    stopped_at: 1,
                    stopped_by: None,
                    reason: None,
                    released_at: None,
                    released_by: None,
                    release_reason: None,
                    first_denied_at: None,
                    last_denied_at: None,
                    denied_count: 0,
                }),
            })
        }

        async fn send(&self, _event: NormalizedEvent) -> Result<EventResponse, GeneratorError> {
            Err(GeneratorError::Timeout)
        }

        async fn session_cursor(&self, _session_id: &str) -> Result<SessionCursor, GeneratorError> {
            Ok(SessionCursor::default())
        }
    }

    #[tokio::test]
    async fn a_lookup_that_began_before_a_stop_is_not_kept() {
        let generator = Arc::new(Slow::default());
        let cache = FlagCache::new(generator.clone(), Duration::from_secs(3_600));
        let early = tokio::spawn({
            let cache = cache.clone();
            async move { cache.get("s").await }
        });
        while *generator.asked.lock().unwrap() == 0 {
            tokio::task::yield_now().await;
        }
        // The stop lands while the first lookup is still out.
        cache.forget("s");
        generator.go.notify_one();
        assert!(early.await.unwrap().unwrap().stop.is_none());
        // The next call asks again and sees the stop.
        assert!(cache.get("s").await.unwrap().stop.is_some());
    }
}
