//! Delivery receipts for the Codex bridge. An unfinished receipt is deliberately not replayed:
//! normalization may already have changed Redis, even when no response reached the client.
use crate::StoreError;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Mutex};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub request: String,
    pub reply: Option<String>,
}

#[derive(Default)]
pub(crate) struct Deliveries {
    redis: Option<ConnectionManager>,
    memory: Mutex<HashMap<String, Receipt>>,
}

impl Deliveries {
    pub fn redis(connection: ConnectionManager) -> Self {
        Self {
            redis: Some(connection),
            memory: Mutex::default(),
        }
    }

    /// None means this caller reserved the event; Some is its previous receipt.
    pub async fn begin(&self, key: &str, request: &str) -> Result<Option<Receipt>, StoreError> {
        let pending = Receipt {
            request: request.to_owned(),
            reply: None,
        };
        if let Some(connection) = &self.redis {
            // Receipts have no expiry: silently losing one could apply an old event twice.
            // The lab's Redis data is retained along with the graph; no replay across resets.
            let old: Option<String> = redis::Script::new(
                "local old=redis.call('GET',KEYS[1]); if old then return old end; redis.call('SET',KEYS[1],ARGV[1]); return nil"
            ).key(key).arg(serde_json::to_string(&pending)?).invoke_async(&mut connection.clone()).await?;
            return old
                .map(|value| serde_json::from_str(&value).map_err(Into::into))
                .transpose();
        }
        let mut memory = self
            .memory
            .lock()
            .map_err(|_| StoreError::Corrupt("delivery lock".into()))?;
        if let Some(old) = memory.get(key) {
            return Ok(Some(old.clone()));
        }
        memory.insert(key.to_owned(), pending);
        Ok(None)
    }

    pub async fn finish(&self, key: &str, request: &str, reply: String) -> Result<(), StoreError> {
        let receipt = Receipt {
            request: request.to_owned(),
            reply: Some(reply),
        };
        if let Some(connection) = &self.redis {
            let _: () = redis::cmd("SET")
                .arg(key)
                .arg(serde_json::to_string(&receipt)?)
                .query_async(&mut connection.clone())
                .await?;
        } else {
            self.memory
                .lock()
                .map_err(|_| StoreError::Corrupt("delivery lock".into()))?
                .insert(key.to_owned(), receipt);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn redis_receipt_survives_a_different_collector_instance() {
        let Ok(url) = std::env::var("REDIS_INTEGRATION_URL") else {
            return;
        };
        let connection = crate::redis_connection(&url).unwrap();
        let first = Deliveries::redis(connection.clone());
        let second = Deliveries::redis(connection.clone());
        let key = format!(
            "withhuman:codex:delivery:test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        assert!(first.begin(&key, "event").await.unwrap().is_none());
        assert!(
            second
                .begin(&key, "event")
                .await
                .unwrap()
                .unwrap()
                .reply
                .is_none()
        );
        first
            .finish(&key, "event", "confirmed".into())
            .await
            .unwrap();
        assert_eq!(
            second
                .begin(&key, "event")
                .await
                .unwrap()
                .unwrap()
                .reply
                .as_deref(),
            Some("confirmed")
        );
        let _: () = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut connection.clone())
            .await
            .unwrap();
    }
}
