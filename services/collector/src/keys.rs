//! Per-user WithHuman keys: the Hooks carry one as `Authorization: Bearer whk_<id>_<secret>`.
//!
//! The Collector alone sees a key whole. It makes new keys, and for every Hook hashes the key it
//! received and asks the Generator, which stores keys as id and SHA-256 hash, whose key it is and
//! whether it was revoked. Answers are kept for a short while (`WITHHUMAN_KEY_CACHE_MS`), so a
//! revocation reaches every replica within that time.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::http::HeaderMap;
use withhuman_common::chunking::sha256;
use withhuman_contracts::inventory::{KeyStatus, VerifyKeyRequest, VerifyKeyResponse};

use crate::{GeneratorError, GeneratorTransport};

pub const KEY_PREFIX: &str = "whk_";
/// Hex digits of a key's public id and of its secret.
const ID_HEX: usize = 16;
const SECRET_HEX: usize = 64;
/// Cached answers kept at most; the cache starts over beyond this.
const CACHE_ENTRIES: usize = 10_000;

/// Why a PreToolUse was turned back because of its key. Shown to the user and the agent.
pub const KEY_REVOKED: &str = "보안팀이 이 사용자의 에이전트 사용을 멈췄습니다. \
도구 호출이 모두 막혀 있으니 작업을 멈추고, 필요하면 보안팀에 문의하세요.";
pub const SESSION_STOPPED: &str = "보안팀이 이 세션의 에이전트 사용을 멈췄습니다. \
이 세션의 도구 호출이 모두 막혀 있으니 작업을 멈추고, 필요하면 보안팀에 문의하세요.";
pub const KEY_MISSING: &str = "WithHuman 키가 없어 이 도구 호출을 막았습니다. \
보안팀에서 키를 받아 설치 스크립트를 --key 와 함께 다시 실행하세요.";
pub const KEY_INVALID: &str = "WithHuman 키가 올바르지 않아 이 도구 호출을 막았습니다. \
보안팀에서 받은 키로 설치 스크립트를 다시 실행하세요.";
pub const KEY_UNCHECKED: &str = "WithHuman 키를 확인하지 못해 이 도구 호출을 막았습니다.";

/// A key as the Hook presented it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedKey {
    pub key_id: String,
    /// SHA-256 of the whole key, in hex.
    pub hash: String,
}

/// What the Hook's `Authorization` header holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presented {
    /// No key: no header, or an empty one (an HTTP Hook whose key variable is unset sends
    /// `Bearer `).
    Nothing,
    Key(PresentedKey),
    /// Something that is not a WithHuman key.
    Malformed,
}

pub fn presented(headers: &HeaderMap) -> Presented {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Presented::Nothing;
    };
    let Ok(value) = value.to_str() else {
        return Presented::Malformed;
    };
    let value = value.trim();
    let token = match value.split_once(char::is_whitespace) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => rest.trim(),
        None if value.eq_ignore_ascii_case("bearer") => "",
        _ => value,
    };
    if token.is_empty() {
        return Presented::Nothing;
    }
    parse(token).map_or(Presented::Malformed, Presented::Key)
}

/// `whk_<16 hex>_<64 hex>` as its id and hash.
pub fn parse(key: &str) -> Option<PresentedKey> {
    let (key_id, secret) = key.strip_prefix(KEY_PREFIX)?.split_once('_')?;
    let hex = |part: &str, length| {
        part.len() == length
            && part
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    (hex(key_id, ID_HEX) && hex(secret, SECRET_HEX)).then(|| PresentedKey {
        key_id: key_id.to_owned(),
        hash: sha256(key),
    })
}

/// A new key from the operating system's randomness.
pub fn generate() -> Result<(String, PresentedKey), getrandom::Error> {
    let mut bytes = [0_u8; (ID_HEX + SECRET_HEX) / 2];
    getrandom::getrandom(&mut bytes)?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let key = format!("{KEY_PREFIX}{}_{}", &hex[..ID_HEX], &hex[ID_HEX..]);
    let presented = parse(&key).expect("a generated key parses");
    Ok((key, presented))
}

/// What the engine knows of a Hook's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCheck {
    Nothing,
    Active {
        key_id: String,
        user: String,
    },
    Revoked {
        key_id: String,
        user: String,
    },
    /// Malformed, or no key has this id and hash.
    Invalid,
    /// The Generator could not answer.
    Unchecked,
}

#[derive(Clone)]
pub struct KeyVerifier {
    generator: Arc<dyn GeneratorTransport>,
    ttl: Duration,
    cache: Arc<Mutex<HashMap<String, (Instant, VerifyKeyResponse)>>>,
}

impl KeyVerifier {
    pub fn new(generator: Arc<dyn GeneratorTransport>, ttl: Duration) -> Self {
        Self {
            generator,
            ttl,
            cache: Arc::default(),
        }
    }

    pub async fn check(&self, headers: &HeaderMap, now_ms: u64) -> KeyCheck {
        let key = match presented(headers) {
            Presented::Nothing => return KeyCheck::Nothing,
            Presented::Malformed => return KeyCheck::Invalid,
            Presented::Key(key) => key,
        };
        let answer = match self.cached(&key.hash) {
            Some(answer) => answer,
            None => match self.verify(&key, now_ms).await {
                Ok(answer) => answer,
                Err(_) => return KeyCheck::Unchecked,
            },
        };
        match (answer.status, answer.user) {
            (KeyStatus::Active, Some(user)) => KeyCheck::Active {
                key_id: key.key_id,
                user,
            },
            (KeyStatus::Revoked, Some(user)) => KeyCheck::Revoked {
                key_id: key.key_id,
                user,
            },
            _ => KeyCheck::Invalid,
        }
    }

    /// Forgets every cached answer, so a revocation made here applies at once.
    pub fn forget(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    fn cached(&self, hash: &str) -> Option<VerifyKeyResponse> {
        let cache = self.cache.lock().ok()?;
        cache
            .get(hash)
            .filter(|(at, _)| at.elapsed() < self.ttl)
            .map(|(_, answer)| answer.clone())
    }

    async fn verify(
        &self,
        key: &PresentedKey,
        now_ms: u64,
    ) -> Result<VerifyKeyResponse, GeneratorError> {
        let answer = self
            .generator
            .verify_key(VerifyKeyRequest {
                key_id: key.key_id.clone(),
                hash: key.hash.clone(),
                used_at: now_ms,
            })
            .await?;
        if !self.ttl.is_zero() {
            if let Ok(mut cache) = self.cache.lock() {
                if cache.len() >= CACHE_ENTRIES {
                    cache.clear();
                }
                cache.insert(key.hash.clone(), (Instant::now(), answer.clone()));
            }
        }
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn generated_keys_parse_to_their_id_and_hash() {
        let (key, presented) = generate().unwrap();
        assert!(key.starts_with(KEY_PREFIX));
        assert_eq!(key.len(), KEY_PREFIX.len() + ID_HEX + 1 + SECRET_HEX);
        assert_eq!(presented.key_id, &key[4..4 + ID_HEX]);
        assert_eq!(presented.hash, sha256(&key));
        assert_ne!(generate().unwrap().0, key);
    }

    #[test]
    fn reads_the_key_from_a_bearer_header() {
        let (key, presented) = generate().unwrap();
        assert_eq!(
            super::presented(&headers(&format!("Bearer {key}"))),
            Presented::Key(presented.clone())
        );
        assert_eq!(super::presented(&headers(&key)), Presented::Key(presented));
        assert_eq!(super::presented(&HeaderMap::new()), Presented::Nothing);
        // An HTTP Hook whose key variable is unset.
        assert_eq!(super::presented(&headers("Bearer ")), Presented::Nothing);
        assert_eq!(super::presented(&headers("Bearer")), Presented::Nothing);
        assert_eq!(
            super::presented(&headers("Bearer sk-ant-oat01-x")),
            Presented::Malformed
        );
        assert_eq!(
            super::presented(&headers(&format!("Bearer {}", key.to_uppercase()))),
            Presented::Malformed
        );
    }
}
