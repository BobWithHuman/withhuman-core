//! Agent inventory contracts: device registration and per-user WithHuman keys.
//!
//! The Collector serves these to clients and administrators and keeps the keys' secrets to
//! itself: the Generator, which stores them, only ever sees a key's id and SHA-256 hash.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What a device's setup reports about itself (`POST /v1/clients/register`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ClientRegistration {
    /// The device's client ID, `<team>/<uuid>`.
    pub client_id: String,
    #[serde(default)]
    pub team: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    /// `linux`, `darwin` or `windows`, with the release when known.
    #[serde(default)]
    pub os: Option<String>,
    /// The OS account that ran the setup.
    #[serde(default)]
    pub os_user: Option<String>,
    /// Version of the hook files installed.
    #[serde(default)]
    pub hook_version: Option<String>,
    /// `claude` or `codex`.
    #[serde(default)]
    pub agent: Option<String>,
    /// The project folder the hooks were written into.
    #[serde(default)]
    pub project: Option<String>,
}

/// A registration as the Collector passes it on: with the key's user when one was verified.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ClientRegistrationRecord {
    #[serde(flatten)]
    pub registration: ClientRegistration,
    #[serde(default)]
    pub user: Option<String>,
    /// Epoch milliseconds.
    pub registered_at: u64,
}

/// A registered or seen device.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ClientRecord {
    pub client_id: String,
    #[serde(default)]
    pub team: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub os_user: Option<String>,
    #[serde(default)]
    pub hook_version: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    /// First registration; none for a device only seen through its Hooks.
    #[serde(default)]
    pub registered_at: Option<u64>,
    /// Latest registration.
    #[serde(default)]
    pub updated_at: Option<u64>,
    #[serde(default)]
    pub first_seen: Option<u64>,
    #[serde(default)]
    pub last_seen: Option<u64>,
    /// Project folders set up on the device.
    #[serde(default)]
    pub projects: Vec<String>,
}

/// `POST /v1/admin/users/{email}/keys`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct IssueKeyRequest {
    /// Who issues the key, for the audit trail (the administrator's email).
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// `POST /v1/admin/keys/{key_id}/revoke`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct RevokeKeyRequest {
    /// Who revokes the key, for the audit trail (the administrator's email).
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// A new key as the Collector stores it: never the key itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct NewKey {
    pub key_id: String,
    /// SHA-256 of the whole key, in hex.
    pub hash: String,
    pub user: String,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// Epoch milliseconds.
    pub created_at: u64,
}

/// A key's record, without its hash.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct KeyRecord {
    pub key_id: String,
    pub user: String,
    pub created_at: u64,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub revoked_at: Option<u64>,
    #[serde(default)]
    pub revoked_by: Option<String>,
    #[serde(default)]
    pub revoke_reason: Option<String>,
    /// The first PreToolUse turned back because the key was revoked.
    #[serde(default)]
    pub first_denied_at: Option<u64>,
    #[serde(default)]
    pub last_denied_at: Option<u64>,
    #[serde(default)]
    pub denied_count: u64,
}

/// A newly issued key: the only time the key itself is shown.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct IssuedKey {
    pub key: String,
    #[serde(flatten)]
    pub record: KeyRecord,
}

/// `POST /v1/keys/verify` (Generator): the key the Collector received, as id and hash.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct VerifyKeyRequest {
    pub key_id: String,
    pub hash: String,
    /// When the key was used, epoch milliseconds; recorded as its last use.
    pub used_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Revoked,
    /// No key has this id and hash.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct VerifyKeyResponse {
    pub status: KeyStatus,
    /// The key's user; none for an unknown key.
    #[serde(default)]
    pub user: Option<String>,
}

/// `POST /v1/keys/{key_id}/denials` (Generator): a PreToolUse turned back for a revoked key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct KeyDenial {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// Epoch milliseconds.
    pub denied_at: u64,
}
