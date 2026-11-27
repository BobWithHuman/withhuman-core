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
    /// The machine's hardware serial number; none when the setup could not read it.
    #[serde(default)]
    pub serial: Option<String>,
    /// The machine's other hardware serial numbers the setup read: the BIOS's or the system's,
    /// which a PC often numbers otherwise than its motherboard (`serial`). The device is matched
    /// with its EDR device by any of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_serials: Vec<String>,
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
    /// The machine's hardware serial number, as its latest setup that could read one reported.
    #[serde(default)]
    pub serial: Option<String>,
    /// The user of the latest key the device presented.
    #[serde(default)]
    pub user: Option<String>,
    /// The person the security team named as the machine's owner; a registration never sets it.
    #[serde(default)]
    pub owner: Option<String>,
    /// Who last named or cleared the owner, and when (epoch milliseconds).
    #[serde(default)]
    pub owner_set_by: Option<String>,
    #[serde(default)]
    pub owner_set_at: Option<u64>,
    /// When the security team stopped the device (epoch milliseconds); none while it runs.
    /// Every PreToolUse carrying its client ID is refused until it is released.
    #[serde(default)]
    pub stopped_at: Option<u64>,
    /// Who stopped it and why; both none while it runs.
    #[serde(default)]
    pub stopped_by: Option<String>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    /// PreToolUse Hooks refused because the device was stopped, over every stop, and the
    /// latest of them (epoch milliseconds). A release keeps both.
    #[serde(default)]
    pub stop_denied_count: u64,
    #[serde(default)]
    pub stop_last_denied_at: Option<u64>,
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

/// `POST /v1/admin/clients/{client_id}/owner`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SetOwnerRequest {
    /// The owner's email, or null to clear it. Required, so a body without it changes nothing.
    #[serde(deserialize_with = "stated")]
    #[schema(required = true)]
    pub owner: Option<String>,
    /// Who names the owner, for the audit trail (the administrator's email).
    #[serde(default)]
    pub actor: Option<String>,
}

/// `POST /v1/admin/clients/{client_id}/stop`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct StopClientRequest {
    /// True stops the device; false releases it. Required, so a body without it changes
    /// nothing.
    pub stopped: bool,
    /// Who stops or releases it, for the record (the administrator's email).
    #[serde(default)]
    pub actor: Option<String>,
    /// Why it is stopped; kept with the stop and not shown on the device.
    #[serde(default)]
    pub reason: Option<String>,
}

/// What `DELETE /v1/admin/clients/{client_id}` took out: the device and the sessions it ran.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct DeletedClient {
    pub client_id: String,
    /// How many of its sessions were deleted, with every record of them.
    pub sessions: u64,
}

/// `GET /v1/clients/{client_id}/state` (Generator): whether the device is stopped. A client
/// ID the engine does not hold is not stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ClientState {
    pub stopped: bool,
}

/// `POST /v1/clients/{client_id}/stop-denials` (Generator): a PreToolUse refused because its
/// device is stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct StopDenial {
    /// Epoch milliseconds.
    pub denied_at: u64,
}

/// A value or an explicit null; unlike a plain `Option`, a missing field is an error.
fn stated<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(deserializer)
}

/// Whom a key is for: a person, or an automation such as CI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserKind {
    #[default]
    Person,
    Service,
}

impl UserKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Service => "service",
        }
    }
}

/// `POST /v1/admin/users/{user}/keys`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct IssueKeyRequest {
    /// Who issues the key, for the audit trail (the administrator's email).
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// `service` for an automation's key; its user is a name such as `ci-deploy`, not an email.
    /// A user keeps the kind of their first key.
    #[serde(default)]
    pub kind: UserKind,
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
    pub kind: UserKind,
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
    #[serde(default)]
    pub user_kind: UserKind,
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

/// `POST /v1/admin/sessions/{session_id}/stop` and `.../release`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SessionStopRequest {
    /// Who stops or releases the session, for the audit trail.
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// A session the security team stopped: its PreToolUse calls are denied until it is released.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SessionStop {
    pub id: u64,
    pub session_id: String,
    pub stopped_at: u64,
    #[serde(default)]
    pub stopped_by: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub released_at: Option<u64>,
    #[serde(default)]
    pub released_by: Option<String>,
    #[serde(default)]
    pub release_reason: Option<String>,
    /// The first PreToolUse turned back by this stop.
    #[serde(default)]
    pub first_denied_at: Option<u64>,
    #[serde(default)]
    pub last_denied_at: Option<u64>,
    #[serde(default)]
    pub denied_count: u64,
}

/// What the Collector checks of a session before passing its Hooks on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SessionFlags {
    /// The session's active stop.
    #[serde(default)]
    pub stop: Option<SessionStop>,
}

/// A PreToolUse turned back by a session stop.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SessionDenial {
    /// Epoch milliseconds.
    pub denied_at: u64,
}

/// The security team's verdict on a call after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Unreviewed,
    NoIssue,
    Issue,
}

impl ReviewStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::NoIssue => "no_issue",
            Self::Issue => "issue",
        }
    }
}

/// `POST /v1/admin/reviews`: a review of the Call `(session_id, seq)`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ReviewRequest {
    pub session_id: String,
    pub seq: u64,
    pub status: ReviewStatus,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
}

/// A review as recorded; later reviews of the same Call are kept beside it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct Review {
    pub id: u64,
    pub session_id: String,
    pub seq: u64,
    pub status: ReviewStatus,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    pub at: u64,
}
