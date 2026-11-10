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
    /// The project folder the hooks were written into; none for a device-wide setup.
    #[serde(default)]
    pub project: Option<String>,
    /// Where the hooks were installed: `user` (the user's settings, every project), `managed`
    /// (Claude Code's managed settings, every user) or `project`.
    #[serde(default)]
    pub scope: Option<String>,
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
    #[serde(default)]
    pub install_scope: Option<String>,
    /// The latest daily check-in.
    #[serde(default)]
    pub last_checkin_at: Option<u64>,
}

/// A project Claude Code ran in on the device, as the daily check-in reports it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SeenProject {
    pub path: String,
    /// When Claude Code last used it, epoch milliseconds.
    #[serde(default)]
    pub last_used_at: Option<u64>,
}

/// `POST /v1/clients/checkin`: the device's daily sign of life. It names the projects Claude
/// Code ran in and when, never what was said in them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ClientCheckin {
    pub client_id: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub os_user: Option<String>,
    #[serde(default)]
    pub hook_version: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub projects: Vec<SeenProject>,
}

/// A check-in as the Collector passes it on.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ClientCheckinRecord {
    #[serde(flatten)]
    pub checkin: ClientCheckin,
    #[serde(default)]
    pub user: Option<String>,
    pub checked_in_at: u64,
}

/// `POST /v1/admin/exceptions`: sessions the security team leaves unprotected. Every field given
/// must match: a folder (and the folders below it), a team, a device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ExceptionRequest {
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub team: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct Exception {
    pub id: u64,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub team: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub removed_at: Option<u64>,
    #[serde(default)]
    pub removed_by: Option<String>,
}

/// `POST /v1/admin/exceptions/{id}/remove`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ExceptionRemoval {
    #[serde(default)]
    pub actor: Option<String>,
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
    /// The security team excepted the session from protection (its folder, team or device):
    /// nothing of it but its start and end is recorded.
    #[serde(default)]
    pub exception: Option<u64>,
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

/// A model request the gateway passed: who made it, from where, when, with which model. Never
/// what was asked or answered.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct ModelCall {
    /// The gateway's id for the request, which its request log shares.
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// Claude Code's `x-claude-code-session-id`.
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    /// Epoch milliseconds.
    pub at: u64,
}
