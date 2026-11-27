//! The versions the engine's two products are matched by. The security team's app reads the
//! company's PostgreSQL, and the personal app carries an engine of its own: each says which
//! engine it works with by these three, served together at the Collector's `GET /version`.
//!
//! - the PostgreSQL schema (`withhuman_common::POSTGRES_SCHEMA_VERSION`, also in the
//!   `engine_meta` table),
//! - the hook HTTP API ([`HOOK_API`], the `/v1/hooks/...` routes and their bodies),
//! - these contracts ([`CONTRACTS`], the crate's own version).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Raised when a hook route or body changes in a way an installed hook would notice.
pub const HOOK_API: u32 = 1;

/// This crate's version.
pub const CONTRACTS: &str = env!("CARGO_PKG_VERSION");

/// `GET /version` at the Collector.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct EngineVersion {
    /// The engine's release.
    pub engine: String,
    /// `enterprise` or `personal`.
    pub profile: String,
    pub schema: u32,
    pub hook_api: u32,
    pub contracts: String,
}
