//! Shared technical infrastructure for WithHuman services.

pub mod chunking;
pub mod graph_store;
pub mod hidden;
pub mod intent;
pub mod origin;
pub mod shutdown;
pub mod tokens;

/// The execution graph tables, initialized on startup by Generator and Decision.
pub const POSTGRES_SCHEMA: &str = include_str!("../sql/postgres_schema.sql");
