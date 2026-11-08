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

/// `text` as PostgreSQL can store it. Neither `text` nor `jsonb` holds U+0000, and a tool result
/// carrying one (the `nul_char` hidden-text rule) would otherwise fail the whole commit and drop
/// the result from the graph. Hidden text is detected on the original before anything is stored,
/// so only the stored copy shows U+FFFD in its place.
pub fn postgres_text(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains('\0') {
        std::borrow::Cow::Owned(text.replace('\0', "\u{FFFD}"))
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

/// [`postgres_text`] in place.
pub fn make_postgres_text(text: &mut String) {
    if let std::borrow::Cow::Owned(stored) = postgres_text(text) {
        *text = stored;
    }
}
