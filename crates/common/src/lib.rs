//! Shared technical infrastructure for WithHuman services.

pub mod chunking;
pub mod grade;
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

#[cfg(test)]
mod tests {
    use super::POSTGRES_SCHEMA;

    /// The table names after `marker` up to the next `;`, in `sql`.
    fn listed(sql: &str, marker: &str) -> Vec<String> {
        let start = sql.find(marker).expect("the viewer's grants") + marker.len();
        let end = start + sql[start..].find(';').expect("a statement end");
        sql[start..end]
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|word| !word.is_empty() && *word != "TO" && *word != "withhuman_viewer")
            .map(str::to_owned)
            .collect()
    }

    /// The viewer can read every table but what is kept from it, so a new table cannot be
    /// forgotten: add it to the viewer's grants (or to `withheld` with a reason).
    #[test]
    fn the_viewer_reads_every_table() {
        let tables: Vec<&str> = POSTGRES_SCHEMA
            .lines()
            .filter_map(|line| line.strip_prefix("CREATE TABLE IF NOT EXISTS "))
            .map(|rest| rest.split_whitespace().next().unwrap())
            .collect();
        let granted = listed(POSTGRES_SCHEMA, "GRANT SELECT ON\n");
        // Readable by column, without its hash.
        let by_column = ["api_keys"];
        for table in &tables {
            assert!(
                granted.iter().any(|name| name == table) || by_column.contains(table),
                "the viewer cannot read {table}: grant it in postgres_schema.sql"
            );
        }
        for name in &granted {
            assert!(
                tables.contains(&name.as_str()),
                "{name} is granted but not created"
            );
        }
        assert!(!granted.iter().any(|name| name == "api_keys"));
        assert!(POSTGRES_SCHEMA.contains("ON api_keys TO withhuman_viewer"));
        let columns = POSTGRES_SCHEMA
            .split("GRANT SELECT (")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .unwrap();
        assert!(!columns.split(',').any(|column| column.trim() == "hash"));
    }
}
