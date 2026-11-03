//! Shared technical infrastructure for WithHuman services.

pub mod chunking;
pub mod hidden;
pub mod intent;
pub mod origin;
pub mod shutdown;
pub mod tokens;

/// The label expression matching every node a hook event creates, for Cypher patterns such as
/// `concat!("(session)-[:CONTAINS]->(node:", node_labels!(), ")")`. Each node carries exactly one
/// of these labels. Their indexes lead with session_id but are composite, and a pattern naming
/// only the session, such as `(node:A|B {session_id: ...})`, uses none of them and reads every
/// node of those labels. Such patterns reach a session's nodes through its Session's CONTAINS
/// edges instead.
/// Prefixed to every statement the services run on Neo4j. Neo4j caches a plan per statement and
/// parameter types and discards it once the graph's statistics drift; the longer a plan has
/// been cached, the less drift it takes, so the first hooks after a quiet night all replanned
/// their statements at once, taking a second or more each, and timed out. The statements look
/// a session up by indexed properties, so a plan made earlier stays good as the graph grows.
pub const CYPHER_OPTIONS: &str = "CYPHER replan=skip ";

#[macro_export]
macro_rules! node_labels {
    () => {
        "Request|Intent|Message|Call|Segment|Error|ToolBatch|SubagentStart|SubagentStop|ConfigChange|ToolDescriptions"
    };
}
