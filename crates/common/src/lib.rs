//! Shared technical infrastructure for WithHuman services.

pub mod chunking;
pub mod hidden;
pub mod intent;
pub mod origin;
pub mod tokens;

/// The label expression matching every node a hook event creates, for Cypher patterns such as
/// `concat!("(session)-[:CONTAINS]->(node:", node_labels!(), ")")`. Each node carries exactly one
/// of these labels. Their indexes lead with session_id but are composite, and a pattern naming
/// only the session, such as `(node:A|B {session_id: ...})`, uses none of them and reads every
/// node of those labels. Such patterns reach a session's nodes through its Session's CONTAINS
/// edges instead.
#[macro_export]
macro_rules! node_labels {
    () => {
        "Request|Intent|Message|Call|Segment|Error|ToolBatch|SubagentStart|SubagentStop|ConfigChange|ToolDescriptions"
    };
}
