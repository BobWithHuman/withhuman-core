//! Shared technical infrastructure for WithHuman services.

pub mod chunking;
pub mod hidden;
pub mod intent;
pub mod origin;
pub mod tokens;

/// The label expression matching every node a hook event creates, for Cypher patterns such as
/// `concat!("(node:", node_labels!(), ")")`. Each node carries exactly one of these labels.
#[macro_export]
macro_rules! node_labels {
    () => {
        "Request|Message|Call|Segment|Error|ToolBatch|SubagentStart|SubagentStop|ConfigChange|ToolDescriptions"
    };
}
