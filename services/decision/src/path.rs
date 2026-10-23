use std::collections::HashSet;

use withhuman_contracts::decisions::{CausalPath, CausalPathEdge, PathStop};

/// A depth 1 node on the `:CAUSE` chain that starts at the judged Call's Sequence.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainNode {
    pub seq: i64,
    pub node_type: String,
    pub parent_state: Option<String>,
    /// `accepted` of the `:CAUSE {kind: "parent"}` edge to the next chain node.
    pub parent_accepted: Option<bool>,
    /// `(call seq, piece seq, accepted)` for every Call of this Sequence with a `from_text` edge.
    pub from_text: Vec<(i64, i64, Option<bool>)>,
}

/// Direct `from_text` edge of the judged Call: `(piece seq, accepted)`.
pub type DirectCause = (i64, Option<bool>);

/// Collects the edges already stored from the judged Call up to its cause (rule 9).
pub fn build_path(
    call_seq: i64,
    direct: Option<DirectCause>,
    chain: &[ChainNode],
    max_hops: u64,
    seq_window: u64,
    prompt_window: u64,
) -> CausalPath {
    let mut edges = Vec::new();
    let mut cause = None;
    if let Some(start) = chain.first() {
        edges.push(edge(call_seq, start.seq, "member", None));
    }
    if let Some((piece, accepted)) = direct {
        edges.push(edge(call_seq, piece, "from_text", accepted));
        cause = Some(piece);
    }

    let mut visited = HashSet::new();
    let mut hops = 0_u64;
    let mut index = 0;
    let stop = loop {
        let Some(current) = chain.get(index) else {
            break PathStop::Unresolved;
        };
        if matches!(current.node_type.as_str(), "Request" | "Instruction") {
            break PathStop::ReachedRoot;
        }
        match current.parent_state.as_deref() {
            Some("none") => break PathStop::None,
            Some("decided") => {}
            _ => break PathStop::Unresolved,
        }
        if !visited.insert(current.seq) || hops > max_hops {
            break PathStop::LoopGuard;
        }
        let Some(parent) = chain.get(index + 1) else {
            break PathStop::Unresolved;
        };
        edges.push(edge(
            current.seq,
            parent.seq,
            "parent",
            current.parent_accepted,
        ));
        hops += 1;
        if cause.is_none() {
            for &(call, piece, accepted) in &parent.from_text {
                edges.push(edge(call, piece, "inherited_from_text", accepted));
                cause = Some(piece);
            }
        }
        index += 1;
    };

    let root = chain.get(index.min(chain.len().saturating_sub(1)));
    CausalPath {
        edges,
        cause_seq: cause,
        stop,
        root_seq: root.map(|node| node.seq),
        root_type: root.map(|node| node.node_type.clone()),
        seq_window,
        prompt_window,
    }
}

fn edge(from_seq: i64, to_seq: i64, kind: &str, accepted: Option<bool>) -> CausalPathEdge {
    CausalPathEdge {
        from_seq,
        to_seq,
        kind: kind.to_owned(),
        accepted,
    }
}
