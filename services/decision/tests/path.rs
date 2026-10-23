use withhuman_contracts::decisions::PathStop;
use withhuman_decision::{ChainNode, build_path};

fn sequence(seq: i64, parent_state: &str, parent_accepted: Option<bool>) -> ChainNode {
    ChainNode {
        seq,
        node_type: "Sequence".into(),
        parent_state: Some(parent_state.into()),
        parent_accepted,
        from_text: Vec::new(),
    }
}

fn request(seq: i64) -> ChainNode {
    ChainNode {
        seq,
        node_type: "Request".into(),
        parent_state: None,
        parent_accepted: None,
        from_text: Vec::new(),
    }
}

fn kinds(path: &withhuman_contracts::decisions::CausalPath) -> Vec<(&str, i64, i64)> {
    path.edges
        .iter()
        .map(|edge| (edge.kind.as_str(), edge.from_seq, edge.to_seq))
        .collect()
}

#[test]
fn follows_parents_to_the_request_and_inherits_the_first_from_text() {
    let mut s6 = sequence(-7, "decided", Some(true));
    s6.from_text.push((60, 900, Some(false)));
    let mut s4 = sequence(-5, "decided", Some(true));
    s4.from_text.push((40, 800, Some(true)));
    let chain = [sequence(-9, "decided", Some(false)), s6, s4, request(30)];

    let path = build_path(80, None, &chain, 50, 3, 3);

    assert_eq!(
        kinds(&path),
        vec![
            ("member", 80, -9),
            ("parent", -9, -7),
            ("inherited_from_text", 60, 900),
            ("parent", -7, -5),
            ("parent", -5, 30),
        ]
    );
    assert_eq!(path.edges[1].accepted, Some(false));
    assert_eq!(path.edges[2].accepted, Some(false));
    assert_eq!(path.cause_seq, Some(900));
    assert_eq!(path.stop, PathStop::ReachedRoot);
    assert_eq!(path.root_seq, Some(30));
    assert_eq!(path.root_type.as_deref(), Some("Request"));
}

#[test]
fn a_direct_from_text_is_the_cause_and_stops_inheriting() {
    let mut s6 = sequence(-7, "none", None);
    s6.from_text.push((60, 900, Some(true)));
    let chain = [sequence(-9, "decided", Some(true)), s6];

    let path = build_path(80, Some((700, Some(true))), &chain, 50, 3, 3);

    assert_eq!(
        kinds(&path),
        vec![
            ("member", 80, -9),
            ("from_text", 80, 700),
            ("parent", -9, -7)
        ]
    );
    assert_eq!(path.cause_seq, Some(700));
    assert_eq!(path.stop, PathStop::None);
    assert_eq!(path.root_seq, Some(-7));
}

#[test]
fn stops_on_unresolved_and_pending_parents() {
    for state in ["unresolved", "pending"] {
        let path = build_path(80, None, &[sequence(-9, state, None)], 50, 3, 3);
        assert_eq!(kinds(&path), vec![("member", 80, -9)]);
        assert_eq!(path.stop, PathStop::Unresolved);
        assert_eq!(path.root_seq, Some(-9));
    }
}

#[test]
fn stops_on_a_loop_and_on_too_many_hops() {
    let chain = [
        sequence(-9, "decided", Some(true)),
        sequence(-7, "decided", Some(true)),
        sequence(-9, "decided", Some(true)),
    ];
    assert_eq!(
        build_path(80, None, &chain, 50, 3, 3).stop,
        PathStop::LoopGuard
    );

    let chain = (0..6)
        .map(|index| sequence(-index - 1, "decided", Some(true)))
        .collect::<Vec<_>>();
    let path = build_path(80, None, &chain, 2, 3, 3);
    assert_eq!(path.stop, PathStop::LoopGuard);
    assert_eq!(path.edges.len(), 1 + 3);
}
