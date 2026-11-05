//! Where each node of a session sits, in the cause tree or the flow of time, and the chain a
//! Call was traced along. The canvas only draws what this module places.
//!
//! A SubGraph is drawn as an area: its prompt, intent or message in the first column, its Calls
//! in the next, each with its results beside it.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::model::{GraphData, Node};

const W: f64 = 190.0;
const H: f64 = 48.0;
const COLUMN_GAP: f64 = 36.0;
const LEAD: &[&str] = &["Request", "Intent", "Message"];
const RESULT: &[&str] = &["Segment", "Error"];
/// Drawn as what came before them, so every edge lands on a node that is on screen.
const HIDDEN: &[&str] = &["ToolBatch", "ToolDescriptions"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum View {
    Tree,
    Flow,
}

/// A cause edge, from a Call to the node it was traced to.
#[derive(Clone, Debug, PartialEq)]
pub struct Cause {
    pub from: i64,
    pub to: i64,
    /// The node the edge points at before hidden nodes are folded into what came before.
    pub via: i64,
    pub paragraph: Option<i64>,
    pub probability: Option<f64>,
}

impl Cause {
    pub fn id(&self) -> String {
        format!("c{}-{}-{}", self.from, self.via, self.paragraph.map(|p| p.to_string()).unwrap_or_default())
    }
}

/// A session's graph, read for drawing.
#[derive(Clone, Debug, PartialEq)]
pub struct Model {
    pub nodes: Vec<Node>,
    index: HashMap<i64, usize>,
    /// A result's Call.
    pub call_of: HashMap<i64, i64>,
    results_of: HashMap<i64, Vec<i64>>,
    group_of: HashMap<i64, i64>,
    subgraph_parent: HashMap<i64, String>,
    /// The shown nodes, in the API's order.
    shown: Vec<i64>,
    flows: Vec<(i64, i64)>,
    pub causes: Vec<Cause>,
}

/// One element for the canvas, in the shape Cytoscape reads.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Element {
    pub group: &'static str,
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<Position>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct Position {
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum AreaKey {
    Number(i64),
    Loose,
}

struct Area {
    items: Vec<(i64, f64, f64)>,
    width: f64,
    height: f64,
}

/// What a selection picks out: element ids to paint, the rest fades.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Highlight {
    pub nodes: Vec<String>,
    pub edges: Vec<String>,
}

impl Model {
    pub fn build(data: &GraphData) -> Self {
        let nodes = data.nodes.clone();
        let index: HashMap<i64, usize> = nodes.iter().enumerate().map(|(i, n)| (n.seq(), i)).collect();
        let mut call_of = HashMap::new();
        let mut previous = HashMap::new();
        let mut call_order = Vec::new();
        for e in &data.edges {
            let (Some(source), Some(target)) = (e.source, e.target) else { continue };
            if e.kind == "RESULT_OF" && index.contains_key(&target)
                && call_of.insert(source, target).is_none() {
                    call_order.push(source);
                }
            if e.kind == "NEXT" && !e.is_cause() {
                previous.insert(target, source);
            }
        }
        let mut results_of: HashMap<i64, Vec<i64>> = HashMap::new();
        for result in call_order {
            results_of.entry(call_of[&result]).or_default().push(result);
        }
        let shown = |seq: i64| index.get(&seq).is_some_and(|&i| !HIDDEN.contains(&nodes[i].kind.as_str()));
        let rep = |seq: i64| {
            let mut seq = seq;
            for _ in 0..=50 {
                if !index.contains_key(&seq) {
                    return None;
                }
                if shown(seq) {
                    return Some(seq);
                }
                seq = *previous.get(&seq)?;
            }
            None
        };
        let mut flows = Vec::new();
        let mut seen = HashSet::new();
        for e in data.edges.iter().filter(|e| e.kind == "NEXT" && !e.is_cause()) {
            let (Some(a), Some(b)) = (e.source.and_then(rep), e.target.and_then(rep)) else { continue };
            if a != b && seen.insert((a, b)) {
                flows.push((a, b));
            }
        }
        let causes = data
            .edges
            .iter()
            .filter(|e| e.is_cause())
            .filter_map(|e| {
                let (from, to) = (e.source.and_then(rep)?, e.target.and_then(rep)?);
                (from != to).then(|| Cause {
                    from,
                    to,
                    via: e.target.unwrap_or(to),
                    paragraph: e.paragraph,
                    probability: e.probability(),
                })
            })
            .collect();
        let mut group_of = HashMap::new();
        let mut subgraph_parent = HashMap::new();
        for s in &data.subgraphs {
            let Some(number) = s.number() else { continue };
            for seq in s.members.iter().flatten() {
                group_of.insert(*seq, number);
            }
            subgraph_parent.insert(number, s.parent().unwrap_or("").to_owned());
        }
        let shown_list = nodes.iter().map(Node::seq).filter(|&s| shown(s)).collect();
        Self { nodes, index, call_of, results_of, group_of, subgraph_parent, shown: shown_list, flows, causes }
    }

    pub fn node(&self, seq: i64) -> Option<&Node> {
        self.index.get(&seq).map(|&i| &self.nodes[i])
    }

    pub fn subgraph_of(&self, seq: i64) -> Option<i64> {
        self.group_of.get(&seq).copied()
    }

    pub fn subgraph_count(&self) -> usize {
        self.subgraph_parent.len()
    }

    pub fn elements(&self, view: View) -> Vec<Element> {
        match view {
            View::Tree => self.tree(),
            View::Flow => self.flow(),
        }
    }

    fn arrange(&self, list: &[i64]) -> Area {
        let node = |seq: i64| self.node(seq).expect("listed node");
        let is = |seq: i64, kinds: &[&str]| kinds.contains(&node(seq).kind.as_str());
        let in_area: HashSet<i64> = list.iter().copied().collect();
        let mut leads: Vec<i64> = list.iter().copied().filter(|&s| is(s, LEAD)).collect();
        leads.sort_by_key(|&s| node(s).order());
        let mut calls: Vec<i64> = list
            .iter()
            .copied()
            .filter(|&s| !is(s, LEAD) && !(is(s, RESULT) && self.call_of.get(&s).is_some_and(|c| in_area.contains(c))))
            .collect();
        calls.sort_by_key(|&s| node(s).order());
        let call_x = if leads.is_empty() { 0.0 } else { W + COLUMN_GAP };
        let result_x = call_x + W + COLUMN_GAP;
        let rows: Vec<(i64, Vec<i64>)> = calls
            .iter()
            .map(|&call| {
                let results = self.results_of.get(&call).map_or_else(Vec::new, |r| {
                    r.iter().copied().filter(|s| in_area.contains(s)).collect()
                });
                (call, results)
            })
            .collect();
        let call_rows: usize = rows.iter().map(|(_, r)| r.len().max(1)).sum();
        let height = leads.len().max(call_rows).max(1) as f64 * H;
        let mut items = Vec::new();
        let lead_top = (height - leads.len() as f64 * H) / 2.0;
        for (i, &seq) in leads.iter().enumerate() {
            items.push((seq, W / 2.0, lead_top + i as f64 * H + H / 2.0));
        }
        let mut y = (height - call_rows as f64 * H) / 2.0;
        for (call, results) in &rows {
            let span = results.len().max(1) as f64 * H;
            items.push((*call, call_x + W / 2.0, y + span / 2.0));
            for (i, &result) in results.iter().enumerate() {
                items.push((result, result_x + W / 2.0, y + i as f64 * H + H / 2.0));
            }
            y += span;
        }
        let has_results = rows.iter().any(|(_, r)| !r.is_empty());
        let width = if has_results {
            result_x
        } else if calls.is_empty() {
            0.0
        } else {
            call_x
        } + W;
        Area { items, width, height }
    }

    fn areas(&self) -> BTreeMap<AreaKey, Area> {
        let mut lists: BTreeMap<AreaKey, Vec<i64>> = BTreeMap::new();
        for &seq in &self.shown {
            let key = self.group_of.get(&seq).map_or(AreaKey::Loose, |&n| AreaKey::Number(n));
            lists.entry(key).or_default().push(seq);
        }
        lists.into_iter().map(|(key, list)| (key, self.arrange(&list))).collect()
    }

    fn area_elements(&self, key: &AreaKey, area: &Area, left: f64, top: f64, out: &mut Vec<Element>) {
        let (id, label) = match key {
            AreaKey::Number(n) => (format!("g{n}"), format!("S{n}")),
            AreaKey::Loose => ("gloose".to_owned(), "서브그래프 없음".to_owned()),
        };
        out.push(Element { group: "nodes", data: json!({"id": id, "area": true, "label": label}), position: None });
        for &(seq, x, y) in &area.items {
            let node = self.node(seq).expect("placed node");
            out.push(Element {
                group: "nodes",
                data: node_data(node, &id),
                position: Some(Position { x: left + x, y: top + y }),
            });
        }
    }

    fn flow_edge(from: i64, to: i64) -> Element {
        Element {
            group: "edges",
            data: json!({"id": format!("f{from}-{to}"), "source": format!("n{from}"), "target": format!("n{to}"), "flow": true}),
            position: None,
        }
    }

    fn cause_edges(&self, on_screen: &HashSet<i64>, out: &mut Vec<Element>) {
        for c in self.causes.iter().filter(|c| on_screen.contains(&c.from) && on_screen.contains(&c.to)) {
            let label = format!(
                "{}{}",
                c.paragraph.map(|p| format!("¶{p} ")).unwrap_or_default(),
                c.probability.map(percent).unwrap_or_default()
            );
            out.push(Element {
                group: "edges",
                data: json!({"id": c.id(), "source": format!("n{}", c.from), "target": format!("n{}", c.to),
                             "cause": true, "label": label.trim_end(), "call": c.from, "to": c.to}),
                position: None,
            });
        }
    }

    /// SubGraph areas left to right, joined by the order of events.
    fn flow(&self) -> Vec<Element> {
        let areas = self.areas();
        let mut keys: Vec<&AreaKey> = areas.keys().collect();
        keys.sort();
        let mut out = Vec::new();
        let mut left = 0.0;
        for key in keys {
            let area = &areas[key];
            self.area_elements(key, area, left, -area.height / 2.0, &mut out);
            left += area.width + 90.0;
        }
        out.extend(self.flows.iter().map(|&(a, b)| Self::flow_edge(a, b)));
        self.cause_edges(&self.shown.iter().copied().collect(), &mut out);
        out
    }

    /// Each SubGraph area under the SubGraph its Calls were traced to (its `parent`), the
    /// session's first prompt on top. A SubGraph that was not traced, such as a closing message
    /// or a later prompt, hangs under the SubGraph the events came from, joined by that order
    /// edge. Cause edges run from each Call up to its cause in the parent area.
    fn tree(&self) -> Vec<Element> {
        const GAP_X: f64 = 60.0;
        const GAP_Y: f64 = 110.0;
        let areas: BTreeMap<i64, Area> = self
            .areas()
            .into_iter()
            .filter_map(|(k, a)| match k {
                AreaKey::Number(n) => Some((n, a)),
                AreaKey::Loose => None,
            })
            .collect();
        let numbers: Vec<i64> = areas.keys().copied().collect();
        let area_of = |seq: i64| self.group_of.get(&seq).copied();
        let mut parent_of = HashMap::new();
        let mut by_order = HashSet::new();
        for &number in &numbers {
            let key = self.subgraph_parent.get(&number).map_or("", String::as_str);
            let parent = key.strip_prefix('s').and_then(|n| n.parse::<i64>().ok());
            if let Some(parent) = parent.filter(|p| *p < number && areas.contains_key(p)) {
                parent_of.insert(number, parent);
                continue;
            }
            let before = self
                .flows
                .iter()
                .filter(|(_, to)| area_of(*to) == Some(number))
                .filter_map(|(from, _)| area_of(*from))
                .filter(|from| *from < number && areas.contains_key(from))
                .max();
            if let Some(from) = before {
                parent_of.insert(number, from);
                by_order.insert(number);
            }
        }
        let mut children: BTreeMap<i64, Vec<i64>> = numbers.iter().map(|&n| (n, Vec::new())).collect();
        let mut pairs: Vec<(i64, i64)> = parent_of.iter().map(|(&c, &p)| (c, p)).collect();
        pairs.sort();
        for (child, parent) in pairs {
            children.get_mut(&parent).expect("parent area").push(child);
        }
        let roots: Vec<i64> = numbers.iter().copied().filter(|n| !parent_of.contains_key(n)).collect();

        // A subtree is as wide as its children side by side, or its own area.
        fn measure(n: i64, areas: &BTreeMap<i64, Area>, children: &BTreeMap<i64, Vec<i64>>, width: &mut HashMap<i64, f64>) -> f64 {
            let kids: f64 = children[&n].iter().map(|&c| measure(c, areas, children, width) + GAP_X).sum::<f64>() - GAP_X;
            let w = areas[&n].width.max(kids);
            width.insert(n, w);
            w
        }
        let mut width = HashMap::new();
        for &root in &roots {
            measure(root, &areas, &children, &mut width);
        }
        struct Placed {
            depth: HashMap<i64, usize>,
            left: HashMap<i64, f64>,
        }
        fn place(n: i64, start: f64, level: usize, areas: &BTreeMap<i64, Area>, children: &BTreeMap<i64, Vec<i64>>, width: &HashMap<i64, f64>, out: &mut Placed) {
            out.depth.insert(n, level);
            out.left.insert(n, start + (width[&n] - areas[&n].width) / 2.0);
            let kids_width: f64 = children[&n].iter().map(|c| width[c] + GAP_X).sum::<f64>() - GAP_X;
            let mut x = start + (width[&n] - kids_width) / 2.0;
            for &c in &children[&n] {
                place(c, x, level + 1, areas, children, width, out);
                x += width[&c] + GAP_X;
            }
        }
        let mut placed = Placed { depth: HashMap::new(), left: HashMap::new() };
        let mut x = 0.0;
        for &root in &roots {
            place(root, x, 0, &areas, &children, &width, &mut placed);
            x += width[&root] + GAP_X * 2.0;
        }
        let levels = placed.depth.values().copied().max().map_or(0, |d| d + 1);
        let mut level_height = vec![0.0_f64; levels];
        for &n in &numbers {
            let d = placed.depth[&n];
            level_height[d] = level_height[d].max(areas[&n].height);
        }
        let mut level_top = vec![0.0; levels];
        for d in 1..levels {
            level_top[d] = level_top[d - 1] + level_height[d - 1] + GAP_Y;
        }

        let mut out = Vec::new();
        for &n in &numbers {
            self.area_elements(&AreaKey::Number(n), &areas[&n], placed.left[&n], level_top[placed.depth[&n]], &mut out);
        }
        let on_screen: HashSet<i64> = areas.values().flat_map(|a| a.items.iter().map(|i| i.0)).collect();
        for &(from_seq, to_seq) in &self.flows {
            if !on_screen.contains(&from_seq) || !on_screen.contains(&to_seq) {
                continue;
            }
            let (from, to) = (area_of(from_seq), area_of(to_seq));
            let joins = from == to || to.is_some_and(|t| by_order.contains(&t) && parent_of.get(&t).copied() == from);
            if joins {
                out.push(Self::flow_edge(from_seq, to_seq));
            }
        }
        self.cause_edges(&on_screen, &mut out);
        out
    }

    /// The chain a Call was traced along: the Call, the result that caused it, the Call that
    /// result came from, and so on up to the prompt.
    pub fn chain(&self, seq: i64) -> Highlight {
        let mut out = Highlight::default();
        let mut seen = HashSet::new();
        let mut stack = vec![seq];
        while let Some(call) = stack.pop() {
            if !seen.insert(call) {
                continue;
            }
            out.nodes.push(format!("n{call}"));
            for c in self.causes.iter().filter(|c| c.from == call) {
                out.edges.push(c.id());
                out.nodes.push(format!("n{}", c.to));
                if let Some(origin) = self.call_of.get(&c.to) {
                    out.edges.push(format!("f{origin}-{}", c.to));
                    stack.push(*origin);
                }
            }
        }
        if out.edges.is_empty() {
            out.nodes.truncate(1);
        }
        out
    }

    /// The causes traced to the paragraphs of a tool result, by paragraph index.
    pub fn paragraph_causes(&self, seq: i64) -> HashMap<i64, Vec<&Cause>> {
        let mut by: HashMap<i64, Vec<&Cause>> = HashMap::new();
        for c in self.causes.iter().filter(|c| c.via == seq) {
            if let Some(p) = c.paragraph {
                by.entry(p).or_default().push(c);
            }
        }
        by
    }
}

fn kind_color(kind: &str) -> &'static str {
    match kind {
        "Request" => "--request",
        "Intent" => "--intent",
        "Message" => "--message",
        "Call" => "--call",
        "Segment" => "--segment",
        "Error" => "--error",
        _ => "--other",
    }
}

pub fn decision_color(decision: &str) -> &'static str {
    match decision {
        "ALLOW" => "--allow",
        "DENY" => "--deny",
        "REVIEW" => "--review",
        _ => "--other",
    }
}

fn node_data(node: &Node, parent: &str) -> Value {
    let color = kind_color(&node.kind);
    let soft = LEAD.contains(&node.kind.as_str()) || RESULT.contains(&node.kind.as_str());
    let decision = node.decision();
    json!({
        "id": format!("n{}", node.seq()),
        "parent": parent,
        "seq": node.seq(),
        "kind": node.kind,
        "label": label(node),
        "fill": if soft { color } else { "--node-bg" },
        "border": decision.map_or(color, decision_color),
        "borderWidth": if decision.is_some() { 3.0 } else { 1.5 },
        "soft": soft,
    })
}

pub fn icon(kind: &str) -> &'static str {
    match kind {
        "Request" => "👤",
        "Intent" => "🎯",
        "Message" => "💬",
        "Segment" => "📄",
        "Error" => "⚠",
        "ConfigChange" => "⚙",
        "SubagentStart" => "⤵",
        "SubagentStop" => "⤴",
        _ => "",
    }
}

pub fn label(node: &Node) -> String {
    let s = &node.summary;
    let text = |v: &Option<String>| v.clone().unwrap_or_default();
    let tool = text(&s.tool_name);
    match node.kind.as_str() {
        "Request" => format!("{} {}", icon("Request"), clip(&text(&s.prompt), 26)),
        "Intent" => format!("{} {}", icon("Intent"), clip(&text(&s.intent), 26)),
        "Message" => format!("{} {}", icon("Message"), clip(&text(&s.text), 26)),
        "Call" => clip(&format!("{} {}", if tool.is_empty() { "Call" } else { &tool }, text(&s.brief)), 28),
        "Segment" => format!("{} {}", icon("Segment"), clip(&format!("{tool} 결과"), 26)),
        "Error" => format!("{} {}", icon("Error"), clip(&format!("{tool} 오류 {}", text(&s.error)), 26)),
        "ConfigChange" => format!("{} {}", icon("ConfigChange"), clip(&text(&s.file_path), 24)),
        kind => format!("{} {kind}", icon(kind)).trim().to_owned(),
    }
}

/// Whitespace folded to single spaces, cut to `n` characters with an ellipsis.
pub fn clip(text: &str, n: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > n { format!("{}…", flat.chars().take(n).collect::<String>()) } else { flat }
}

/// A probability with at most two decimals and no trailing zeros.
pub fn percent(p: f64) -> String {
    let text = format!("{p:.2}");
    text.trim_end_matches('0').trim_end_matches('.').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::Demo;

    fn fixture(session: &str) -> Model {
        let graph = Demo::load().graph(session).expect("fixture session");
        Model::build(&serde_json::from_value(graph).expect("graph shape"))
    }

    fn ids(elements: &[Element], key: &str) -> Vec<String> {
        elements
            .iter()
            .filter(|e| e.group == "edges" && e.data[key] == true)
            .map(|e| e.data["id"].as_str().unwrap().to_owned())
            .collect()
    }

    // The same counts the page's own code gives for the fixture.
    #[test]
    fn places_the_injection_session_like_the_page() {
        let model = fixture("demo-injection-0001");
        let tree = model.elements(View::Tree);
        assert_eq!(tree.iter().filter(|e| e.data.get("seq").is_some()).count(), 16);
        assert_eq!(ids(&tree, "flow").len(), 12);
        assert_eq!(ids(&tree, "cause").len(), 7);
        let flow = model.elements(View::Flow);
        assert_eq!(ids(&flow, "flow").len(), 15);
        assert_eq!(ids(&flow, "cause").len(), 7);
    }

    #[test]
    fn tree_hangs_subgraphs_under_their_parent() {
        let tree = fixture("demo-injection-0001").elements(View::Tree);
        let y = |seq: i64| tree.iter().find(|e| e.data["seq"] == seq).and_then(|e| e.position).unwrap().y;
        // S1's prompt above S2's denied Edit, above S4's closing message.
        assert!(y(1) < y(7));
        assert!(y(7) < y(16));
    }

    #[test]
    fn chain_runs_from_a_call_up_to_the_prompt() {
        let chain = fixture("demo-injection-0001").chain(7);
        assert_eq!(chain.nodes, ["n7", "n4", "n3", "n1"]);
        assert_eq!(chain.edges, ["c7-4-2", "f3-4", "c3-1-"]);
    }

    #[test]
    fn paragraphs_know_the_calls_traced_to_them() {
        let model = fixture("demo-injection-0001");
        let readme = model.paragraph_causes(4);
        // The hidden ¶2 led to the denied Edit, ¶1 to the reviewed Write.
        assert_eq!(readme[&2].iter().map(|c| c.from).collect::<Vec<_>>(), [7]);
        assert_eq!(readme[&1].iter().map(|c| c.from).collect::<Vec<_>>(), [8]);
        assert!(!readme.contains_key(&0));
    }

    #[test]
    fn labels_and_numbers_read_like_the_page() {
        assert_eq!(clip("a  b\nc", 3), "a b…");
        assert_eq!(percent(0.70), "0.7");
        assert_eq!(percent(1.0), "1");
        assert_eq!(percent(0.0), "0");
    }
}
