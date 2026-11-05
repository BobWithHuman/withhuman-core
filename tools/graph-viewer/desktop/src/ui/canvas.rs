//! The graph canvas: Cytoscape draws the elements `layout` placed, and tells Rust what was
//! clicked. Everything it shows is decided here; the script only paints and reports.

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;
use serde::Deserialize;
use serde_json::json;

use super::{AppState, Load, Selection};
use crate::layout::{Highlight, Model, View};

const SCRIPT: &str = include_str!("canvas.js");

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Event {
    Node { seq: i64 },
    Edge { call: i64, to: i64, id: String },
    Blank,
}

fn highlight(model: &Model, selection: &Selection) -> serde_json::Value {
    match selection {
        Selection::None => serde_json::Value::Null,
        Selection::Node(seq) => {
            let chain = model.chain(*seq);
            json!({"select": format!("n{seq}"), "nodes": chain.nodes, "edges": chain.edges})
        }
        Selection::Edge { call, to, id } => {
            let h = Highlight { nodes: vec![format!("n{call}"), format!("n{to}")], edges: vec![id.clone()] };
            json!({"select": id, "nodes": h.nodes, "edges": h.edges})
        }
    }
}

#[component]
pub fn Canvas() -> Element {
    let mut state = use_context::<AppState>();
    let eval = use_hook(|| document::eval(SCRIPT));
    // The session and view last drawn, so a refresh keeps the zoom and a new session fits.
    let drawn = use_hook(|| Rc::new(RefCell::new(None::<(Option<String>, View)>)));

    use_future(move || async move {
        let mut eval = eval;
        while let Ok(event) = eval.recv::<Event>().await {
            match event {
                Event::Node { seq } => state.selected.set(Selection::Node(seq)),
                Event::Edge { call, to, id } => state.selected.set(Selection::Edge { call, to, id }),
                Event::Blank => state.selected.set(Selection::None),
            }
        }
    });

    use_effect(move || {
        let graph = (state.graph)();
        let view = (state.view)();
        let Load::Ready(model) = graph else {
            let _ = eval.send(json!({"type": "clear"}));
            *drawn.borrow_mut() = None;
            return;
        };
        let key = (state.current.peek().clone(), view);
        let keep = drawn.borrow().as_ref() == Some(&key);
        *drawn.borrow_mut() = Some(key);
        let _ = eval.send(json!({
            "type": "render",
            "elements": model.elements(view),
            "keepView": keep,
            "highlight": highlight(&model, &state.selected.peek()),
        }));
    });

    use_effect(move || {
        let selection = (state.selected)();
        if let Load::Ready(model) = &*state.graph.peek() {
            let _ = eval.send(json!({"type": "highlight", "highlight": highlight(model, &selection)}));
        }
    });

    use_effect(move || {
        if let Some(seq) = (state.focus)() {
            let _ = eval.send(json!({"type": "focus", "id": format!("n{seq}")}));
            state.focus.set(None);
        }
    });

    use_effect(move || {
        if (state.fit)() > 0 {
            let _ = eval.send(json!({"type": "fit"}));
        }
    });

    rsx! { div { id: "graph-canvas", class: "canvas" } }
}

#[component]
pub fn Toolbar() -> Element {
    let mut state = use_context::<AppState>();
    let view = (state.view)();
    let status = match &*state.graph.read() {
        Load::Ready(model) => format!("노드 {} · 서브그래프 {}", model.nodes.len(), model.subgraph_count()),
        _ => String::new(),
    };
    rsx! {
        div { class: "toolbar",
            div { class: "segmented",
                button { class: if view == View::Tree { "on" } else { "" }, onclick: move |_| state.view.set(View::Tree), "원인 트리" }
                button { class: if view == View::Flow { "on" } else { "" }, onclick: move |_| state.view.set(View::Flow), "시간 흐름" }
            }
            button { onclick: move |_| state.fit += 1, "전체 보기" }
            button {
                onclick: move |_| {
                    state.reload += 1;
                    state.refresh += 1;
                },
                "새로고침"
            }
            label { class: "check",
                input { r#type: "checkbox", checked: (state.live)(), oninput: move |e| state.live.set(e.checked()) }
                "자동 갱신"
            }
            div { class: "spacer" }
            span { class: "muted", "{status}" }
        }
    }
}

#[component]
pub fn Legend() -> Element {
    let items = [
        ("--request", "요청"),
        ("--intent", "의도"),
        ("--message", "메시지"),
        ("--segment", "결과"),
        ("--allow", "허용"),
        ("--review", "확인"),
        ("--deny", "차단"),
        ("--cause", "원인선"),
    ];
    rsx! {
        div { class: "legend",
            for (color, name) in items {
                span { i { style: "background: var({color})" } "{name}" }
            }
        }
    }
}
