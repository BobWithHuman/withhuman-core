//! The app's screens. One state, shared by context, drives them all: the sessions, the one
//! open, its graph, and what is selected in it.

mod canvas;
mod inspector;
mod settings;
mod sidebar;

use std::sync::Arc;
use std::time::Duration;

use dioxus::prelude::*;

use crate::api::Backend;
use crate::layout::{Model, View};
use crate::menu;
use crate::model::Session;
use crate::prefs::{Prefs, WindowPlace};
use crate::settings::Public;

pub const CSS: &str = include_str!("style.css");

/// Something loaded from the data source.
#[derive(Clone, Debug, PartialEq)]
pub enum Load<T> {
    Loading,
    Ready(T),
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Selection {
    None,
    Node(i64),
    /// A cause edge, from a Call to what it was traced to.
    Edge { call: i64, to: i64, id: String },
}

#[derive(Clone, Copy)]
pub struct AppState {
    pub public: Signal<Public>,
    pub prefs: Signal<Prefs>,
    pub sessions: Signal<Load<Vec<Session>>>,
    pub current: Signal<Option<String>>,
    pub graph: Signal<Load<Arc<Model>>>,
    pub view: Signal<View>,
    pub selected: Signal<Selection>,
    /// A node for the canvas to bring into view.
    pub focus: Signal<Option<i64>>,
    pub settings_open: Signal<bool>,
    pub live: Signal<bool>,
    pub inspector_width: Signal<f64>,
    /// Bumped to read the sessions, the graph, or fit the canvas again.
    pub reload: Signal<u32>,
    pub refresh: Signal<u32>,
    pub fit: Signal<u32>,
}

impl AppState {
    /// Opens a node of the session on screen: selects it and brings it into view.
    pub fn go_to(mut self, seq: i64) {
        self.selected.set(Selection::Node(seq));
        self.focus.set(Some(seq));
    }

    pub fn open_session(mut self, id: String) {
        if self.current.peek().as_deref() == Some(id.as_str()) {
            return;
        }
        self.selected.set(Selection::None);
        self.prefs.write().last_session = Some(id.clone());
        self.current.set(Some(id));
    }

    pub fn toggle_demo(mut self, backend: &Backend) {
        let demo = !self.public.peek().demo;
        if let Ok(next) = backend.set_demo(demo) {
            self.public.set(next);
            self.current.set(None);
            self.selected.set(Selection::None);
            self.reload += 1;
        }
    }
}

#[component]
pub fn App() -> Element {
    let backend = use_context::<Arc<Backend>>();
    let prefs = use_hook(Prefs::load);
    let view = if prefs.flow_view { View::Flow } else { View::Tree };
    let width = prefs.inspector_width.unwrap_or(INSPECTOR_WIDTH.1);
    let mut state = use_context_provider(|| AppState {
        public: Signal::new(backend.settings()),
        prefs: Signal::new(prefs),
        sessions: Signal::new(Load::Loading),
        current: Signal::new(None),
        graph: Signal::new(Load::Loading),
        view: Signal::new(view),
        selected: Signal::new(Selection::None),
        focus: Signal::new(None),
        settings_open: Signal::new(false),
        live: Signal::new(false),
        inspector_width: Signal::new(width),
        reload: Signal::new(0),
        refresh: Signal::new(0),
        fit: Signal::new(0),
    });
    use_loaders(backend.clone(), state);
    use_menu(backend.clone(), state);
    use_window_place(state);

    // Dragging the line between the graph and the inspector sets the inspector's width.
    let mut dragging = use_signal(|| false);
    let drag = move |e: MouseEvent| {
        if !dragging() {
            return;
        }
        let window = dioxus::desktop::window();
        let scale = window.scale_factor();
        let right = window.inner_size().to_logical::<f64>(scale).width;
        let width = (right - e.client_coordinates().x).clamp(INSPECTOR_WIDTH.0, INSPECTOR_WIDTH.2);
        state.inspector_width.set(width);
    };
    let drop = move |_| {
        if dragging() {
            dragging.set(false);
            state.prefs.write().inspector_width = Some((state.inspector_width)());
        }
    };

    rsx! {
        div {
            class: if dragging() { "app resizing" } else { "app" },
            onmousemove: drag,
            onmouseup: drop,
            onmouseleave: drop,
            TopBar {}
            div { class: "columns",
                sidebar::Sidebar {}
                main { class: "stage",
                    canvas::Toolbar {}
                    div { class: "canvas-wrap",
                        canvas::Canvas {}
                        StageNotice {}
                        canvas::Legend {}
                    }
                }
                div {
                    class: "splitter",
                    title: "끌어서 폭 조절 · 두 번 누르면 기본 폭",
                    onmousedown: move |e| {
                        e.prevent_default();
                        dragging.set(true);
                    },
                    ondoubleclick: move |_| {
                        state.inspector_width.set(INSPECTOR_WIDTH.1);
                        state.prefs.write().inspector_width = None;
                    },
                }
                inspector::Inspector {}
            }
            if (state.settings_open)() {
                settings::SettingsSheet {}
            }
        }
    }
}

/// The inspector's narrowest, default and widest width.
const INSPECTOR_WIDTH: (f64, f64, f64) = (300.0, 380.0, 760.0);

/// What the menu items and their shortcuts do.
fn use_menu(backend: Arc<Backend>, mut state: AppState) {
    dioxus::desktop::use_muda_event_handler(move |event| match event.id().as_ref() {
        menu::SETTINGS => state.settings_open.toggle(),
        menu::RELOAD => {
            state.reload += 1;
            state.refresh += 1;
        }
        menu::SEARCH => {
            document::eval("const s = document.getElementById('session-search'); s?.focus(); s?.select();");
        }
        menu::TREE => state.view.set(View::Tree),
        menu::FLOW => state.view.set(View::Flow),
        menu::FIT => state.fit += 1,
        menu::DEMO => state.toggle_demo(&backend),
        _ => {}
    });
}

/// Puts the window where it was last time, if that place is still on a screen, and remembers
/// where it goes: once it has stayed put for half a second.
fn use_window_place(mut state: AppState) {
    use dioxus::desktop::tao::event::{Event, WindowEvent};
    use dioxus::desktop::{LogicalPosition, LogicalSize};

    use_hook(move || {
        let Some(place) = state.prefs.peek().window else { return };
        let window = dioxus::desktop::window();
        let on_screen = window.available_monitors().any(|m| {
            let scale = m.scale_factor();
            let at = m.position().to_logical::<f64>(scale);
            let size = m.size().to_logical::<f64>(scale);
            place.x + 80.0 > at.x && place.x < at.x + size.width - 80.0 && place.y >= at.y - 10.0 && place.y < at.y + size.height - 80.0
        });
        window.set_inner_size(LogicalSize::new(place.width, place.height));
        if on_screen {
            window.set_outer_position(LogicalPosition::new(place.x, place.y));
        }
    });

    let mut moves = use_signal(|| 0u64);
    dioxus::desktop::use_wry_event_handler(move |event, _| {
        if !matches!(event, Event::WindowEvent { event: WindowEvent::Moved(_) | WindowEvent::Resized(_), .. }) {
            return;
        }
        moves += 1;
        let seen = *moves.peek();
        spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if *moves.peek() != seen {
                return;
            }
            let window = dioxus::desktop::window();
            if window.is_minimized() || window.fullscreen().is_some() || window.is_maximized() {
                return;
            }
            let scale = window.scale_factor();
            let (Ok(at), size) = (window.outer_position(), window.inner_size()) else { return };
            let at = at.to_logical::<f64>(scale);
            let size = size.to_logical::<f64>(scale);
            let place = WindowPlace { x: at.x, y: at.y, width: size.width, height: size.height };
            if state.prefs.peek().window != Some(place) {
                state.prefs.write().window = Some(place);
            }
        });
    });
}

/// Reads the sessions and the open session's graph whenever what they depend on changes.
fn use_loaders(backend: Arc<Backend>, mut state: AppState) {
    // Sessions: on launch, on reload, after the settings change.
    let b = backend.clone();
    use_effect(move || {
        let _ = (state.reload)();
        let _ = (state.public)();
        let b = b.clone();
        spawn(async move {
            let found = b.sessions().await;
            let mut current = state.current;
            match found {
                Ok(list) => {
                    // Keep the open session; else the last one opened, else the newest.
                    let open = current.peek().clone().filter(|id| list.iter().any(|s| &s.id == id));
                    let last = state.prefs.peek().last_session.clone().filter(|id| list.iter().any(|s| &s.id == id));
                    let pick = open.or(last).or_else(|| list.first().map(|s| s.id.clone()));
                    if *current.peek() != pick {
                        current.set(pick);
                    }
                    if *state.sessions.peek() != Load::Ready(list.clone()) {
                        state.sessions.set(Load::Ready(list));
                    }
                }
                Err(e) => {
                    current.set(None);
                    state.sessions.set(Load::Failed(e));
                }
            }
        });
    });

    // The graph: when another session opens, or on refresh.
    let b = backend.clone();
    use_effect(move || {
        let id = (state.current)();
        let _ = (state.refresh)();
        let b = b.clone();
        let Some(id) = id else {
            state.graph.set(Load::Loading);
            return;
        };
        if !matches!(*state.graph.peek(), Load::Ready(_)) {
            state.graph.set(Load::Loading);
        }
        spawn(async move {
            let found = b.graph(&id).await.map(|data| Arc::new(Model::build(&data)));
            if state.current.peek().as_deref() != Some(id.as_str()) {
                return;
            }
            let next = match found {
                Ok(model) => Load::Ready(model),
                Err(e) => Load::Failed(e),
            };
            if *state.graph.peek() != next {
                state.graph.set(next);
            }
        });
    });

    // Live: reads again every 3 seconds while it is on.
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if *state.live.peek() {
                state.reload += 1;
                state.refresh += 1;
            }
        }
    });

    // What to remember between launches.
    use_effect(move || {
        let flow = (state.view)() == View::Flow;
        if state.prefs.peek().flow_view != flow {
            state.prefs.write().flow_view = flow;
        }
    });
    use_effect(move || state.prefs.read().save());
}

#[component]
fn TopBar() -> Element {
    let backend = use_context::<Arc<Backend>>();
    let mut state = use_context::<AppState>();
    let p = (state.public)();
    rsx! {
        header { class: "topbar",
            span { class: "brand", "WithHuman Viewer" }
            div { class: "segmented",
                button { class: "on", "그래프" }
                button { disabled: true, title: "준비 중", "조건 비교" }
            }
            div { class: "spacer" }
            button {
                class: if p.demo { "source demo" } else { "source" },
                title: "연결 설정",
                onclick: move |_| state.settings_open.set(true),
                span { class: "dot" }
                if p.demo { "데모 데이터" } else { "Neo4j · {p.neo4j_url}" }
            }
            button {
                onclick: move |_| state.toggle_demo(&backend),
                if p.demo { "데모 끄기" } else { "데모 보기" }
            }
            button { class: "icon", title: "설정", onclick: move |_| state.settings_open.set(true), "⚙" }
        }
    }
}

/// A card over the canvas when there is nothing to draw: the source failed, it has no
/// sessions, or the graph is on its way.
#[component]
fn StageNotice() -> Element {
    let backend = use_context::<Arc<Backend>>();
    let mut state = use_context::<AppState>();
    let demo = (state.public)().demo;
    let sessions = (state.sessions)();
    let graph = (state.graph)();
    let retry = move |_| state.reload += 1;
    let b = backend.clone();
    let demo_button = rsx! {
        if !demo {
            button { onclick: move |_| state.toggle_demo(&b), "데모로 둘러보기" }
        }
    };
    match (sessions, graph) {
        (Load::Failed(message), _) => rsx! {
            Notice { title: if demo { "데모 데이터를 읽지 못했습니다" } else { "Neo4j에 연결할 수 없습니다" }, message,
                button { class: "primary", onclick: move |_| state.settings_open.set(true), "연결 설정" }
                {demo_button}
                button { onclick: retry, "다시 시도" }
            }
        },
        (Load::Loading, _) => rsx! { div { class: "loading", "불러오는 중…" } },
        (Load::Ready(list), _) if list.is_empty() => rsx! {
            Notice {
                title: "아직 세션이 없습니다",
                message: "에이전트를 WithHuman에 연결해 실행하면 세션이 여기에 나타납니다.",
                {demo_button}
                button { onclick: retry, "새로고침" }
            }
        },
        (_, Load::Failed(message)) => rsx! {
            Notice { title: "그래프를 불러오지 못했습니다", message,
                button { onclick: move |_| state.refresh += 1, "다시 시도" }
            }
        },
        (_, Load::Loading) => rsx! { div { class: "loading", "그래프를 불러오는 중…" } },
        _ => rsx! {},
    }
}

#[component]
fn Notice(title: String, message: String, children: Element) -> Element {
    rsx! {
        div { class: "notice-wrap",
            div { class: "notice",
                h2 { "{title}" }
                p { "{message}" }
                div { class: "actions", {children} }
            }
        }
    }
}
