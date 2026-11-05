//! The connection sheet: where Neo4j is, tried before it is saved, or the demo instead.

use std::sync::Arc;

use dioxus::prelude::*;

use super::{AppState, Selection};
use crate::api::{Backend, Probe};
use crate::settings::Change;

#[derive(Clone, PartialEq)]
enum Status {
    Idle,
    Busy,
    Ok(String),
    Err(String),
}

#[component]
pub fn SettingsSheet() -> Element {
    let backend = use_context::<Arc<Backend>>();
    let mut state = use_context::<AppState>();
    let current = state.public.peek().clone();
    let mut url = use_signal(|| current.neo4j_url.clone());
    let mut database = use_signal(|| current.database.clone());
    let mut user = use_signal(|| current.user.clone());
    // Empty keeps the stored password.
    let mut password = use_signal(String::new);
    let mut demo = use_signal(|| current.demo);
    let mut status = use_signal(|| Status::Idle);

    let change = move || Change {
        neo4j_url: url(),
        database: database(),
        user: user(),
        password: Some(password()).filter(|p| !p.is_empty()),
        demo: demo(),
    };
    let test = {
        let backend = backend.clone();
        move |_| {
            let backend = backend.clone();
            let change = change();
            status.set(Status::Busy);
            spawn(async move {
                status.set(match backend.test(change).await {
                    Ok(Probe { sessions, ms }) => {
                        Status::Ok(format!("연결됨 · 세션 {sessions}개 · {ms}ms"))
                    }
                    Err(e) => Status::Err(e),
                });
            });
        }
    };
    let save = move |_| match backend.save(change()) {
        Ok(next) => {
            state.public.set(next);
            state.current.set(None);
            state.selected.set(Selection::None);
            state.settings_open.set(false);
        }
        Err(e) => status.set(Status::Err(e)),
    };
    let busy = status() == Status::Busy;
    let hint = if current.has_password {
        "비워 두면 저장된 비밀번호 유지"
    } else {
        ""
    };

    rsx! {
        div {
            class: "sheet-backdrop",
            tabindex: "-1",
            onmounted: move |e| async move {
                let _ = e.set_focus(true).await;
            },
            onkeydown: move |e| {
                if e.key() == Key::Escape {
                    state.settings_open.set(false);
                }
            },
            onclick: move |_| state.settings_open.set(false),
            div { class: "sheet", onclick: move |e| e.stop_propagation(),
                h2 { "데이터 연결" }
                div { class: "choice",
                    button { class: if !demo() { "on" } else { "" }, onclick: move |_| demo.set(false),
                        strong { "Neo4j" }
                        span { "WithHuman 엔진이 기록한 실제 세션" }
                    }
                    button { class: if demo() { "on" } else { "" }, onclick: move |_| demo.set(true),
                        strong { "데모로 둘러보기" }
                        span { "Neo4j 없이 예시 세션으로" }
                    }
                }
                fieldset { disabled: demo(),
                    label { "주소"
                        input { r#type: "text", value: "{url}", oninput: move |e| url.set(e.value()) }
                    }
                    div { class: "row",
                        label { "데이터베이스"
                            input { r#type: "text", value: "{database}", oninput: move |e| database.set(e.value()) }
                        }
                        label { "사용자"
                            input { r#type: "text", value: "{user}", oninput: move |e| user.set(e.value()) }
                        }
                    }
                    label { "비밀번호"
                        input { r#type: "password", value: "{password}", placeholder: hint, oninput: move |e| password.set(e.value()) }
                    }
                }
                match status() {
                    Status::Idle => rsx! {},
                    Status::Busy => rsx! { p { class: "status", "연결하는 중…" } },
                    Status::Ok(text) => rsx! { p { class: "status ok", "{text}" } },
                    Status::Err(text) => rsx! { p { class: "status error", "{text}" } },
                }
                div { class: "actions",
                    span { class: "muted path", "{current.path}" }
                    button { onclick: move |_| state.settings_open.set(false), "취소" }
                    button { disabled: busy || demo(), onclick: test, "연결 테스트" }
                    button { class: "primary", disabled: busy, onclick: save, "저장" }
                }
            }
        }
    }
}
