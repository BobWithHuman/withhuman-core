//! The app's own screens, as Dioxus components: a bar naming the data source, and the
//! settings panel. The graph itself is the existing page, framed below the bar; screens can
//! move out of it into components here one at a time.

use std::sync::Arc;

use dioxus::prelude::*;

use crate::api::{Backend, Probe};
use crate::protocol;
use crate::settings::{Change, Public};

const CSS: &str = r#"
:root { --bg: #f6f7f9; --panel: #ffffff; --text: #1d2330; --muted: #6b7280; --line: #d9dde4;
        --accent: #2f6fde; --allow: #2f9e5b; --deny: #d64545; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #14171c; --panel: #1c2027; --text: #e4e7ec; --muted: #9aa3b1; --line: #2e343e; }
}
* { box-sizing: border-box; }
html, body, #main { margin: 0; height: 100%; }
body { background: var(--bg); color: var(--text);
       font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", "Apple SD Gothic Neo", "Noto Sans KR", sans-serif; }
.shell { height: 100%; display: flex; flex-direction: column; }
.bar { display: flex; align-items: center; gap: 10px; padding: 6px 14px; background: var(--panel);
       border-bottom: 1px solid var(--line); }
.bar .title { font-weight: 600; }
.bar .source { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
.bar .source.demo { color: var(--accent); }
button, input { font: inherit; color: var(--text); background: var(--bg); border: 1px solid var(--line);
                border-radius: 6px; padding: 4px 10px; }
button { cursor: pointer; }
button:disabled { opacity: .5; cursor: default; }
button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.body { flex: 1; position: relative; min-height: 0; }
.body iframe { border: 0; width: 100%; height: 100%; display: block; }
.panel { position: absolute; top: 0; right: 0; bottom: 0; width: min(380px, 100%); overflow: auto;
         background: var(--panel); border-left: 1px solid var(--line); box-shadow: -8px 0 24px rgba(0,0,0,.12);
         padding: 16px; display: flex; flex-direction: column; gap: 12px; }
.panel h2 { font-size: 14px; margin: 0; }
.panel label { display: flex; flex-direction: column; gap: 4px; color: var(--muted); }
.panel label.check { flex-direction: row; align-items: center; gap: 8px; color: var(--text); }
.panel input[type=text], .panel input[type=password] { width: 100%; padding: 6px 8px; }
.panel fieldset { border: 0; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 12px; }
.panel fieldset:disabled { opacity: .5; }
.panel .actions { display: flex; gap: 8px; justify-content: flex-end; }
.panel .path { color: var(--muted); font-size: 11px; word-break: break-all; }
.status.ok { color: var(--allow); }
.status.err { color: var(--deny); }
"#;

#[derive(Clone, PartialEq)]
enum Status {
    Idle,
    Busy(&'static str),
    Ok(String),
    Err(String),
}

#[component]
pub fn App() -> Element {
    let backend = use_context::<Arc<Backend>>();
    let mut public = use_signal(|| backend.settings());
    let mut open = use_signal(|| false);
    // Bumping it reloads the page, which then reads from the saved settings.
    let mut reload = use_signal(|| 0u32);

    let p = public();
    let src = format!("{}?r={}", protocol::URL, reload());
    rsx! {
        style { {CSS} }
        div { class: "shell",
            div { class: "bar",
                span { class: "title", "WithHuman Viewer" }
                if p.demo {
                    span { class: "source demo", "데모 데이터" }
                } else {
                    span { class: "source", title: "{p.neo4j_url}", "{p.neo4j_url} · {p.database} · {p.user}" }
                }
                button { onclick: move |_| reload += 1, "새로고침" }
                button { onclick: move |_| open.toggle(), if open() { "닫기" } else { "설정" } }
            }
            div { class: "body",
                iframe { src }
                if open() {
                    SettingsPanel {
                        current: p.clone(),
                        on_saved: move |next: Public| {
                            public.set(next);
                            open.set(false);
                            reload += 1;
                        },
                    }
                }
            }
        }
    }
}

#[component]
fn SettingsPanel(current: Public, on_saved: EventHandler<Public>) -> Element {
    let backend = use_context::<Arc<Backend>>();
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
            status.set(Status::Busy("연결하는 중…"));
            spawn(async move {
                status.set(match backend.test(change).await {
                    Ok(Probe { sessions, ms }) => Status::Ok(format!("연결됨 · 세션 {sessions}개 · {ms}ms")),
                    Err(e) => Status::Err(e),
                });
            });
        }
    };
    let save = move |_| match backend.save(change()) {
        Ok(next) => on_saved.call(next),
        Err(e) => status.set(Status::Err(e)),
    };

    let busy = matches!(status(), Status::Busy(_));
    let password_hint = if current.has_password { "비워 두면 저장된 비밀번호 유지" } else { "" };
    rsx! {
        div { class: "panel",
            h2 { "Neo4j 연결" }
            label { class: "check",
                input { r#type: "checkbox", checked: demo(), oninput: move |e| demo.set(e.checked()) }
                "데모 데이터 보기 (Neo4j 없이)"
            }
            fieldset { disabled: demo(),
                label { "주소"
                    input { r#type: "text", value: "{url}", oninput: move |e| url.set(e.value()) }
                }
                label { "데이터베이스"
                    input { r#type: "text", value: "{database}", oninput: move |e| database.set(e.value()) }
                }
                label { "사용자"
                    input { r#type: "text", value: "{user}", oninput: move |e| user.set(e.value()) }
                }
                label { "비밀번호"
                    input {
                        r#type: "password",
                        value: "{password}",
                        placeholder: password_hint,
                        oninput: move |e| password.set(e.value()),
                    }
                }
            }
            match status() {
                Status::Idle => rsx! {},
                Status::Busy(text) => rsx! { p { class: "status", "{text}" } },
                Status::Ok(text) => rsx! { p { class: "status ok", "{text}" } },
                Status::Err(text) => rsx! { p { class: "status err", "{text}" } },
            }
            div { class: "actions",
                button { disabled: busy || demo(), onclick: test, "연결 테스트" }
                button { class: "primary", disabled: busy, onclick: save, "저장" }
            }
            p { class: "path", "설정 파일: {current.path}" }
        }
    }
}
