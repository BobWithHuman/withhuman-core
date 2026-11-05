//! The sessions, newest first and grouped by day, pinned ones on top. Search, a folder filter
//! and "only with denials or reviews" narrow the list.

use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::{Datelike, Local, TimeZone};
use dioxus::prelude::*;

use super::{AppState, Load};
use crate::api::Backend;
use crate::layout::clip;
use crate::model::Session;

fn local(ms: i64) -> Option<chrono::DateTime<Local>> {
    Local.timestamp_millis_opt(ms).single()
}

/// "오늘", "어제", or the date, for the heading above a day's sessions.
fn day_label(ms: i64) -> String {
    let Some(at) = local(ms) else { return "날짜 없음".into() };
    let today = Local::now().date_naive();
    let day = at.date_naive();
    if day == today {
        "오늘".into()
    } else if today.pred_opt() == Some(day) {
        "어제".into()
    } else {
        const WEEKDAY: [&str; 7] = ["월", "화", "수", "목", "금", "토", "일"];
        let weekday = WEEKDAY[day.weekday().num_days_from_monday() as usize];
        if day.year() == today.year() {
            format!("{}월 {}일 ({weekday})", day.month(), day.day())
        } else {
            format!("{}년 {}월 {}일", day.year(), day.month(), day.day())
        }
    }
}

fn hhmm(ms: i64) -> String {
    local(ms).map(|t| t.format("%H:%M").to_string()).unwrap_or_default()
}

fn matches(s: &Session, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    query.is_empty()
        || [s.prompt.as_deref(), s.intent.as_deref(), s.cwd.as_deref(), Some(s.id.as_str())]
            .into_iter()
            .flatten()
            .any(|text| text.to_lowercase().contains(&query))
}

#[component]
pub fn Sidebar() -> Element {
    let state = use_context::<AppState>();
    let mut query = use_signal(String::new);
    let mut folder = use_signal(String::new);
    let mut flagged = use_signal(|| false);
    let mut message = use_signal(|| None::<(bool, String)>);

    let Load::Ready(list) = (state.sessions)() else {
        return rsx! { aside { class: "sidebar" } };
    };
    let folders: BTreeSet<String> = list.iter().map(Session::folder).filter(|f| !f.is_empty()).collect();
    let prefs = state.prefs.read().clone();
    let shown: Vec<&Session> = list
        .iter()
        .filter(|s| matches(s, &query()))
        .filter(|s| folder().is_empty() || s.folder() == folder())
        .filter(|s| !flagged() || s.flagged())
        .collect();
    let pinned: Vec<&Session> = shown.iter().copied().filter(|s| prefs.is_pinned(&s.id)).collect();
    let mut days: Vec<(String, Vec<&Session>)> = Vec::new();
    for s in shown.iter().copied().filter(|s| !prefs.is_pinned(&s.id)) {
        let label = day_label(s.created_at.unwrap_or(0));
        match days.last_mut() {
            Some((day, items)) if *day == label => items.push(s),
            _ => days.push((label, vec![s])),
        }
    }

    rsx! {
        aside { class: "sidebar",
            div { class: "filters",
                input {
                    id: "session-search",
                    r#type: "search",
                    placeholder: "프롬프트, 의도, 폴더, ID 검색",
                    value: "{query}",
                    oninput: move |e| query.set(e.value()),
                }
                div { class: "row",
                    select { value: "{folder}", onchange: move |e| folder.set(e.value()),
                        option { value: "", "모든 폴더" }
                        for f in folders {
                            option { value: "{f}", "{f}" }
                        }
                    }
                    label { class: "check",
                        input { r#type: "checkbox", checked: flagged(), oninput: move |e| flagged.set(e.checked()) }
                        "차단·확인만"
                    }
                }
            }
            if let Some((error, text)) = message() {
                p { class: if error { "message error" } else { "message" }, onclick: move |_| message.set(None), "{text}" }
            }
            div { class: "sessions",
                if shown.is_empty() {
                    p { class: "muted pad", "맞는 세션이 없습니다." }
                }
                if !pinned.is_empty() {
                    h3 { "고정됨" }
                    for s in pinned {
                        SessionItem { key: "{s.id}", session: s.clone(), pinned: true, message }
                    }
                }
                for (day, items) in days {
                    h3 { key: "{day}", "{day}" }
                    for s in items {
                        SessionItem { key: "{s.id}", session: s.clone(), pinned: false, message }
                    }
                }
            }
        }
    }
}

#[component]
fn SessionItem(session: Session, pinned: bool, message: Signal<Option<(bool, String)>>) -> Element {
    let backend = use_context::<Arc<Backend>>();
    let mut state = use_context::<AppState>();
    let current = state.current.read().as_deref() == Some(session.id.as_str());
    let id = session.id.clone();
    let open = {
        let id = id.clone();
        move |_| state.open_session(id.clone())
    };
    let pin = {
        let id = id.clone();
        move |e: MouseEvent| {
            e.stop_propagation();
            state.prefs.write().toggle_pin(&id);
        }
    };
    let delete = {
        let s = session.clone();
        move |e: MouseEvent| {
            e.stop_propagation();
            let backend = backend.clone();
            let s = s.clone();
            spawn(async move {
                let what = [s.folder(), clip(s.title(), 80), s.id.clone()]
                    .into_iter()
                    .filter(|t| !t.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n");
                let answer = rfd::AsyncMessageDialog::new()
                    .set_level(rfd::MessageLevel::Warning)
                    .set_title("세션 삭제")
                    .set_description(format!("이 세션을 삭제할까요? 그래프에서 영구히 지워지고 되돌릴 수 없습니다.\n\n{what}"))
                    .set_buttons(rfd::MessageButtons::OkCancelCustom("삭제".into(), "취소".into()))
                    .show()
                    .await;
                if answer != rfd::MessageDialogResult::Custom("삭제".into()) {
                    return;
                }
                match backend.delete(&s.id).await {
                    Ok(deleted) => {
                        state.prefs.write().pinned.retain(|p| p != &s.id);
                        if state.current.peek().as_deref() == Some(s.id.as_str()) {
                            state.current.set(None);
                        }
                        state.reload += 1;
                        let short: String = s.id.chars().take(8).collect();
                        message.set(Some((false, format!("세션 {short}을 삭제했습니다 (노드 {deleted}개)."))));
                    }
                    Err(e) => message.set(Some((true, format!("삭제하지 못했습니다: {e}")))),
                }
            });
        }
    };
    let folder = session.folder();
    let title = clip(session.title(), 90);
    rsx! {
        div {
            class: if current { "session current" } else { "session" },
            onclick: open,
            div { class: "top",
                span { class: "time", "{hhmm(session.created_at.unwrap_or(0))}" }
                if !folder.is_empty() {
                    span { class: "folder", "{folder}" }
                }
                div { class: "spacer" }
                span { class: "actions",
                    button { class: if pinned { "pin on" } else { "pin" }, title: if pinned { "고정 해제" } else { "고정" }, onclick: pin, "★" }
                    button { class: "delete", title: "삭제", onclick: delete, "✕" }
                }
            }
            p { class: "title", if title.is_empty() { "(프롬프트 없음)" } else { "{title}" } }
            div { class: "badges",
                if session.denied > 0 {
                    span { class: "badge deny", "차단 {session.denied}" }
                }
                if session.reviewed > 0 {
                    span { class: "badge review", "확인 {session.reviewed}" }
                }
                span { class: "badge", "Call {session.calls}" }
            }
        }
    }
}
