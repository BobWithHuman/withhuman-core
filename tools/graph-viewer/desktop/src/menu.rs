//! The menu bar and its shortcuts. Each item's id names the action the app takes for it.

use std::str::FromStr;

use dioxus::desktop::muda::accelerator::Accelerator;
use dioxus::desktop::muda::{AboutMetadata, Menu, MenuItem, PredefinedMenuItem, Submenu};

pub const SETTINGS: &str = "settings";
pub const RELOAD: &str = "reload";
pub const SEARCH: &str = "search";
pub const TREE: &str = "view-tree";
pub const FLOW: &str = "view-flow";
pub const FIT: &str = "fit";
pub const DEMO: &str = "demo";

fn item(id: &str, text: &str, shortcut: Option<&str>) -> MenuItem {
    let accelerator = shortcut.map(|s| Accelerator::from_str(s).expect("valid shortcut"));
    MenuItem::with_id(id, text, true, accelerator)
}

pub fn build() -> Menu {
    let menu = Menu::new();
    let about = AboutMetadata {
        name: Some("WithHuman Viewer".into()),
        version: Some(env!("CARGO_PKG_VERSION").into()),
        ..Default::default()
    };
    let app = Submenu::with_items(
        "WithHuman Viewer",
        true,
        &[
            &PredefinedMenuItem::about(Some("WithHuman Viewer에 관하여"), Some(about)),
            &PredefinedMenuItem::separator(),
            &item(SETTINGS, "설정…", Some("CmdOrCtrl+Comma")),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::hide(Some("WithHuman Viewer 가리기")),
            &PredefinedMenuItem::hide_others(Some("기타 가리기")),
            &PredefinedMenuItem::show_all(Some("모두 보기")),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::quit(Some("WithHuman Viewer 종료")),
        ],
    )
    .expect("app menu");
    let edit = Submenu::with_items(
        "편집",
        true,
        &[
            &PredefinedMenuItem::undo(Some("실행 취소")),
            &PredefinedMenuItem::redo(Some("실행 복귀")),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::cut(Some("오려두기")),
            &PredefinedMenuItem::copy(Some("복사하기")),
            &PredefinedMenuItem::paste(Some("붙여넣기")),
            &PredefinedMenuItem::select_all(Some("모두 선택")),
            &PredefinedMenuItem::separator(),
            &item(SEARCH, "세션 검색", Some("CmdOrCtrl+F")),
        ],
    )
    .expect("edit menu");
    let view = Submenu::with_items(
        "보기",
        true,
        &[
            &item(TREE, "원인 트리", Some("CmdOrCtrl+1")),
            &item(FLOW, "시간 흐름", Some("CmdOrCtrl+2")),
            &PredefinedMenuItem::separator(),
            &item(FIT, "전체 보기", Some("CmdOrCtrl+0")),
            &item(RELOAD, "새로고침", Some("CmdOrCtrl+R")),
            &PredefinedMenuItem::separator(),
            &item(DEMO, "데모 데이터 보기/끄기", None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::fullscreen(Some("전체 화면")),
        ],
    )
    .expect("view menu");
    let window = Submenu::with_items(
        "윈도우",
        true,
        &[
            &PredefinedMenuItem::minimize(Some("최소화")),
            &PredefinedMenuItem::maximize(Some("확대/축소")),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::close_window(Some("닫기")),
        ],
    )
    .expect("window menu");
    menu.append_items(&[&app, &edit, &view, &window]).expect("menu bar");
    menu
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcuts_parse() {
        for s in ["CmdOrCtrl+Comma", "CmdOrCtrl+F", "CmdOrCtrl+1", "CmdOrCtrl+2", "CmdOrCtrl+0", "CmdOrCtrl+R"] {
            assert!(Accelerator::from_str(s).is_ok(), "{s}");
        }
    }
}
