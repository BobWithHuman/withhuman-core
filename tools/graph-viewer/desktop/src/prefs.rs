//! What the viewer remembers between launches: pinned sessions, the last one opened, the view.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::api::config_dir;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub pinned: Vec<String>,
    pub last_session: Option<String>,
    pub flow_view: bool,
    pub inspector_width: Option<f64>,
    pub window: Option<WindowPlace>,
}

/// Where the window was, in logical points.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WindowPlace {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

fn path() -> PathBuf {
    config_dir().join("prefs.json")
}

impl Prefs {
    pub fn load() -> Self {
        fs::read_to_string(path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Best effort: losing a pin is not worth interrupting the user.
    pub fn save(&self) {
        let path = path();
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, text);
        }
    }

    pub fn is_pinned(&self, id: &str) -> bool {
        self.pinned.iter().any(|p| p == id)
    }

    pub fn toggle_pin(&mut self, id: &str) {
        if self.is_pinned(id) {
            self.pinned.retain(|p| p != id);
        } else {
            self.pinned.push(id.to_owned());
        }
    }
}
