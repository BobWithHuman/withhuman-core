//! WithHuman Viewer: the execution graph the WithHuman engine records, read from Neo4j (or a
//! bundled demo) in a desktop app built with Dioxus.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod demo;
mod graph;
mod layout;
mod model;
mod prefs;
mod settings;
mod ui;

use std::sync::Arc;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

/// Cytoscape draws the graph canvas; it ships inside the app so the viewer works offline.
const CYTOSCAPE: &str = include_str!("../vendor/cytoscape.min.js");

fn main() {
    let backend = Arc::new(api::Backend::load());
    let window = WindowBuilder::new()
        .with_title("WithHuman Viewer")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(1000.0, 620.0));
    let head = format!("<meta charset=\"utf-8\"><style>{}</style><script>{CYTOSCAPE}</script>", ui::CSS);
    let config = Config::new().with_window(window).with_custom_head(head);
    dioxus::LaunchBuilder::desktop().with_cfg(config).with_context(backend).launch(ui::App);
}
