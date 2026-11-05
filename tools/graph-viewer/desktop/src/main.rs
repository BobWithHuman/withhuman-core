//! WithHuman Viewer, built with Dioxus: the app's chrome and settings are Dioxus components,
//! and the graph page that `server.py` serves runs inside it with Neo4j read from Rust, so it
//! runs without `server.py` or Python.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod demo;
mod graph;
mod protocol;
mod settings;
mod ui;

use std::sync::Arc;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

fn main() {
    // The page's requests run here, apart from the runtime that drives the components.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("viewer-api")
        .build()
        .expect("tokio runtime");
    let backend = Arc::new(api::Backend::load());

    let window = WindowBuilder::new()
        .with_title("WithHuman Viewer")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(960.0, 600.0));
    let config = Config::new()
        .with_window(window)
        .with_asynchronous_custom_protocol(protocol::SCHEME, protocol::handler(backend.clone(), runtime.handle().clone()));

    dioxus::LaunchBuilder::desktop().with_cfg(config).with_context(backend).launch(ui::App);
}
