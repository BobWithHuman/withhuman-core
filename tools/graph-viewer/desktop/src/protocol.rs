//! The `viewer://` scheme: the graph page that `server.py` serves, unchanged, with its
//! `fetch('/api/...')` calls answered from Rust. The page needs no desktop-specific code.

use std::borrow::Cow;
use std::sync::Arc;

use dioxus::desktop::wry::http::{Request, Response};
use dioxus::desktop::wry::RequestAsyncResponder;
use tokio::runtime::Handle;

use crate::api::Backend;

pub const SCHEME: &str = "viewer";

/// Where the webview reaches the scheme: WebView2 maps custom schemes onto http hosts.
pub const URL: &str = if cfg!(windows) { "http://viewer.localhost/" } else { "viewer://localhost/" };

static PAGE: &str = include_str!("../../index.html");
static CYTOSCAPE: &str = include_str!("../vendor/cytoscape.min.js");
const CDN_CYTOSCAPE: &str = "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js";

/// The page with Cytoscape served locally, so the app works offline.
fn page() -> String {
    PAGE.replace(CDN_CYTOSCAPE, "/vendor/cytoscape.min.js")
}

pub fn handler(
    backend: Arc<Backend>,
    runtime: Handle,
) -> impl Fn(dioxus::desktop::wry::WebViewId, Request<Vec<u8>>, RequestAsyncResponder) + 'static {
    move |_, request, responder| {
        let method = request.method().as_str().to_owned();
        let target = request.uri().path_and_query().map_or("/", |p| p.as_str()).to_owned();
        let backend = backend.clone();
        runtime.spawn(async move {
            let route = target.split('?').next().unwrap_or("/");
            let response = match route {
                "/" | "/index.html" => reply(200, "text/html; charset=utf-8", page().into_bytes()),
                "/vendor/cytoscape.min.js" => reply(200, "text/javascript", CYTOSCAPE.as_bytes().to_vec()),
                _ if route.starts_with("/api/") => {
                    let (status, body) = match backend.handle(&method, &target).await {
                        Ok(value) => (200, value),
                        Err(e) => (e.status, serde_json::json!({ "error": e.error })),
                    };
                    reply(status, "application/json", serde_json::to_vec(&body).unwrap_or_default())
                }
                _ => reply(404, "text/plain", b"not found".to_vec()),
            };
            responder.respond(response);
        });
    }
}

fn reply(status: u16, content_type: &str, body: Vec<u8>) -> Response<Cow<'static, [u8]>> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(Cow::Owned(body))
        .expect("valid response")
}
