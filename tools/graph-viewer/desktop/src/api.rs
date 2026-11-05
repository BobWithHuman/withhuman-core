//! The app's state, and the page's `/api/...` requests answered as `server.py` answers them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::demo::Demo;
use crate::graph::{ApiError, Neo4j};
use crate::settings::{Change, Public, Settings};

pub struct Backend {
    client: reqwest::Client,
    settings: Mutex<Settings>,
    path: PathBuf,
    demo: Mutex<Demo>,
}

/// What a settings test found: how many sessions the graph holds, and how long it took.
#[derive(Clone, Debug, PartialEq)]
pub struct Probe {
    pub sessions: i64,
    pub ms: u128,
}

impl Backend {
    /// Settings live where the Tauri build kept them, so switching builds keeps the connection.
    pub fn load() -> Self {
        let path = dirs::config_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("dev.withhuman.viewer")
            .join("settings.json");
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("HTTP client");
        Self { client, settings: Mutex::new(Settings::load(&path)), path, demo: Mutex::new(Demo::load()) }
    }

    pub async fn handle(&self, method: &str, path: &str) -> Result<Value, ApiError> {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let query: HashMap<String, String> = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (decode(k), decode(v)))
            .collect();
        let arg = |key: &str| query.get(key).cloned().ok_or_else(|| ApiError::new(400, format!("{key}가 없습니다.")));
        let settings = self.settings.lock().expect("settings lock").clone();

        if settings.demo {
            let mut demo = self.demo.lock().expect("demo lock");
            return match (method, route) {
                ("GET", "/api/sessions") => Ok(demo.sessions()),
                ("GET", "/api/graph") => demo.graph(&arg("session")?),
                ("GET", "/api/node") => Ok(demo.node(&arg("session")?, seq(&arg("seq")?)?)),
                ("GET", "/api/calls") => Ok(demo.calls(&list(&arg("sessions")?))),
                ("DELETE", "/api/session") => demo.delete(&arg("session")?),
                _ => Err(ApiError::new(404, "not found")),
            };
        }

        let db = Neo4j { client: &self.client, settings: &settings };
        match (method, route) {
            ("GET", "/api/sessions") => db.sessions().await,
            ("GET", "/api/graph") => db.graph(&arg("session")?).await,
            ("GET", "/api/node") => db.node(&arg("session")?, seq(&arg("seq")?)?).await,
            ("GET", "/api/calls") => db.calls(&list(&arg("sessions")?)).await,
            ("DELETE", "/api/session") => db.delete_session(&arg("session")?).await,
            _ => Err(ApiError::new(404, "not found")),
        }
    }

    pub fn settings(&self) -> Public {
        self.settings.lock().expect("settings lock").public(&self.path)
    }

    pub fn save(&self, change: Change) -> Result<Public, String> {
        let mut settings = self.settings.lock().expect("settings lock");
        let next = settings.apply(change)?;
        next.save(&self.path)?;
        *settings = next;
        Ok(settings.public(&self.path))
    }

    /// Switches between the demo graph and Neo4j, keeping the connection as it is.
    pub fn set_demo(&self, demo: bool) -> Result<Public, String> {
        let mut settings = self.settings.lock().expect("settings lock");
        let next = Settings { demo, ..settings.clone() };
        next.save(&self.path)?;
        *settings = next;
        Ok(settings.public(&self.path))
    }

    /// Tries settings from the form before they are saved: connects and counts the sessions.
    pub async fn test(&self, change: Change) -> Result<Probe, String> {
        let candidate = self.settings.lock().expect("settings lock").apply(change)?;
        let started = Instant::now();
        let db = Neo4j { client: &self.client, settings: &candidate };
        let rows = db
            .cypher("MATCH (s:Session) RETURN count(s) AS sessions", "READ", json!({}))
            .await
            .map_err(|e| match e.status {
                401 => "사용자 이름이나 비밀번호가 맞지 않습니다.".to_owned(),
                _ => e.error,
            })?;
        let sessions = rows.first().and_then(|r| r.get("sessions")).and_then(Value::as_i64).unwrap_or(0);
        Ok(Probe { sessions, ms: started.elapsed().as_millis() })
    }
}

fn seq(text: &str) -> Result<i64, ApiError> {
    text.parse().map_err(|_| ApiError::new(400, "seq는 정수여야 합니다."))
}

fn list(text: &str) -> Vec<String> {
    text.split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

/// Percent-decoding for the query strings the page builds with `encodeURIComponent`.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match (escaped, bytes[i]) {
            (Some(byte), _) => {
                out.push(byte);
                i += 3;
                continue;
            }
            (None, b'+') => out.push(b' '),
            (None, byte) => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decodes_what_encode_uri_component_makes() {
        assert_eq!(decode("a%2Cb"), "a,b");
        assert_eq!(decode("%ED%95%9C"), "한");
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
    }
}
