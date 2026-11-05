//! The app's data source: Neo4j or the demo graph, chosen by the settings. The screens call
//! these functions directly and get typed answers.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::demo::Demo;
use crate::graph::{ApiError, Neo4j};
use crate::model::{GraphData, NodeDetail, Session};
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

/// The folder the app keeps its files in.
pub fn config_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(std::env::temp_dir).join("dev.withhuman.viewer")
}

impl Backend {
    pub fn load() -> Self {
        let path = config_dir().join("settings.json");
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("HTTP client");
        Self { client, settings: Mutex::new(Settings::load(&path)), path, demo: Mutex::new(Demo::load()) }
    }

    fn current(&self) -> Settings {
        self.settings.lock().expect("settings lock").clone()
    }

    pub async fn sessions(&self) -> Result<Vec<Session>, String> {
        let settings = self.current();
        let value = if settings.demo {
            Ok(self.demo.lock().expect("demo lock").sessions())
        } else {
            Neo4j { client: &self.client, settings: &settings }.sessions().await
        };
        typed(value)
    }

    pub async fn graph(&self, session: &str) -> Result<GraphData, String> {
        let settings = self.current();
        let value = if settings.demo {
            self.demo.lock().expect("demo lock").graph(session)
        } else {
            Neo4j { client: &self.client, settings: &settings }.graph(session).await
        };
        typed(value)
    }

    pub async fn node(&self, session: &str, seq: i64) -> Result<Option<NodeDetail>, String> {
        let settings = self.current();
        let value = if settings.demo {
            Ok(self.demo.lock().expect("demo lock").node(session, seq))
        } else {
            Neo4j { client: &self.client, settings: &settings }.node(session, seq).await
        };
        typed(value)
    }

    /// Deletes a session for good; returns how many nodes went with it.
    pub async fn delete(&self, session: &str) -> Result<i64, String> {
        let settings = self.current();
        let value = if settings.demo {
            self.demo.lock().expect("demo lock").delete(session)
        } else {
            Neo4j { client: &self.client, settings: &settings }.delete_session(session).await
        };
        value.map(|v| v["deleted"].as_i64().unwrap_or(0)).map_err(|e| e.error)
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

fn typed<T: DeserializeOwned>(value: Result<Value, ApiError>) -> Result<T, String> {
    let value = value.map_err(|e| e.error)?;
    serde_json::from_value(value).map_err(|e| format!("응답 형식이 예상과 다릅니다: {e}"))
}
