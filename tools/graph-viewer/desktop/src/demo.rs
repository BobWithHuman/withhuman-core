//! The demo graph: the API's answers stored whole in `mock/fixture.json`, so the app can be
//! tried, and its screens worked on, without Neo4j. Read at launch rather than compiled in, so
//! the app still builds while the fixture is missing; without one the demo has no sessions.

use serde_json::{Map, Value, json};

use crate::graph::{ApiError, check_idle};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../mock/fixture.json");

pub struct Demo {
    data: Value,
}

impl Demo {
    pub fn load() -> Self {
        let path = std::env::var("VIEWER_FIXTURE").unwrap_or_else(|_| FIXTURE.to_owned());
        let data = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
            .unwrap_or_else(|e| {
                eprintln!("데모 데이터를 읽지 못했습니다 ({path}): {e}");
                json!({"sessions": [], "graphs": {}, "nodes": {}, "calls": {}})
            });
        Self { data }
    }

    pub fn sessions(&self) -> Value {
        self.data["sessions"].clone()
    }

    pub fn graph(&self, session: &str) -> Result<Value, ApiError> {
        self.data["graphs"].get(session).cloned().ok_or_else(|| ApiError::new(404, "세션을 찾지 못했습니다."))
    }

    pub fn node(&self, session: &str, seq: i64) -> Value {
        self.data["nodes"][session].get(seq.to_string()).cloned().unwrap_or(Value::Null)
    }

    pub fn calls(&self, sessions: &[String]) -> Value {
        let found: Map<String, Value> = sessions
            .iter()
            .map(|s| (s.clone(), self.data["calls"].get(s).cloned().unwrap_or_else(|| json!([]))))
            .collect();
        Value::Object(found)
    }

    /// Forgets a session until the app restarts, with the same refusal as Neo4j for an active one.
    pub fn delete(&mut self, session: &str) -> Result<Value, ApiError> {
        let list = self.data["sessions"].as_array_mut().ok_or_else(|| ApiError::new(500, "데모 데이터가 손상됐습니다."))?;
        let index = list
            .iter()
            .position(|s| s["id"] == session)
            .ok_or_else(|| ApiError::new(404, "세션을 찾지 못했습니다."))?;
        let s = &list[index];
        check_idle(s["last_at"].as_i64().or_else(|| s["created_at"].as_i64()))?;
        list.remove(index);
        let deleted = self.data["graphs"][session]["nodes"].as_array().map_or(0, Vec::len);
        for key in ["graphs", "nodes", "calls"] {
            if let Some(map) = self.data[key].as_object_mut() {
                map.remove(session);
            }
        }
        Ok(json!({"deleted": deleted}))
    }
}
