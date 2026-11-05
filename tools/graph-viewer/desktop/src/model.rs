//! The API's answers as types. Node properties stay a JSON map: their keys differ by kind and
//! grow with the engine, and the inspector lists them all.

use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Session {
    pub id: String,
    pub created_at: Option<i64>,
    pub last_at: Option<i64>,
    pub nodes: i64,
    pub calls: i64,
    pub denied: i64,
    pub reviewed: i64,
    pub allowed: i64,
    pub failed: i64,
    pub prompt: Option<String>,
    pub intent: Option<String>,
    pub cwd: Option<String>,
}

impl Session {
    /// The last part of the working folder, whether it uses / or \.
    pub fn folder(&self) -> String {
        self.cwd
            .as_deref()
            .unwrap_or("")
            .split(['/', '\\'])
            .rfind(|s| !s.is_empty())
            .unwrap_or("")
            .to_owned()
    }

    pub fn title(&self) -> &str {
        self.prompt
            .as_deref()
            .or(self.intent.as_deref())
            .unwrap_or("")
    }

    pub fn flagged(&self) -> bool {
        self.denied + self.reviewed > 0
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct GraphData {
    pub nodes: Vec<Node>,
    pub subgraphs: Vec<SubGraph>,
    pub edges: Vec<Edge>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Node {
    pub kind: String,
    pub props: Map<String, Value>,
    pub summary: Summary,
}

/// The fields a node's caption needs, read by the API before its payload is cut short.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Summary {
    pub tool_name: Option<String>,
    pub brief: Option<String>,
    pub prompt: Option<String>,
    pub intent: Option<String>,
    pub text: Option<String>,
    pub error: Option<String>,
    pub file_path: Option<String>,
}

impl Node {
    pub fn seq(&self) -> i64 {
        self.props.get("seq").and_then(Value::as_i64).unwrap_or(-1)
    }

    pub fn order(&self) -> i64 {
        self.props.get("order").and_then(Value::as_i64).unwrap_or(0)
    }

    pub fn decision(&self) -> Option<&str> {
        self.props.get("decision").and_then(Value::as_str)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct SubGraph {
    pub props: Map<String, Value>,
    pub members: Vec<Option<i64>>,
}

impl SubGraph {
    pub fn number(&self) -> Option<i64> {
        self.props.get("number").and_then(Value::as_i64)
    }

    pub fn parent(&self) -> Option<&str> {
        self.props.get("parent").and_then(Value::as_str)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Edge {
    pub source: Option<i64>,
    pub target: Option<i64>,
    #[serde(rename = "type")]
    pub kind: String,
    pub props: Map<String, Value>,
    pub paragraph: Option<i64>,
}

impl Edge {
    pub fn is_cause(&self) -> bool {
        self.props.get("kind").and_then(Value::as_str) == Some("cause")
    }

    pub fn probability(&self) -> Option<f64> {
        self.props.get("probability").and_then(Value::as_f64)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct NodeDetail {
    pub kind: String,
    pub props: Map<String, Value>,
    pub paragraphs: Vec<Paragraph>,
    pub tokens: Vec<Token>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Paragraph {
    pub index: Option<i64>,
    pub hidden: Option<bool>,
    pub text: Option<String>,
    pub instructs: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Token {
    pub kind: Option<String>,
    pub category: Option<String>,
    pub slot: Option<String>,
    pub decoded: Value,
}

/// A JSON document stored as a string property; anything unreadable reads as nothing.
pub fn parse_json(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null)
}
