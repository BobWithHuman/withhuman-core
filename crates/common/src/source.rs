//! What a tool result came from, by every name the security team may distrust it under
//! (`distrusted_sources.source`). The Generator names a Call's cause with it for the team, and
//! Decision holds what a distrusted source caused, so both must read a source the same way.

use serde_json::Value;

/// The fields of a tool's input that say what a Call acts on, the first present one first.
pub const TARGET_FIELDS: [&str; 6] = ["command", "file_path", "url", "path", "pattern", "query"];
/// Those of them that name a document or a page: what a result came from.
pub const SOURCE_FIELDS: [&str; 3] = ["file_path", "url", "path"];

/// The distrusted ones among `$1::text[]`, compared as written.
pub const DISTRUSTED_SQL: &str =
    "SELECT source FROM distrusted_sources WHERE source = ANY($1::text[])";

/// The payload that says what told the agent: the Call's whose result it was, or the result's
/// own when the session does not hold that Call (a result still carries the tool and its input).
pub fn telling<'a>(call: &'a Value, result: &'a Value) -> &'a Value {
    if call.is_object() { call } else { result }
}

/// The payload's tool.
pub fn tool(payload: &Value) -> Option<String> {
    string(payload, "tool_name")
}

/// What the payload's Call acts on: the first of [`TARGET_FIELDS`] its input has.
pub fn target(payload: &Value) -> Option<String> {
    first(payload, &TARGET_FIELDS)
}

/// The document or page the payload's Call names: the first of [`SOURCE_FIELDS`] its input has.
pub fn document(payload: &Value) -> Option<String> {
    first(payload, &SOURCE_FIELDS)
}

/// Every name the source of the payload's result may be distrusted under, the most specific
/// first: its document or page, its target, each of them as written from the Call's folder
/// `cwd`, and its tool. The first of them the team distrusts is the one a match is shown under.
pub fn names(payload: &Value, cwd: Option<&str>) -> Vec<String> {
    let document = document(payload);
    let target = target(payload);
    let mut names: Vec<String> = Vec::new();
    let mut offer = |name: Option<String>| match name.filter(|name| !name.trim().is_empty()) {
        Some(name) if !names.contains(&name) => names.push(name),
        _ => {}
    };
    offer(document.clone());
    offer(target.clone());
    for name in [&document, &target] {
        offer(
            name.as_deref()
                .zip(cwd)
                .and_then(|(name, cwd)| below(name, cwd)),
        );
    }
    offer(tool(payload));
    names
}

/// `name` as written from the folder `cwd`: `.` for the folder itself, none outside it.
pub fn below(name: &str, cwd: &str) -> Option<String> {
    let cwd = cwd.trim_end_matches('/');
    if cwd.is_empty() {
        return None;
    }
    if name == cwd {
        return Some(".".to_owned());
    }
    name.strip_prefix(cwd)?
        .strip_prefix('/')
        .filter(|rest| !rest.is_empty())
        .map(str::to_owned)
}

fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

fn first(payload: &Value, fields: &[&str]) -> Option<String> {
    let input = payload.get("tool_input")?;
    fields
        .iter()
        .find_map(|field| string(input, field).filter(|value| !value.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_target_is_the_first_field_that_says_what_the_call_acts_on() {
        let read = json!({"tool_name": "Read", "tool_input": {"file_path": "/r/a.md", "limit": 5}});
        assert_eq!(target(&read).as_deref(), Some("/r/a.md"));
        let fetch = json!({"tool_name": "WebFetch",
            "tool_input": {"url": "https://example.com/a", "prompt": "summarise"}});
        assert_eq!(document(&fetch).as_deref(), Some("https://example.com/a"));
        let bash = json!({"tool_name": "Bash", "tool_input": {"command": "ls"}});
        assert_eq!(target(&bash).as_deref(), Some("ls"));
        assert_eq!(document(&bash), None);
        assert_eq!(target(&json!({"tool_name": "Task"})), None);
    }

    #[test]
    fn a_path_is_also_named_from_the_calls_folder() {
        assert_eq!(below("/r/docs/a.md", "/r").as_deref(), Some("docs/a.md"));
        assert_eq!(below("/r/docs/a.md", "/r/").as_deref(), Some("docs/a.md"));
        assert_eq!(below("/r", "/r").as_deref(), Some("."));
        assert_eq!(below("/rr/a.md", "/r"), None);
        assert_eq!(below("https://example.com/a", "/r"), None);
        assert_eq!(below("/r/a.md", ""), None);
    }

    #[test]
    fn a_source_is_named_by_its_document_target_folder_path_and_tool() {
        let read = json!({"tool_name": "Read", "tool_input": {"file_path": "/r/docs/a.md"}});
        assert_eq!(
            names(&read, Some("/r")),
            ["/r/docs/a.md", "docs/a.md", "Read"]
        );
        assert_eq!(names(&read, None), ["/r/docs/a.md", "Read"]);
        // A command is a target but no document, and a blank name is none.
        let bash = json!({"tool_name": "Bash", "tool_input": {"command": "cat a.md", "path": " "}});
        assert_eq!(names(&bash, Some("/r")), ["cat a.md", "Bash"]);
        assert_eq!(names(&json!({}), Some("/r")), Vec::<String>::new());
    }

    #[test]
    fn the_calls_payload_tells_before_the_results_own() {
        let call = json!({"tool_name": "Read"});
        let result = json!({"tool_name": "Bash"});
        assert_eq!(telling(&call, &result), &call);
        assert_eq!(telling(&Value::Null, &result), &result);
    }
}
