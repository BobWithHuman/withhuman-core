use serde_json::{Value, json};
use withhuman_common::origin::{
    Origin, OriginContext, downloaded_paths, looks_rendered, tool_origin, tool_output,
};

fn origin(tool: &str, input: Value) -> Origin {
    tool_origin(
        tool,
        Some(&input),
        None,
        &OriginContext {
            cwd: Some("/repo"),
            ..Default::default()
        },
    )
}

#[test]
fn tells_external_tool_results_from_local_ones() {
    assert_eq!(
        origin("WebFetch", json!({"url":"https://a.test"})),
        Origin::External
    );
    assert_eq!(origin("WebSearch", json!({"query":"x"})), Origin::External);
    assert_eq!(
        origin("mcp__browser__navigate", json!({})),
        Origin::External
    );
    assert_eq!(
        origin("Bash", json!({"command":"curl -s https://a.test"})),
        Origin::External
    );
    assert_eq!(
        origin("Bash", json!({"command":"cd /tmp && wget a.test/x"})),
        Origin::External
    );
    assert_eq!(
        origin("Bash", json!({"command":"gh issue view 42"})),
        Origin::External
    );
    assert_eq!(
        origin("Bash", json!({"command":"/usr/bin/curl.exe a.test"})),
        Origin::External
    );
    assert_eq!(
        origin(
            "Read",
            json!({"file_path":"/home/me/Downloads/invoice.html"})
        ),
        Origin::External
    );
    assert_eq!(
        origin("Grep", json!({"pattern":"x","path":"/etc"})),
        Origin::External
    );

    assert_eq!(
        origin("Bash", json!({"command":"cat index.html"})),
        Origin::Local
    );
    assert_eq!(
        origin(
            "Bash",
            json!({"command":"git remote add origin https://github.com/a/b"})
        ),
        Origin::Local
    );
    assert_eq!(
        origin("Bash", json!({"command":"echo 'curl is a tool'"})),
        Origin::Local
    );
    assert_eq!(
        origin("Read", json!({"file_path":"/repo/web/index.html"})),
        Origin::Local
    );
    assert_eq!(
        origin("Read", json!({"file_path":"web/index.html"})),
        Origin::Local
    );
    assert_eq!(origin("Task", json!({"prompt":"summarize"})), Origin::Local);
}

#[test]
fn treats_vendored_code_as_external() {
    assert_eq!(
        origin(
            "Read",
            json!({"file_path":"/repo/node_modules/left-pad/README.md"})
        ),
        Origin::External
    );
    assert_eq!(
        origin("Read", json!({"file_path":"vendor/lib/a.php"})),
        Origin::External
    );
    assert_eq!(
        origin(
            "Bash",
            json!({"command":"cat .venv/lib/python3.12/site-packages/x/__init__.py"})
        ),
        Origin::External
    );
    assert_eq!(
        origin("Read", json!({"file_path":"/repo/src/vendors.ts"})),
        Origin::Local
    );
}

#[test]
fn treats_rendered_output_of_local_commands_as_external() {
    let page = "<!DOCTYPE html>\n<html><head><title>x</title></head><body>hi</body></html>";
    let judge = |command: &str, output: &str| {
        tool_origin(
            "Bash",
            Some(&json!({ "command": command })),
            Some(output),
            &OriginContext {
                cwd: Some("/repo"),
                ..Default::default()
            },
        )
    };
    assert_eq!(judge("python fetch.py", page), Origin::External);
    assert_eq!(
        judge(
            "python fetch.py",
            "HTTP/1.1 200 OK\nContent-Type: text/html"
        ),
        Origin::External
    );
    assert_eq!(judge("cat web/index.html", page), Origin::Local);
    assert_eq!(judge("python fetch.py", "fetched 3 items"), Origin::Local);
    assert!(looks_rendered("  <html lang=\"en\">\n<head>"));
    assert!(!looks_rendered("<div>fragment</div>"));
}

#[test]
fn accepts_configured_network_commands() {
    let commands = vec!["corp-fetch".to_owned()];
    let context = OriginContext {
        cwd: Some("/repo"),
        network_commands: &commands,
        downloaded_paths: &[],
    };
    let judge =
        |command: &str| tool_origin("Bash", Some(&json!({ "command": command })), None, &context);
    assert_eq!(judge("corp-fetch --page wiki/Home"), Origin::External);
    assert_eq!(judge("corp-build"), Origin::Local);
}

#[test]
fn finds_where_commands_save_downloads() {
    let paths = |command: &str| downloaded_paths(command, Some("/repo"));

    assert_eq!(
        paths("git clone https://github.com/acme/tool.git"),
        ["/repo/tool"]
    );
    assert_eq!(
        paths("git clone --depth 1 -b main git@github.com:acme/tool.git deps/tool"),
        ["/repo/deps/tool"]
    );
    assert_eq!(paths("gh repo clone acme/site"), ["/repo/site"]);
    assert_eq!(
        paths("cd vendor && git clone https://x.test/a/lib"),
        ["/repo/vendor/lib"]
    );
    assert_eq!(
        paths("curl -sL https://x.test/p.html -o page.html"),
        ["/repo/page.html"]
    );
    assert_eq!(
        paths("curl -O https://x.test/files/report.pdf"),
        ["/repo/report.pdf"]
    );
    assert_eq!(
        paths("curl https://x.test/a > /tmp/a.html"),
        ["/tmp/a.html"]
    );
    assert_eq!(
        paths("wget https://x.test/docs/guide.html"),
        ["/repo/guide.html"]
    );
    assert_eq!(
        paths("wget -O out.html https://x.test/"),
        ["/repo/out.html"]
    );
    assert_eq!(paths("wget -P dl https://x.test/"), ["/repo/dl/index.html"]);
    assert_eq!(
        paths("Invoke-WebRequest https://x.test -OutFile .\\page.html"),
        ["/repo/.\\page.html"]
    );
    assert!(paths("curl -s https://x.test | jq .").is_empty());
    assert!(paths("git status && cargo build > build.log").is_empty());
}

#[test]
fn treats_files_from_downloads_as_external() {
    let downloads = downloaded_paths(
        "curl -o page.html https://x.test && git clone https://x.test/a/lib",
        Some("/repo"),
    );
    let context = OriginContext {
        cwd: Some("/repo"),
        network_commands: &[],
        downloaded_paths: &downloads,
    };
    let judge =
        |path: &str| tool_origin("Read", Some(&json!({ "file_path": path })), None, &context);
    assert_eq!(judge("page.html"), Origin::External);
    assert_eq!(judge("/repo/lib/src/index.js"), Origin::External);
    assert_eq!(judge("/repo/library.md"), Origin::Local);
    assert_eq!(judge("/repo/src/main.rs"), Origin::Local);
}

#[test]
fn reads_web_search_results() {
    let response = json!({
        "query": "shared office",
        "results": [
            {"tool_use_id": "srvtoolu_1", "content": [
                {"title": "Office A", "url": "https://a.example.test"},
                {"title": "Office B", "url": "https://b.example.test"}
            ]},
            "Office A is next to the station."
        ],
        "durationSeconds": 1.2
    });

    assert_eq!(
        tool_output(&response).as_deref(),
        Some(
            "Office A\nhttps://a.example.test\n\nOffice B\nhttps://b.example.test\n\n\
             Office A is next to the station."
        )
    );
}
