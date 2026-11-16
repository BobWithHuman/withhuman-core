//! A Codex shell command that ran and exited non-zero keeps its output.

use serde_json::{Value, json};
use withhuman_collector::codex::{Translated, translate};
use withhuman_contracts::codex::{CodexHookEvent, CodexHookInput, CodexShell};

const OUTPUT: &str = "Chunk ID: 1\nWall time: 0.2 seconds\nProcess exited with code 1\nOutput:\n\
# AGENT_INSTRUCTIONS.md\nEvery module MUST carry # MARKER\npytest : The term 'pytest' is not recognized\n";

fn failed(command: &str, response: Value) -> CodexHookInput {
    serde_json::from_value(json!({
        "session_id": "s", "turn_id": "t", "cwd": "C:\\proj", "tool_name": "Bash",
        "tool_use_id": "exec-1", "withhuman_workdir": "C:\\proj",
        "tool_input": {"command": command},
        "tool_response": response,
        "withhuman_failure": "exit code 1"
    }))
    .unwrap()
}

const READ_AND_TEST: &str =
    "Get-Content AGENT_INSTRUCTIONS.md; Get-Content src\\core.py; pytest -q";

#[test]
fn a_failed_command_is_a_result_with_what_it_printed() {
    let translation = translate(
        CodexHookEvent::PostToolUse,
        failed(READ_AND_TEST, json!(OUTPUT)),
        CodexShell::PowerShell,
    )
    .unwrap();
    let Translated::PostToolUse(request) = translation.request else {
        panic!("expected PostToolUse");
    };
    assert_eq!(request.tool_name, "PowerShell");
    assert_eq!(request.tool_response["stdout"], OUTPUT);
    assert_eq!(request.tool_response["stderr"], "(exit code 1)");
}

#[test]
fn still_a_failure_when_nothing_was_printed_or_it_is_not_a_command() {
    for response in [json!(""), json!("   \n"), Value::Null] {
        let translation = translate(
            CodexHookEvent::PostToolUse,
            failed(READ_AND_TEST, response),
            CodexShell::PowerShell,
        )
        .unwrap();
        assert!(matches!(
            translation.request,
            Translated::PostToolUseFailure(_)
        ));
    }
    // A shell write translated to Write stays a failed write.
    let translation = translate(
        CodexHookEvent::PostToolUse,
        failed(
            "Set-Content -LiteralPath 'a.txt' -Value 'hello'",
            json!(OUTPUT),
        ),
        CodexShell::PowerShell,
    )
    .unwrap();
    assert!(matches!(
        translation.request,
        Translated::PostToolUseFailure(_)
    ));
}
