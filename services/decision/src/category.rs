//! What kind of thing a tool call does, from the tool's name: the groups the second question is
//! asked by (read, change, delete, send, transact, execute, access, delegate).
//!
//! Service tools are named for what they do (`ShopifyUpdateProduct`, `GmailSendEmail`,
//! `mcp__notes__create_note`): the name is split into words and its first verb gives the group,
//! with a few corrections (a "send" of money is a transaction). The agent's built-in tools are
//! listed. A name with no known verb is `Unknown`.
//!
//! A tool's own description of itself (MCP tool annotations such as `readOnlyHint`) is written by
//! whoever serves the tool, so it is not read here.
//!
//! A table of known tools (`WITHHUMAN_TOOL_CATEGORIES`: a CSV of `tool_name,category`, the
//! category one of the eleven classes or a group name) is read at start and used before the name.

use std::{collections::HashMap, path::Path, sync::OnceLock};

use serde::Serialize;

static TABLE: OnceLock<HashMap<String, Group>> = OnceLock::new();

/// The group a table's category names: the eleven classes (`read`, `search`, `compute`, `plan`,
/// `create`, `update`, `delete`, `send`, `transact`, `execute`, `browse`, `access`, `delegate`)
/// or a group's own name.
pub fn group_named(name: &str) -> Option<Group> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "read" | "search" | "compute" | "plan" => Group::Read,
        "create" | "update" | "change" => Group::Change,
        "delete" => Group::Delete,
        "send" => Group::Send,
        "transact" => Group::Transact,
        "execute" | "browse" => Group::Execute,
        "access" => Group::Access,
        "delegate" => Group::Delegate,
        _ => return None,
    })
}

/// Reads the table at `path` (once; later calls keep the first). Lines that name no known
/// category, and a header, are skipped. Returns how many tools it names.
pub fn load(path: &Path) -> std::io::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let table = parse(&text);
    let count = table.len();
    let _ = TABLE.set(table);
    Ok(count)
}

fn parse(text: &str) -> HashMap<String, Group> {
    text.lines()
        .filter_map(|line| {
            let (name, category) = line.rsplit_once(',')?;
            let name = name.trim().trim_matches('"');
            Some((
                name.to_ascii_lowercase(),
                group_named(category.trim_matches('"'))?,
            ))
        })
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

fn from_table(tool_name: &str) -> Option<Group> {
    let table = TABLE.get()?;
    let lower = tool_name.to_ascii_lowercase();
    table
        .get(&lower)
        .or_else(|| table.get(lower.rsplit("__").next().unwrap_or(&lower)))
        .copied()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Reads, searches, computes or plans; changes nothing outside.
    Read,
    /// Creates or updates something.
    Change,
    Delete,
    /// Sends or publishes something to someone.
    Send,
    /// Moves money or assets.
    Transact,
    /// Runs, operates or browses: what it does is in what it runs or presses.
    Execute,
    /// Grants, shares or changes access.
    Access,
    /// Hands work to another agent.
    Delegate,
    Unknown,
}

/// The group of a call to `tool_name`, and the word of the name that gave it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Category {
    pub group: Group,
    pub verb: Option<String>,
}

const READ: &[&str] = &[
    "get",
    "list",
    "search",
    "read",
    "view",
    "fetch",
    "find",
    "query",
    "check",
    "show",
    "lookup",
    "retrieve",
    "download",
    "describe",
    "count",
    "verify",
    "estimate",
    "look",
    "access",
    "browse",
    "inspect",
    "scan",
    "compute",
    "calculate",
    "plan",
    "recommend",
    "compare",
    "analyze",
];
const CHANGE: &[&str] = &[
    "create",
    "add",
    "insert",
    "update",
    "edit",
    "write",
    "set",
    "put",
    "append",
    "patch",
    "save",
    "upload",
    "modify",
    "rename",
    "move",
    "copy",
    "schedule",
    "book",
    "manage",
    "new",
    "make",
    "generate",
    "register",
    "enable",
    "disable",
    "configure",
    "assign",
    "complete",
    "mark",
];
const DELETE: &[&str] = &[
    "delete", "remove", "erase", "purge", "destroy", "drop", "unlink", "trash", "clear", "wipe",
];
const SEND: &[&str] = &[
    "send", "email", "mail", "reply", "forward", "post", "publish", "tweet", "notify", "sms",
    "message", "retweet", "comment",
];
const TRANSACT: &[&str] = &[
    "transfer", "pay", "withdraw", "deposit", "buy", "sell", "trade", "purchase", "checkout",
    "refund", "place",
];
const EXECUTE: &[&str] = &[
    "run", "execute", "exec", "click", "navigate", "go", "apply", "open", "launch", "start",
    "deploy", "install", "eval", "control", "action", "operate", "press", "type",
];
const ACCESS: &[&str] = &[
    "grant",
    "share",
    "revoke",
    "invite",
    "authorize",
    "permit",
    "unblock",
    "block",
    "allow",
];
const DELEGATE: &[&str] = &["delegate"];
/// Words that make a send, a transfer or a placing a transaction.
const MONEY: &[&str] = &[
    "money", "funds", "fund", "ether", "eth", "btc", "bitcoin", "crypto", "payment", "order",
    "cash", "coin", "token",
];

/// The group of a call to `tool_name`.
pub fn category(tool_name: &str) -> Category {
    let builtin = |group: Group| Category { group, verb: None };
    match tool_name {
        "Read" | "Glob" | "Grep" | "LS" | "WebFetch" | "WebSearch" | "TodoWrite" | "TodoRead" => {
            return builtin(Group::Read);
        }
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" | "apply_patch" => {
            return builtin(Group::Change);
        }
        "Bash" | "PowerShell" | "BashOutput" | "KillShell" => return builtin(Group::Execute),
        "Task" | "Agent" => return builtin(Group::Delegate),
        _ => {}
    }
    if let Some(group) = from_table(tool_name) {
        return Category {
            group,
            verb: Some("table".to_owned()),
        };
    }
    let words = words(tool_name);
    let found = words.iter().find_map(|word| {
        let group = if DELETE.contains(&word.as_str()) {
            Group::Delete
        } else if TRANSACT.contains(&word.as_str()) {
            Group::Transact
        } else if ACCESS.contains(&word.as_str()) {
            Group::Access
        } else if DELEGATE.contains(&word.as_str()) {
            Group::Delegate
        } else if SEND.contains(&word.as_str()) {
            Group::Send
        } else if EXECUTE.contains(&word.as_str()) {
            Group::Execute
        } else if CHANGE.contains(&word.as_str()) {
            Group::Change
        } else if READ.contains(&word.as_str()) {
            Group::Read
        } else {
            return None;
        };
        Some((group, word.clone()))
    });
    match found {
        Some((group, verb)) => {
            let money = words.iter().any(|word| MONEY.contains(&word.as_str()));
            let group = match group {
                // "SendMoney", "TransferEther": money moves.
                Group::Send if money => Group::Transact,
                // "PlaceOrder" is a transaction; "place" with no money is not.
                Group::Transact if verb == "place" && !money => Group::Change,
                group => group,
            };
            Category {
                group,
                verb: Some(verb),
            }
        }
        None => builtin(Group::Unknown),
    }
}

/// The lower-case words of a tool's name, past its `mcp__<server>__` prefix: split at `_`, `-`,
/// `.`, and where a capital follows a small letter or starts a word after capitals (`UIAction`:
/// `ui`, `action`).
fn words(tool_name: &str) -> Vec<String> {
    let name = tool_name.rsplit("__").next().unwrap_or(tool_name);
    let chars: Vec<char> = name.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        let boundary = c.is_uppercase()
            && i > 0
            && (chars[i - 1].is_lowercase()
                || chars[i - 1].is_ascii_digit()
                || chars.get(i + 1).is_some_and(|next| next.is_lowercase())
                    && chars[i - 1].is_uppercase());
        if boundary && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        word.extend(c.to_lowercase());
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(name: &str) -> Group {
        category(name).group
    }

    #[test]
    fn splits_names_into_words() {
        assert_eq!(words("mcp__rjudge__UIAction"), ["ui", "action"]);
        assert_eq!(
            words("EpicFHIRManagePatientRecords"),
            ["epic", "fhir", "manage", "patient", "records"]
        );
        assert_eq!(words("mcp__notes__create_note"), ["create", "note"]);
        assert_eq!(words("The23andMeGetGeneticData")[..2], ["the23and", "me"]);
    }

    #[test]
    fn groups_service_tools_by_their_verb() {
        assert_eq!(group("mcp__rjudge__ShopifyUpdateProduct"), Group::Change);
        assert_eq!(group("EvernoteManagerSearchNotes"), Group::Read);
        assert_eq!(group("GmailSendEmail"), Group::Send);
        assert_eq!(group("TwitterManagerPostTweet"), Group::Send);
        assert_eq!(group("BankManagerPayBill"), Group::Transact);
        assert_eq!(group("BankManagerSearchPayee"), Group::Read);
        assert_eq!(group("VenmoSendMoney"), Group::Transact);
        assert_eq!(group("EthereumManagerTransferEther"), Group::Transact);
        assert_eq!(group("BinancePlaceOrder"), Group::Transact);
        assert_eq!(group("BinanceGetOrderHistory"), Group::Read);
        assert_eq!(group("InventoryManagementSystemDeleteItem"), Group::Delete);
        assert_eq!(group("AugustSmartLockGrantGuestAccess"), Group::Access);
        assert_eq!(group("DropboxShareItem"), Group::Access);
        assert_eq!(group("WebBrowserClickElement"), Group::Execute);
        assert_eq!(group("IFTTTCreateApplet"), Group::Change);
        assert_eq!(group("SlackLeaveChannel"), Group::Unknown);
    }

    #[test]
    fn reads_a_table_of_classes_and_groups() {
        let table = parse(
            "tool_name,category
mcp__crm__sync_contacts,update
notion-move,create
weird,unknown
\"Lookup\",search
",
        );
        assert_eq!(table.get("mcp__crm__sync_contacts"), Some(&Group::Change));
        assert_eq!(table.get("notion-move"), Some(&Group::Change));
        assert_eq!(table.get("lookup"), Some(&Group::Read));
        assert!(!table.contains_key("weird"));
        assert!(!table.contains_key("tool_name"));
    }

    #[test]
    fn lists_the_agents_own_tools() {
        assert_eq!(group("Read"), Group::Read);
        assert_eq!(group("Edit"), Group::Change);
        assert_eq!(group("Bash"), Group::Execute);
        assert_eq!(group("Task"), Group::Delegate);
    }
}
