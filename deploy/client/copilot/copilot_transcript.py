"""Reads a GitHub Copilot session transcript for the WithHuman Copilot hook.

Copilot's hooks carry no model answer, and the answer is where a turn states its `[의도]`
line. The session transcript has it: Copilot appends one JSON record per line to
`~/.copilot/session-state/<session>/events.jsonl`, and writes an `assistant.message` record
before it runs the calls that message asked for — so a message read here reaches the engine
before the Call it leads to is judged.

This module is the only code that knows that format, which Copilot does not promise to keep;
what it cannot read it leaves out rather than guesses.

Everything in the transcript is data the agent or a web page may have written. It is only
copied into events for the engine to judge, never acted on here.

Checked against Copilot CLI 1.0.115-7: `assistant.message` records (`messageId`, `content`),
and the MCP configuration files `copilot help mcp` names.

Python 3.8 or later, standard library only.
"""

import hashlib
import json
import os

import withhuman_bridge as bridge  # beside this file, or one directory up in the repository

COPILOT_VERSION = "1.0.115-7"
#: How far up from the working directory a workspace MCP configuration is looked for.
MAX_WORKSPACE_DEPTH = 24
#: MCP server names kept per session, so a long session's state stays small.
MAX_SERVERS = 200


def copilot_home():
    """Copilot's own directory, which `COPILOT_HOME` moves."""
    home = os.environ.get("COPILOT_HOME", "").strip()
    return home or os.path.join(os.path.expanduser("~"), ".copilot")


def transcript_path(session_id):
    """The session's transcript. No hook that judges a Call carries the path, so it is built
    from the session id the hook does carry."""
    if not session_id:
        return None
    return os.path.join(copilot_home(), "session-state", session_id, "events.jsonl")


# ---- which MCP server a call goes to ----


def _server_names(path):
    """The server names of one `mcpServers` file; none when it cannot be read."""
    try:
        with open(path, encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (OSError, ValueError):
        return []
    servers = loaded.get("mcpServers") if isinstance(loaded, dict) else None
    return [name for name in servers if isinstance(name, str)] if isinstance(servers, dict) else []


def configured_servers(cwd):
    """The MCP servers Copilot's configuration names: the user's own, and a workspace's.

    A call's tool name is `<server>-<tool>`, which cannot be taken apart without knowing the
    server — the server's own name holds hyphens. A server named nowhere here is still judged,
    under the name Copilot gave it, and learned from the MCP hook for the calls that follow.
    """
    found = set(_server_names(os.path.join(copilot_home(), "mcp-config.json")))
    directory = os.path.abspath(cwd) if cwd else None
    for _ in range(MAX_WORKSPACE_DEPTH):
        if not directory:
            break
        # A directory's `.github/mcp.json` is ignored when it also has a `.mcp.json`.
        own = os.path.join(directory, ".mcp.json")
        names = _server_names(own) if os.path.isfile(own) else _server_names(
            os.path.join(directory, ".github", "mcp.json"))
        found.update(names)
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    return found


def server_of(tool_name, servers):
    """The server a call goes to: the longest name the tool's own starts with. The longest wins
    because one server's name can begin with another's."""
    if not isinstance(tool_name, str):
        return None
    matching = [name for name in servers if tool_name.startswith(name + "-")]
    return max(matching, key=len) if matching else None


# ---- what the hook remembers of a session ----


class Session(bridge.State):
    """One Copilot session, as the hook remembers it between its runs.

    `turn` is a turn of this hook's own making. No Copilot hook carries one, and the
    transcript's `turnId` only appears once the model has answered — after the prompt whose
    turn it is. A turn minted when the prompt arrives covers every event until the next one,
    which is what the engine judges a Call against.

    Kept as `.state`, not `.json`: Copilot CLI 1.0.116 reads every `.json` file under
    `.github/hooks` as a hooks file — this bridge's state included — and warns at each session's
    start that its `hooks` is not an object.
    """

    SUFFIX = ".state"

    DEFAULTS = {
        #: Bytes of the transcript already read.
        "offset": 0,
        #: The turn every event belongs to until the next prompt.
        "turn": None,
        #: MCP servers seen in this session, learned from Copilot's own MCP hook.
        "servers": [],
    }

    def skip_to(self, offset):
        """Leaves earlier history unread: a resumed session's messages were judged when they
        happened."""
        self.state["offset"] = offset

    def learn_server(self, name):
        if not isinstance(name, str) or not name:
            return
        servers = [server for server in self.state["servers"] if server != name]
        servers.append(name)
        self.state["servers"] = servers[-MAX_SERVERS:]

    def sync(self, path, session_id):
        """The model's answers written since the last read, as Claude Code `MessageDisplay`
        events. Sent before the hook's own event, so the turn's intent reaches the engine
        before the Call it explains is judged."""
        records, offset = bridge.read_records(path, self.state["offset"])
        events = []
        for record in records:
            if record.get("type") != "assistant.message":
                continue
            data = record.get("data")
            if not isinstance(data, dict):
                continue
            text = data.get("content")
            if not isinstance(text, str) or not text.strip():
                # A message that only asked for tools carries no text.
                continue
            message_id = data.get("messageId")
            if not isinstance(message_id, str) or not message_id:
                message_id = hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]
            events.append(("MessageDisplay", {
                "session_id": session_id,
                "message_id": message_id,
                "index": 0,
                "delta": text,
                "final": True,
                "turn_id": self.state["turn"],
            }))
        self.state["offset"] = offset
        return events
